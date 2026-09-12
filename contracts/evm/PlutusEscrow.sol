// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "./interfaces/IERC20.sol";
import {SafeERC20} from "./libraries/SafeERC20.sol";
import {IProtocolRegistry} from "./interfaces/IProtocolRegistry.sol";

/// @title PlutusEscrow
/// @notice Non-custodial escrow with mandatory protocol fee enforcement.
/// @dev All token transfers use SafeERC20 to handle non-standard ERC20 tokens.
///
/// Lifecycle:
///   1. Constructor sets all parameters, reads fees from PRC
///   2. fund() — buyer deposits tokens
///   3. release() — buyer releases to seller (fees auto-deducted)
///   4. dispute(arbitrator) — buyer or seller flags dispute
///   5. settle(buyerPct, sellerPct) — arbitrator settles
///   6. refund() — after timeout, buyer can reclaim
contract PlutusEscrow {
    using SafeERC20 for IERC20;

    // --- State ---

    enum State {
        Pending,    // 0: created, awaiting funding
        Funded,     // 1: buyer has deposited tokens
        Released,   // 2: seller paid, escrow complete
        Disputed,   // 3: dispute flag raised
        Settled,    // 4: arbitrator ruled, funds distributed
        Refunded,   // 5: timeout reached, buyer refunded
        Cancelled   // 6: cancelled before funding
    }

    IProtocolRegistry public immutable prc;
    IERC20 public immutable token;
    address public immutable buyer;
    address public immutable seller;
    uint256 public immutable amount;
    uint256 public immutable timeoutBlock;
    address public immutable maintainerPayout;
    uint256 public immutable maintainerFeeBPS;
    uint256 public immutable witnessBPS;
    uint256 public immutable serviceProviderBPS;
    address public immutable serviceProviderPayout;
    uint256 public immutable arbitratorBPS;

    State public state;
    address public arbitrator;

    bytes32 public receiptHash;
    bytes32[] public witnessHashes;

    // --- Events ---

    event Funded(address indexed buyer, uint256 amount);
    event Released(address indexed seller, uint256 sellerAmount, uint256 maintainerFee, uint256 witnessFee);
    event Disputed(address indexed disputer, address indexed arbitrator);
    event Settled(address indexed arbitrator, uint256 buyerAmount, uint256 sellerAmount);
    event Refunded(address indexed buyer, uint256 amount);

    // --- Errors ---

    error OnlyBuyer();
    error OnlySeller();
    error OnlyBuyerOrSeller();
    error OnlyArbitrator();
    error InvalidState(State current, State required);
    error TimeoutNotReached();
    error TimeoutReached();
    error InvalidPercentages();
    error ZeroAddress();

    // --- Constructor ---

    /// @param _prc Protocol Registry Contract address
    /// @param _token ERC20 token used for payment
    /// @param _buyer Buyer's address
    /// @param _seller Seller's address
    /// @param _amount Escrow amount in token's smallest unit
    /// @param _timeoutBlock Block number after which buyer can refund
    /// @param _receiptHash Hash of the service receipt (bytes32(0) if none)
    /// @param _witnessHashes Hashes of witness attestations
    /// @param _serviceProviderBPS Service provider fee in basis points (0 if none)
    /// @param _serviceProviderPayout Address to receive service provider fee (address(0) if none)
    /// @param _arbitratorBPS Arbitrator fee in basis points (0 if no dispute expected)
    constructor(
        address _prc,
        address _token,
        address _buyer,
        address _seller,
        uint256 _amount,
        uint256 _timeoutBlock,
        bytes32 _receiptHash,
        bytes32[] memory _witnessHashes,
        uint256 _serviceProviderBPS,
        address _serviceProviderPayout,
        uint256 _arbitratorBPS
    ) {
        if (_prc == address(0)) revert ZeroAddress();
        if (_token == address(0)) revert ZeroAddress();
        if (_buyer == address(0)) revert ZeroAddress();
        if (_seller == address(0)) revert ZeroAddress();
        require(_amount > 0, "amount must be > 0");
        require(_timeoutBlock > block.number, "timeout must be in the future");

        prc = IProtocolRegistry(_prc);
        token = IERC20(_token);
        buyer = _buyer;
        seller = _seller;
        amount = _amount;
        timeoutBlock = _timeoutBlock;
        receiptHash = _receiptHash;
        witnessHashes = _witnessHashes;

        // Read immutable fee parameters from PRC at construction time.
        maintainerPayout = prc.maintainerPayout();
        maintainerFeeBPS = prc.maintainerFeeBPS();
        witnessBPS = prc.witnessBPS();

        // Service provider and arbitrator fees from constructor params.
        serviceProviderBPS = _serviceProviderBPS;
        serviceProviderPayout = _serviceProviderPayout;
        arbitratorBPS = _arbitratorBPS;

        state = State.Pending;
    }

    // --- Modifiers ---

    modifier onlyBuyer() {
        if (msg.sender != buyer) revert OnlyBuyer();
        _;
    }

    modifier onlySeller() {
        if (msg.sender != seller) revert OnlySeller();
        _;
    }

    modifier onlyBuyerOrSeller() {
        if (msg.sender != buyer && msg.sender != seller) revert OnlyBuyerOrSeller();
        _;
    }

    modifier onlyArbitrator() {
        if (msg.sender != arbitrator) revert OnlyArbitrator();
        _;
    }

    modifier inState(State required) {
        if (state != required) revert InvalidState(state, required);
        _;
    }

    modifier beforeTimeout() {
        if (block.number >= timeoutBlock) revert TimeoutReached();
        _;
    }

    modifier afterTimeout() {
        if (block.number < timeoutBlock) revert TimeoutNotReached();
        _;
    }

    // --- External Functions ---

    /// @notice Buyer deposits the escrow amount. Requires prior ERC20 approval.
    function fund() external onlyBuyer inState(State.Pending) beforeTimeout {
        token.safeTransferFrom(buyer, address(this), amount);
        state = State.Funded;
        emit Funded(buyer, amount);
    }

    /// @notice Buyer releases funds to the seller. Mandatory fees are deducted first.
    /// @dev The maintainer fee and witness fee are transferred before the seller receives
    ///      the remainder. This is the critical fee enforcement point — no code path
    ///      allows the seller to receive funds without the maintainer fee.
    function release() external onlyBuyer inState(State.Funded) {
        state = State.Released;

        // Calculate fees.
        uint256 mFee = (amount * maintainerFeeBPS) / 10000;
        uint256 wFee = witnessHashes.length > 0 ? (amount * witnessBPS) / 10000 : 0;
        uint256 remaining = amount - mFee - wFee;

        // Single transfer for maintainer + witness fees (witness fee distributed off-chain per protocol design).
        uint256 combinedMaintainerFee = mFee + wFee;
        if (combinedMaintainerFee > 0) {
            token.safeTransfer(maintainerPayout, combinedMaintainerFee);
        }

        // Service provider fee (if receipt hash present).
        if (receiptHash != bytes32(0)) {
            uint256 serviceFee = (amount * serviceProviderBPS) / 10000;
            if (serviceFee > 0 && serviceProviderPayout != address(0)) {
                token.safeTransfer(serviceProviderPayout, serviceFee);
                remaining -= serviceFee;
            }
        }

        // Transfer remainder to seller.
        token.safeTransfer(seller, remaining);

        emit Released(seller, remaining, mFee, wFee);
    }

    /// @notice Buyer or seller flags a dispute, nominating an arbitrator.
    /// @param _arbitrator Address of the arbitrator to resolve the dispute
    function dispute(address _arbitrator) external onlyBuyerOrSeller inState(State.Funded) {
        if (_arbitrator == address(0)) revert ZeroAddress();
        arbitrator = _arbitrator;
        state = State.Disputed;
        emit Disputed(msg.sender, _arbitrator);
    }

    /// @notice Arbitrator settles a disputed escrow by splitting funds.
    /// @param buyerPct Percentage of (amount - fees) to send to buyer (0-100)
    /// @param sellerPct Percentage of (amount - fees) to send to seller (0-100)
    function settle(uint256 buyerPct, uint256 sellerPct) external onlyArbitrator inState(State.Disputed) {
        if (buyerPct + sellerPct != 100) revert InvalidPercentages();

        state = State.Settled;

        // Calculate fees (same as release — maintainer fee is always mandatory).
        uint256 mFee = (amount * maintainerFeeBPS) / 10000;
        uint256 wFee = witnessHashes.length > 0 ? (amount * witnessBPS) / 10000 : 0;
        uint256 distributable = amount - mFee - wFee;

        // Service provider fee (if receipt hash present) — same gate as release().
        uint256 serviceFee = 0;
        if (receiptHash != bytes32(0)) {
            uint256 sf = (amount * serviceProviderBPS) / 10000;
            if (sf > 0 && serviceProviderPayout != address(0)) {
                serviceFee = sf;
                distributable -= sf;
            }
        }

        // Arbitrator fee (dispute was filed, so arbitrator is set).
        uint256 arbitratorFee = (amount * arbitratorBPS) / 10000;
        if (arbitratorFee > 0) {
            distributable -= arbitratorFee;
        }

        // Distribute remainder per ruling.
        uint256 buyerAmount = (distributable * buyerPct) / 100;
        uint256 sellerAmount = distributable - buyerAmount; // remainder to avoid rounding

        // Collect non-zero payouts into arrays, then loop once.
        address[] memory recipients = new address[](5);
        uint256[] memory amounts = new uint256[](5);
        uint256 count = 0;

        // Single transfer for maintainer + witness fees (witness fee distributed off-chain per protocol design).
        uint256 combinedMaintainerFee = mFee + wFee;
        if (combinedMaintainerFee > 0) {
            recipients[count] = maintainerPayout;
            amounts[count] = combinedMaintainerFee;
            count++;
        }
        if (serviceFee > 0) {
            recipients[count] = serviceProviderPayout;
            amounts[count] = serviceFee;
            count++;
        }
        if (arbitratorFee > 0) {
            recipients[count] = arbitrator;
            amounts[count] = arbitratorFee;
            count++;
        }
        if (buyerAmount > 0) {
            recipients[count] = buyer;
            amounts[count] = buyerAmount;
            count++;
        }
        if (sellerAmount > 0) {
            recipients[count] = seller;
            amounts[count] = sellerAmount;
            count++;
        }

        for (uint256 i = 0; i < count; i++) {
            token.safeTransfer(recipients[i], amounts[i]);
        }

        emit Settled(arbitrator, buyerAmount, sellerAmount);
    }

    /// @notice After timeout, buyer can reclaim the full escrow amount.
    /// @dev No fees are deducted on refund — the escrow was never fulfilled.
    function refund() external onlyBuyer inState(State.Funded) afterTimeout {
        state = State.Refunded;
        token.safeTransfer(buyer, amount);
        emit Refunded(buyer, amount);
    }

    // --- View Functions ---

    /// @notice Returns the number of witness hashes.
    function witnessHashCount() external view returns (uint256) {
        return witnessHashes.length;
    }

    /// @notice Returns a specific witness hash by index.
    function witnessHashAt(uint256 index) external view returns (bytes32) {
        return witnessHashes[index];
    }
}

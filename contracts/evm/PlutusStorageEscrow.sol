// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "./interfaces/IERC20.sol";
import {SafeERC20} from "./libraries/SafeERC20.sol";
import {IProtocolRegistry} from "./interfaces/IProtocolRegistry.sol";

/// @title PlutusStorageEscrow
/// @notice Pinning escrow: seller pays up-front for guaranteed retention of a
///         single CID by a single replicator; replicator posts a 10% bond; any
///         peer can challenge; missed responses slash the bond.
/// @dev One contract instance per (cid, replicator) pair. Replicator-side and
///      seller-side lifecycles are intentionally small — the heavy lifting
///      (fetching, holding, signing responses) happens off-chain; the contract
///      is a commitment + payout + slashing state machine.
///
/// Lifecycle:
///   1. constructor  — seller funds total fee; replicator must post bond via bondReplicator()
///   2. bondReplicator — replicator deposits 10% bond; status → Active
///   3. openChallenge — any peer posts a challenge with nonce + expectedHash
///   4. respond      — replicator submits response within 24h; contract checks hash
///                     - correct  → clearChallenge; missCount stays put
///                     - wrong    → miss recorded
///                     - timeout  → miss recorded (no response within 24h)
///   5. releaseWeekly — anyone can call; advances lastReleaseWeek; pays replicator
///                      1/weeksInDuration of the total fee. SEE DESIGN NOTE below.
///   6. slash        — 2nd miss in same week triggers slashing: bond split
///                     (90% to seller + 10% bounty to last challenger) + remaining
///                     weekly fees refunded to seller; status → Slashed
///   7. withdrawBond — after Status.Completed, replicator reclaims their bond.
///
/// DESIGN NOTE — WEEKLY RELEASE IS UNCONDITIONAL (by design):
///   releaseWeekly() pays the replicator the weekly fee REGARDLESS of whether
///   any individual in-week miss occurred. Enforcement lives entirely in the
///   2-misses-in-a-week slash rule: the first miss is a warning; the second
///   miss immediately slashes the bond AND refunds all unreleased weekly fees
///   to the seller (the contract transitions to Status.Slashed and
///   releaseWeekly reverts from then on). This keeps the weekly-release path
///   a simple cursor advance without a per-week liveness gate, at the
///   explicit cost of paying out for a week where exactly one response was
///   missed. The trade-off is deliberate: a single missed challenge is noisy
///   (transient connectivity, gossip lag) and we prefer false-negatives on
///   payment-withholding over griefing replicators with unpaid weeks.
///
/// ERC20 SUPPORT:
///   Fee-on-transfer / rebasing tokens are NOT supported. Bond + fee
///   accounting assumes the amount debited by safeTransferFrom equals the
///   amount credited to this contract's balance. The constructor and
///   bondReplicator enforce this with an explicit balance-delta check;
///   deployments MUST use a vanilla ERC20 (USDC, DAI, WETH, etc.).
///
/// CRYPTO PRIMITIVE DECISION:
///   On-chain BLAKE2b-256 is gas-prohibitive. Instead the challenge record on
///   chain stores an `expectedHash` (`keccak256(piece || nonce)`) the
///   challenger computed off-chain from the publicly known piece. The
///   replicator's defense path is to submit their response within the 24h
///   window, and the contract checks `keccak256(claimedResponse) ==
///   keccak256(claimedResponse)` trivially — the real verification is that
///   the response matches the CHALLENGER's pre-committed expectedHash
///   (which the challenger only knew because they actually held the piece).
///   See ROADMAP.md section 2 and PlutusStorageEscrow.t.sol.
contract PlutusStorageEscrow {
    using SafeERC20 for IERC20;

    // --- Constants --------------------------------------------------------

    /// @dev Challenge response window: replicator must respond within 24h.
    uint256 public constant CHALLENGE_WINDOW_SECONDS = 24 hours;

    /// @dev Bond is 10% of total fee.
    uint256 public constant BOND_BPS = 1_000; // 10%

    /// @dev Bounty share of slashed bond paid to the challenger who logged the 2nd miss.
    uint256 public constant BOUNTY_BPS = 1_000; // 10% of bond

    /// @dev Seconds per week, used to compute weeksInDuration.
    uint256 public constant WEEK_SECONDS = 7 days;

    // --- State ------------------------------------------------------------

    enum Status {
        Created,     // 0: constructor set parameters; seller has funded totalFee
        Active,      // 1: replicator bonded; pinning commitment live
        Completed,   // 2: full duration elapsed, all weekly releases paid out
        Slashed,     // 3: bond slashed, remainder refunded to seller
        Refunded     // 4: seller refunded before bond was posted (timeout)
    }

    // Immutable pinning parameters.
    IProtocolRegistry public immutable prc;
    IERC20 public immutable token;
    address public immutable seller;
    address public immutable replicator;
    bytes32 public immutable cidHash; // keccak256(cid-ASCII) — binds the contract to one CID
    uint256 public immutable duration;
    uint256 public immutable replicationFactor; // informational; fees are per-replicator
    uint256 public immutable totalFee;
    uint256 public immutable weeklyFee;
    uint256 public immutable weeksInDuration;
    uint256 public immutable bondAmount;
    uint256 public immutable startTime;
    uint256 public immutable endTime;
    uint256 public immutable bondDeadline; // if bond not posted by this time, seller can refund

    // Mutable state.
    Status public status;
    uint256 public lastReleaseWeek;   // 0..weeksInDuration, advances on each releaseWeekly
    uint256 public missCount;          // total misses across the whole lifecycle
    uint256 public missCountThisWeek;  // resets on each weekly release
    uint256 public slashedAmount;
    address public lastChallenger;     // last address to record a missed challenge (eligible for bounty)
    uint256 public lastResponseTime;   // wall-clock of the last accepted response (used by releaseWeekly)
    bool    public bondWithdrawn;      // true once replicator reclaims bond post-completion

    // Open-challenge tracking. At most one open challenge at a time to keep
    // state cheap + prevent griefing via challenge-spam. A new challenge
    // cannot be opened while one is outstanding.
    struct Challenge {
        address challenger;
        bytes32 nonce;         // random 32 bytes chosen by the challenger
        bytes32 expectedHash;  // keccak256(piece || nonce), precomputed off-chain
        uint256 openedAt;      // wall-clock when the challenge was opened
        bool open;             // true until respond() or expireChallenge() closes it
    }

    Challenge public currentChallenge;

    // --- Events -----------------------------------------------------------

    event PinCreated(
        address indexed seller,
        address indexed replicator,
        bytes32 indexed cidHash,
        uint256 totalFee,
        uint256 bondRequired,
        uint256 duration
    );
    event ReplicatorBonded(address indexed replicator, uint256 bondAmount);
    event ChallengeOpened(
        address indexed challenger,
        bytes32 nonce,
        bytes32 expectedHash,
        uint256 openedAt
    );
    event ChallengeResponded(address indexed replicator, bool ok, uint256 respondedAt);
    event ChallengeExpired(address indexed challenger, uint256 expiredAt);
    event MissLogged(address indexed challenger, uint256 weekIndex, uint256 missCountThisWeek);
    event WeeklyReleased(uint256 weekIndex, uint256 amountToReplicator);
    event BondSlashed(uint256 slashedAmount, uint256 refundToSeller, uint256 bounty, address bountyTo);
    event BondWithdrawn(address indexed replicator, uint256 amount);
    event RefundedToSeller(uint256 amount);
    event PinCompleted(uint256 totalPaid);

    // --- Errors -----------------------------------------------------------

    error OnlyReplicator();
    error OnlySeller();
    error InvalidStatus(Status current, Status required);
    error ChallengeAlreadyOpen();
    error NoOpenChallenge();
    error ChallengeWindowNotExpired();
    error ChallengeWindowClosed();
    error ChallengeResponseWrong();
    error BondAlreadyPosted();
    error BondNotPosted();
    error BondDeadlineNotPassed();
    error NoWeeklyReleaseReady();
    error AllWeeksReleased();
    error ZeroAddress();
    error ZeroAmount();
    error DurationTooShort();
    error FeeOnTransferUnsupported();
    error BondAlreadyWithdrawn();

    // --- Constructor ------------------------------------------------------

    /// @param _prc Protocol Registry Contract
    /// @param _token ERC20 used for fee + bond
    /// @param _seller Seller who funded the pin
    /// @param _replicator Replicator who will store the CID
    /// @param _cidHash keccak256 of the CID string (ASCII); binds this contract to one CID
    /// @param _duration Total pinning duration in seconds (must be multiple of WEEK_SECONDS)
    /// @param _replicationFactor Informational: how many replicators the seller paid for globally
    /// @param _feePerReplicator Total fee this replicator is owed (across the whole duration)
    /// @param _bondDeadline Unix time after which seller can refund if replicator never bonds
    constructor(
        address _prc,
        address _token,
        address _seller,
        address _replicator,
        bytes32 _cidHash,
        uint256 _duration,
        uint256 _replicationFactor,
        uint256 _feePerReplicator,
        uint256 _bondDeadline
    ) {
        if (_prc == address(0)) revert ZeroAddress();
        if (_token == address(0)) revert ZeroAddress();
        if (_seller == address(0)) revert ZeroAddress();
        if (_replicator == address(0)) revert ZeroAddress();
        if (_feePerReplicator == 0) revert ZeroAmount();
        if (_duration < WEEK_SECONDS) revert DurationTooShort();

        prc = IProtocolRegistry(_prc);
        token = IERC20(_token);
        seller = _seller;
        replicator = _replicator;
        cidHash = _cidHash;
        duration = _duration;
        replicationFactor = _replicationFactor;
        totalFee = _feePerReplicator;
        weeksInDuration = _duration / WEEK_SECONDS;
        weeklyFee = _feePerReplicator / (_duration / WEEK_SECONDS);
        bondAmount = (_feePerReplicator * BOND_BPS) / 10_000;
        startTime = block.timestamp;
        endTime = block.timestamp + _duration;
        bondDeadline = _bondDeadline;

        // Seller must have already approved `_feePerReplicator` to this
        // contract's address. We pull it now in the constructor so the
        // contract is immediately funded with the full fee. Bond is posted
        // separately (replicator calls bondReplicator()).
        //
        // Fee-on-transfer guard: this contract is not designed for tokens
        // that apply a transfer tax / rebase / skim. We verify the
        // transferred amount equals the requested amount so mis-wired
        // deployments fail fast rather than silently accumulating a
        // shortfall that would manifest as failed weekly payouts months
        // later.
        uint256 balanceBefore = token.balanceOf(address(this));
        token.safeTransferFrom(_seller, address(this), _feePerReplicator);
        uint256 balanceAfter = token.balanceOf(address(this));
        if (balanceAfter - balanceBefore != _feePerReplicator) revert FeeOnTransferUnsupported();

        status = Status.Created;

        emit PinCreated(
            _seller,
            _replicator,
            _cidHash,
            _feePerReplicator,
            bondAmount,
            _duration
        );
    }

    // --- Modifiers --------------------------------------------------------

    modifier onlyReplicator() {
        if (msg.sender != replicator) revert OnlyReplicator();
        _;
    }

    modifier onlySeller() {
        if (msg.sender != seller) revert OnlySeller();
        _;
    }

    modifier inStatus(Status required) {
        if (status != required) revert InvalidStatus(status, required);
        _;
    }

    // --- Replicator: bond posting ----------------------------------------

    /// @notice Replicator posts the 10% bond. Must have approved `bondAmount` first.
    /// @dev Enforces the same fee-on-transfer guard as the constructor so the
    ///      bond can be accounted for exactly during slashing + withdrawBond.
    function bondReplicator() external onlyReplicator inStatus(Status.Created) {
        uint256 balanceBefore = token.balanceOf(address(this));
        token.safeTransferFrom(replicator, address(this), bondAmount);
        uint256 balanceAfter = token.balanceOf(address(this));
        if (balanceAfter - balanceBefore != bondAmount) revert FeeOnTransferUnsupported();
        status = Status.Active;
        // Initialize lastResponseTime so the first week's release doesn't immediately
        // trigger a miss just because no challenge happened yet.
        lastResponseTime = block.timestamp;
        emit ReplicatorBonded(replicator, bondAmount);
    }

    /// @notice Seller can reclaim the total fee if replicator never bonded before deadline.
    function refundUnbonded() external onlySeller inStatus(Status.Created) {
        if (block.timestamp < bondDeadline) revert BondDeadlineNotPassed();
        status = Status.Refunded;
        token.safeTransfer(seller, totalFee);
        emit RefundedToSeller(totalFee);
    }

    // --- Challenges -------------------------------------------------------

    /// @notice Any peer opens a challenge: supply a random nonce + the
    ///         expected keccak256(piece || nonce) they computed off-chain.
    /// @dev A challenge that is never answered within CHALLENGE_WINDOW_SECONDS
    ///      can be converted to a miss via expireChallenge().
    function openChallenge(bytes32 nonce, bytes32 expectedHash) external inStatus(Status.Active) {
        if (currentChallenge.open) revert ChallengeAlreadyOpen();
        currentChallenge = Challenge({
            challenger: msg.sender,
            nonce: nonce,
            expectedHash: expectedHash,
            openedAt: block.timestamp,
            open: true
        });
        emit ChallengeOpened(msg.sender, nonce, expectedHash, block.timestamp);
    }

    /// @notice Replicator responds to the open challenge. If the response
    ///         matches the challenger's precomputed expectedHash, the
    ///         challenge is cleared; otherwise a miss is logged.
    /// @param response keccak256(piece || nonce) computed by the replicator
    function respond(bytes32 response) external onlyReplicator inStatus(Status.Active) {
        if (!currentChallenge.open) revert NoOpenChallenge();

        // Must be within the 24h window. After expiration only the challenger
        // (or anyone, via expireChallenge) can convert it to a miss.
        if (block.timestamp > currentChallenge.openedAt + CHALLENGE_WINDOW_SECONDS) {
            revert ChallengeWindowClosed();
        }

        bool ok = (response == currentChallenge.expectedHash);
        address challenger = currentChallenge.challenger;
        delete currentChallenge;

        if (ok) {
            lastResponseTime = block.timestamp;
            emit ChallengeResponded(replicator, true, block.timestamp);
            return;
        }

        // Wrong response — log miss.
        _logMiss(challenger);
        emit ChallengeResponded(replicator, false, block.timestamp);
    }

    /// @notice After the 24h response window, any caller can finalize the
    ///         missed challenge as a miss. Typically called by the challenger
    ///         themselves because they stand to earn the bounty on slash.
    function expireChallenge() external inStatus(Status.Active) {
        if (!currentChallenge.open) revert NoOpenChallenge();
        if (block.timestamp <= currentChallenge.openedAt + CHALLENGE_WINDOW_SECONDS) {
            revert ChallengeWindowNotExpired();
        }
        address challenger = currentChallenge.challenger;
        delete currentChallenge;
        _logMiss(challenger);
        emit ChallengeExpired(challenger, block.timestamp);
    }

    /// @dev Internal miss-logger. First miss in a week → warning. Second → slash.
    function _logMiss(address challenger) internal {
        missCount += 1;
        missCountThisWeek += 1;
        lastChallenger = challenger;
        emit MissLogged(challenger, lastReleaseWeek, missCountThisWeek);
        if (missCountThisWeek >= 2) {
            _slash(challenger);
        }
    }

    // --- Weekly release ---------------------------------------------------

    /// @notice Advance the release cursor by one week, paying the replicator
    ///         their weekly fee. Anyone can call (stateless poke). Reverts if
    ///         the week hasn't elapsed, if all weeks are paid, or if the
    ///         contract has been slashed.
    /// @dev Payment is UNCONDITIONAL (no per-week liveness gate). A single
    ///      miss is a warning; a second miss within the same week triggers
    ///      _slash() immediately inside respond()/expireChallenge(), which
    ///      moves the contract to Status.Slashed and this function reverts
    ///      thereafter via the inStatus(Active) modifier. See the DESIGN
    ///      NOTE at the top of the contract.
    function releaseWeekly() external inStatus(Status.Active) {
        if (lastReleaseWeek >= weeksInDuration) revert AllWeeksReleased();
        uint256 weekEnd = startTime + ((lastReleaseWeek + 1) * WEEK_SECONDS);
        if (block.timestamp < weekEnd) revert NoWeeklyReleaseReady();

        // Reset the per-week miss counter at week boundary.
        uint256 newWeek = lastReleaseWeek + 1;
        lastReleaseWeek = newWeek;
        missCountThisWeek = 0;

        // Pay replicator weekly fee. Per the DESIGN NOTE above, a single
        // miss earlier in the week is warning-only and does NOT block
        // payment; two misses would have already slashed the contract and
        // moved it out of Active, so reaching this line implies at most
        // one in-week miss.
        token.safeTransfer(replicator, weeklyFee);
        emit WeeklyReleased(newWeek, weeklyFee);

        // Mark completion when all weeks have been released.
        if (newWeek >= weeksInDuration) {
            status = Status.Completed;
            emit PinCompleted(totalFee);
        }
    }

    /// @notice Replicator reclaims their bond after normal completion.
    /// @dev Only callable in Status.Completed; Slashed contracts already
    ///      disbursed the bond inside _slash(). Idempotent via the
    ///      bondWithdrawn flag so a replicator cannot drain the bond
    ///      twice even if a token's nonstandard hook re-enters this
    ///      function (SafeERC20 uses standard transfer which does not
    ///      give call-back opportunities, but the flag is belt-and-
    ///      braces). The refund uses weeklyFee × weeksInDuration dust
    ///      mathematics accounting: if weeklyFee × weeksInDuration <
    ///      totalFee (integer-division truncation), the stranded dust
    ///      stays in the contract forever — withdrawBond deliberately
    ///      does NOT sweep it because the dust is, in the unslashed
    ///      happy path, owed to neither seller nor replicator per the
    ///      terms (fees are quoted per-week, weeklyFee rounded down).
    ///      Upstream UIs should size totalFee as a multiple of
    ///      weeksInDuration to avoid any dust at all.
    function withdrawBond() external onlyReplicator inStatus(Status.Completed) {
        if (bondWithdrawn) revert BondAlreadyWithdrawn();
        bondWithdrawn = true;
        token.safeTransfer(replicator, bondAmount);
        emit BondWithdrawn(replicator, bondAmount);
    }

    // --- Slashing ---------------------------------------------------------

    /// @dev Slash the bond: 10% bounty to the last challenger (if any), the
    ///      remainder refunded to the seller along with all unreleased weekly
    ///      fees. Status → Slashed.
    /// @dev DUST-SAFE MATH: `weeklyFee = totalFee / weeksInDuration` truncates,
    ///      so `unreleasedWeeks * weeklyFee` would strand up to
    ///      `weeksInDuration - 1` wei in the contract after a slash. Instead
    ///      we compute the refund as `totalFee - alreadyReleased` where
    ///      `alreadyReleased = lastReleaseWeek * weeklyFee` is the exact
    ///      amount paid out so far. Since every releaseWeekly transfers
    ///      exactly `weeklyFee`, that subtraction captures the unreleased
    ///      balance including any truncation dust, so the seller receives
    ///      every token left in the fee pot.
    function _slash(address challenger) internal {
        // Exact amount already paid out via weekly releases = lastReleaseWeek
        // transfers of exactly weeklyFee each. The remainder of totalFee
        // (naturally including the integer-division dust) refunds to seller.
        uint256 alreadyReleased = lastReleaseWeek * weeklyFee;
        uint256 refundFees = totalFee - alreadyReleased;

        uint256 bounty = (bondAmount * BOUNTY_BPS) / 10_000;
        uint256 sellerShareOfBond = bondAmount - bounty;
        uint256 totalToSeller = refundFees + sellerShareOfBond;

        slashedAmount = bondAmount;
        status = Status.Slashed;

        if (bounty > 0 && challenger != address(0)) {
            token.safeTransfer(challenger, bounty);
        }
        if (totalToSeller > 0) {
            token.safeTransfer(seller, totalToSeller);
        }

        emit BondSlashed(bondAmount, totalToSeller, bounty, challenger);
    }

    // --- View functions ---------------------------------------------------

    /// @notice Composite status snapshot for off-chain monitors.
    function getPinStatus()
        external
        view
        returns (
            Status _status,
            uint256 _lastReleaseWeek,
            uint256 _missCount,
            uint256 _missCountThisWeek,
            uint256 _slashedAmount,
            uint256 _endTime
        )
    {
        return (status, lastReleaseWeek, missCount, missCountThisWeek, slashedAmount, endTime);
    }

    /// @notice Per-replicator tally for reputation subsystems.
    function getReplicatorStats()
        external
        view
        returns (uint256 _totalFee, uint256 _bondAmount, uint256 _missCount, Status _status)
    {
        return (totalFee, bondAmount, missCount, status);
    }

    function getMissCount() external view returns (uint256) {
        return missCount;
    }

    function getSlashedAmount() external view returns (uint256) {
        return slashedAmount;
    }

    /// @notice Whether a challenge is currently outstanding.
    function hasOpenChallenge() external view returns (bool) {
        return currentChallenge.open;
    }
}

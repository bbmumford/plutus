// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IProtocolRegistry} from "./interfaces/IProtocolRegistry.sol";
import {IERC20} from "./interfaces/IERC20.sol";
import {SafeERC20} from "./libraries/SafeERC20.sol";
import {MerkleProof} from "./libraries/MerkleProof.sol";

/// @title ProtocolRegistry (PRC)
/// @notice Immutable Protocol Registry Contract — the constitutional root of Plutus fee enforcement.
/// @dev One deployment per chain. All escrows on this chain reference the same PRC.
///      Parameters are immutable after construction — the maintainer cannot change fees
///      or the payout address after deployment.
///
/// Core fields:
///   - PROTOCOL_ID: "plutus-v1" (constant, universal)
///   - maintainerPayout: address that receives all protocol fees
///   - maintainerFeeBPS: fee in basis points (max 500 = 5%)
///   - witnessBPS: witness attestation fee (max 100 = 1%)
///   - maintainerPubKeyHash: SHA256 of maintainer's Ed25519 public key
///
/// Optional features:
///   - App registration for analytics (no enforcement)
///   - Adapter approval via maintainer signature
///   - DESIGN §17 fee distribution: first-writer-wins via `distributedWindows`
///     idempotency mapping; anti-omission via `attestationLogRoot` Merkle proof.
contract ProtocolRegistry is IProtocolRegistry {
    using SafeERC20 for IERC20;

    string public constant PROTOCOL_ID = "plutus-v1";

    address public immutable override maintainerPayout;
    uint256 public immutable override maintainerFeeBPS;
    uint256 public immutable override witnessBPS;
    bytes32 public immutable maintainerPubKeyHash;
    bytes32 public immutable manifestHash;

    /// @notice Registered apps (for analytics only — unregistered apps still work).
    mapping(bytes32 => bool) public registeredApps;

    /// @notice Approved adapter hashes — set at construction time (immutable).
    /// @dev To add new adapters, deploy a new PRC with a rotation cert
    ///      authorizing the transition from the old PRC to the new one.
    mapping(bytes32 => bool) public approvedAdapters;

    /// @notice First-writer-wins gate for fee-distribution windows.
    /// @dev Key = (chainID, windowID) → attestationLogRoot. A zero value means
    ///      the window has NOT yet been distributed; a non-zero value is the
    ///      Merkle root of the attestation log that minted this window's
    ///      earnings. See DESIGN §17.
    mapping(bytes32 => mapping(uint64 => bytes32)) public distributedWindows;

    // --- Events ---

    event AppRegistered(bytes32 indexed appIDHash, address indexed registrant);

    /// @notice Emitted on the successful landing of a fee-distribution window.
    /// @param chainID The chain identifier (hash-encoded bytes32).
    /// @param windowID The window nonce (window-start Unix timestamp truncated
    ///                 to the distributor's window duration).
    /// @param attestationLogRoot Merkle root of the attestation IDs that fed
    ///                           this window's aggregated earnings.
    /// @param payoutCount Number of recipient payouts in the batch.
    event WindowDistributed(
        bytes32 indexed chainID,
        uint64 indexed windowID,
        bytes32 attestationLogRoot,
        uint256 payoutCount
    );

    /// @notice Emitted when an attester successfully proves they were omitted
    ///         from a distributed window (stub — slashing is a follow-up).
    event DistributionDisputed(
        bytes32 indexed chainID,
        uint64 indexed windowID,
        address indexed attester
    );

    // --- Errors ---

    error FeeTooHigh(string field, uint256 value, uint256 max);
    error ZeroAddress();
    error WindowAlreadyDistributed(bytes32 chainID, uint64 windowID);
    error LengthMismatch();
    error RootRequired();
    error WindowNotDistributed(bytes32 chainID, uint64 windowID);
    error ProofInvalid();

    // --- Constructor ---

    /// @param _payout Address to receive all protocol fees
    /// @param _maintainerBPS Maintainer fee in basis points (max 500)
    /// @param _witnessBPS Witness fee in basis points (max 100)
    /// @param _pubKeyHash SHA256 hash of the maintainer's Ed25519 public key
    /// @param _manifestHash SHA256 hash of the protocol manifest
    /// @param _approvedAdapters Array of pre-approved adapter hashes (immutable after deploy)
    constructor(
        address _payout,
        uint256 _maintainerBPS,
        uint256 _witnessBPS,
        bytes32 _pubKeyHash,
        bytes32 _manifestHash,
        bytes32[] memory _approvedAdapters
    ) {
        if (_payout == address(0)) revert ZeroAddress();
        if (_maintainerBPS > 500) revert FeeTooHigh("maintainerFeeBPS", _maintainerBPS, 500);
        if (_witnessBPS > 100) revert FeeTooHigh("witnessBPS", _witnessBPS, 100);

        maintainerPayout = _payout;
        maintainerFeeBPS = _maintainerBPS;
        witnessBPS = _witnessBPS;
        maintainerPubKeyHash = _pubKeyHash;
        manifestHash = _manifestHash;

        for (uint256 i = 0; i < _approvedAdapters.length; i++) {
            approvedAdapters[_approvedAdapters[i]] = true;
        }
    }

    // --- External Functions ---

    /// @notice Register an app for analytics tracking.
    /// @dev Any address can register an app. Registration is informational only —
    ///      unregistered apps still create escrows that enforce fees identically.
    /// @param appIDHash Keccak256 hash of the app identifier
    function registerApp(bytes32 appIDHash) external {
        registeredApps[appIDHash] = true;
        emit AppRegistered(appIDHash, msg.sender);
    }

    /// @notice Check if an adapter hash has been approved by the maintainer.
    /// @param adapterHash SHA256 hash of the adapter binary
    /// @return True if the adapter is approved
    function isApprovedAdapter(bytes32 adapterHash) external view returns (bool) {
        return approvedAdapters[adapterHash];
    }

    /// @notice Land a fee-distribution window on-chain.
    /// @dev DESIGN §17 first-writer-wins: the first successful call for a
    ///      (chainID, windowID) pair writes the attestationLogRoot and
    ///      disburses the payouts; every subsequent call with the same
    ///      (chainID, windowID) reverts with WindowAlreadyDistributed. This
    ///      is the on-chain idempotency gate that lets multiple witnesses
    ///      race the same window without double-paying.
    ///
    ///      Token transfers use SafeERC20 so USDT-style non-standard tokens
    ///      (no return value on success) are handled identically to
    ///      standards-compliant tokens.
    ///
    ///      The caller must have pre-approved this contract to spend at
    ///      least sum(amounts) of `token` on behalf of the pool — typically
    ///      the pool is an EOA that calls an external approve+distribute
    ///      script. Production deployments that store the pool balance
    ///      inside this contract should extend with a deposit path.
    ///
    /// @param chainID Canonical chain identifier (hash-encoded bytes32 — use
    ///                `bytes32(keccak256("polygon"))` etc).
    /// @param windowID Window nonce (window-start Unix timestamp truncated
    ///                 to the distributor's window duration).
    /// @param attestationLogRoot Merkle root of the attestation IDs that fed
    ///                           this window. Must be non-zero so auditors
    ///                           can detect omitted attesters via
    ///                           disputeDistribution.
    /// @param token ERC20 address of the witness-pool token to disburse.
    /// @param recipients Payout recipient addresses, in distributor-determined
    ///                   order. Length must equal amounts.length.
    /// @param amounts Per-recipient amounts in token's smallest unit.
    function distributeWindow(
        bytes32 chainID,
        uint64 windowID,
        bytes32 attestationLogRoot,
        address token,
        address[] calldata recipients,
        uint256[] calldata amounts
    ) external {
        if (distributedWindows[chainID][windowID] != bytes32(0)) {
            revert WindowAlreadyDistributed(chainID, windowID);
        }
        if (recipients.length != amounts.length) revert LengthMismatch();
        if (attestationLogRoot == bytes32(0)) revert RootRequired();

        // CEI: write the idempotency marker BEFORE transferring out. A
        // reentering ERC20 cannot re-enter distributeWindow for this
        // (chainID, windowID) because the mapping is already populated.
        distributedWindows[chainID][windowID] = attestationLogRoot;

        IERC20 erc20 = IERC20(token);
        for (uint256 i = 0; i < recipients.length; i++) {
            erc20.safeTransfer(recipients[i], amounts[i]);
        }

        emit WindowDistributed(chainID, windowID, attestationLogRoot, recipients.length);
    }

    /// @notice Prove that `msg.sender` was omitted from a distributed window.
    /// @dev DESIGN §17 anti-omission: an attester who earned fees in the
    ///      window but was NOT included as a `recipient` in the matching
    ///      `distributeWindow` call submits a Merkle proof that their
    ///      `attestationID` is a leaf of the stored `attestationLogRoot`.
    ///      A valid proof emits `DistributionDisputed`, which the off-chain
    ///      slashing watcher observes to dock the submitter's reward.
    ///
    ///      TODO: wire slashing. Full slashing requires tracking which
    ///      submitter landed each window (a deeper contract change: add a
    ///      `submitters` mapping populated by distributeWindow, plus a bond
    ///      collection path so there's something to slash). The stub
    ///      intentionally lands the proof-verification primitive first so
    ///      the off-chain watcher can start observing events and operators
    ///      have a shape to iterate on.
    ///
    /// @param chainID Chain identifier (must match a landed window).
    /// @param windowID Window nonce of the disputed distribution.
    /// @param attestationID The attestation-ID leaf the caller is asserting
    ///                      should have been paid.
    /// @param proof Merkle proof from the leaf up to the stored root (per
    ///              OpenZeppelin sorted-pair convention — see
    ///              libraries/MerkleProof.sol).
    function disputeDistribution(
        bytes32 chainID,
        uint64 windowID,
        bytes32 attestationID,
        bytes32[] calldata proof
    ) external {
        bytes32 root = distributedWindows[chainID][windowID];
        if (root == bytes32(0)) revert WindowNotDistributed(chainID, windowID);
        if (!MerkleProof.verify(proof, root, attestationID)) revert ProofInvalid();

        // TODO: wire slashing. See NatSpec above — needs submitter tracking
        // + a bond path so there's something to dock.
        emit DistributionDisputed(chainID, windowID, msg.sender);
    }

    // --- View Functions ---

    /// @notice Returns the protocol identifier.
    function protocolID() external pure returns (string memory) {
        return PROTOCOL_ID;
    }
}

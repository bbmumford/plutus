// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {ProtocolRegistry} from "../ProtocolRegistry.sol";

/// @title Deploy
/// @notice Deterministic PRC deployment via the Safe Singleton Factory (CREATE2).
/// Same address on every EVM chain the Singleton Factory is deployed to — but
/// the address CHANGES whenever the maintainer public key hash changes. This
/// couples the on-chain deployment identity to the off-chain trust anchor:
/// rotating the maintainer key forces buyers to migrate to a fresh PRC.
///
/// Usage:
///   forge script script/Deploy.s.sol --rpc-url $RPC_URL --broadcast --verify
///
/// Required env:
///   MAINTAINER_PAYOUT, MAINTAINER_PUBKEY_HASH, MANIFEST_HASH
/// Optional env:
///   MAINTAINER_FEE_BPS (default 100), WITNESS_BPS (default 25),
///   APPROVED_ADAPTERS (comma-sep bytes32 list, default empty)
contract Deploy is Script {
    address constant SAFE_SINGLETON_FACTORY = 0x914d7Fec6aaC8cd542e72Bca78B30650d45643d7;

    // Salt is computed per-run from MAINTAINER_PUBKEY_HASH; see computeSalt().
    // Must match canonical.PlutusPRCSalt() in Go: keccak256("plutus-v1-prc" || pkHash)
    // with raw byte concatenation (NOT abi.encode).
    bytes32 internal plutusPRCSalt;

    function run() external {
        address payout = vm.envAddress("MAINTAINER_PAYOUT");
        uint256 mBPS = vm.envOr("MAINTAINER_FEE_BPS", uint256(100));
        uint256 wBPS = vm.envOr("WITNESS_BPS", uint256(25));
        bytes32 pkHash = vm.envBytes32("MAINTAINER_PUBKEY_HASH");
        bytes32 manifestHash = vm.envBytes32("MANIFEST_HASH");
        bytes32[] memory adapters = vm.envOr("APPROVED_ADAPTERS", ",", new bytes32[](0));

        // Composite salt: bakes maintainer pubkey hash into the CREATE2 address,
        // so a key rotation ceremony yields a different canonical PRC address.
        plutusPRCSalt = computeSalt(pkHash);

        bytes memory initCode = abi.encodePacked(
            type(ProtocolRegistry).creationCode,
            abi.encode(payout, mBPS, wBPS, pkHash, manifestHash, adapters)
        );

        // Pre-compute the deterministic address before deploying for sanity-check + UX.
        address predicted = computeAddress(initCode);
        console.log("Predicted PRC address:", predicted);

        vm.startBroadcast();
        (bool ok, bytes memory ret) = SAFE_SINGLETON_FACTORY.call(
            abi.encodePacked(plutusPRCSalt, initCode)
        );
        require(ok, "PRC deployment via singleton factory failed");
        // Singleton factory returns the deployed address (20 bytes).
        address prc = address(uint160(uint256(bytes32(ret))));
        require(prc == predicted, "deployed address != predicted (factory unavailable on this chain?)");
        vm.stopBroadcast();

        console.log("PRC deployed at:", prc);
    }

    /// @notice Computes the CREATE2 salt as keccak256("plutus-v1-prc" || pkHash).
    /// @dev Uses abi.encodePacked for raw concatenation (no length prefix, no
    /// padding). The Go mirror is canonical.PlutusPRCSalt(); any divergence
    /// in the byte layout here breaks cross-language address prediction.
    function computeSalt(bytes32 pkHash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("plutus-v1-prc", pkHash));
    }

    function computeAddress(bytes memory initCode) internal view returns (address) {
        bytes32 hash = keccak256(
            abi.encodePacked(
                bytes1(0xff),
                SAFE_SINGLETON_FACTORY,
                plutusPRCSalt,
                keccak256(initCode)
            )
        );
        return address(uint160(uint256(hash)));
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title MerkleProof
/// @notice Minimal MerkleProof verifier compatible with OpenZeppelin-style
///         sorted-pair keccak256 binary Merkle trees, adequate for the
///         Plutus attestation-log anti-omission proof (PRC disputeDistribution).
/// @dev Inlined here so the contracts subtree stays dependency-free (no
///      node_modules / OpenZeppelin import). Mirror of the canonical
///      OpenZeppelin MerkleProof.verify / processProof routines at the
///      commit hashed in contracts/evm/foundry.toml — any drift must be
///      caught by testDisputeDistribution_ValidProofEmits.
library MerkleProof {
    /// @notice Returns true if a `leaf` can be proved to be part of a Merkle
    ///         tree defined by `root`. For this, a `proof` must be provided,
    ///         containing sibling hashes on the path from the leaf to the
    ///         root. Each pair of leaves and each pair of pre-images are
    ///         assumed to be sorted to match the OpenZeppelin convention.
    function verify(bytes32[] calldata proof, bytes32 root, bytes32 leaf) internal pure returns (bool) {
        return processProof(proof, leaf) == root;
    }

    /// @dev Returns the rebuilt hash obtained by traversing a Merkle tree up
    ///      from `leaf` using `proof`. A `proof` is valid if and only if the
    ///      rebuilt hash matches the root of the tree. When processing the
    ///      proof, the pairs of hashes are sorted using commutative hashing.
    function processProof(bytes32[] calldata proof, bytes32 leaf) internal pure returns (bytes32) {
        bytes32 computedHash = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            computedHash = _hashPair(computedHash, proof[i]);
        }
        return computedHash;
    }

    /// @dev Sorted-pair hash: keccak256(min || max). Matches the OpenZeppelin
    ///      standard tree convention (v4.9+).
    function _hashPair(bytes32 a, bytes32 b) private pure returns (bytes32) {
        return a < b ? _efficientHash(a, b) : _efficientHash(b, a);
    }

    function _efficientHash(bytes32 a, bytes32 b) private pure returns (bytes32) {
        bytes32 value;
        /// @solidity memory-safe-assembly
        assembly {
            mstore(0x00, a)
            mstore(0x20, b)
            value := keccak256(0x00, 0x40)
        }
        return value;
    }
}

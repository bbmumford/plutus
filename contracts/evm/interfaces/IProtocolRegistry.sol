// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IProtocolRegistry
/// @notice Interface for the Protocol Registry Contract (PRC).
interface IProtocolRegistry {
    function maintainerPayout() external view returns (address);
    function maintainerFeeBPS() external view returns (uint256);
    function witnessBPS() external view returns (uint256);
}

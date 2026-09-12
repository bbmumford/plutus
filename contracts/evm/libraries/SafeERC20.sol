// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "../interfaces/IERC20.sol";

/// @title SafeERC20
/// @notice Wrappers around ERC20 operations that throw on failure (when the
/// token contract returns false or does not return a value).
/// @dev Handles both compliant (returns bool) and non-compliant (reverts or
/// returns nothing) ERC20 tokens like USDT.
library SafeERC20 {
    error SafeERC20FailedOperation(address token);

    function safeTransfer(IERC20 token, address to, uint256 value) internal {
        _callOptionalReturn(token, abi.encodeCall(token.transfer, (to, value)));
    }

    function safeTransferFrom(IERC20 token, address from, address to, uint256 value) internal {
        _callOptionalReturn(token, abi.encodeCall(token.transferFrom, (from, to, value)));
    }

    function safeApprove(IERC20 token, address spender, uint256 value) internal {
        _callOptionalReturn(token, abi.encodeCall(token.approve, (spender, value)));
    }

    /// @dev Execute a call to an ERC20 token and check the return value.
    /// Handles tokens that return no value on success (like USDT).
    function _callOptionalReturn(IERC20 token, bytes memory data) private {
        (bool success, bytes memory returndata) = address(token).call(data);
        if (!success) {
            revert SafeERC20FailedOperation(address(token));
        }
        // If the call returned data, check it decoded to true.
        if (returndata.length > 0) {
            if (!abi.decode(returndata, (bool))) {
                revert SafeERC20FailedOperation(address(token));
            }
        }
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice A one-token list for `HandleEscrow.claim`.
function one(address token) pure returns (address[] memory tokens) {
    tokens = new address[](1);
    tokens[0] = token;
}

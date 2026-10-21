// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice The log every libid contract writes when a call carries a handle's text.
interface IHandleReveal {
    /// @notice `by` put `handle` on chain, folded; it hashes to `handleNode`
    ///         under `platformId`'s handle tag.
    event HandleRevealed(address indexed by, bytes32 indexed platformId, bytes32 indexed handleNode, string handle);
}

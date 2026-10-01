// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice ENSIP-10 wildcard resolution.
///
/// @dev A client that fails to find a resolver for the full ENS name strips
///      the leftmost label and asks again, until something answers. Whatever
///      it finds receives the ORIGINAL, complete ENS name — which is what lets
///      one resolver at `handles.link` serve every ENS name beneath it without
///      a registry entry per handle.
///
///      Declared here rather than vendored: one function does not justify a
///      dependency on the ENS contracts package.
interface IExtendedResolver {
    /// @param ensName DNS wire format, e.g. `\x05alice\x01x\x07handles\x04link\x00`.
    /// @param data    The resolution call the client wanted to make, such as
    ///                `addr(node, coinType)`.
    function resolve(bytes calldata ensName, bytes calldata data) external view returns (bytes memory);
}

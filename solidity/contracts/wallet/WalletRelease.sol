// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title WalletRelease - the release slot every wallet routes by.
/// @dev `{address implementation; uint64 version}` packed into one word as `implementation | version << 160`,
///      at `erc7201:libid.webwallet.release`. WebWallet, WalletProxy and WalletForwarder share it, so its
///      layout is frozen across releases.
library WalletRelease {
    // cast index-erc7201 libid.webwallet.release
    bytes32 internal constant SLOT = 0xe1dba8fb066a3b169f681c6818aeab86343e7484c7e0cee1cbf00e41a55c2800;

    function read() internal view returns (address, uint64) {
        uint256 word;
        assembly ("memory-safe") {
            word := sload(SLOT)
        }
        // forge-lint: disable-next-line(unsafe-typecast)
        return (address(uint160(word)), uint64(word >> 160));
    }

    function implementation() internal view returns (address impl) {
        assembly ("memory-safe") {
            impl := and(sload(SLOT), 0xffffffffffffffffffffffffffffffffffffffff)
        }
    }

    function write(address impl, uint64 version) internal {
        uint256 word = uint256(uint160(impl)) | (uint256(version) << 160);
        assembly ("memory-safe") {
            sstore(SLOT, word)
        }
    }
}

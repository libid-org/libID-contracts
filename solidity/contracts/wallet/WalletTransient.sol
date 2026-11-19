// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title WalletTransient - the wallet's transient flags.
/// @dev Each at its ERC-7201 slot under `libid.transient.webwallet`. Every release reads and writes them,
///      so their slots are frozen across releases.
library WalletTransient {
    // cast index-erc7201 libid.transient.webwallet.lock
    bytes32 internal constant LOCK = 0xc9e10f29671c1e91671796ae10cf0910e186e77a658823020379090d44874400;
    // cast index-erc7201 libid.transient.webwallet.entryPointBlocked
    bytes32 internal constant ENTRY_POINT_BLOCKED = 0xd9893535c4c4b5cd665ca764f2da4f77d7dc5ab6d2372696ca69936a0c362100;
    // cast index-erc7201 libid.transient.webwallet.dataStep
    bytes32 internal constant DATA_STEP = 0x634693ff7eb334934b2860ed0d3d3a4ad5bfbd5aa7959baa8bf9f0bcd8c88000;

    function get(bytes32 slot) internal view returns (bool set) {
        assembly ("memory-safe") {
            set := tload(slot)
        }
    }

    function put(bytes32 slot, bool set) internal {
        assembly ("memory-safe") {
            tstore(slot, set)
        }
    }
}

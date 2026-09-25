// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {HandleEscrow} from "../HandleEscrow.sol";

/// @notice Holds `HandleEscrow`'s namespaced struct as an ordinary state
///         variable, so the compiler's storage layout lists its fields.
///
/// @dev `forge inspect HandleEscrow storageLayout` is empty: every field the
///      escrow keeps is under its ERC-7201 root, which the layout output does
///      not describe. Declared here at slot 0, the struct's fields come out
///      with their slots and offsets relative to that root, and
///      `scripts/check-storage-layout.py` compares them with the committed
///      snapshot. Never deployed; nothing calls it.
contract HandleEscrowStorageLayout {
    HandleEscrow.HandleEscrowStorage internal root;
}

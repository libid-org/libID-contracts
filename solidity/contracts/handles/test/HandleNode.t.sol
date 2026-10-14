// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";

import {CeremonyProfile} from "../../ceremony/CeremonyProfile.sol";
import {HandleNode} from "../HandleNode.sol";
import {HandleTable} from "./HandleTable.sol";

/// @notice The shared handle vector table's accepted rows, run against the Solidity fold.
contract HandleNodeTest is Test {
    /// An accepted row folds to its output and hashes to its handle node.
    function test_everyAcceptedRowFoldsToItsHandleNode() public view {
        HandleTable.Row[] memory rows = HandleTable.accepted();
        assertGt(rows.length, 0, "no accepted row was checked");
        for (uint256 i = 0; i < rows.length; i++) {
            HandleTable.Row memory r = rows[i];
            (string memory folded, bytes32 node) =
                HandleNode.nodeOf(CeremonyProfile.handleTag(keccak256(bytes(r.platform))), r.input);
            assertEq(folded, r.output, string.concat("row ", vm.toString(i), " folded to the wrong handle"));
            assertEq(node, r.handleNode, string.concat("row ", vm.toString(i), " names the wrong node"));
        }
    }

    /// Case folding is the only change, to any text: nothing is trimmed, stripped or refused.
    function test_foldingIsTheOnlyChange() public pure {
        assertEq(HandleNode.fold("A.B+tag@Example.COM"), "a.b+tag@example.com");
        assertEq(HandleNode.fold(" @Alice_1 "), " @alice_1 ");
        assertEq(HandleNode.fold(""), "");
        // The bytes either side of A-Z, and a byte above 0x7f.
        assertEq(HandleNode.fold("@AZ[`az{\xc3\x89"), "@az[`az{\xc3\x89");
    }

    /// The fold copies: the caller's text is unchanged.
    function test_theFoldLeavesItsInputAlone() public pure {
        string memory raw = "Alice";
        HandleNode.fold(raw);
        assertEq(raw, "Alice");
    }
}

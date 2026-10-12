// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {HandleNormalizer} from "../HandleNormalizer.sol";
import {HandlePlatforms} from "../HandlePlatforms.sol";
import {HandleVectors} from "../HandleVectors.sol";

/// @notice The shared handle vector table's accepted cases, run against the Solidity fold.
contract HandleNormalizerTest is Test {
    /// An accepted vector folds to its output and hashes to its handle node.
    function test_everyAcceptedVectorFoldsToItsHandleNode() public pure {
        HandleVectors.Vector[] memory vectors = HandleVectors.all();
        uint256 checked;
        for (uint256 i = 0; i < vectors.length; i++) {
            HandleVectors.Vector memory v = vectors[i];
            if (!v.accepted) {
                assertEq(v.handleNode, bytes32(0), string.concat("refused vector ", vm.toString(i), " names a node"));
                continue;
            }
            (string memory folded, bytes32 node) = HandlePlatforms.handleNodeOf(keccak256(bytes(v.platform)), v.input);
            assertEq(folded, v.output, string.concat("vector ", vm.toString(i), " folded to the wrong handle"));
            assertEq(node, v.handleNode, string.concat("vector ", vm.toString(i), " names the wrong node"));
            checked++;
        }
        assertGt(checked, 0, "no accepted vector was checked");
        assertEq(vectors.length, HandleVectors.COUNT, "the table lost cases");
    }

    /// Case folding is the only change, to any text: nothing is trimmed, stripped or refused.
    function test_foldingIsTheOnlyChange() public pure {
        assertEq(HandleNormalizer.fold("A.B+tag@Example.COM"), "a.b+tag@example.com");
        assertEq(HandleNormalizer.fold(" @Alice_1 "), " @alice_1 ");
        assertEq(HandleNormalizer.fold(""), "");
        // The bytes either side of A-Z, and a byte above 0x7f.
        assertEq(HandleNormalizer.fold("@AZ[`az{\xc3\x89"), "@az[`az{\xc3\x89");
    }

    /// The fold copies: the caller's text is unchanged.
    function test_theFoldLeavesItsInputAlone() public pure {
        string memory raw = "Alice";
        HandleNormalizer.fold(raw);
        assertEq(raw, "Alice");
    }

    /// @dev The generated constants carry the SHA-256 of this handles.json.
    function test_theGeneratedConstantsComeFromThisTable() public view {
        assertEq(
            sha256(vm.readFileBinary("contracts/handles/handles.json")),
            HandlePlatforms.TABLE_SHA256,
            "HandlePlatforms.sol is stale: run scripts/regen-identity-handles.py"
        );
    }
}

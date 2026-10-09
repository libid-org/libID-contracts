// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {HandleNormalizer} from "../HandleNormalizer.sol";
import {HandlePlatforms} from "../HandlePlatforms.sol";
import {HandleVectors} from "../HandleVectors.sol";

/// @notice The shared handle vector table, run against the Solidity normalizer.
contract HandleNormalizerTest is Test {
    /// The rules the table names a platform by, from the generated table.
    function _rules(string memory platform) internal pure returns (HandleNormalizer.Rules memory) {
        return HandlePlatforms.rulesFor(keccak256(bytes(platform)));
    }

    /// Exposed so `vm.expectRevert` has an external call to watch.
    function normalize(string memory raw, string memory platform) external pure returns (string memory) {
        return HandleNormalizer.normalize(raw, _rules(platform));
    }

    function test_everyVectorMatchesTheSharedTable() public {
        HandleVectors.Vector[] memory vectors = HandleVectors.all();
        for (uint256 i = 0; i < vectors.length; i++) {
            HandleVectors.Vector memory v = vectors[i];
            if (v.accepted) {
                assertEq(
                    this.normalize(v.input, v.platform),
                    v.output,
                    string.concat("vector ", vm.toString(i), " normalized to the wrong handle")
                );
            } else {
                vm.expectRevert(_refusal(v.errorKind));
                this.normalize(v.input, v.platform);
            }
        }
    }

    /// An accepted vector hashes to its handle node under the platform's handle tag.
    function test_everyAcceptedVectorHashesToItsHandleNode() public pure {
        HandleVectors.Vector[] memory vectors = HandleVectors.all();
        uint256 checked;
        for (uint256 i = 0; i < vectors.length; i++) {
            HandleVectors.Vector memory v = vectors[i];
            if (!v.accepted) {
                assertEq(v.handleNode, bytes32(0), string.concat("refused vector ", vm.toString(i), " names a node"));
                continue;
            }
            bytes memory tag = HandlePlatforms.handleTagFor(keccak256(bytes(v.platform)));
            assertEq(
                sha256(abi.encodePacked(tag, v.output)),
                v.handleNode,
                string.concat("vector ", vm.toString(i), " names the wrong node")
            );
            checked++;
        }
        assertTrue(checked > 0, "no accepted vector was checked");
    }

    /// The refusal a vector expects, so a refusal for the wrong reason fails.
    function _refusal(uint8 kind) internal pure returns (bytes memory) {
        HandleNormalizer.Problem problem;
        if (kind == HandleVectors.ERROR_EMPTY) problem = HandleNormalizer.Problem.Empty;
        else if (kind == HandleVectors.ERROR_TOOLONG) problem = HandleNormalizer.Problem.TooLong;
        else if (kind == HandleVectors.ERROR_BADCHARACTER) problem = HandleNormalizer.Problem.BadChar;
        else if (kind == HandleVectors.ERROR_BADSHAPE) problem = HandleNormalizer.Problem.Shape;
        else revert("unknown error kind in the vector table");
        return abi.encodeWithSelector(HandleNormalizer.UnusableHandle.selector, problem);
    }

    function _badChar() internal pure returns (bytes memory) {
        return abi.encodeWithSelector(HandleNormalizer.UnusableHandle.selector, HandleNormalizer.Problem.BadChar);
    }

    /// The table covers both accepted and refused handles.
    function test_theTableCoversBothOutcomes() public pure {
        HandleVectors.Vector[] memory vectors = HandleVectors.all();
        uint256 accepted;
        uint256 refused;
        for (uint256 i = 0; i < vectors.length; i++) {
            if (vectors[i].accepted) accepted++;
            else refused++;
        }
        assertTrue(accepted > 0, "the table accepts nothing");
        assertTrue(refused > 0, "the table refuses nothing");
        assertEq(vectors.length, HandleVectors.COUNT, "the table lost cases");
    }

    /// Case folding is the only change to an accepted handle.
    function test_foldingIsTheOnlyChange() public view {
        assertEq(this.normalize("A.B+tag@Example.COM", "google"), "a.b+tag@example.com");
        assertEq(this.normalize("Alice_1", "x"), "alice_1");
        assertEq(this.normalize("Octo-Cat", "github"), "octo-cat");
    }

    /// The normalizer refuses padding and a leading at sign rather than stripping them.
    function test_paddingAndALeadingAtAreRefusedNotStripped() public {
        vm.expectRevert(_badChar());
        this.normalize(" alice", "x");
        vm.expectRevert(_badChar());
        this.normalize("@alice", "x");
        vm.expectRevert(_badChar());
        this.normalize("octocat ", "github");
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

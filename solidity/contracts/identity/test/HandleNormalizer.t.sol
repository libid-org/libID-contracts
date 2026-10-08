// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {HandleNormalizer} from "../HandleNormalizer.sol";
import {HandleVectors} from "../HandleVectors.sol";

/// @notice The shared handle vector table, run against the Solidity normalizer.
///
/// @dev The circuits, Rust and TypeScript run the same table from the same
///      JSON. That is the whole guard: several hand-written normalizers, one
///      set of cases, so an implementation that disagrees fails here instead of
///      naming a different node on chain.
contract HandleNormalizerTest is Test {
    /// The rules the table names a platform by, from the generated table the
    /// deploy installs: a second copy here could drift from it unnoticed.
    function _rules(string memory platform) internal pure returns (HandleNormalizer.Rules memory) {
        return HandleVectors.rulesFor(keccak256(bytes(platform)));
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
                vm.expectRevert(_selector(v.errorKind));
                this.normalize(v.input, v.platform);
            }
        }
    }

    /// An accepted vector carries the node its output hashes to under the
    /// platform's handle tag: the node a circuit outputs and the registry keys
    /// a binding by. The circuits, Rust and TypeScript check the same column,
    /// so a tag or a hash that disagrees anywhere fails somewhere.
    function test_everyAcceptedVectorHashesToItsHandleNode() public pure {
        HandleVectors.Vector[] memory vectors = HandleVectors.all();
        uint256 checked;
        for (uint256 i = 0; i < vectors.length; i++) {
            HandleVectors.Vector memory v = vectors[i];
            if (!v.accepted) {
                assertEq(v.handleNode, bytes32(0), string.concat("refused vector ", vm.toString(i), " names a node"));
                continue;
            }
            bytes memory tag = HandleVectors.handleTagFor(keccak256(bytes(v.platform)));
            assertEq(
                sha256(abi.encodePacked(tag, v.output)),
                v.handleNode,
                string.concat("vector ", vm.toString(i), " names the wrong node")
            );
            checked++;
        }
        assertTrue(checked > 0, "no accepted vector was checked");
    }

    /// The vector table names WHICH refusal, not merely that one happened. A
    /// bare `expectRevert` would pass when the normalizer refused for the wrong
    /// reason, and the reason is what the implementations must agree on.
    function _selector(uint8 kind) internal pure returns (bytes4) {
        if (kind == HandleVectors.ERROR_EMPTY) return HandleNormalizer.EmptyHandle.selector;
        if (kind == HandleVectors.ERROR_TOOLONG) return HandleNormalizer.HandleTooLong.selector;
        if (kind == HandleVectors.ERROR_BADCHARACTER) return HandleNormalizer.BadCharacter.selector;
        if (kind == HandleVectors.ERROR_BADSHAPE) return HandleNormalizer.BadShape.selector;
        revert("unknown error kind in the vector table");
    }

    /// The table must keep covering both outcomes. A regeneration that dropped
    /// every refusal would leave the test green and prove nothing.
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

    /// Case folding is the only change to an accepted handle. Anything else
    /// could map the handles of two identities onto one node.
    function test_foldingIsTheOnlyChange() public view {
        assertEq(this.normalize("A.B+tag@Example.COM", "google"), "a.b+tag@example.com");
        assertEq(this.normalize("Alice_1", "x"), "alice_1");
        assertEq(this.normalize("Octo-Cat", "github"), "octo-cat");
    }

    /// The normalizer refuses rather than repairs. A space or a leading at sign is
    /// not stripped into a handle: the circuit hashes the bytes the platform
    /// sent, and a repaired copy would name a node nobody proved.
    function test_paddingAndALeadingAtAreRefusedNotStripped() public {
        vm.expectRevert(HandleNormalizer.BadCharacter.selector);
        this.normalize(" alice", "x");
        vm.expectRevert(HandleNormalizer.BadCharacter.selector);
        this.normalize("@alice", "x");
        vm.expectRevert(HandleNormalizer.BadCharacter.selector);
        this.normalize("octocat ", "github");
    }
}

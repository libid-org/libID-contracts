// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";

import {CeremonyAuthorization} from "../CeremonyAuthorization.sol";
import {IOperationLists} from "../IOperationLists.sol";
import {OperationList} from "../OperationList.sol";
import {OperationListVector as V, operationList} from "./OperationListVector.sol";

/// Calls the library externally, so a test can expect its reverts.
contract OperationListHarness {
    function own(bytes32 operationDomain, bytes calldata transactionData, bytes32 domain)
        external
        pure
        returns (bytes memory)
    {
        return OperationList.own(operationDomain, transactionData, domain);
    }

    function select(bytes calldata list, bytes32 domain) external pure returns (bytes memory) {
        return OperationList.select(list, domain);
    }

    function find(bytes calldata list, bytes32 domain) external pure returns (uint256[] memory) {
        return OperationList.find(list, domain);
    }

    function reencode(bytes calldata list) external pure returns (bytes memory) {
        return abi.encode(abi.decode(list, (OperationList.Operation[])));
    }
}

/// @notice The chain profiles §3.3 vector and the list encoding itself (TEST-CHAIN-05).
///         `OperationListBind.t.sol` runs the bind Consumer's cases.
contract OperationListTest is Test {
    OperationListHarness internal h = new OperationListHarness();

    bytes32 constant WRAP = bytes32(type(uint256).max - 31);

    function _noncanonical(bytes memory list) internal {
        vm.expectRevert(IOperationLists.NoncanonicalOperationList.selector);
        h.select(list, V.BIND);
    }

    function test_theVectorReproducesItsDigest() public pure {
        assertEq(OperationList.DOMAIN, V.OPERATIONS, "libid.operations");
        assertEq(keccak256("libid.bind-identity"), V.BIND, "libid.bind-identity");
        assertEq(keccak256("libid.test.a"), V.TEST_A, "libid.test.a");
        assertEq(keccak256("libid.test.b"), V.TEST_B, "libid.test.b");
        bytes memory data = V.transactionData();
        assertEq(data.length, 384, "length");
        assertEq(CeremonyAuthorization.digest(V.OPERATIONS, 1, V.NONCE, data), V.DIGEST, "digest");
        assertEq(operationList(V.BIND, abi.encode(V.TARGET), V.TEST_A, hex"ff"), data, "entries");
        assertEq(CeremonyAuthorization.digest(V.OPERATIONS, 1, V.NONCE, V.bindOnly()), V.BIND_DIGEST, "bind only");
    }

    function test_eachConsumerTakesItsOwnEntry() public view {
        assertEq(h.select(V.transactionData(), V.BIND), abi.encode(V.TARGET), "bind");
        assertEq(h.select(V.transactionData(), V.TEST_A), hex"ff", "libid.test.a");
        assertEq(h.select(V.bindOnly(), V.BIND), abi.encode(V.TARGET), "bind only");
    }

    /// The single form is the Consumer's data itself; the list form is its one entry.
    function test_ownReadsEitherForm() public view {
        bytes memory target = abi.encode(V.TARGET);
        assertEq(h.own(V.BIND, target, V.BIND), target, "single form");
        assertEq(h.own(V.OPERATIONS, V.transactionData(), V.BIND), target, "list");
    }

    function test_ownRefusesAForeignDomain() public {
        vm.expectRevert(abi.encodeWithSelector(IOperationLists.ForeignOperationDomain.selector, V.TEST_A));
        h.own(V.TEST_A, abi.encode(V.TARGET), V.BIND);
    }

    /// Asked for `libid.operations` as its own domain, `own` reads the list and finds no entry.
    function test_ownUnderTheListDomainIsNoConsumers() public {
        vm.expectRevert(IOperationLists.NoOwnOperation.selector);
        h.own(V.OPERATIONS, V.transactionData(), V.OPERATIONS);
    }

    function test_bindBesideForeignEntriesInEitherOrder() public view {
        bytes memory target = abi.encode(V.TARGET);
        assertEq(h.select(operationList(V.TEST_A, hex"ff", V.BIND, target), V.BIND), target, "bind second");
        assertEq(h.select(operationList(V.BIND, target, V.TEST_A, hex"ff"), V.BIND), target, "bind first");
        // An entry under libid.operations is no Consumer's, and is checked for its encoding only.
        assertEq(h.select(operationList(V.OPERATIONS, hex"00", V.BIND, target), V.BIND), target, "nested");
    }

    function test_noEntryOfTheDomainIsRefused() public {
        vm.expectRevert(IOperationLists.NoOwnOperation.selector);
        h.select(V.transactionData(), V.TEST_B);
        vm.expectRevert(IOperationLists.NoOwnOperation.selector);
        h.select(abi.encode(new OperationList.Operation[](0)), V.BIND);
    }

    function test_twoEntriesOfTheDomainAreRefused() public {
        vm.expectRevert(IOperationLists.SeveralOwnOperations.selector);
        h.select(operationList(V.BIND, abi.encode(V.TARGET), V.BIND, abi.encode(address(0xBEEF))), V.BIND);
        vm.expectRevert(IOperationLists.SeveralOwnOperations.selector);
        h.select(V.withWord(8, V.BIND), V.BIND);
    }

    function test_libidOperationsIsNoConsumersDomain() public {
        vm.expectRevert(IOperationLists.NoOwnOperation.selector);
        h.select(operationList(V.OPERATIONS, hex"00"), V.OPERATIONS);
    }

    /// Each head offset one word early or late.
    function test_anOffsetOffByOneWordIsRefused() public {
        _noncanonical(V.withWord(2, bytes32(uint256(0x20))));
        _noncanonical(V.withWord(2, bytes32(uint256(0x60))));
        _noncanonical(V.withWord(3, bytes32(uint256(0xa0))));
        _noncanonical(V.withWord(3, bytes32(uint256(0xe0))));
    }

    /// A tuple's inner data offset other than 0x40.
    function test_anInnerOffsetOtherThan0x40IsRefused() public {
        bytes32[3] memory wrong = [bytes32(uint256(0x20)), bytes32(uint256(0x60)), WRAP];
        for (uint256 i; i < wrong.length; ++i) {
            _noncanonical(V.withWord(5, wrong[i]));
            _noncanonical(V.withWord(9, wrong[i]));
        }
    }

    /// `abi.decode` accepts the second offset pointing back at the first tuple; the walk does not.
    function test_anAliasedTupleIsRefused() public {
        bytes memory aliased = V.withWord(3, bytes32(uint256(0x40)));
        _noncanonical(aliased);
        assertEq(h.reencode(aliased).length, 384, "abi.decode reads it");
    }

    function test_anOffsetThatWrapsIsRefused() public {
        _noncanonical(V.withWord(2, WRAP));
        _noncanonical(V.withWord(3, WRAP));
    }

    function test_aLengthPastTheEndIsRefused() public {
        _noncanonical(V.withWord(6, bytes32(uint256(0x21))));
        _noncanonical(V.withWord(10, bytes32(uint256(0x21))));
        _noncanonical(V.withWord(10, WRAP));
        _noncanonical(V.withWord(10, bytes32(type(uint256).max)));
    }

    function test_dirtyPaddingIsRefused() public {
        _noncanonical(V.withWord(11, 0xff00000000000000000000000000000000000000000000000000000000000001));
        // A length short of its data leaves the rest as dirty padding.
        _noncanonical(V.withWord(6, bytes32(uint256(0x1f))));
    }

    function test_trailingBytesAreRefused() public {
        _noncanonical(bytes.concat(V.transactionData(), hex"00"));
        _noncanonical(bytes.concat(V.transactionData(), bytes32(0)));
    }

    function test_aCountTooLargeForTheBytesIsRefused() public {
        _noncanonical(V.withWord(1, bytes32(uint256(3))));
        _noncanonical(V.withWord(1, bytes32(uint256(11))));
        _noncanonical(V.withWord(1, bytes32(type(uint256).max)));
        _noncanonical(V.withWord(1, bytes32(type(uint256).max / 32 + 1)));
    }

    function test_bytesThatAreNoListAreRefused() public {
        _noncanonical(new bytes(0));
        _noncanonical(hex"ff");
        _noncanonical(abi.encode(V.TARGET));
        _noncanonical(V.withWord(0, bytes32(uint256(0x40))));
    }

    /// Any list the encoder builds decodes to the entries it was built from.
    function testFuzz_theWalkReadsWhatTheEncoderWrote(bytes32[4] memory domains, bytes[4] memory data, uint8 count)
        public
        view
    {
        uint256 n = bound(count, 0, 4);
        OperationList.Operation[] memory entries = new OperationList.Operation[](n);
        for (uint256 i; i < n; ++i) {
            // Few distinct domains, so lists hold repeats.
            bytes32 d = domains[i] == OperationList.DOMAIN ? bytes32(0) : bytes32(uint256(domains[i]) % 3);
            entries[i] = OperationList.Operation(d, data[i]);
        }
        bytes memory list = abi.encode(entries);
        for (uint256 i; i < n; ++i) {
            uint256[] memory found = h.find(list, entries[i].domain);
            uint256 k;
            for (uint256 j; j < n; ++j) {
                if (entries[j].domain != entries[i].domain) continue;
                assertEq(OperationList.dataAt(list, found[k]), entries[j].data, "data");
                ++k;
            }
            assertEq(found.length, k, "count");
        }
    }

    /// The walk accepts bytes only if they are `abi.encode` of what they decode to: a valid list with a
    /// word flipped, inserted or deleted is either refused or still canonical.
    function testFuzz_whatTheWalkAcceptsIsCanonical(uint8 at, uint8 op, bytes32 word) public view {
        bytes32[] memory w = V.words();
        uint256 i = bound(at, 0, w.length - 1);
        bytes memory mutated;
        uint256 kind = op % 3;
        if (kind == 0) {
            w[i] = word;
            mutated = V.join(w);
        } else if (kind == 1) {
            mutated = bytes.concat(_slice(V.join(w), 0, 32 * i), word, _slice(V.join(w), 32 * i, 32 * w.length));
        } else {
            mutated = bytes.concat(_slice(V.join(w), 0, 32 * i), _slice(V.join(w), 32 * i + 32, 32 * w.length));
        }
        try h.find(mutated, V.BIND) {
            assertEq(h.reencode(mutated), mutated, "accepted bytes are canonical");
        } catch (bytes memory reason) {
            assertEq(reason, abi.encodeWithSelector(IOperationLists.NoncanonicalOperationList.selector), "reason");
        }
    }

    function _slice(bytes memory b, uint256 from, uint256 to) internal pure returns (bytes memory out) {
        out = new bytes(to - from);
        for (uint256 i; i < out.length; ++i) {
            out[i] = b[from + i];
        }
    }
}

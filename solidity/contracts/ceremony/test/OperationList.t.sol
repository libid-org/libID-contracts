// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";

import {CeremonyAuthorization} from "../CeremonyAuthorization.sol";
import {IOperationLists} from "../IOperationLists.sol";
import {OperationList} from "../OperationList.sol";
import {OperationListVector as V, operationList} from "./OperationListVector.sol";

/// Calls the library externally, so a test can expect its reverts.
contract OperationListHarness {
    function select(bytes calldata list, bytes calldata data, bytes32[] calldata own, bool chainBound)
        external
        pure
        returns (bytes32)
    {
        return OperationList.select(list, data, own, chainBound);
    }
}

/// @notice The chain profiles §3.3 vector and the list encoding itself (TEST-CHAIN-05).
///         `OperationListBind.t.sol` runs the bind Consumer's cases.
contract OperationListTest is Test {
    OperationListHarness internal h = new OperationListHarness();

    function _own(bytes32 a) internal pure returns (bytes32[] memory own) {
        own = new bytes32[](1);
        own[0] = a;
    }

    function _own(bytes32 a, bytes32 b) internal pure returns (bytes32[] memory own) {
        own = new bytes32[](2);
        own[0] = a;
        own[1] = b;
    }

    function test_theVectorReproducesItsDigest() public pure {
        assertEq(OperationList.DOMAIN, V.OPERATIONS, "libid.operations");
        assertEq(keccak256("libid.bind-identity"), V.BIND, "libid.bind-identity");
        assertEq(keccak256("libid.test.a"), V.TEST_A, "libid.test.a");
        assertEq(keccak256("libid.test.b"), V.TEST_B, "libid.test.b");
        bytes memory data = V.transactionData();
        assertEq(data.length, 192, "length");
        assertEq(CeremonyAuthorization.digest(V.OPERATIONS, 1, V.NONCE, data), V.DIGEST, "digest");
        assertEq(operationList(V.BIND, abi.encode(V.TARGET), V.TEST_A, hex"ff"), data, "entries");
    }

    function test_eachConsumerTakesItsOwnEntry() public view {
        assertEq(h.select(V.transactionData(), abi.encode(V.TARGET), _own(V.BIND), false), V.BIND);
        assertEq(h.select(V.transactionData(), hex"ff", _own(V.TEST_A), false), V.TEST_A);
    }

    function test_theDerivedListsAreRefused() public {
        vm.expectRevert(IOperationLists.SeveralOwnOperations.selector);
        h.select(V.twoOwnDomains(), hex"ff", _own(V.TEST_A, V.TEST_B), false);
        vm.expectRevert(IOperationLists.NestedOperationList.selector);
        h.select(V.nestedEntry(), abi.encode(V.TARGET), _own(V.BIND), false);
    }

    /// Chain-bound domains may hold several entries; the data selects one of them.
    function test_chainBoundDomainsSelectByData() public view {
        bytes memory list = operationList(V.TEST_A, hex"01", V.TEST_A, hex"02");
        assertEq(h.select(list, hex"02", _own(V.TEST_A), true), V.TEST_A);
        assertEq(h.select(V.twoOwnDomains(), hex"ff", _own(V.TEST_A, V.TEST_B), true), V.TEST_A);
    }

    function test_twoEntriesCommittingTheDataAreRefused() public {
        vm.expectRevert(IOperationLists.SeveralOwnOperations.selector);
        h.select(operationList(V.TEST_A, hex"ff", V.TEST_B, hex"ff"), hex"ff", _own(V.TEST_A, V.TEST_B), true);
    }

    function test_noEntryCommittingTheDataIsRefused() public {
        vm.expectRevert(IOperationLists.NoOwnOperation.selector);
        h.select(V.transactionData(), hex"00", _own(V.BIND), false);
    }

    /// The vector's trailing byte and gap, a wrong count, and bytes that are no list.
    function test_noncanonicalListsAreRefused() public {
        bytes32[] memory miscounted = V.words();
        miscounted[1] = bytes32(uint256(3));
        bytes[6] memory lists =
            [V.trailingByte(), V.gap(), V.join(miscounted), bytes(hex"ff"), abi.encode(V.TARGET), new bytes(0)];
        for (uint256 i; i < lists.length; ++i) {
            vm.expectRevert(IOperationLists.NoncanonicalOperationList.selector);
            h.select(lists[i], abi.encode(V.TARGET), _own(V.BIND), false);
        }
    }
}

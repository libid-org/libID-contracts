// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";

import {CeremonyAuthorization} from "../CeremonyAuthorization.sol";
import {OperationList} from "../OperationList.sol";
import {OperationListVector as V} from "./OperationListVector.sol";

/// Calls the library externally, so a test can expect its reverts.
contract OperationListHarness {
    function select(bytes32 domain, bytes calldata data, bytes32[] calldata own)
        external
        pure
        returns (bytes32, bytes memory)
    {
        return OperationList.select(domain, data, own);
    }
}

/// @notice TEST-COMMON-02B/02C and TEST-CHAIN-05 on the list encoding itself.
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
        assertEq(data.length, 384, "length");
        assertEq(CeremonyAuthorization.digest(V.OPERATIONS, 1, V.NONCE, data), V.DIGEST, "digest");
    }

    function test_theEntriesEncodeToTheVector() public pure {
        OperationList.Operation[] memory entries = new OperationList.Operation[](2);
        entries[0] = OperationList.Operation({domain: V.BIND, data: abi.encode(V.TARGET)});
        entries[1] = OperationList.Operation({domain: V.TEST_A, data: hex"ff"});
        assertEq(abi.encode(entries), V.transactionData());
    }

    function test_eachConsumerTakesItsOwnEntry() public view {
        (bytes32 domain, bytes memory data) = h.select(V.OPERATIONS, V.transactionData(), _own(V.BIND));
        assertEq(domain, V.BIND);
        assertEq(data, abi.encode(V.TARGET));

        (domain, data) = h.select(V.OPERATIONS, V.transactionData(), _own(V.TEST_A));
        assertEq(domain, V.TEST_A);
        assertEq(data, hex"ff");
    }

    function test_aSingleOperationPassesThrough() public view {
        (bytes32 domain, bytes memory data) = h.select(V.BIND, hex"ff", _own(V.BIND));
        assertEq(domain, V.BIND);
        assertEq(data, hex"ff");
    }

    function test_twoOwnDomainsAreRefused() public {
        vm.expectRevert(OperationList.SeveralOwnOperations.selector);
        h.select(V.OPERATIONS, V.twoOwnDomains(), _own(V.TEST_A, V.TEST_B));
    }

    /// Each decodes under `abi.decode` to the vector's entries; only the re-encoding tells them apart.
    function test_noncanonicalListsAreRefused() public {
        bytes[4] memory lists = [V.trailingByte(), V.gap(), V.swappedBodies(), V.outerPadding()];
        for (uint256 i; i < lists.length; ++i) {
            assertEq(abi.encode(abi.decode(lists[i], (OperationList.Operation[]))), V.transactionData(), "decodes");
            vm.expectRevert(OperationList.NoncanonicalOperationList.selector);
            h.select(V.OPERATIONS, lists[i], _own(V.BIND));
        }
    }

    function test_bytesThatAreNoListAreRefused() public {
        vm.expectRevert();
        h.select(V.OPERATIONS, hex"ff", _own(V.BIND));
    }
}

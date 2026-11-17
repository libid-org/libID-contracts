// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IOperationLists} from "../../ceremony/IOperationLists.sol";
import {operationList} from "../../ceremony/test/OperationListVector.sol";
import {IdentityRegistry} from "../../identity/IdentityRegistry.sol";
import {IWalletRegistry} from "../IWalletRegistry.sol";
import {WalletTestBase} from "./WalletTestBase.sol";

/// @notice WalletRegistry under `libid.operations`, and one list spent once at each of two Consumers.
contract OperationListWalletTest is WalletTestBase {
    function _linkData(address w) internal view returns (bytes memory) {
        return _txData(w, _key(ALICE_PK), _ph(_admin()));
    }

    /// One proof: the wallet's first session at WalletRegistry and its binding at IdentityRegistry.
    function test_bothConsumersAcceptOneListOnce() public {
        vm.prank(relayer);
        address w = factory.createWallet(X, ALICE);
        bytes memory link = _linkData(w);
        bytes memory payload = _payload(X, ALICE, OPERATIONS, operationList(BIND, abi.encode(w), LINK, link));

        vm.prank(w);
        registry.linkIdentity(X, V1, payload, link, _admin());
        vm.prank(w);
        identities.bindPrivately(X, V1, payload, 0, address(0));

        bytes32 digest = xStub.lastDigest();
        assertLe(validator.sessionOf(w, _key(ALICE_PK)).activeAt, _now(), "no active first session");
        assertEq(identities.resolveId(ALICE), w, "not bound");
        assertTrue(registry.digestSpent(digest) && identities.digestSpent(digest), "not spent at both");

        vm.prank(w);
        vm.expectRevert(abi.encodeWithSelector(IWalletRegistry.DigestAlreadySpent.selector, digest));
        registry.linkIdentity(X, V1, payload, link, _admin());
        vm.prank(w);
        vm.expectRevert(abi.encodeWithSelector(IdentityRegistry.DigestAlreadySpent.selector, digest));
        identities.bindPrivately(X, V1, payload, 0, address(0));
    }

    /// The entry the data selects decides the function: an add-session entry is no link.
    function test_theEntryMustBeTheCalledFunctions() public {
        address w = _claim();
        bytes memory add = _txData(w, _key(ALICE2_PK), _ph(_app()));
        bytes memory payload = _payload(X, ALICE, OPERATIONS, operationList(ADD, add, BIND, hex"ff"));
        vm.expectRevert(abi.encodeWithSelector(IWalletRegistry.ForeignOperationDomain.selector, ADD));
        registry.linkIdentity(X, V1, payload, add, _app());

        registry.addSessionByProof(X, V1, payload, add, _app());
        assertEq(validator.sessionOf(w, _key(ALICE2_PK)).identity, _identity(X, ALICE), "no session");
    }

    /// The registry cannot refuse a list with a link and an add-session for one chain, which
    /// REQ-COMMON-01L forbids the Application to compose; only one of them is applied.
    function test_aListWithBothWalletDomainsIsSpentOnce() public {
        address w = factory.createWallet(X, ALICE);
        bytes memory link = _linkData(w);
        bytes memory add = _txData(w, _key(ALICE2_PK), _ph(_admin()));
        bytes memory payload = _payload(X, ALICE, OPERATIONS, operationList(LINK, link, ADD, add));
        vm.prank(w);
        registry.linkIdentity(X, V1, payload, link, _admin());
        vm.expectRevert(abi.encodeWithSelector(IWalletRegistry.DigestAlreadySpent.selector, xStub.lastDigest()));
        registry.addSessionByProof(X, V1, payload, add, _admin());
    }

    function test_aListWithoutTheCallsEntryIsRefused() public {
        address w = factory.createWallet(X, ALICE);
        bytes memory payload = _payload(X, ALICE, OPERATIONS, operationList(BIND, abi.encode(w), BIND, hex"ff"));
        vm.expectRevert(IOperationLists.NoOwnOperation.selector);
        registry.linkIdentity(X, V1, payload, _linkData(w), _admin());

        payload = _payload(X, ALICE, OPERATIONS, operationList(LINK, _linkData(w), OPERATIONS, hex"ff"));
        vm.expectRevert(IOperationLists.NestedOperationList.selector);
        registry.linkIdentity(X, V1, payload, _linkData(w), _admin());
    }

    /// Link data itself, and a list with a trailing byte, under `libid.operations`.
    function test_bytesThatAreNoListAreRefused() public {
        address w = factory.createWallet(X, ALICE);
        bytes memory link = _linkData(w);
        bytes[2] memory lists = [link, bytes.concat(operationList(LINK, link, BIND, hex"ff"), hex"00")];
        for (uint256 i; i < lists.length; ++i) {
            bytes memory payload = _payload(X, ALICE, OPERATIONS, lists[i]);
            vm.expectRevert(IOperationLists.NoncanonicalOperationList.selector);
            registry.linkIdentity(X, V1, payload, link, _admin());
        }
    }

    function test_dataBesideOneOperationIsRefused() public {
        address w = factory.createWallet(X, ALICE);
        bytes memory payload = _payload(X, ALICE, LINK, _linkData(w));
        vm.expectRevert(IWalletRegistry.DataWithoutList.selector);
        registry.linkIdentity(X, V1, payload, _linkData(w), _admin());
    }

    /// The entry's data is held to the domain's own encoding.
    function test_anEntryOnAnotherChainIsRefused() public {
        address w = factory.createWallet(X, ALICE);
        bytes memory data = abi.encode(block.chainid + 1, w, _key(ALICE_PK), _ph(_admin()));
        bytes memory payload = _payload(X, ALICE, OPERATIONS, operationList(LINK, data, BIND, hex"ff"));
        vm.expectRevert(abi.encodeWithSelector(IWalletRegistry.WrongChain.selector, block.chainid + 1));
        registry.linkIdentity(X, V1, payload, data, _admin());
    }

    /// TEST-COMMON-02D: link entries naming chains A and B, accepted once on each.
    function test_entriesForTwoChainsAreAcceptedOnEach() public {
        address w = factory.createWallet(X, ALICE);
        (uint256 a, uint256 b) = (vm.getChainId(), vm.getChainId() + 1);
        bytes memory dataA = abi.encode(a, w, _key(ALICE_PK), _ph(_admin()));
        bytes memory dataB = abi.encode(b, w, _key(ALICE_PK), _ph(_admin()));
        bytes memory payload = _payload(X, ALICE, OPERATIONS, operationList(LINK, dataA, LINK, dataB));

        uint256 fresh = vm.snapshotState();
        vm.prank(w);
        vm.expectRevert(abi.encodeWithSelector(IWalletRegistry.WrongChain.selector, b));
        registry.linkIdentity(X, V1, payload, dataB, _admin());
        vm.prank(w);
        registry.linkIdentity(X, V1, payload, dataA, _admin());

        vm.revertToState(fresh);
        vm.chainId(b);
        vm.prank(w);
        registry.linkIdentity(X, V1, payload, dataB, _admin());
        assertEq(validator.sessionOf(w, _key(ALICE_PK)).identity, _identity(X, ALICE), "not linked on B");
    }
}

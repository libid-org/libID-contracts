// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {OperationList} from "../../ceremony/OperationList.sol";
import {IdentityRegistry} from "../../identity/IdentityRegistry.sol";
import {IWalletRegistry} from "../IWalletRegistry.sol";
import {operationList} from "./ClaimExecutor.t.sol";
import {WalletTestBase} from "./WalletTestBase.sol";

/// @notice WalletRegistry under `libid.operations`, and one list spent once at each of two Consumers.
contract OperationListWalletTest is WalletTestBase {
    function _list(bytes32 d0, bytes memory data0) internal pure returns (bytes memory) {
        OperationList.Operation[] memory e = new OperationList.Operation[](1);
        e[0] = OperationList.Operation({domain: d0, data: data0});
        return abi.encode(e);
    }

    function _linkData(address w) internal view returns (bytes memory) {
        return _txData(w, _key(ALICE_PK), _ph(_admin()));
    }

    /// One proof: the wallet's first session at WalletRegistry and its binding at IdentityRegistry.
    function test_bothConsumersAcceptOneListOnce() public {
        vm.prank(relayer);
        address w = factory.createWallet(X, ALICE);
        bytes memory payload = _payload(X, ALICE, OPERATIONS, operationList(BIND, abi.encode(w), LINK, _linkData(w)));

        vm.prank(relayer);
        registry.linkIdentity(X, V1, payload, _admin());
        vm.prank(w);
        identities.bindPrivately(X, V1, payload, 0, address(0));

        bytes32 digest = xStub.lastDigest();
        assertLe(validator.sessionOf(w, _key(ALICE_PK)).activeAt, _now(), "no active first session");
        assertEq(identities.resolveId(ALICE), w, "not bound");
        assertTrue(registry.digestSpent(digest) && identities.digestSpent(digest), "not spent at both");

        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(IWalletRegistry.DigestAlreadySpent.selector, digest));
        registry.linkIdentity(X, V1, payload, _admin());
        vm.prank(w);
        vm.expectRevert(abi.encodeWithSelector(IdentityRegistry.DigestAlreadySpent.selector, digest));
        identities.bindPrivately(X, V1, payload, 0, address(0));
    }

    /// The entry selects the function: an add-session entry is no link.
    function test_theEntryMustBeTheCalledFunctions() public {
        address w = _claim();
        bytes memory payload =
            _payload(X, ALICE, OPERATIONS, operationList(ADD, _txData(w, _key(ALICE2_PK), _ph(_app())), BIND, hex"ff"));
        vm.expectRevert(abi.encodeWithSelector(IWalletRegistry.ForeignOperationDomain.selector, ADD));
        registry.linkIdentity(X, V1, payload, _app());

        registry.addSessionByProof(X, V1, payload, _app());
        assertEq(validator.sessionOf(w, _key(ALICE2_PK)).identity, _identity(X, ALICE), "no session");
    }

    function test_aListWithBothWalletDomainsIsRefused() public {
        address w = factory.createWallet(X, ALICE);
        bytes memory payload = _payload(
            X, ALICE, OPERATIONS, operationList(LINK, _linkData(w), ADD, _txData(w, _key(ALICE2_PK), _ph(_admin())))
        );
        vm.expectRevert(OperationList.SeveralOwnOperations.selector);
        registry.linkIdentity(X, V1, payload, _admin());
        vm.expectRevert(OperationList.SeveralOwnOperations.selector);
        registry.addSessionByProof(X, V1, payload, _admin());
    }

    function test_aListWithoutAWalletEntryIsRefused() public {
        address w = factory.createWallet(X, ALICE);
        bytes memory payload = _payload(X, ALICE, OPERATIONS, _list(BIND, abi.encode(w)));
        vm.expectRevert(OperationList.NoOwnOperation.selector);
        registry.linkIdentity(X, V1, payload, _admin());
    }

    /// The entry's data is held to the domain's own encoding.
    function test_anEntryOnAnotherChainIsRefused() public {
        address w = factory.createWallet(X, ALICE);
        bytes memory data = abi.encode(block.chainid + 1, w, _key(ALICE_PK), _ph(_admin()));
        bytes memory payload = _payload(X, ALICE, OPERATIONS, _list(LINK, data));
        vm.expectRevert(abi.encodeWithSelector(IWalletRegistry.WrongChain.selector, block.chainid + 1));
        registry.linkIdentity(X, V1, payload, _admin());
    }
}

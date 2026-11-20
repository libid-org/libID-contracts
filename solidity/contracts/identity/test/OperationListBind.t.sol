// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {CeremonyProfile} from "../../ceremony/CeremonyProfile.sol";
import {CeremonyProofVerifier} from "../../ceremony/CeremonyProofVerifier.sol";
import {IPlatformVerifier} from "../../ceremony/IPlatformVerifier.sol";
import {IProofVerifier} from "../../ceremony/IProofVerifier.sol";
import {IOperationLists} from "../../ceremony/IOperationLists.sol";
import {OperationListVector as V, operationList} from "../../ceremony/test/OperationListVector.sol";
import {IdentityRegistry} from "../IdentityRegistry.sol";
import {StubPlatformVerifier} from "./StubPlatformVerifier.sol";
import {TestNodes} from "./TestNodes.sol";

/// @notice The bind Consumer under `libid.operations`: the list cases of TEST-CHAIN-05 and TEST-PLAT-20E.
contract OperationListBindTest is Test {
    bytes32 constant PLATFORM = CeremonyProfile.PLATFORM_X;
    address constant OWNER = address(0xA11CE);

    IdentityRegistry registry;
    StubPlatformVerifier verifier;

    function setUp() public {
        vm.warp(1_770_000_100);
        registry = IdentityRegistry(
            address(
                new ERC1967Proxy(address(new IdentityRegistry()), abi.encodeCall(IdentityRegistry.initialize, (OWNER)))
            )
        );
        CeremonyProofVerifier pv = CeremonyProofVerifier(
            address(
                new ERC1967Proxy(
                    address(new CeremonyProofVerifier()), abi.encodeCall(CeremonyProofVerifier.initialize, (OWNER))
                )
            )
        );
        verifier = new StubPlatformVerifier(PLATFORM, 0);
        vm.startPrank(OWNER);
        registry.setProofVerifier(IProofVerifier(address(pv)));
        pv.setVerifier(PLATFORM, 1, IPlatformVerifier(address(verifier)));
        vm.stopPrank();
    }

    /// The stub's payload for `transactionData` under `domain`, with the vector's nonce.
    function _payload(bytes32 domain, bytes memory transactionData) internal pure returns (bytes memory) {
        return abi.encode(
            StubPlatformVerifier.StubPayload({
                ceremonyVersion: 1,
                operationDomain: domain,
                authorizationNonce: V.NONCE,
                transactionData: transactionData
            })
        );
    }

    function _bind(bytes memory transactionData) internal {
        bytes memory payload = _payload(V.OPERATIONS, transactionData);
        vm.prank(V.TARGET);
        registry.bindPrivately(PLATFORM, 1, payload, 0, address(0));
    }

    function _refused(bytes32 domain, bytes memory transactionData, bytes memory err) internal {
        bytes memory payload = _payload(domain, transactionData);
        vm.prank(V.TARGET);
        vm.expectRevert(err);
        registry.bindPrivately(PLATFORM, 1, payload, 0, address(0));
    }

    function _refused(bytes memory transactionData, bytes memory err) internal {
        _refused(V.OPERATIONS, transactionData, err);
    }

    /// The bind Consumer takes its entry; the `libid.test.a` entry is not its.
    function test_theVectorBindsItsTargetOnce() public {
        _bind(V.transactionData());
        assertEq(verifier.lastDigest(), V.DIGEST, "digest");
        assertTrue(registry.digestSpent(V.DIGEST), "not spent");
        assertEq(registry.resolveId(TestNodes.idNode(PLATFORM, "2244994945")), V.TARGET, "not bound");

        _refused(V.transactionData(), abi.encodeWithSelector(IdentityRegistry.DigestAlreadySpent.selector, V.DIGEST));
    }

    function test_aOneEntryListBinds() public {
        _bind(V.bindOnly());
        assertEq(verifier.lastDigest(), V.BIND_DIGEST, "digest");
        assertEq(registry.resolveId(TestNodes.idNode(PLATFORM, "2244994945")), V.TARGET, "not bound");
    }

    /// The single form `libid.bind-identity` with `abi.encode(target)` is no longer a bind.
    function test_theSingleFormIsRefused() public {
        _refused(
            V.BIND,
            abi.encode(V.TARGET),
            abi.encodeWithSelector(IdentityRegistry.ForeignOperationDomain.selector, V.BIND)
        );
    }

    function test_anotherCallerIsNotTheTarget() public {
        bytes memory payload = _payload(V.OPERATIONS, V.transactionData());
        vm.prank(address(0xBEEF));
        vm.expectRevert(abi.encodeWithSelector(IdentityRegistry.NotProofTarget.selector, V.TARGET, address(0xBEEF)));
        registry.bindPrivately(PLATFORM, 1, payload, 0, address(0));
    }

    function test_listsWithoutOneBindEntryAreRefused() public {
        _refused(operationList(V.TEST_A, hex"ff"), abi.encodeWithSelector(IOperationLists.NoOwnOperation.selector));
        _refused(V.withWord(8, V.BIND), abi.encodeWithSelector(IOperationLists.SeveralOwnOperations.selector));
    }

    function test_bindDataOtherThanOneAddressIsRefused() public {
        _refused(
            operationList(V.BIND, new bytes(31)),
            abi.encodeWithSelector(IdentityRegistry.BadTransactionData.selector, 31)
        );
        _refused(
            operationList(V.BIND, new bytes(33)),
            abi.encodeWithSelector(IdentityRegistry.BadTransactionData.selector, 33)
        );
        bytes memory dirty = abi.encodePacked(bytes12(0x000000000000000000000001), V.TARGET);
        _refused(operationList(V.BIND, dirty), abi.encodeWithSelector(IdentityRegistry.BadTransactionData.selector, 32));
    }

    function test_noncanonicalListsAreRefused() public {
        bytes memory err = abi.encodeWithSelector(IOperationLists.NoncanonicalOperationList.selector);
        _refused(bytes.concat(V.transactionData(), hex"00"), err);
        _refused(V.withWord(3, bytes32(uint256(0x40))), err);
        _refused(abi.encode(V.TARGET), err);
    }
}

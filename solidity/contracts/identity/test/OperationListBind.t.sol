// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {CeremonyProfile} from "../../ceremony/CeremonyProfile.sol";
import {CeremonyProofVerifier} from "../../ceremony/CeremonyProofVerifier.sol";
import {IPlatformVerifier} from "../../ceremony/IPlatformVerifier.sol";
import {IProofVerifier} from "../../ceremony/IProofVerifier.sol";
import {OperationList} from "../../ceremony/OperationList.sol";
import {OperationListVector as V} from "../../ceremony/test/OperationListVector.sol";
import {IdentityRegistry} from "../IdentityRegistry.sol";
import {StubPlatformVerifier} from "./StubPlatformVerifier.sol";
import {TestNodes} from "./TestNodes.sol";

/// @notice The bind Consumer under `libid.operations`: TEST-COMMON-02B/02C, TEST-CHAIN-05, TEST-PLAT-20E.
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

    /// The stub's payload for `transactionData` under `libid.operations`, with the vector's nonce.
    function _payload(bytes memory transactionData) internal pure returns (bytes memory) {
        return abi.encode(
            StubPlatformVerifier.StubPayload({
                ceremonyVersion: 1,
                operationDomain: V.OPERATIONS,
                authorizationNonce: V.NONCE,
                transactionData: transactionData
            })
        );
    }

    function _bind(address caller, bytes memory transactionData) internal {
        bytes memory payload = _payload(transactionData);
        vm.prank(caller);
        registry.bindPrivately(PLATFORM, 1, payload, 0, address(0));
    }

    function _refused(bytes memory transactionData, bytes memory err) internal {
        bytes memory payload = _payload(transactionData);
        vm.prank(V.TARGET);
        vm.expectRevert(err);
        registry.bindPrivately(PLATFORM, 1, payload, 0, address(0));
    }

    /// The `libid.test.a` entry's `0xff` is no target, and is never decoded.
    function test_theVectorBindsItsTargetOnce() public {
        _bind(V.TARGET, V.transactionData());
        assertEq(verifier.lastDigest(), V.DIGEST, "digest");
        assertTrue(registry.digestSpent(V.DIGEST), "not spent");
        assertEq(registry.resolveId(TestNodes.idNode(PLATFORM, "2244994945")), V.TARGET, "not bound");

        _refused(V.transactionData(), abi.encodeWithSelector(IdentityRegistry.DigestAlreadySpent.selector, V.DIGEST));
    }

    function test_theEntryTargetMustBeTheCaller() public {
        bytes memory payload = _payload(V.transactionData());
        vm.prank(address(0xBEEF));
        vm.expectRevert(abi.encodeWithSelector(IdentityRegistry.NotProofTarget.selector, V.TARGET, address(0xBEEF)));
        registry.bindPrivately(PLATFORM, 1, payload, 0, address(0));
    }

    function test_theDerivedListsAreRefused() public {
        _refused(V.duplicateEntry(), abi.encodeWithSelector(OperationList.SeveralOwnOperations.selector));
        _refused(V.nestedEntry(), abi.encodeWithSelector(OperationList.NestedOperationList.selector));
        _refused(V.noEntry(), abi.encodeWithSelector(OperationList.NoOwnOperation.selector));
        // Entries only under libid.test.b and libid.test.a: none of them the bind Consumer's.
        _refused(V.twoOwnDomains(), abi.encodeWithSelector(OperationList.NoOwnOperation.selector));
    }

    function test_theNoncanonicalListsAreRefused() public {
        bytes memory err = abi.encodeWithSelector(OperationList.NoncanonicalOperationList.selector);
        _refused(V.trailingByte(), err);
        _refused(V.gap(), err);
        _refused(V.swappedBodies(), err);
        _refused(V.outerPadding(), err);
    }

    /// The entry's `data` is exactly one target: a chain id after it is refused.
    function test_anEntryWithTrailingBytesIsRefused() public {
        OperationList.Operation[] memory entries = new OperationList.Operation[](1);
        entries[0] = OperationList.Operation({domain: V.BIND, data: abi.encode(V.TARGET, block.chainid)});
        _refused(abi.encode(entries), abi.encodeWithSelector(IdentityRegistry.BadTransactionData.selector, 64));
    }
}

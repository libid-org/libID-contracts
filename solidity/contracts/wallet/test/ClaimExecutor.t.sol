// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC7579Execution} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {ERC7579Utils} from "@openzeppelin/contracts/account/utils/draft-ERC7579Utils.sol";

import {IPlatformVerifier} from "../../ceremony/IPlatformVerifier.sol";
import {OperationList} from "../../ceremony/OperationList.sol";
import {NATIVE_TOKEN} from "../../escrow/HandleEscrow.sol";
import {IdentityRegistry} from "../../identity/IdentityRegistry.sol";
import {StubPlatformVerifier} from "../../identity/test/StubPlatformVerifier.sol";
import {IClaimExecutor} from "../IClaimExecutor.sol";
import {IIdentityValidator} from "../IIdentityValidator.sol";
import {IWalletFactory} from "../IWalletFactory.sol";
import {IWalletRegistry} from "../IWalletRegistry.sol";
import {WalletTestBase} from "./WalletTestBase.sol";

/// The escrow's native token, as a claim's token list.
function nativeOnly() pure returns (address[] memory tokens) {
    tokens = new address[](1);
    tokens[0] = NATIVE_TOKEN;
}

/// The Operation List of two entries, `abi.encode(Operation[])`.
function operationList(bytes32 d0, bytes memory data0, bytes32 d1, bytes memory data1) pure returns (bytes memory) {
    OperationList.Operation[] memory e = new OperationList.Operation[](2);
    e[0] = OperationList.Operation({domain: d0, data: data0});
    e[1] = OperationList.Operation({domain: d1, data: data1});
    return abi.encode(e);
}

/// Sends the whole claim as one transaction, as a relayer's multicall does.
contract Relay {
    function claim(
        IWalletFactory factory,
        IClaimExecutor executor,
        bytes32 platformId,
        uint16 verifierVersion,
        bytes32 idNode,
        bytes32 handleNode,
        bytes calldata bindPayload
    ) external payable {
        address w = factory.createWallet(platformId, idNode);
        executor.bind{value: msg.value}(w, platformId, verifierVersion, bindPayload);
        executor.claimToSelf(w, handleNode, nativeOnly());
    }

    /// The claim with the wallet's first session, from one proof of a bind and a link entry.
    function claimWithSession(
        IWalletFactory factory,
        IWalletRegistry registry,
        IClaimExecutor executor,
        bytes32 platformId,
        uint16 verifierVersion,
        bytes32 idNode,
        bytes32 handleNode,
        bytes calldata payload,
        IIdentityValidator.Policy calldata policy
    ) external payable {
        address w = factory.createWallet(platformId, idNode);
        uint256 linkFee = registry.quote(platformId, verifierVersion);
        registry.linkIdentity{value: linkFee}(platformId, verifierVersion, payload, policy);
        executor.bind{value: msg.value - linkFee}(w, platformId, verifierVersion, payload);
        executor.claimToSelf(w, handleNode, nativeOnly());
    }
}

/// @notice D20: the claim as one plain relayer transaction, and nothing else through the executor.
contract ClaimExecutorTest is WalletTestBase {
    bytes32 internal constant HANDLE = keccak256("some handle node");
    uint256 internal constant FEE = 5;
    StubPlatformVerifier internal paid;
    uint256 private paidNonce;

    function setUp() public override {
        super.setUp();
        paid = new StubPlatformVerifier(X, FEE);
        vm.prank(owner);
        proofVerifier.setVerifier(X, 2, IPlatformVerifier(address(paid)));
        escrow.deposit{value: 1 ether}(X, HANDLE, NATIVE_TOKEN, 1 ether);
    }

    /// A payload of the paid verifier proving `idNode` for `domain` and `data`.
    function _paidPayload(bytes32 idNode, bytes32 domain, bytes memory data) internal returns (bytes memory) {
        paid.setNodes(idNode, HANDLE);
        return abi.encode(
            StubPlatformVerifier.StubPayload({
                ceremonyVersion: 1,
                operationDomain: domain,
                authorizationNonce: bytes32(++paidNonce),
                transactionData: data
            })
        );
    }

    /// One proof: the wallet links its genesis identity when it is created.
    function test_relayerClaimsInOnePlainTransaction() public {
        address w = factory.walletAddress(X, ALICE);
        bytes memory bind = _paidPayload(ALICE, BIND, abi.encode(w));
        Relay relay = new Relay();
        vm.deal(relayer, 1 ether);
        vm.prank(relayer);
        relay.claim{value: FEE}(factory, executor, X, 2, ALICE, HANDLE, bind);
        // The frame's gas, written only by `FOUNDRY_PROFILE=gas forge test`. The proof is stubbed.
        vm.snapshotValue("wallet-claim", "Relay.claim(stub proof)", vm.lastFrameGas().gasTotalUsed);

        assertGt(w.code.length, 0, "no wallet");
        assertEq(identities.resolveId(ALICE), w, "not bound to the wallet");
        assertEq(w.balance, 1 ether, "escrow not claimed to the wallet");
        assertEq(paid.lastValue(), FEE, "the bind fee was not forwarded");
    }

    /// One proof of [bind-identity(w), link-identity(w, key, policy)]: the wallet with its
    /// first session, bound and paid, in one transaction.
    function test_relayerClaimsWithAFirstSessionFromOneList() public {
        address w = factory.walletAddress(X, ALICE);
        bytes memory list = operationList(BIND, abi.encode(w), LINK, _txData(w, _key(ALICE_PK), _ph(_admin())));
        bytes memory payload = _paidPayload(ALICE, OPERATIONS, list);
        Relay relay = new Relay();
        vm.deal(relayer, 1 ether);
        vm.prank(relayer);
        relay.claimWithSession{value: 2 * FEE}(factory, registry, executor, X, 2, ALICE, HANDLE, payload, _admin());
        vm.snapshotValue(
            "wallet-claim", "Relay.claimWithSession(stub proof, operation list)", vm.lastFrameGas().gasTotalUsed
        );

        assertEq(identities.resolveId(ALICE), w, "not bound to the wallet");
        assertEq(w.balance, 1 ether, "escrow not claimed to the wallet");
        _handle(_signed(_op(w, 0, _hit()), _pks(ALICE_PK)));
        assertEq(target.calls(), 1, "the first session could not act");
    }

    function test_bindRefusesAnIdentityNotLinkedToTheWallet() public {
        address w = _claim();
        bytes memory bind = _paidPayload(MALLORY, BIND, abi.encode(w));
        vm.expectRevert(abi.encodeWithSelector(IClaimExecutor.HeldIdentityNotLinked.selector, w, X, MALLORY));
        executor.bind{value: FEE}(w, X, 2, bind);
        assertEq(identities.resolveId(MALLORY), address(0), "bound anyway");
    }

    /// A new identity is checked when the wallet already holds another.
    function test_bindChecksANewIdentityAfterEarlierOnes() public {
        address w = _claim();
        executor.bind{value: FEE}(w, X, 2, _paidPayload(ALICE, BIND, abi.encode(w)));
        bytes memory bind = _paidPayload(MALLORY, BIND, abi.encode(w));
        paid.setNodes(MALLORY, keccak256("mallory's handle node"));
        vm.expectRevert(abi.encodeWithSelector(IClaimExecutor.HeldIdentityNotLinked.selector, w, X, MALLORY));
        executor.bind{value: FEE}(w, X, 2, bind);
    }

    /// A held identity the wallet has since unlinked does not block binding another.
    function test_bindIgnoresIdentitiesHeldBefore() public {
        address w = _claim();
        _link(w, GITHUB, BOB, w, "", _admin());
        bytes memory bind = _payload(GITHUB, BOB, BIND, abi.encode(w));
        githubStub.setNodes(BOB, keccak256("bob's handle node"));
        executor.bind(w, GITHUB, V1, bind);
        _root(w, address(validator), abi.encodeCall(IIdentityValidator.unlink, (_identity(GITHUB, BOB))));

        executor.bind{value: FEE}(w, X, 2, _paidPayload(ALICE, BIND, abi.encode(w)));
        assertEq(identities.resolveId(ALICE), w, "not bound");
        assertEq(identities.resolveId(BOB), w, "the earlier binding moved");
    }

    function test_theExecutorCannotMakeTheWalletDoAnythingElse() public {
        address w = _claim();
        address other = factory.createWallet(GITHUB, BOB);

        // A proof naming another wallet binds nothing here.
        bytes memory bind = _paidPayload(ALICE, BIND, abi.encode(other));
        vm.expectRevert(abi.encodeWithSelector(IdentityRegistry.NotProofTarget.selector, other, w));
        executor.bind{value: FEE}(w, X, 2, bind);

        // Only the installed executor may drive the wallet.
        vm.prank(mallory);
        vm.expectRevert(abi.encodeWithSelector(ERC7579Utils.ERC7579UninstalledModule.selector, 2, mallory));
        IERC7579Execution(w).executeFromExecutor(MODE_SINGLE, abi.encodePacked(mallory, uint256(0), ""));

        // A claim pays the wallet, whoever sends it.
        bind = _paidPayload(ALICE, BIND, abi.encode(w));
        executor.bind{value: FEE}(w, X, 2, bind);
        vm.prank(mallory);
        executor.claimToSelf(w, HANDLE, nativeOnly());
        assertEq(w.balance, 1 ether, "not paid to the wallet");
        assertEq(mallory.balance, 0, "paid to the caller");
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC7579Execution} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {ERC7579Utils} from "@openzeppelin/contracts/account/utils/draft-ERC7579Utils.sol";

import {IPlatformVerifier} from "../../ceremony/IPlatformVerifier.sol";
import {NATIVE_TOKEN} from "../../escrow/HandleEscrow.sol";
import {IdentityRegistry} from "../../identity/IdentityRegistry.sol";
import {StubPlatformVerifier} from "../../identity/test/StubPlatformVerifier.sol";
import {IClaimExecutor} from "../IClaimExecutor.sol";
import {IIdentityValidator} from "../IIdentityValidator.sol";
import {IWalletFactory} from "../IWalletFactory.sol";
import {IWalletRegistry} from "../IWalletRegistry.sol";
import {WalletTestBase} from "./WalletTestBase.sol";

/// Sends the whole claim as one transaction, as a relayer's multicall does.
contract Relay {
    function claim(
        IWalletFactory factory,
        IWalletRegistry registry,
        IClaimExecutor executor,
        bytes32 platformId,
        bytes32 idNode,
        bytes32 handleNode,
        bytes calldata linkPayload,
        bytes calldata bindPayload,
        uint256 fee
    ) external payable {
        address w = factory.createWallet(platformId, idNode);
        registry.linkIdentity{value: fee}(platformId, 2, linkPayload, IIdentityValidator.Policy(0, 0, false));
        executor.bind{value: fee}(w, platformId, 2, bindPayload);
        address[] memory tokens = new address[](1);
        tokens[0] = NATIVE_TOKEN;
        executor.claimToSelf(w, handleNode, tokens);
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

    function test_relayerClaimsInOnePlainTransaction() public {
        address w = factory.walletAddress(X, ALICE);
        bytes memory link = _paidPayload(ALICE, LINK, _txData(w, "", bytes32(0)));
        bytes memory bind = _paidPayload(ALICE, BIND, abi.encode(w));
        Relay relay = new Relay();
        vm.deal(relayer, 1 ether);
        vm.prank(relayer);
        relay.claim{value: 2 * FEE}(factory, registry, executor, X, ALICE, HANDLE, link, bind, FEE);

        assertGt(w.code.length, 0, "no wallet");
        assertEq(identities.resolveId(ALICE), w, "not bound to the wallet");
        assertEq(w.balance, 1 ether, "escrow not claimed to the wallet");
        assertEq(paid.lastValue(), FEE, "the bind fee was not forwarded");
    }

    function test_bindRefusesAnIdentityNotLinkedToTheWallet() public {
        address w = _claim();
        bytes memory bind = _paidPayload(MALLORY, BIND, abi.encode(w));
        vm.expectRevert(abi.encodeWithSelector(IClaimExecutor.NotLinked.selector, w, X, MALLORY));
        executor.bind{value: FEE}(w, X, 2, bind);
        assertEq(identities.resolveId(MALLORY), address(0), "bound anyway");
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
        address[] memory tokens = new address[](1);
        tokens[0] = NATIVE_TOKEN;
        vm.prank(mallory);
        executor.claimToSelf(w, HANDLE, tokens);
        assertEq(w.balance, 1 ether, "not paid to the wallet");
        assertEq(mallory.balance, 0, "paid to the caller");
    }
}

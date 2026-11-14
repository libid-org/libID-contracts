// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Execution} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";

import {IPlatformVerifier} from "../../ceremony/IPlatformVerifier.sol";
import {NATIVE_TOKEN} from "../../NativeToken.sol";
import {IHandleEscrow} from "../../escrow/IHandleEscrow.sol";
import {TestERC20} from "../../escrow/test/EscrowMocks.sol";
import {IIdentityRegistry} from "../../identity/IIdentityRegistry.sol";
import {StubPlatformVerifier} from "../../identity/test/StubPlatformVerifier.sol";
import {IIdentityValidator} from "../IIdentityValidator.sol";
import {IWalletFactoryOnboarding} from "../IWalletFactory.sol";
import {IWalletRegistry} from "../IWalletRegistry.sol";
import {AUTHORIZED_MODE} from "../IWebWallet.sol";
import {operationList} from "./WalletTestBase.sol";
import {ExecuteBase} from "./DirectExecute.t.sol";

/// @notice Onboarding in one `createAndExecute`: the batch Alice's first session K signs links K from a genesis
///         Operation List proof, binds her handle, claims the escrow, repays the relayer
///         and adds a bot's session.
contract CreateAndExecuteTest is ExecuteBase {
    bytes32 internal constant HANDLE = keccak256("alice's handle node");
    uint16 internal constant V2 = 2;
    uint256 internal constant FEE = 0.001 ether;
    uint256 internal constant CLAIMED = 1 ether;
    uint256 internal constant BOT_PK = 0xB07;

    StubPlatformVerifier internal paid;
    TestERC20 internal token;
    address internal bob = makeAddr("bob");
    address internal w;
    bytes internal list;
    uint256 internal linkFee;

    function setUp() public override {
        super.setUp();
        paid = new StubPlatformVerifier(X, FEE);
        paid.setNodes(ALICE, HANDLE);
        vm.prank(owner);
        proofVerifier.setVerifier(X, V2, IPlatformVerifier(address(paid)));
        w = factory.walletAddress(X, ALICE);
        list = abi.encode(
            StubPlatformVerifier.StubPayload({
                ceremonyVersion: 1,
                operationDomain: OPERATIONS,
                authorizationNonce: bytes32(uint256(1)),
                transactionData: operationList(BIND, abi.encode(w), LINK, _txData(w, _key(ALICE_PK), _ph(_admin())))
            })
        );
        linkFee = registry.quote(X, V2);
        token = new TestERC20();
        vm.deal(bob, CLAIMED);
        token.mint(bob, CLAIMED);
        vm.startPrank(bob);
        token.approve(address(escrow), CLAIMED);
        escrow.deposit{value: CLAIMED}(X, HANDLE, NATIVE_TOKEN, CLAIMED);
        escrow.deposit(X, HANDLE, address(token), CLAIMED);
        vm.stopPrank();
        vm.deal(relayer, 1 ether);
    }

    /// The batch, for a wallet that does not exist yet.
    function _onboarding() internal view returns (bytes memory) {
        address[] memory tokens = new address[](2);
        (tokens[0], tokens[1]) = (NATIVE_TOKEN, address(token));
        Execution[] memory x = new Execution[](5);
        x[0] = _x(address(registry), linkFee, abi.encodeCall(IWalletRegistry.linkIdentity, (X, V2, list, _admin())));
        x[1] =
            _x(address(identities), FEE, abi.encodeCall(IIdentityRegistry.bindPrivately, (X, V2, list, 0, address(0))));
        x[2] = _x(address(escrow), 0, abi.encodeCall(IHandleEscrow.claim, (HANDLE, tokens, w)));
        x[3] = _x(relayer, linkFee + FEE, "");
        x[4] = _x(
            address(validator),
            0,
            abi.encodeCall(IIdentityValidator.addSession, (_identity(X, ALICE), _key(BOT_PK), _hitOnly()))
        );
        return abi.encode(x);
    }

    /// `pk` signs `calls` for nonce 0 under the validator's key, written by hand: the wallet has no code yet.
    function _signedBy(uint256 pk, bytes memory calls) internal view returns (bytes memory) {
        uint256 n = uint256(uint160(address(validator))) << 96;
        return _directAt(w, _pks(pk), calls, n, uint48(_now()), false, _hitProofs(0));
    }

    function _send(bytes memory calls, bytes memory auth) internal {
        vm.prank(relayer, relayer);
        IWalletFactoryOnboarding(address(factory)).createAndExecute{value: linkFee + FEE}(
            X, ALICE, AUTHORIZED_MODE, _data(calls, auth)
        );
    }

    function test_oneCreateAndExecuteOnboardsAlice() public {
        assertEq(w.code.length, 0, "the wallet exists");
        bytes memory calls = _onboarding();
        _send(calls, _signedBy(ALICE_PK, calls));

        assertGt(w.code.length, 0, "no wallet");
        (address holder,) = identities.handleBinding(HANDLE);
        assertEq(holder, w, "handle not bound to the wallet");
        assertEq(escrow.escrowed(HANDLE, NATIVE_TOKEN), 0, "native left in the escrow");
        assertEq(escrow.escrowed(HANDLE, address(token)), 0, "token left in the escrow");
        assertEq(w.balance, CLAIMED - linkFee - FEE, "wallet native");
        assertEq(token.balanceOf(w), CLAIMED, "wallet token");
        assertEq(relayer.balance, 1 ether, "the relayer is not even");
        assertEq(address(factory).balance, 0, "value left in the factory");
        assertEq(_nonce(w, address(validator)), (uint256(uint160(address(validator))) << 96) + 1, "nonce");

        IIdentityValidator.Session memory k = validator.sessionOf(w, _key(ALICE_PK));
        assertTrue(k.admin && !k.byProof && k.activeAt == 0, "K is not the first session");
        IIdentityValidator.Session memory bot = validator.sessionOf(w, _key(BOT_PK));
        assertEq(bot.identity, _identity(X, ALICE), "no bot session");
        assertTrue(!bot.admin && !bot.byProof, "the bot session is admin or by proof");
        assertEq(bot.activeAt, _now(), "the bot session's start");

        // The bot acts alone within its rules, from the next second.
        bytes memory hit = _one(_hitX());
        _refuses(w, hit, _direct(w, address(validator), _pks(BOT_PK), hit, true), NOT_AUTHORIZED);
        vm.warp(_now() + 1);
        _runs(w, hit, _direct(w, address(validator), _pks(BOT_PK), hit, true));
    }

    /// Someone else signing for Alice's new wallet is refused, though the batch would link K.
    function test_onlyTheLinkedKeySignsTheOnboarding() public {
        bytes memory calls = _onboarding();
        vm.expectRevert(NOT_AUTHORIZED);
        _send(calls, _signedBy(MALLORY_PK, calls));
        assertEq(w.code.length, 0, "the wallet was created");
        _send(calls, _signedBy(ALICE_PK, calls));
        assertEq(token.balanceOf(w), CLAIMED, "control");
    }
}

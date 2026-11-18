// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";
import {IAccount, PackedUserOperation} from "@openzeppelin/contracts/interfaces/IERC4337.sol";
import {Execution} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";

import {IExecutionCheck, IIdentityValidator} from "../IIdentityValidator.sol";
import {IWalletRegistry} from "../IWalletRegistry.sol";
import {AUTHORIZED_MODE, IWebWallet} from "../IWebWallet.sol";
import {ExecuteBase, OtherVersionWallet, Reenter} from "./DirectExecute.t.sol";
import {LeftoverDelegate} from "./Eip7702Account.t.sol";

/// An implementation planted in the ERC-1967 slot before setup: it answers a view and marks its use.
contract PlantedImpl {
    function identityValidator() external pure returns (address) {
        return address(0xBAD);
    }

    function mark() external {
        assembly {
            sstore(0x1234, 1)
        }
    }
}

/// A leftover validator that accepts every signature and UserOperation.
contract MagicModule {
    function isModuleType(uint256) external pure returns (bool) {
        return true;
    }

    function onInstall(bytes calldata) external {}

    function hello() external pure returns (bool) {
        return true;
    }

    function isValidSignatureWithSender(address, bytes32, bytes calldata) external pure returns (bytes4) {
        return 0x1626ba7e;
    }

    function validateUserOp(PackedUserOperation calldata, bytes32) external pure returns (uint256) {
        return 0;
    }
}

/// Sends with the 2,300-gas stipend.
contract Payer {
    function pay(address payable to) external payable {
        to.transfer(msg.value);
    }
}

/// @notice An EOA delegated with EIP-7702 to `WalletForwarder`, which routes to the implementation its setup
///         wrote to the ERC-1967 slot. The key signs only the onboarding batch.
/// forge-config: default.evm_version = "prague"
contract WalletForwarderTest is ExecuteBase {
    uint256 internal constant KEY_PK = 0x7702;
    uint256 internal constant SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    bytes4 internal constant NOT_DELEGATED = bytes4(keccak256("NotDelegated()"));
    bytes32 internal constant UPGRADED = keccak256("Upgraded(address)");

    address internal a;
    address internal fwd;

    function setUp() public override {
        super.setUp();
        a = vm.addr(KEY_PK);
        fwd = deployCode("WalletForwarder.sol:WalletForwarder", abi.encode(address(factory)));
        vm.deal(a, 1 ether);
    }

    /// The key's authorization of the forwarder, sent with an empty call: no setup.
    function _delegate() internal {
        vm.signAndAttachDelegation(fwd, KEY_PK);
        vm.prank(relayer);
        (bool ok,) = a.call("");
        assertTrue(ok, "an empty call reverted");
        assertEq(a.code, abi.encodePacked(hex"ef0100", fwd), "not delegated");
    }

    function _implIs(address impl, string memory why) internal view {
        assertEq(vm.load(a, IMPL_SLOT), bytes32(uint256(uint160(impl))), why);
    }

    /// `pk` signs `calls` for `w` as a 65-byte authorization over the `Execute` digest with `at = 0`.
    function _keySigned(address w, uint256 pk, bytes memory calls, uint256 n, uint48 deadline, uint256 callGas)
        internal
        view
        returns (bytes memory)
    {
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(pk, _execDigestGas(w, AUTHORIZED_MODE, calls, 0, n, deadline, callGas));
        return abi.encode(calls, signedValue, deadline, callGas, abi.encodePacked(r, s, v));
    }

    function _keyNow(bytes memory calls) internal view returns (bytes memory) {
        return _keySigned(a, KEY_PK, calls, _nonce(a, address(validator)), uint48(_now() + 1 hours), CALL_GAS);
    }

    function _send(address w, bytes memory data) internal {
        vm.prank(relayer);
        IWebWallet(w).execute(AUTHORIZED_MODE, data);
    }

    function _sendReverts(address w, bytes memory data, bytes memory err) internal {
        vm.prank(relayer);
        vm.expectRevert(err);
        IWebWallet(w).execute(AUTHORIZED_MODE, data);
    }

    /// Link Alice's X identity with a link-only proof, add her admin session, repay the relayer.
    function _onboarding() internal returns (bytes memory) {
        Execution[] memory x = new Execution[](3);
        bytes memory payload = _payload(X, ALICE, LINK, _txData(a, "", 0));
        x[0] = _x(address(registry), 0, abi.encodeCall(IWalletRegistry.linkIdentity, (X, V1, payload, "", _app())));
        x[1] = _x(
            address(validator),
            0,
            abi.encodeCall(IIdentityValidator.addSession, (_identity(X, ALICE), _key(ALICE_PK), _admin()))
        );
        x[2] = _x(relayer, 0.01 ether, "");
        return abi.encode(x);
    }

    /// The relayer's one type-4 transaction: the authorization, then the key-signed onboarding batch.
    function _onboard() internal {
        bytes memory data = _keyNow(_onboarding());
        vm.signAndAttachDelegation(fwd, KEY_PK);
        _send(a, data);
        vm.warp(_now() + 1);
    }

    // ─── Onboarding ─────────────────────────────────────────────────

    function test_oneTransactionOnboardsAndTheSessionTakesOver() public {
        _onboard();
        assertEq(a.code, abi.encodePacked(hex"ef0100", fwd), "not delegated");
        _implIs(walletImpl, "setup's implementation");
        assertTrue(validator.isLinked(a, _identity(X, ALICE)), "not linked");
        assertTrue(validator.hadSession(a), "no session");
        assertEq(relayer.balance, 0.01 ether, "not repaid");

        bytes memory hit = _one(_hitX());
        _runs(a, hit, _aliceFor(a, hit, _nonce(a, address(validator))));
        // The key is onboarding only, and a 65-byte authorization is never decoded as an `Authorization`.
        _sendReverts(a, _keyNow(hit), abi.encodeWithSelector(NOT_SIGNED));
    }

    /// A stranger's first call runs setup and nothing else; the key's batch then runs as if it had not.
    function test_aStrangersSetupIsTheKeysAndRunsOnce() public {
        _delegate();
        vm.recordLogs();
        vm.prank(mallory);
        (bool ok,) = a.call(abi.encodeCall(IWebWallet.identityValidator, ()));
        assertTrue(ok, "a stranger's call reverted");
        _implIs(walletImpl, "setup's implementation");
        assertFalse(validator.hadSession(a), "a session");

        address next = _walletImpl();
        _factoryNames(next);
        _send(a, _keyNow(_onboarding()));
        _implIs(walletImpl, "setup ran again");
        assertTrue(validator.hadSession(a), "no session");

        Vm.Log[] memory logs = vm.getRecordedLogs();
        uint256 upgrades;
        for (uint256 i; i < logs.length; ++i) {
            if (logs[i].emitter == a && logs[i].topics[0] == UPGRADED) {
                assertEq(logs[i].topics[1], bytes32(uint256(uint160(walletImpl))), "Upgraded's implementation");
                upgrades++;
            }
        }
        assertEq(upgrades, 1, "Upgraded events");
    }

    function test_aDirectCallToTheForwarderReverts() public {
        (bool ok, bytes memory err) = fwd.call(abi.encodeCall(IWebWallet.identityValidator, ()));
        assertFalse(ok, "the forwarder answered");
        assertEq(err, abi.encodeWithSelector(NOT_DELEGATED), "the error");
        assertEq(vm.load(fwd, IMPL_SLOT), bytes32(0), "the forwarder set itself up");
    }

    function test_aStipendTransferArrivesBeforeAndAfterSetup() public {
        Payer payer = new Payer();
        _delegate();
        payer.pay{value: 1}(payable(a));
        assertEq(vm.load(a, IMPL_SLOT), bytes32(0), "a transfer ran setup");
        _onboard();
        payer.pay{value: 1}(payable(a));
        assertEq(a.balance, 1 ether + 2 - 0.01 ether, "a transfer did not arrive");
    }

    /// Routing waits for the flag: a planted slot is overwritten at setup and its code never runs.
    function test_aLeftoverSlotIsOverwrittenAndNeverRouted() public {
        PlantedImpl planted = new PlantedImpl();
        _delegate();
        vm.store(a, IMPL_SLOT, bytes32(uint256(uint160(address(planted)))));
        // Accepted: before setup a static call reverts, since setup writes storage.
        vm.expectRevert();
        IWebWallet(a).identityValidator();

        _send(a, _keyNow(_onboarding()));
        _implIs(walletImpl, "the planted slot stayed");
        assertEq(IWebWallet(a).identityValidator(), address(validator), "routed to the planted code");
        vm.expectRevert();
        PlantedImpl(a).mark();
        assertEq(vm.load(a, bytes32(uint256(0x1234))), bytes32(0), "the planted code ran");
    }

    // ─── The key's signature ────────────────────────────────────────

    /// Every mutation is refused with `ExecutionNotSigned`, the unmutated batch then runs, and its replay is
    /// refused.
    function test_theKeysSignatureBindsTheBatch() public {
        _delegate();
        bytes memory hit = _one(_hitX());
        uint256 n = _nonce(a, address(validator));
        uint48 deadline = uint48(_now() + 1 hours);
        bytes memory good = _keySigned(a, KEY_PK, hit, n, deadline, CALL_GAS);
        bytes memory notSigned = abi.encodeWithSelector(NOT_SIGNED);

        _sendReverts(a, _keySigned(a, MALLORY_PK, hit, n, deadline, CALL_GAS), notSigned);
        _sendReverts(a, _withAuth(good, _highS(_authOf(good))), notSigned);
        _sendReverts(a, _withAuth(good, new bytes(65)), notSigned);
        // The neighbour of 65 bytes is not a key signature.
        vm.prank(relayer);
        vm.expectRevert();
        IWebWallet(a).execute(AUTHORIZED_MODE, _withAuth(good, abi.encodePacked(_authOf(good), bytes1(0))));

        (, uint256 v, uint48 d, uint256 g, bytes memory sig) = abi.decode(good, (bytes, uint256, uint48, uint256, bytes));
        _sendReverts(a, abi.encode(_then(_hitX()), v, d, g, sig), notSigned);
        _sendReverts(a, abi.encode(hit, v, d, g + 1, sig), notSigned);
        vm.deal(relayer, 1);
        vm.prank(relayer);
        vm.expectRevert(notSigned);
        IWebWallet(a).execute{value: 1}(AUTHORIZED_MODE, abi.encode(hit, uint256(1), d, g, sig));

        uint256 hits = target.calls();
        _send(a, good);
        assertEq(target.calls(), hits + 1, "the key's batch did not run");
        assertEq(target.last(), a, "not from the account");
        _sendReverts(a, good, notSigned);
    }

    function test_theKeysSignatureExpires() public {
        _delegate();
        uint48 deadline = uint48(_now());
        bytes memory data =
            _keySigned(a, KEY_PK, _one(_hitX()), _nonce(a, address(validator)), deadline, CALL_GAS);
        vm.warp(_now() + 1);
        _sendReverts(a, data, abi.encodeWithSelector(IExecutionCheck.ExecutionExpired.selector, deadline));
    }

    /// A factory wallet's address has no key: a 65-byte authorization is refused, not decoded.
    function test_aFactoryWalletHasNoKey() public {
        address w = factory.createWallet(X, ALICE, 0);
        assertFalse(validator.hadSession(w), "a session");
        bytes memory hit = _one(_hitX());
        uint48 deadline = uint48(_now() + 1 hours);
        uint256 n = _nonce(w, address(validator));
        _sendReverts(w, _keySigned(w, KEY_PK, hit, n, deadline, CALL_GAS), abi.encodeWithSelector(NOT_SIGNED));
        _sendReverts(w, _keySigned(w, ALICE_PK, hit, n, deadline, CALL_GAS), abi.encodeWithSelector(NOT_SIGNED));
    }

    function _authOf(bytes memory data) internal pure returns (bytes memory sig) {
        (,,,, sig) = abi.decode(data, (bytes, uint256, uint48, uint256, bytes));
    }

    function _withAuth(bytes memory data, bytes memory sig) internal pure returns (bytes memory) {
        (bytes memory calls, uint256 v, uint48 d, uint256 g,) =
            abi.decode(data, (bytes, uint256, uint48, uint256, bytes));
        return abi.encode(calls, v, d, g, sig);
    }

    /// The same signature with `s` mirrored to the upper half and `v` flipped.
    function _highS(bytes memory sig) internal pure returns (bytes memory) {
        (bytes32 r, bytes32 s) = abi.decode(sig, (bytes32, bytes32));
        uint8 v = uint8(sig[64]);
        return abi.encodePacked(r, bytes32(SECP256K1_N - uint256(s)), v == 27 ? uint8(28) : uint8(27));
    }

    // ─── Upgrades ───────────────────────────────────────────────────

    /// Setup names the factory's implementation: `upgradeToAndCall` is open to a matured root operation alone,
    /// only to the factory's next implementation, and the account then runs it.
    function test_onlyAMaturedRootUpgrades() public {
        _onboard();
        address next = address(new OtherVersionWallet(address(validator)));
        bytes memory up = abi.encodeCall(IWebWallet.upgradeToAndCall, (next, ""));
        address[2] memory callers = [mallory, a];
        for (uint256 i; i < callers.length; ++i) {
            vm.prank(callers[i], callers[i]);
            vm.expectRevert(abi.encodeWithSelector(IWebWallet.NotValidator.selector, callers[i]));
            IWebWallet(a).upgradeToAndCall(next, "");
        }
        vm.prank(a);
        vm.expectRevert(abi.encodeWithSelector(IWebWallet.NotFactoryImplementation.selector, next, walletImpl));
        validator.queueRoot(a, up);
        _factoryNames(next);
        vm.prank(a);
        bytes32 opId = validator.queueRoot(a, up);
        vm.expectRevert(abi.encodeWithSelector(IIdentityValidator.RootNotReady.selector, opId));
        validator.executeRoot(a, a, up);
        vm.warp(_now() + 48 hours);
        validator.executeRoot(a, a, up);
        _implIs(next, "not upgraded");
        (, string memory name, string memory version,,,,) = OtherVersionWallet(a).eip712Domain();
        assertEq(abi.encode(name, version), abi.encode("WebWallet", "2"), "not routed to the upgrade");
    }

    /// The validator is not in OpenZeppelin's module set: a migrating upgrade reverts.
    function test_migrateReverts() public {
        _onboard();
        IWalletRegistry r2 = _newRegistry(address(factory));
        address impl2 = deployCode("WebWallet.sol:WebWallet", abi.encode(r2.identityValidator()));
        _factoryNames(impl2);
        bytes memory migrate = abi.encodeCall(IWebWallet.migrate, (_install(X, ALICE, _key(ALICE_PK), _admin())));
        bytes memory up = abi.encodeCall(IWebWallet.upgradeToAndCall, (impl2, migrate));
        vm.prank(a);
        validator.queueRoot(a, up);
        vm.warp(_now() + 48 hours);
        vm.expectRevert();
        validator.executeRoot(a, a, up);
        _implIs(walletImpl, "migrated");
    }

    // ─── As on any wallet ───────────────────────────────────────────

    function test_reentryReverts() public {
        _onboard();
        Reenter re = new Reenter();
        uint256 n = _nonce(a, address(validator));
        bytes memory inner = _one(_hitX());
        bytes memory outer =
            _then(_x(address(re), 0, abi.encodeCall(Reenter.go, (a, _data(inner, _aliceFor(a, inner, n + 1))))));
        _refuses(a, outer, _aliceFor(a, outer, n), ReentrancyGuardTransient.ReentrancyGuardReentrantCall.selector);
    }

    /// A leftover validator that answers the ERC-1271 magic value and accepts any UserOperation has no power.
    function test_aLeftoverMagicValidatorIsInert() public {
        MagicModule m = new MagicModule();
        vm.signAndAttachDelegation(address(new LeftoverDelegate()), KEY_PK);
        LeftoverDelegate(payable(a)).rig(address(m));
        bytes32 h = keccak256("a message");
        bytes memory sig = abi.encodePacked(address(m), hex"00");
        assertEq(IWebWallet(a).isValidSignature(h, sig), bytes4(0x1626ba7e), "control: the module answered");

        _onboard();
        assertEq(IWebWallet(a).isValidSignature(h, sig), bytes4(0xffffffff), "the leftover validator signed");
        PackedUserOperation memory op = _op(a, 0, _hit());
        op.nonce = uint256(uint160(address(m))) << 96;
        _refused(op, "a leftover validator");
    }

    // ─── Gas and ERC-7562 ───────────────────────────────────────────

    /// The forwarder's cost on a cold call, against a factory wallet's proxy.
    function test_forwarderOverheadPerCall() public {
        _onboard();
        address w = factory.createWallet(X, BOB, 0);
        vm.cool(a);
        vm.cool(fwd);
        vm.cool(w);
        vm.cool(walletImpl);
        uint256 g = gasleft();
        IWebWallet(a).identityValidator();
        uint256 viaForwarder = g - gasleft();
        vm.cool(walletImpl);
        g = gasleft();
        IWebWallet(w).identityValidator();
        uint256 viaProxy = g - gasleft();
        emit log_named_uint("cold view via the forwarder", viaForwarder);
        emit log_named_uint("cold view via a factory proxy", viaProxy);
        assertLt(viaForwarder, viaProxy + 10_000, "forwarder overhead");
    }

    /// After setup, validation reads no factory storage and only the validator's slots associated with
    /// the account.
    function test_validationStorageIsTheAccounts() public {
        _onboard();
        PackedUserOperation memory op = _signed(_op(a, 0, _hit()), _pks(ALICE_PK));
        vm.startMappingRecording();
        vm.record();
        vm.prank(EP);
        assertEq(IAccount(a).validateUserOp(op, keccak256("unused"), 0) & 1, 0, "not validated");
        (bytes32[] memory reads,) = vm.accesses(address(factory));
        assertEq(reads.length, 0, "validation read the factory");
        (reads,) = vm.accesses(address(validator));
        for (uint256 i; i < reads.length; ++i) {
            assertTrue(_associated(a, reads[i]), "validation read a slot not associated with the account");
        }
    }
}

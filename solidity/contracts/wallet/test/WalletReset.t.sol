// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IAccount, PackedUserOperation} from "@openzeppelin/contracts/interfaces/IERC4337.sol";
import {Execution} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {IWalletFactory} from "../IWalletFactory.sol";
import {IWalletForwarder} from "../IWalletForwarder.sol";
import {AUTHORIZED_MODE, IWebWallet} from "../IWebWallet.sol";
import {CallTarget, IUserOpHash, WalletBase} from "./WalletBase.sol";

/// Measures one call from its own isolated transaction, where the target and everything it reads are cold.
contract ColdMeter {
    function cost(address target) external view returns (uint256 gas) {
        gas = gasleft();
        IWebWallet(target).VERSION();
        gas -= gasleft();
    }
}

/// Sends with the 2,300-gas stipend.
contract Payer {
    function pay(address payable to) external payable {
        to.transfer(msg.value);
    }
}

/// Code a key delegates to while away: it points the release slot at its own implementation.
contract Planter {
    fallback() external {}

    function plant(address impl) external {
        bytes32 slot = 0xe1dba8fb066a3b169f681c6818aeab86343e7484c7e0cee1cbf00e41a55c2800;
        assembly {
            sstore(slot, or(impl, shl(160, 99)))
        }
    }
}

/// A release whose `reset` has no gate: it pays the account's balance to its caller.
contract OpenRelease {
    uint64 public constant VERSION = 2;
    address public immutable FACTORY;
    address public immutable REGISTRY;

    constructor(address factory, address registry) {
        (FACTORY, REGISTRY) = (factory, registry);
    }

    function reset(bytes calldata) external payable {
        (bool ok,) = msg.sender.call{value: address(this).balance}("");
        require(ok);
    }
}

/// @notice EIP-7702 accounts on WalletForwarder: `reset` and its epoch, the forwarder's routing, and the key's
///         own powers.
/// forge-config: default.evm_version = "prague"
contract WalletResetTest is WalletBase {
    uint256 internal constant KEY_PK = 0x7702;
    uint256 internal constant SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    address internal a;
    address internal fwd;

    function setUp() public override {
        super.setUp();
        a = vm.addr(KEY_PK);
        fwd = deployCode("WalletForwarder.sol:WalletForwarder", abi.encode(address(factory)));
    }

    function _delegateTo(address code) internal {
        vm.signAndAttachDelegation(code, KEY_PK);
        vm.prank(relayer);
        (bool ok,) = a.call("");
        assertTrue(ok, "an empty call reverted");
        assertEq(a.code, abi.encodePacked(hex"ef0100", code), "not delegated");
    }

    /// The key's onboarding batch: link Alice's X identity, then add her admin session.
    function _onboarding() internal returns (bytes memory) {
        return _two(
            _linkX(a, X, ALICE, "", _admin()),
            _x(a, 0, abi.encodeCall(IWebWallet.addSession, (_identity(X, ALICE), _key(ALICE_PK), _admin())))
        );
    }

    function _reset(bytes memory calls) internal {
        vm.prank(a, a);
        IWebWallet(a).reset(calls);
    }

    function _onboard() internal {
        _delegateTo(fwd);
        _reset(_onboarding());
        vm.deal(a, 1 ether);
        vm.warp(_now() + 1);
    }

    function test_resetOnboardsAndTheSessionActs() public {
        _onboard();
        (address impl, uint64 version) = IWebWallet(a).release();
        (address latest, uint64 latestVersion) = factory.latest();
        assertEq(abi.encode(impl, version), abi.encode(latest, latestVersion), "not the factory's latest");
        assertTrue(IWebWallet(a).isLinked(_identity(X, ALICE)), "not linked");
        (bytes32 p,,) = IWebWallet(a).genesisIdentity();
        assertEq(p, bytes32(0), "a forwarder account has a genesis");
        _run(a, _one(_hitX()));
        _handle(_ops(_signOp(_op(a, _hitCall()), 1, _pks(ALICE_PK))));
        assertEq(target.calls(), 2, "the session did not act");
    }

    /// Acceptance 9: before `reset`, only an empty call returns; a UserOperation is refused, and a stranger's
    /// `reset` writes nothing.
    function test_beforeResetNothingRuns() public {
        _delegateTo(fwd);
        vm.prank(a, a);
        vm.expectRevert(IWalletForwarder.NotSetUp.selector);
        IWebWallet(a).execute(MODE_BATCH, _one(_hitX()));
        _refusedOp(_signOp(_op(a, _hitCall()), 1, _pks(ALICE_PK)));
        bytes memory onboarding = _onboarding();
        vm.prank(mallory, mallory);
        vm.expectRevert(IWebWallet.ResetRefused.selector);
        IWebWallet(a).reset(onboarding);
        assertEq(vm.load(a, RELEASE_SLOT), bytes32(0), "a stranger's reset wrote the slot");
    }

    /// The epoch moves to `keccak256(abi.encode(old, blockhash(n - 1), timestamp))`, and kills what code the key
    /// ran while away planted: sessions and the release slot.
    function test_plantedStateIsDeadAfterReset() public {
        _onboard();
        bytes32 old = IWebWallet(a).epoch();
        address planter = address(new Planter());
        _delegateTo(planter);
        vm.prank(a, a);
        Planter(a).plant(makeAddr("evil implementation"));
        _delegateTo(fwd);

        vm.roll(vm.getBlockNumber() + 1);
        bytes32 expected = keccak256(abi.encode(old, blockhash(vm.getBlockNumber() - 1), _now()));
        vm.expectEmit(a);
        emit IWebWallet.EpochReset(expected);
        _reset(_one(_hitX()));
        assertEq(IWebWallet(a).epoch(), expected, "epoch");
        assertEq(IWebWallet(a).sessionOf(_key(ALICE_PK)).identity, bytes32(0), "a planted session lives");
        assertFalse(IWebWallet(a).isLinked(_identity(X, ALICE)), "a planted link lives");
        (address impl,) = IWebWallet(a).release();
        (address latest,) = factory.latest();
        assertEq(impl, latest, "the planted release survived");
        bytes memory data = _signed(a, _pks(ALICE_PK), _one(_hitX()));
        vm.expectPartialRevert(IWebWallet.ExecutionNotSigned.selector);
        IWebWallet(a).execute(AUTHORIZED_MODE, data);
    }

    /// Acceptance 9: `reset` only from the key's own top-level transaction, never under the lock.
    function test_resetRefusals() public {
        _onboard();
        bytes32 epoch = IWebWallet(a).epoch();
        bytes memory reset = abi.encodeCall(IWebWallet.reset, (_one(_hitX())));
        address[2] memory senders = [mallory, mallory];
        address[2] memory origins = [mallory, a];
        for (uint256 i; i < senders.length; ++i) {
            vm.prank(senders[i], origins[i]);
            vm.expectRevert(IWebWallet.ResetRefused.selector);
            IWebWallet(a).reset(_one(_hitX()));
        }
        // Inside the key's own batch, and inside a relayed session batch the key's transaction carries.
        vm.prank(a, a);
        vm.expectRevert(IWebWallet.ResetRefused.selector);
        IWebWallet(a).execute(MODE_BATCH, _one(_x(a, 0, reset)));
        bytes memory data = _signed(a, _pks(ALICE_PK), _one(_x(a, 0, reset)));
        vm.prank(a, a);
        vm.expectRevert(IWebWallet.ResetRefused.selector);
        IWebWallet(a).execute(AUTHORIZED_MODE, data);
        // Never a root operation, so never inside `executeRoot`.
        bytes memory queue = abi.encodeCall(IWebWallet.queueRoot, (reset));
        vm.prank(a, a);
        vm.expectPartialRevert(IWebWallet.RootOperationNotAllowed.selector);
        IWebWallet(a).execute(MODE_BATCH, _one(_x(a, 0, queue)));
        assertEq(IWebWallet(a).epoch(), epoch, "the epoch moved");
        assertEq(target.calls(), 0, "a refused reset ran its batch");
    }

    /// The forwarder routes `reset` only for the key's own top-level transaction, so a release published later
    /// runs in no account for anyone else.
    function test_aNewReleasesResetRunsOnlyForTheKey() public {
        _onboard();
        bytes32 epoch = IWebWallet(a).epoch();
        address open = address(new OpenRelease(address(factory), address(registry)));
        vm.prank(owner);
        factory.publish(open);
        address[2] memory senders = [mallory, a];
        address[2] memory origins = [mallory, mallory];
        for (uint256 i; i < senders.length; ++i) {
            vm.prank(senders[i], origins[i]);
            vm.expectRevert(IWebWallet.ResetRefused.selector);
            IWebWallet(a).reset("");
        }
        assertEq(a.balance, 1 ether, "the account paid");
        assertEq(IWebWallet(a).epoch(), epoch, "the epoch moved");
        (address impl, uint64 version) = IWebWallet(a).release();
        assertEq(abi.encode(impl, version), abi.encode(impl1, 1), "the release moved");
        assertEq(IWebWallet(a).sessionOf(_key(ALICE_PK)).identity, _identity(X, ALICE), "the session died");
    }

    /// L1: the epoch is the domain's `salt`, so a `reset` retires every earlier Execute, UserOperation and
    /// ERC-7739 signature, even when the key adds the same session key again.
    function test_aResetRetiresEverySignatureBeforeIt() public {
        _assertDomain(_claim(), 0, 0);
        _onboard();
        bytes32 old = IWebWallet(a).epoch();
        _assertDomain(a, old, 0);
        bytes memory batch = _signed(a, _pks(ALICE_PK), _one(_hitX()));
        PackedUserOperation memory op = _signOp(_op(a, _hitCall()), 1, _pks(ALICE_PK));
        (bytes32 h, bytes memory sig) = _typedDataSign(a, _salt(a));
        assertEq(IWebWallet(a).isValidSignature(h, sig), bytes4(0x1626ba7e), "control: TypedDataSign before");

        _reset(_onboarding());
        vm.warp(_now() + 1);
        bytes32 epoch = IWebWallet(a).epoch();
        assertNotEq(epoch, old, "the epoch did not move");
        _assertDomain(a, epoch, 0);
        vm.prank(relayer);
        vm.expectRevert(IWebWallet.ExecutionNotSigned.selector);
        IWebWallet(a).execute(AUTHORIZED_MODE, batch);
        _refusedOp(op);
        assertEq(IWebWallet(a).isValidSignature(h, sig), bytes4(0xffffffff), "an old TypedDataSign");

        (h, sig) = _typedDataSign(a, _salt(a));
        assertEq(IWebWallet(a).isValidSignature(h, sig), bytes4(0x1626ba7e), "control: TypedDataSign after");
        _run(a, _one(_hitX()));
        _handle(_ops(_signOp(_op(a, _hitCall()), 1, _pks(ALICE_PK))));
        assertEq(target.calls(), 2, "control: the new signatures");
    }

    /// `eip712Domain()` reports the domain the wallet signs under, written from the spec at `epoch` and `rootEpoch`.
    function _assertDomain(address w, bytes32 epoch, uint32 rootEpoch) internal view {
        (bytes1 fields, string memory name, string memory version, uint256 chainId, address verifying, bytes32 salt,) =
            IWebWallet(w).eip712Domain();
        assertEq(fields, bytes1(0x1f), "fields");
        assertEq(salt, keccak256(abi.encode(epoch, rootEpoch)), "salt");
        bytes32 reported = keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"
                ),
                keccak256(bytes(name)),
                keccak256(bytes(version)),
                chainId,
                verifying,
                salt
            )
        );
        assertEq(reported, _domain(w, 1, salt), "eip712Domain() is not the signed domain");
    }

    /// Alice's ERC-7739 `TypedDataSign` of a fixed Mail, under `w`'s release 1 domain at `salt`.
    function _typedDataSign(address w, bytes32 salt) internal view returns (bytes32 h, bytes memory sig) {
        bytes32 app = keccak256("an app's domain");
        bytes32 typehash = keccak256(
            abi.encodePacked(
                "TypedDataSign(Mail contents,string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)",
                MAIL_TYPE
            )
        );
        bytes32 structHash =
            keccak256(abi.encode(typehash, MAIL, keccak256("WebWallet"), keccak256("1"), block.chainid, w, salt));
        bytes memory auth = _auth(_pks(ALICE_PK), keccak256(abi.encodePacked(hex"1901", app, structHash)), 0, false, 0);
        h = keccak256(abi.encodePacked(hex"1901", app, MAIL));
        sig = abi.encodePacked(auth, app, MAIL, MAIL_TYPE, uint16(bytes(MAIL_TYPE).length));
    }

    /// Audit L1: threshold 2 over X and GitHub. Alice signs a batch alone over the at-quorum digest. A keyless login
    /// removal of the GitHub identity drops the threshold to 1, and the same bytes are still refused.
    function test_aThresholdDropRetiresAHalfSignedBatch() public {
        address w = _claim();
        IWebWallet.Policy memory none;
        vm.warp(_now() + 1);
        _run(
            w,
            _two(
                _linkX(w, GITHUB, BOB, "", none),
                _x(w, 0, abi.encodeCall(IWebWallet.addSession, (_identity(GITHUB, BOB), _key(BOB_PK), _admin())))
            )
        );
        vm.warp(_now() + 1);
        _root(w, abi.encodeCall(IWebWallet.setThreshold, (2)));
        bytes memory data = _signedAt(w, 1, _pks(ALICE_PK), _one(_hitX()), false);
        vm.prank(mallory);
        vm.expectRevert(IWebWallet.ExecutionNotSigned.selector);
        IWebWallet(w).execute(AUTHORIZED_MODE, data);

        bytes memory remove = _payload(GITHUB, BOB, REMOVE, _txData(w, "", 0));
        vm.prank(mallory);
        IWebWallet(w).removeSessionsByLogin(GITHUB, V1, remove, "", none);
        assertEq(IWebWallet(w).threshold(), 1, "the threshold did not drop");
        vm.prank(mallory);
        vm.expectRevert(IWebWallet.ExecutionNotSigned.selector);
        IWebWallet(w).execute(AUTHORIZED_MODE, data);
        _run(w, _one(_hitX()));
        assertEq(target.calls(), 1, "control: a batch signed after");
    }

    /// Revoking an older admin, changing the threshold and a login removal each move the root epoch, and each
    /// retires every Execute, UserOperation and ERC-7739 signature made before it.
    function test_aRootEpochMoveRetiresEverySignatureBeforeIt() public {
        _onboard();
        IWebWallet.Policy memory none;
        bytes memory link = _linkPayload(a, GITHUB, BOB, "", none);
        vm.prank(a);
        IWebWallet(a).linkIdentity(GITHUB, V1, link, "", none);
        vm.prank(a);
        IWebWallet(a).addSession(_identity(GITHUB, BOB), _key(BOB_PK), _admin());
        vm.warp(_now() + 1);
        bytes memory remove = _payload(GITHUB, BOB, REMOVE, _txData(a, "", 0));
        bytes memory batch = _signed(a, _pks(ALICE_PK), _one(_hitX()));
        PackedUserOperation memory op = _signOp(_op(a, _hitCall()), 1, _pks(ALICE_PK));
        (bytes32 h, bytes memory sig) = _typedDataSign(a, _salt(a));
        assertEq(IWebWallet(a).isValidSignature(h, sig), bytes4(0x1626ba7e), "control: TypedDataSign");

        for (uint256 i; i < 3; ++i) {
            uint256 snap = vm.snapshotState();
            if (i == 0) {
                vm.prank(a);
                IWebWallet(a).revokeSession(_key(BOB_PK));
            } else if (i == 1) {
                vm.prank(a, a);
                IWebWallet(a).setThreshold(2);
            } else {
                IWebWallet(a).removeSessionsByLogin(GITHUB, V1, remove, "", none);
            }
            vm.prank(relayer);
            vm.expectRevert(IWebWallet.ExecutionNotSigned.selector);
            IWebWallet(a).execute(AUTHORIZED_MODE, batch);
            _refusedOp(op);
            assertEq(IWebWallet(a).isValidSignature(h, sig), bytes4(0xffffffff), vm.toString(i));
            vm.revertToState(snap);
        }
        vm.prank(relayer);
        IWebWallet(a).execute(AUTHORIZED_MODE, batch);
        assertEq(target.calls(), 1, "control: the batch with no move");
    }

    /// The key's top-level call reaches a root-only entry; its batch does not.
    function test_theKeysRootOnlyCallsAreTopLevel() public {
        _onboard();
        address impl2 = _publish(2);
        bytes[4] memory calls = [
            abi.encodeCall(IWebWallet.bump, (2)),
            abi.encodeCall(IWebWallet.setThreshold, (2)),
            abi.encodeCall(IWebWallet.setRootDelay, (72 hours)),
            abi.encodeCall(IWebWallet.unlink, (_identity(X, ALICE)))
        ];
        for (uint256 i; i < calls.length; ++i) {
            vm.prank(a, a);
            vm.expectRevert(IWebWallet.RootOperationRequired.selector);
            IWebWallet(a).execute(MODE_BATCH, _one(_x(a, 0, calls[i])));
        }
        vm.prank(mallory, mallory);
        vm.expectRevert(IWebWallet.RootOperationRequired.selector);
        IWebWallet(a).setRootDelay(72 hours);
        vm.prank(a, a);
        vm.expectEmit(a);
        emit IWebWallet.RootDelaySet(72 hours);
        IWebWallet(a).setRootDelay(72 hours);
        assertEq(IWebWallet(a).rootDelay(), 72 hours, "the key's own call");
        vm.prank(a, a);
        vm.expectEmit(a);
        emit IWebWallet.Bumped(1, 2, impl2);
        IWebWallet(a).bump(2);
    }

    /// The default mode in direct: the key's own call on its account runs; anyone else's does not.
    function test_defaultModeInDirect() public {
        _onboard();
        bytes memory hit = abi.encodePacked(address(target), uint256(0), abi.encodeWithSignature("hit()"));
        vm.prank(mallory, mallory);
        vm.expectRevert(abi.encodeWithSelector(IWebWallet.AccountUnauthorized.selector, mallory));
        IWebWallet(a).execute(MODE_SINGLE, hit);
        address w = _claim();
        vm.prank(relayer, relayer);
        vm.expectRevert(abi.encodeWithSelector(IWebWallet.AccountUnauthorized.selector, relayer));
        IWebWallet(w).execute(MODE_SINGLE, hit);
        assertEq(target.calls(), 0, "a stranger's default mode ran");
        vm.prank(a, a);
        IWebWallet(a).execute(MODE_SINGLE, hit);
        assertEq(target.calls(), 1, "the key's default mode");
    }

    /// A1: no genesis bootstrap on a forwarder account, and a login is never the first session.
    function test_noFirstSessionWithoutTheKeysAddSession() public {
        _delegateTo(fwd);
        bytes memory keyed = _one(_linkX(a, X, ALICE, _key(ALICE_PK), _admin()));
        vm.prank(a, a);
        vm.expectRevert(IWebWallet.LinkSessionRefused.selector);
        IWebWallet(a).reset(keyed);
        _reset(_one(_linkX(a, X, ALICE, "", _admin())));
        bytes memory login = _loginPayload(a, X, ALICE, _key(ALICE_PK), _admin());
        vm.prank(relayer);
        vm.expectRevert(IWebWallet.FirstSessionRefused.selector);
        IWebWallet(a).addSessionByLogin(X, V1, login, "", _admin());
        // A stranger's batch adding her own session signs only from the next second: still refused.
        Execution[] memory x = new Execution[](2);
        x[0] = _linkX(a, X, MALLORY, "", _admin());
        x[1] = _x(a, 0, abi.encodeCall(IWebWallet.addSession, (_identity(X, MALLORY), _key(MALLORY_PK), _admin())));
        bytes memory data = _signed(a, _pks(MALLORY_PK), abi.encode(x));
        vm.prank(mallory);
        vm.expectRevert(IWebWallet.ExecutionNotSigned.selector);
        IWebWallet(a).execute(AUTHORIZED_MODE, data);
        assertEq(IWebWallet(a).sessionOf(_key(MALLORY_PK)).identity, bytes32(0), "a stranger's first session");
    }

    /// Threshold 2 over X and GitHub. A keyed login removal leaves admins on X alone, short of the threshold; the
    /// key still revokes a limited session.
    function test_theKeyRevokesALimitedSessionBelowTheThreshold() public {
        _onboard();
        IWebWallet.Policy memory none;
        bytes memory link = _linkPayload(a, GITHUB, BOB, "", none);
        vm.prank(a);
        IWebWallet(a).linkIdentity(GITHUB, V1, link, "", none);
        vm.startPrank(a);
        IWebWallet(a).addSession(_identity(GITHUB, BOB), _key(BOB_PK), _admin());
        IWebWallet(a).addSession(_identity(X, ALICE), _key(MALLORY_PK), _hitOnly());
        vm.stopPrank();
        vm.prank(a, a);
        IWebWallet(a).setThreshold(2);
        vm.warp(_now() + 1);

        bytes memory remove = _payload(GITHUB, BOB, REMOVE, _txData(a, _key(BOT_PK), _ph(_hitOnly())));
        IWebWallet(a).removeSessionsByLogin(GITHUB, V1, remove, "", _hitOnly());
        assertEq(IWebWallet(a).threshold(), 2, "the threshold moved");

        vm.prank(a);
        IWebWallet(a).revokeSession(_key(MALLORY_PK));
        assertEq(IWebWallet(a).sessionOf(_key(MALLORY_PK)).identity, bytes32(0), "the limited session lives");
    }

    // ─── The forwarder ──────────────────────────────────────────────

    /// At its own address the forwarder refuses every call, `reset` and plain ETH included.
    function test_theForwarderRefusesDirectCalls() public {
        bytes[3] memory calls =
            [abi.encodeCall(IWebWallet.reset, (_one(_hitX()))), abi.encodeCall(IWebWallet.release, ()), ""];
        for (uint256 i; i < calls.length; ++i) {
            (bool ok, bytes memory err) = fwd.call{value: i == 2 ? 1 : 0}(calls[i]);
            assertFalse(ok, "the forwarder answered");
            assertEq(err, abi.encodeWithSelector(IWebWallet.NotDelegated.selector), "the error");
        }
    }

    /// Plain ETH with the 2,300-gas stipend reaches an account before and after `reset`.
    /// forge-config: default.isolate = true
    function test_aStipendTransferArrivesBeforeAndAfterReset() public {
        Payer payer = new Payer();
        _delegateTo(fwd);
        payer.pay{value: 1}(payable(a));
        assertEq(a.balance, 1, "before reset");
        assertEq(vm.load(a, RELEASE_SLOT), bytes32(0), "a transfer wrote the slot");
        _onboard();
        payer.pay{value: 1}(payable(a));
        assertEq(a.balance, 1 ether + 1, "after reset");
    }

    /// The same transfer after `reset` alone, so it is checked whatever the row before it does.
    /// forge-config: default.isolate = true
    function test_aStipendTransferArrivesAfterReset() public {
        Payer payer = new Payer();
        _onboard();
        payer.pay{value: 1}(payable(a));
        assertEq(a.balance, 1 ether + 1, "after reset");
    }

    /// Plain ETH with the 2,300-gas stipend reaches a factory wallet.
    /// forge-config: default.isolate = true
    function test_aStipendTransferReachesAFactoryWallet() public {
        Payer payer = new Payer();
        address w = factory.createWallet(X, BOB, 0);
        uint256 before = w.balance;
        payer.pay{value: 1}(payable(w));
        assertEq(w.balance, before + 1, "a factory wallet");
    }

    /// With no release published, `reset` has nowhere to go.
    function test_resetWithoutAReleaseIsNotSetUp() public {
        bytes memory init = abi.encodeCall(IWalletFactory.initialize, (owner));
        address bare = address(new ERC1967Proxy(_factoryImpl(), init));
        fwd = deployCode("WalletForwarder.sol:WalletForwarder", abi.encode(bare));
        _delegateTo(fwd);
        bytes memory onboarding = _onboarding();
        vm.prank(a, a);
        vm.expectRevert(IWalletForwarder.NotSetUp.selector);
        IWebWallet(a).reset(onboarding);
    }

    /// Delegating away and back without `reset` resumes the sessions: the state is the account's.
    function test_reDelegatingBackResumesSessions() public {
        _onboard();
        _delegateTo(address(new Planter()));
        _delegateTo(fwd);
        _handle(_ops(_signOp(_op(a, _hitCall()), 1, _pks(ALICE_PK))));
        assertEq(target.last(), a, "the old session did not act");
    }

    /// A root-executed bump moves the account to the next release, whose sessions then act.
    function test_theAccountFollowsABump() public {
        _onboard();
        address impl2 = _publish(2);
        _root(a, abi.encodeCall(IWebWallet.bump, (2)));
        (address impl, uint64 version) = IWebWallet(a).release();
        assertEq(abi.encode(impl, version, IWebWallet(a).VERSION()), abi.encode(impl2, 2, 2), "release");
        _run(a, _one(_hitX()));
        assertEq(target.calls(), 1, "the session did not act on release 2");
    }

    /// A cold view through the forwarder costs one through a factory proxy plus the delegation lookup.
    /// forge-config: default.isolate = true
    function test_forwarderOverheadPerCall() public {
        _onboard();
        address w = factory.createWallet(X, BOB, 0);
        ColdMeter meter = new ColdMeter();
        uint256 viaForwarder = meter.cost(a);
        uint256 viaProxy = meter.cost(w);
        assertGt(viaForwarder, viaProxy, "the forwarder's path was not cold");
        emit log_named_uint("forwarder overhead", viaForwarder - viaProxy);
        assertLt(viaForwarder, viaProxy + 10_000, "forwarder overhead");
    }

    /// The account's validation reads neither the factory nor the registry.
    function test_validationReadsNoFactoryOrRegistry() public {
        _onboard();
        PackedUserOperation memory op = _signOp(_op(a, _hitCall()), 1, _pks(ALICE_PK));
        bytes32 h = IUserOpHash(EP).getUserOpHash(op);
        vm.record();
        vm.prank(EP);
        assertEq(IAccount(a).validateUserOp(op, h, 0) & 1, 0, "not validated");
        (bytes32[] memory reads,) = vm.accesses(address(factory));
        assertEq(reads.length, 0, "validation read the factory");
        (reads,) = vm.accesses(address(registry));
        assertEq(reads.length, 0, "validation read the registry");
    }

    // ─── The key ────────────────────────────────────────────────────

    /// Acceptance 4: the key's own call to the registry spends its proof and links nothing.
    function test_theKeysDirectCheckLinksNothing() public {
        _onboard();
        bytes memory payload = _linkPayload(a, GITHUB, BOB, "", _admin());
        vm.prank(a, a);
        registry.check(LINK, GITHUB, V1, payload, "", 0);
        assertTrue(registry.spentDigests(_digestOf(payload)), "the proof is unspent");
        assertFalse(IWebWallet(a).isLinked(_identity(GITHUB, BOB)), "a direct check linked");
    }

    /// ERC-1271 takes the account's own key's 65-byte ECDSA signature, never a stranger's or a high-s one, and only
    /// under an EIP-7702 delegation: a factory wallet's code at a key's address refuses it.
    function test_theKeySignsWith65Bytes() public {
        _onboard();
        bytes32 h = keccak256("a message");
        assertEq(IWebWallet(a).isValidSignature(h, _sig65(KEY_PK, h)), bytes4(0x1626ba7e), "the key");
        assertEq(IWebWallet(a).isValidSignature(h, _sig65(MALLORY_PK, h)), bytes4(0xffffffff), "a stranger");
        assertEq(IWebWallet(a).isValidSignature(h, _highS(_sig65(KEY_PK, h))), bytes4(0xffffffff), "high s");
        assertTrue(_valid1271(a, 1, ALICE_PK, h), "the session");

        address w = _claim();
        assertEq(IWebWallet(w).isValidSignature(h, _sig65(ALICE_PK, h)), bytes4(0xffffffff), "a factory wallet");
        address k = vm.addr(BOB_PK);
        vm.etch(k, w.code);
        vm.store(k, RELEASE_SLOT, vm.load(w, RELEASE_SLOT));
        assertEq(IWebWallet(k).VERSION(), 1, "control: the etched wallet runs");
        assertEq(IWebWallet(k).isValidSignature(h, _sig65(BOB_PK, h)), bytes4(0xffffffff), "without a delegation");
    }

    /// A quorum batch calling the account's own `execute` in the default mode is the account under a delegation:
    /// only the lock refuses it. The key's top-level call is the control.
    function test_aBatchCannotReenterTheDefaultMode() public {
        _onboard();
        bytes memory hit = abi.encodePacked(address(target), uint256(0), abi.encodeCall(CallTarget.hit, ()));
        bytes memory inner = abi.encodeCall(IWebWallet.execute, (MODE_SINGLE, hit));
        bytes memory data = _signed(a, _pks(ALICE_PK), _one(_x(a, 0, inner)));
        vm.prank(relayer);
        vm.expectRevert(IWebWallet.Locked.selector);
        IWebWallet(a).execute(AUTHORIZED_MODE, data);
        assertEq(target.calls(), 0, "the default mode ran inside a batch");
        vm.prank(a, a);
        (bool ok,) = a.call(inner);
        assertTrue(ok && target.calls() == 1, "control: the key's default mode");
    }

    function _sig65(uint256 pk, bytes32 h) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, h);
        return abi.encodePacked(r, s, v);
    }

    /// The same signature with `s` mirrored to the upper half and `v` flipped.
    function _highS(bytes memory sig) internal pure returns (bytes memory) {
        (bytes32 r, bytes32 s) = abi.decode(sig, (bytes32, bytes32));
        uint8 v = uint8(sig[64]);
        return abi.encodePacked(r, bytes32(SECP256K1_N - uint256(s)), v == 27 ? uint8(28) : uint8(27));
    }
}

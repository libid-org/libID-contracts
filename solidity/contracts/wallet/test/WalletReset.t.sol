// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Execution} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";

import {IWalletForwarder} from "../IWalletForwarder.sol";
import {AUTHORIZED_MODE, IWebWallet} from "../IWebWallet.sol";
import {WalletBase} from "./WalletBase.sol";

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

/// @notice EIP-7702 accounts on WalletForwarder: `reset` and its epoch, the key's own powers, and `initialize`.
/// forge-config: default.evm_version = "prague"
contract WalletResetTest is WalletBase {
    uint256 internal constant KEY_PK = 0x7702;

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

    /// Acceptance 9: before `reset`, only an empty call returns; a UserOperation is refused.
    function test_beforeResetNothingRuns() public {
        _delegateTo(fwd);
        vm.prank(a, a);
        vm.expectRevert(IWalletForwarder.NotSetUp.selector);
        IWebWallet(a).execute(MODE_BATCH, _one(_hitX()));
        _refusedOp(_signOp(_op(a, _hitCall()), 1, _pks(ALICE_PK)));
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

    /// The key's top-level call reaches a root-only entry; its batch does not.
    function test_theKeysRootOnlyCallsAreTopLevel() public {
        _onboard();
        _publish(2);
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
        IWebWallet(a).setRootDelay(72 hours);
        assertEq(IWebWallet(a).rootDelay(), 72 hours, "the key's own call");
    }

    /// The default mode in direct: the key's own call on its account runs; anyone else's does not.
    function test_defaultModeInDirect() public {
        _onboard();
        bytes memory hit = abi.encodePacked(address(target), uint256(0), abi.encodeWithSignature("hit()"));
        vm.prank(mallory, mallory);
        vm.expectRevert();
        IWebWallet(a).execute(MODE_SINGLE, hit);
        address w = _claim();
        vm.prank(relayer, relayer);
        vm.expectRevert();
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
        vm.expectRevert();
        IWebWallet(a).execute(AUTHORIZED_MODE, data);
        assertEq(IWebWallet(a).sessionOf(_key(MALLORY_PK)).identity, bytes32(0), "a stranger's first session");
    }
}

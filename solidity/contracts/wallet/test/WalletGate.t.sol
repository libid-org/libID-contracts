// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Test.sol";
import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/IERC4337.sol";
import {Execution} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";

import {AUTHORIZED_MODE, IIdentityAdmin, IWalletCore, IWebWallet} from "../IWebWallet.sol";
import {WalletBase} from "./WalletBase.sol";

/// @notice The whole-ABI gate: for every wallet selector, a stranger, a session below quorum, and a quorum
///         batch calling a root-only or construction entry, relayed or in an EIP-7702 key's own transaction, change
///         no storage.
/// forge-config: default.evm_version = "prague"
contract WalletGateTest is WalletBase {
    /// View: anyone, writes nothing. Public: anyone, writes only when signed or proven. Self: the wallet's own
    /// call. Root: inside `executeRoot` only. Special: construction, reset, data steps, the EntryPoint, nesting.
    enum Gate {
        View,
        Public,
        Self,
        Root,
        Special
    }

    struct Row {
        bytes data;
        Gate gate;
    }

    address internal w;
    bytes32 internal matured;

    function setUp() public override {
        super.setUp();
        w = _claim();
        _publish(2);
        Execution[] memory x = new Execution[](3);
        x[0] = _x(w, 0, abi.encodeCall(IIdentityAdmin.addSession, (_identity(X, ALICE), _key(ALICE2_PK), _admin())));
        x[1] = _linkX(w, GITHUB, BOB, "", _admin());
        x[2] = _x(w, 0, abi.encodeCall(IIdentityAdmin.addSession, (_identity(X, ALICE), _key(BOT_PK), _hitOnly())));
        _run(w, abi.encode(x));
        vm.warp(_now() + 1);
        matured = _queue(w, abi.encodeCall(IIdentityAdmin.setRootDelay, (72 hours)));
        _mature(w);
    }

    function _rows() internal returns (Row[] memory r) {
        r = new Row[](46);
        uint256 i;
        bytes memory hit = _one(_hitX());
        PackedUserOperation memory op = _signOp(_op(w, _hitCall()), 1, _pks(MALLORY_PK));
        bytes memory login = _payload(X, MALLORY, ADD, _txData(w, _key(MALLORY_PK), _ph(_admin())));
        bytes memory link = _payload(X, MALLORY, LINK, _txData(w, _key(MALLORY_PK), _ph(_admin())));
        bytes memory remove = _payload(X, MALLORY, REMOVE, _txData(w, "", 0));
        bytes32[] memory apps = new bytes32[](1);
        apps[0] = keccak256("client");

        r[i++] = Row(abi.encodeCall(IWalletCore.entryPoint, ()), Gate.View);
        r[i++] = Row(abi.encodeWithSignature("getNonce()"), Gate.View);
        r[i++] = Row(abi.encodeWithSignature("getNonce(uint192)", uint192(0)), Gate.View);
        r[i++] = Row(abi.encodeCall(IWalletCore.validateUserOp, (op, keccak256("h"), 0)), Gate.Special);
        r[i++] = Row(abi.encodeCall(IWalletCore.isValidSignature, (keccak256("h"), "")), Gate.View);
        r[i++] = Row(abi.encodeCall(IWalletCore.eip712Domain, ()), Gate.View);
        r[i++] = Row(
            abi.encodeCall(IWalletCore.execute, (AUTHORIZED_MODE, _signedAt(w, 1, _pks(MALLORY_PK), hit, false))),
            Gate.Special
        );
        r[i++] = Row(abi.encodeCall(IWalletCore.execute, (MODE_BATCH, hit)), Gate.Special);
        r[i++] = Row(abi.encodeCall(IWalletCore.supportsInterface, (bytes4(0x150b7a02))), Gate.View);
        r[i++] = Row(abi.encodeCall(IWalletCore.onERC721Received, (mallory, mallory, 1, "")), Gate.View);
        r[i++] = Row(abi.encodeCall(IWalletCore.onERC1155Received, (mallory, mallory, 1, 1, "")), Gate.View);
        r[i++] = Row(
            abi.encodeCall(
                IWalletCore.onERC1155BatchReceived, (mallory, mallory, new uint256[](1), new uint256[](1), "")
            ),
            Gate.View
        );
        r[i++] = Row(abi.encodeCall(IWalletCore.VERSION, ()), Gate.View);
        r[i++] = Row(abi.encodeCall(IWalletCore.FACTORY, ()), Gate.View);
        r[i++] = Row(abi.encodeCall(IWalletCore.REGISTRY, ()), Gate.View);
        r[i++] = Row(abi.encodeCall(IWalletCore.initialize, (X, MALLORY, 0)), Gate.Special);
        r[i++] = Row(abi.encodeCall(IWalletCore.reset, (hit)), Gate.Special);
        r[i++] = Row(abi.encodeCall(IWalletCore.release, ()), Gate.View);
        r[i++] = Row(abi.encodeCall(IWalletCore.epoch, ()), Gate.View);
        r[i++] = Row(abi.encodeCall(IIdentityAdmin.genesisIdentity, ()), Gate.View);
        r[i++] = Row(abi.encodeCall(IWalletCore.runDataSteps, (1)), Gate.Special);
        r[i++] = Row(abi.encodeCall(IIdentityAdmin.linkIdentity, (X, V1, link, "", _admin())), Gate.Self);
        r[i++] = Row(abi.encodeCall(IIdentityAdmin.addSessionByLogin, (X, V1, login, "", _admin())), Gate.Public);
        r[i++] = Row(abi.encodeCall(IIdentityAdmin.removeSessionsByLogin, (X, V1, remove, "", _admin())), Gate.Public);
        r[i++] = Row(
            abi.encodeCall(IIdentityAdmin.addSession, (_identity(X, MALLORY), _key(MALLORY_PK), _admin())), Gate.Self
        );
        r[i++] = Row(abi.encodeCall(IIdentityAdmin.revokeSession, (_key(ALICE2_PK))), Gate.Self);
        r[i++] = Row(abi.encodeCall(IIdentityAdmin.setAppList, (_identity(X, ALICE), apps)), Gate.Self);
        r[i++] = Row(abi.encodeCall(IIdentityAdmin.sessionOf, (_key(ALICE_PK))), Gate.View);
        r[i++] = Row(abi.encodeCall(IIdentityAdmin.isLinked, (_identity(X, ALICE))), Gate.View);
        r[i++] = Row(abi.encodeCall(IIdentityAdmin.appList, (_identity(X, ALICE))), Gate.View);
        r[i++] = Row(abi.encodeCall(IIdentityAdmin.allowanceOf, (_key(BOT_PK), address(0))), Gate.View);
        r[i++] = Row(abi.encodeCall(IIdentityAdmin.generationOf, (_identity(X, ALICE))), Gate.View);
        r[i++] = Row(abi.encodeCall(IIdentityAdmin.linkedPlatforms, ()), Gate.View);
        r[i++] = Row(abi.encodeCall(IIdentityAdmin.hadSession, ()), Gate.View);
        r[i++] = Row(
            abi.encodeCall(IIdentityAdmin.queueRoot, (abi.encodeCall(IIdentityAdmin.setThreshold, (2)))), Gate.Self
        );
        r[i++] = Row(abi.encodeCall(IIdentityAdmin.cancelRoot, (matured)), Gate.Self);
        r[i++] = Row(abi.encodeCall(IIdentityAdmin.executeRoot, (bytes32(uint256(1)))), Gate.Public);
        r[i++] = Row(abi.encodeCall(IIdentityAdmin.rootOperation, (matured)), Gate.View);
        r[i++] = Row(abi.encodeCall(IIdentityAdmin.rootReadyAt, (matured)), Gate.View);
        r[i++] = Row(abi.encodeCall(IIdentityAdmin.threshold, ()), Gate.View);
        r[i++] = Row(abi.encodeCall(IIdentityAdmin.rootDelay, ()), Gate.View);
        r[i++] = Row(abi.encodeCall(IIdentityAdmin.rootEpoch, ()), Gate.View);
        r[i++] = Row(abi.encodeCall(IIdentityAdmin.bump, (2)), Gate.Root);
        r[i++] = Row(abi.encodeCall(IIdentityAdmin.setThreshold, (2)), Gate.Root);
        r[i++] = Row(abi.encodeCall(IIdentityAdmin.setRootDelay, (1)), Gate.Root);
        r[i++] = Row(abi.encodeCall(IIdentityAdmin.unlink, (_identity(GITHUB, BOB))), Gate.Root);
        assertEq(i, r.length, "row count");
    }

    /// The rows are distinct, and their selectors, each counted once, XOR to both halves' interface ids: every
    /// wallet selector is listed.
    function test_everySelectorIsListed() public {
        Row[] memory r = _rows();
        bytes4 id;
        for (uint256 i; i < r.length; ++i) {
            bool seen;
            for (uint256 j; j < i; ++j) {
                assertNotEq(keccak256(r[i].data), keccak256(r[j].data), "a row listed twice");
                seen = seen || bytes4(r[i].data) == bytes4(r[j].data);
            }
            if (!seen) id ^= bytes4(r[i].data);
        }
        assertEq(
            id, type(IWalletCore).interfaceId ^ type(IIdentityAdmin).interfaceId, "a wallet selector is not listed"
        );
    }

    function test_aStrangerChangesNothing() public {
        Row[] memory r = _rows();
        for (uint256 i; i < r.length; ++i) {
            vm.startStateDiffRecording();
            vm.prank(mallory, mallory);
            (bool ok,) = w.call(r[i].data);
            ok;
            _assertNoWrites(vm.stopAndReturnStateDiff(), vm.toString(r[i].data));
        }
        assertEq(target.calls(), 0, "a stranger's call ran");
    }

    function test_aSessionBelowQuorumChangesNothing() public {
        // Control: the bot's own scope runs below quorum.
        bytes memory data = _signedAt(w, 1, _pks(BOT_PK), _one(_hitX()), true);
        vm.prank(relayer);
        IWebWallet(w).execute(AUTHORIZED_MODE, data);
        assertEq(target.calls(), 1, "control: the bot's batch did not run");

        Row[] memory r = _rows();
        for (uint256 i; i < r.length; ++i) {
            if (r[i].gate == Gate.View) continue;
            _batchChangesNothing(_signedAt(w, 1, _pks(BOT_PK), _one(_x(w, 0, r[i].data)), true), r[i].data);
        }
    }

    function test_aQuorumBatchCannotReachRootOrSpecialEntries() public {
        bytes32[] memory apps = new bytes32[](1);
        apps[0] = keccak256("client");
        _run(w, _one(_x(w, 0, abi.encodeCall(IIdentityAdmin.setAppList, (_identity(X, ALICE), apps)))));
        assertEq(IWebWallet(w).appList(_identity(X, ALICE)).length, 1, "control: a quorum self-call did not run");

        _rootAndSpecialChangeNothing(relayer);
        // A matured root operation, refused inside a batch (A7): the lock is held.
        bytes memory inBatch = abi.encodeCall(IIdentityAdmin.executeRoot, (matured));
        _batchChangesNothing(_signed(w, _pks(ALICE_PK), _one(_x(w, 0, inBatch))), inBatch);
        vm.prank(relayer);
        IWebWallet(w).executeRoot(matured);
        assertEq(IWebWallet(w).rootDelay(), 72 hours, "control: the matured operation did not run");
    }

    /// The same batches on an EIP-7702 account, sent by its key: the key's top-level powers stay outside the lock.
    function test_aQuorumBatchInTheKeysTransactionCannotReachRootOrSpecialEntries() public {
        uint256 keyPk = 0x7702;
        address a = vm.addr(keyPk);
        address fwd = deployCode("WalletForwarder.sol:WalletForwarder", abi.encode(address(factory)));
        bytes memory add = abi.encodeCall(IIdentityAdmin.addSession, (_identity(X, ALICE), _key(ALICE_PK), _admin()));
        bytes memory onboarding = _two(_linkX(a, X, ALICE, "", _admin()), _x(a, 0, add));
        vm.signAndAttachDelegation(fwd, keyPk);
        vm.prank(a, a);
        IWebWallet(a).reset(onboarding);
        vm.warp(_now() + 1);
        w = a;
        bytes32[] memory apps = new bytes32[](1);
        bytes memory set = abi.encodeCall(IIdentityAdmin.setAppList, (_identity(X, ALICE), apps));
        bytes memory data = _signed(a, _pks(ALICE_PK), _one(_x(a, 0, set)));
        vm.prank(a, a);
        IWebWallet(a).execute(AUTHORIZED_MODE, data);
        assertEq(IWebWallet(a).appList(_identity(X, ALICE)).length, 1, "control: the key's quorum batch did not run");
        _rootAndSpecialChangeNothing(a);
    }

    /// Root-only entries do run through `executeRoot`.
    function test_rootEntriesRunInsideExecuteRoot() public {
        // A second admin platform, so the threshold may reach 2; then both platforms queue the unlink.
        bytes memory add = abi.encodeCall(IIdentityAdmin.addSession, (_identity(GITHUB, BOB), _key(BOB_PK), _admin()));
        _run(w, _one(_x(w, 0, add)));
        _root(w, abi.encodeCall(IIdentityAdmin.setThreshold, (2)));
        assertEq(IWebWallet(w).threshold(), 2, "setThreshold");
        bytes memory unlink = abi.encodeCall(IIdentityAdmin.unlink, (_identity(GITHUB, BOB)));
        bytes memory data =
            _signed(w, _pks(ALICE_PK, BOB_PK), _one(_x(w, 0, abi.encodeCall(IIdentityAdmin.queueRoot, (unlink)))));
        vm.prank(relayer);
        IWebWallet(w).execute(AUTHORIZED_MODE, data);
        _mature(w);
        vm.prank(relayer);
        IWebWallet(w).executeRoot(keccak256(unlink));
        assertFalse(IWebWallet(w).isLinked(_identity(GITHUB, BOB)), "unlink");
    }

    /// Alice's quorum batch calling each root-only or special row, sent by `by`, changes nothing.
    function _rootAndSpecialChangeNothing(address by) internal {
        Row[] memory r = _rows();
        for (uint256 i; i < r.length; ++i) {
            if (r[i].gate != Gate.Root && r[i].gate != Gate.Special) continue;
            _batchChangesNothing(_signed(w, _pks(ALICE_PK), _one(_x(w, 0, r[i].data))), r[i].data, by);
        }
    }

    function _batchChangesNothing(bytes memory data, bytes memory row) internal {
        _batchChangesNothing(data, row, relayer);
    }

    /// `by`'s own transaction.
    function _batchChangesNothing(bytes memory data, bytes memory row, address by) internal {
        vm.startStateDiffRecording();
        vm.prank(by, by);
        (bool ok,) = w.call(abi.encodeCall(IWalletCore.execute, (AUTHORIZED_MODE, data)));
        ok;
        Vm.AccountAccess[] memory acc = vm.stopAndReturnStateDiff();
        _assertNoWrites(acc, vm.toString(row));
    }
}

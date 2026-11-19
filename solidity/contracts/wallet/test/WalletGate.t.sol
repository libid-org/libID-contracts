// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Test.sol";
import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/IERC4337.sol";
import {Execution} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";

import {AUTHORIZED_MODE, IWebWallet} from "../IWebWallet.sol";
import {WalletBase} from "./WalletBase.sol";

/// @notice The whole-ABI gate: for every `IWebWallet` selector, a stranger, a session below quorum, and a quorum
///         batch calling a root-only or construction entry change no storage.
contract WalletGateTest is WalletBase {
    // cast keccak "libid.webwallet.remove-sessions"
    bytes32 internal constant REMOVE = 0x7cabdd831000d819c7b2ae4f79b4d6b566aa21992764e735f944b1459cb43c1b;

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
        x[0] = _x(w, 0, abi.encodeCall(IWebWallet.addSession, (_identity(X, ALICE), _key(ALICE2_PK), _admin())));
        x[1] = _linkX(w, GITHUB, BOB, "", _admin());
        x[2] = _x(w, 0, abi.encodeCall(IWebWallet.addSession, (_identity(X, ALICE), _key(BOT_PK), _hitOnly())));
        _run(w, abi.encode(x));
        vm.warp(_now() + 1);
        matured = _queue(w, abi.encodeCall(IWebWallet.setRootDelay, (72 hours)));
        _mature(w);
    }

    function _rows() internal returns (Row[] memory r) {
        r = new Row[](45);
        uint256 i;
        bytes memory hit = _one(_hitX());
        PackedUserOperation memory op = _signOp(_op(w, _hitCall()), 1, _pks(MALLORY_PK));
        bytes memory login = _payload(X, MALLORY, ADD, _txData(w, _key(MALLORY_PK), _ph(_admin())));
        bytes memory link = _payload(X, MALLORY, LINK, _txData(w, _key(MALLORY_PK), _ph(_admin())));
        bytes memory remove = _payload(X, MALLORY, REMOVE, _txData(w, "", 0));
        bytes[] memory apps = new bytes[](1);
        apps[0] = "client";

        r[i++] = Row(abi.encodeCall(IWebWallet.entryPoint, ()), Gate.View);
        r[i++] = Row(abi.encodeWithSignature("getNonce()"), Gate.View);
        r[i++] = Row(abi.encodeWithSignature("getNonce(uint192)", uint192(0)), Gate.View);
        r[i++] = Row(abi.encodeCall(IWebWallet.validateUserOp, (op, keccak256("h"), 0)), Gate.Special);
        r[i++] = Row(abi.encodeCall(IWebWallet.isValidSignature, (keccak256("h"), "")), Gate.View);
        r[i++] = Row(abi.encodeCall(IWebWallet.eip712Domain, ()), Gate.View);
        r[i++] = Row(
            abi.encodeCall(IWebWallet.execute, (AUTHORIZED_MODE, _signedAt(w, 1, _pks(MALLORY_PK), hit, false))),
            Gate.Special
        );
        r[i++] = Row(abi.encodeCall(IWebWallet.execute, (MODE_BATCH, hit)), Gate.Special);
        r[i++] = Row(abi.encodeCall(IWebWallet.supportsInterface, (bytes4(0x150b7a02))), Gate.View);
        r[i++] = Row(abi.encodeCall(IWebWallet.onERC721Received, (mallory, mallory, 1, "")), Gate.View);
        r[i++] = Row(abi.encodeCall(IWebWallet.onERC1155Received, (mallory, mallory, 1, 1, "")), Gate.View);
        r[i++] = Row(
            abi.encodeCall(
                IWebWallet.onERC1155BatchReceived, (mallory, mallory, new uint256[](1), new uint256[](1), "")
            ),
            Gate.View
        );
        r[i++] = Row(abi.encodeCall(IWebWallet.VERSION, ()), Gate.View);
        r[i++] = Row(abi.encodeCall(IWebWallet.FACTORY, ()), Gate.View);
        r[i++] = Row(abi.encodeCall(IWebWallet.REGISTRY, ()), Gate.View);
        r[i++] = Row(abi.encodeCall(IWebWallet.initialize, (X, MALLORY, 0)), Gate.Special);
        r[i++] = Row(abi.encodeCall(IWebWallet.reset, (hit)), Gate.Special);
        r[i++] = Row(abi.encodeCall(IWebWallet.release, ()), Gate.View);
        r[i++] = Row(abi.encodeCall(IWebWallet.epoch, ()), Gate.View);
        r[i++] = Row(abi.encodeCall(IWebWallet.genesisIdentity, ()), Gate.View);
        r[i++] = Row(abi.encodeCall(IWebWallet.runDataSteps, (1)), Gate.Special);
        r[i++] = Row(abi.encodeCall(IWebWallet.linkIdentity, (X, V1, link, "", _admin())), Gate.Self);
        r[i++] = Row(abi.encodeCall(IWebWallet.addSessionByLogin, (X, V1, login, "", _admin())), Gate.Public);
        r[i++] = Row(abi.encodeCall(IWebWallet.removeSessionsByLogin, (X, V1, remove, "", _admin())), Gate.Public);
        r[i++] =
            Row(abi.encodeCall(IWebWallet.addSession, (_identity(X, MALLORY), _key(MALLORY_PK), _admin())), Gate.Self);
        r[i++] = Row(abi.encodeCall(IWebWallet.revokeSession, (_key(ALICE2_PK))), Gate.Self);
        r[i++] = Row(abi.encodeCall(IWebWallet.setAppList, (X, apps)), Gate.Self);
        r[i++] = Row(abi.encodeCall(IWebWallet.sessionOf, (_key(ALICE_PK))), Gate.View);
        r[i++] = Row(abi.encodeCall(IWebWallet.isLinked, (_identity(X, ALICE))), Gate.View);
        r[i++] = Row(abi.encodeCall(IWebWallet.appList, (X)), Gate.View);
        r[i++] = Row(abi.encodeCall(IWebWallet.allowanceOf, (_key(BOT_PK), address(0))), Gate.View);
        r[i++] = Row(abi.encodeCall(IWebWallet.generationOf, (_identity(X, ALICE))), Gate.View);
        r[i++] = Row(abi.encodeCall(IWebWallet.linkedPlatforms, ()), Gate.View);
        r[i++] = Row(abi.encodeCall(IWebWallet.hadSession, ()), Gate.View);
        r[i++] = Row(abi.encodeCall(IWebWallet.queueRoot, (abi.encodeCall(IWebWallet.setThreshold, (2)))), Gate.Self);
        r[i++] = Row(abi.encodeCall(IWebWallet.cancelRoot, (matured)), Gate.Self);
        r[i++] = Row(abi.encodeCall(IWebWallet.executeRoot, (bytes32(uint256(1)))), Gate.Public);
        r[i++] = Row(abi.encodeCall(IWebWallet.rootOperation, (matured)), Gate.View);
        r[i++] = Row(abi.encodeCall(IWebWallet.rootReadyAt, (matured)), Gate.View);
        r[i++] = Row(abi.encodeCall(IWebWallet.threshold, ()), Gate.View);
        r[i++] = Row(abi.encodeCall(IWebWallet.rootDelay, ()), Gate.View);
        r[i++] = Row(abi.encodeCall(IWebWallet.bump, (2)), Gate.Root);
        r[i++] = Row(abi.encodeCall(IWebWallet.setThreshold, (2)), Gate.Root);
        r[i++] = Row(abi.encodeCall(IWebWallet.setRootDelay, (1)), Gate.Root);
        r[i++] = Row(abi.encodeCall(IWebWallet.unlink, (_identity(GITHUB, BOB))), Gate.Root);
        assertEq(i, r.length, "row count");
    }

    /// A selector of `IWebWallet` this table does not list fails the gate.
    function test_everySelectorIsListed() public {
        Row[] memory r = _rows();
        string memory json = vm.readFile("out/IWebWallet.sol/IWebWallet.json");
        string[] memory sigs = vm.parseJsonKeys(json, ".methodIdentifiers");
        for (uint256 s; s < sigs.length; ++s) {
            bytes4 sel = bytes4(keccak256(bytes(sigs[s])));
            bool listed;
            for (uint256 i; i < r.length && !listed; ++i) {
                listed = bytes4(r[i].data) == sel;
            }
            assertTrue(listed, string.concat("not in the gate table: ", sigs[s]));
        }
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
        bytes[] memory apps = new bytes[](1);
        apps[0] = "client";
        _run(w, _one(_x(w, 0, abi.encodeCall(IWebWallet.setAppList, (X, apps)))));
        assertEq(IWebWallet(w).appList(X).length, 1, "control: a quorum self-call did not run");

        Row[] memory r = _rows();
        for (uint256 i; i < r.length; ++i) {
            if (r[i].gate != Gate.Root && r[i].gate != Gate.Special) continue;
            _batchChangesNothing(_signed(w, _pks(ALICE_PK), _one(_x(w, 0, r[i].data))), r[i].data);
        }
        // A matured root operation, refused inside a batch (A7): the lock is held.
        bytes memory inBatch = abi.encodeCall(IWebWallet.executeRoot, (matured));
        _batchChangesNothing(_signed(w, _pks(ALICE_PK), _one(_x(w, 0, inBatch))), inBatch);
        vm.prank(relayer);
        IWebWallet(w).executeRoot(matured);
        assertEq(IWebWallet(w).rootDelay(), 72 hours, "control: the matured operation did not run");
    }

    /// Root-only entries do run through `executeRoot`.
    function test_rootEntriesRunInsideExecuteRoot() public {
        // A second admin platform, so the threshold may reach 2; the unlink is queued while Alice alone is quorum.
        bytes memory add = abi.encodeCall(IWebWallet.addSession, (_identity(GITHUB, BOB), _key(BOB_PK), _admin()));
        _run(w, _one(_x(w, 0, add)));
        bytes32 unlink = _queue(w, abi.encodeCall(IWebWallet.unlink, (_identity(GITHUB, BOB))));
        _root(w, abi.encodeCall(IWebWallet.setThreshold, (2)));
        assertEq(IWebWallet(w).threshold(), 2, "setThreshold");
        vm.prank(relayer);
        IWebWallet(w).executeRoot(unlink);
        assertFalse(IWebWallet(w).isLinked(_identity(GITHUB, BOB)), "unlink");
    }

    function _batchChangesNothing(bytes memory data, bytes memory row) internal {
        vm.startStateDiffRecording();
        vm.prank(relayer);
        (bool ok,) = w.call(abi.encodeCall(IWebWallet.execute, (AUTHORIZED_MODE, data)));
        ok;
        Vm.AccountAccess[] memory acc = vm.stopAndReturnStateDiff();
        _assertNoWrites(acc, vm.toString(row));
    }
}

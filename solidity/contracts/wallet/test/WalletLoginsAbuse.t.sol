// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Planned ABI: see the header of WalletLogins.t.sol.

import {Execution} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";

import {operationList} from "../../ceremony/test/OperationListVector.sol";
import {IIdentityValidator} from "../IIdentityValidator.sol";
import {IWalletRegistry} from "../IWalletRegistry.sol";
import {AUTHORIZED_MODE, IWebWallet} from "../IWebWallet.sol";
import {LoginBase} from "./WalletLogins.t.sol";

/// @notice Logins the registry and validator must refuse, one row each, from one state.
contract WalletLoginsAbuseTest is LoginBase {
    struct Row {
        string name;
        bytes32 platformId;
        bytes32 idNode;
        bytes32 domain;
        bytes txData;
        /// The call's `data`: the Operation List entry's bytes, or empty.
        bytes data;
        /// The revert data, or only its selector when `partial`.
        bytes err;
        bool partial;
    }

    address internal w;

    function setUp() public override {
        super.setUp();
        w = _wallet(2, 2);
    }

    function _bob() internal view returns (bytes32) {
        return _identity(GITHUB, BOB);
    }

    /// Each row, submitted by a stranger to `removeSessionsByLogin` (or `addSessionByLogin`), reverts with its
    /// error and leaves the wallet as it was.
    function _run(Row[] memory rows, bool add) internal {
        for (uint256 i; i < rows.length; ++i) {
            Row memory r = rows[i];
            uint256 state = vm.snapshotState();
            bytes memory payload = _payload(r.platformId, r.idNode, r.domain, r.txData);
            if (r.partial) vm.expectPartialRevert(bytes4(r.err));
            else vm.expectRevert(r.err);
            vm.prank(mallory);
            if (add) registry.addSessionByLogin(r.platformId, V1, payload, r.data, _admin());
            else registry.removeSessionsByLogin(r.platformId, V1, payload, r.data);
            assertTrue(validator.isLinked(w, _bob()), r.name);
            assertEq(validator.threshold(w), 2, r.name);
            vm.revertToState(state);
        }
    }

    function _err(bytes4 s, uint256 a) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(s, a);
    }

    function test_removalRows() public {
        bytes memory good = _removeData(w);
        uint256 dirty = uint256(uint160(w)) | (uint256(1) << 200);
        bytes4 bad = IWalletRegistry.BadTransactionData.selector;
        bytes4 notLinked = IIdentityValidator.NotLinked.selector;
        bytes4 foreign = IWalletRegistry.ForeignOperationDomain.selector;
        bytes memory addData = _txData(w, _key(NEW_PK), _ph(_admin()));
        Row[] memory rows = new Row[](10);
        rows[0] = Row("another chain", GITHUB, BOB, REMOVE, abi.encode(block.chainid + 1, w), "",
            _err(IWalletRegistry.WrongChain.selector, block.chainid + 1), false);
        rows[1] = Row("trailing byte", GITHUB, BOB, REMOVE, bytes.concat(good, hex"00"), "", _err(bad, 65), false);
        rows[2] =
            Row("dirty address word", GITHUB, BOB, REMOVE, abi.encode(block.chainid, dirty), "", _err(bad, 64), false);
        rows[3] = Row("no wallet", GITHUB, BOB, REMOVE, abi.encode(block.chainid), "", _err(bad, 32), false);
        rows[4] = Row("an identity not linked here", GITHUB, DAVE, REMOVE, good, "",
            abi.encodeWithSelector(notLinked, w, _identity(GITHUB, DAVE)), false);
        rows[5] = Row("Bob's id on another platform", X, BOB, REMOVE, good, "",
            abi.encodeWithSelector(notLinked, w, _identity(X, BOB)), false);
        rows[6] =
            Row("an add-session proof", GITHUB, BOB, ADD, addData, "", abi.encodeWithSelector(foreign, ADD), false);
        rows[7] = Row("a link proof", GITHUB, BOB, LINK, addData, "", abi.encodeWithSelector(foreign, LINK), false);
        rows[8] = Row("data without a list", GITHUB, BOB, REMOVE, good, good,
            abi.encodeWithSelector(IWalletRegistry.DataWithoutList.selector), false);
        rows[9] = Row("a list's add-session entry", GITHUB, BOB, OPERATIONS,
            operationList(ADD, addData, BIND, abi.encode(w)), addData, abi.encodeWithSelector(foreign, ADD), false);
        _run(rows, false);
    }

    function test_addRows() public {
        bytes memory good = _txData(w, _key(NEW_PK), _ph(_admin()));
        address fresh = factory.createWallet(X, CAROL, 0);
        Row[] memory rows = new Row[](5);
        rows[0] = Row("a removal proof", GITHUB, BOB, REMOVE, _removeData(w), "",
            abi.encodeWithSelector(IWalletRegistry.ForeignOperationDomain.selector, REMOVE), false);
        rows[1] = Row("another chain", GITHUB, BOB, ADD, abi.encode(block.chainid + 1, w, _key(NEW_PK), _ph(_admin())),
            "", _err(IWalletRegistry.WrongChain.selector, block.chainid + 1), false);
        rows[2] = Row("an identity not linked here", GITHUB, DAVE, ADD, good, "",
            abi.encodeWithSelector(IIdentityValidator.NotLinked.selector, w, _identity(GITHUB, DAVE)), false);
        // Q1: a wallet that never had a session takes its first one from its own link only.
        rows[3] = Row("a wallet with no session", X, CAROL, ADD, _txData(fresh, _key(NEW_PK), _ph(_admin())), "",
            abi.encodeWithSelector(IIdentityValidator.FirstSessionRefused.selector, fresh), false);
        rows[4] = Row("a policy the proof does not commit", GITHUB, BOB, ADD,
            _txData(w, _key(NEW_PK), _ph(_app())), "", abi.encodePacked(IWalletRegistry.PolicyMismatch.selector), true);
        _run(rows, true);
    }

    /// A spent removal does not run twice, even while its identity, the genesis, stays linked.
    function test_aRemovalIsSpentOnce() public {
        bytes memory payload = _removePayload(w, X, ALICE);
        registry.removeSessionsByLogin(X, V1, payload, "");
        bytes32 digest = xStub.lastDigest();
        vm.prank(w);
        validator.addSession(_identity(X, ALICE), _key(NEW_PK), _admin());
        vm.expectRevert(abi.encodeWithSelector(IWalletRegistry.DigestAlreadySpent.selector, digest));
        registry.removeSessionsByLogin(X, V1, payload, "");
        assertEq(validator.sessionOf(w, _key(NEW_PK)).identity, _identity(X, ALICE), "the replay removed");
    }

    function test_theValidatorsLoginEntriesAreTheRegistrys() public {
        address[2] memory callers = [mallory, w];
        for (uint256 i; i < 2; ++i) {
            vm.prank(callers[i]);
            vm.expectRevert(abi.encodeWithSelector(IIdentityValidator.NotRegistry.selector, callers[i]));
            validator.removeByLogin(w, _bob());
            vm.prank(callers[i]);
            vm.expectRevert(abi.encodeWithSelector(IIdentityValidator.NotRegistry.selector, callers[i]));
            validator.addSessionByRegistry(w, _bob(), _key(MALLORY_PK), _admin(), true);
        }
    }

    /// The design's second must-fail row: a phished platform revokes the owner's admins and removes a platform by
    /// login, in one batch signed below quorum.
    function test_revokesThenALoginRemovalBelowQuorumFail() public {
        _link(w, GOOGLE, CAROL, w, _key(CAROL_PK), _admin());
        vm.warp(_now() + 1);
        bytes memory payload = _removePayload(w, GITHUB, BOB);
        Execution[] memory x = new Execution[](3);
        x[0] = _x(address(validator), 0, abi.encodeCall(IIdentityValidator.revokeSession, (_key(BOB_PK))));
        bytes memory rm = abi.encodeCall(IWalletRegistry.removeSessionsByLogin, (GITHUB, V1, payload, ""));
        x[1] = _x(address(registry), 0, rm);
        x[2] = _hitX();
        bytes memory calls = abi.encode(x);
        uint256 n = _nonce(w, address(validator));
        // Control: the same batch at quorum runs.
        uint256 state = vm.snapshotState();
        _runsBy(w, calls, _pks(ALICE_PK, CAROL_PK));
        assertFalse(validator.isLinked(w, _bob()), "control: Bob stays");
        vm.revertToState(state);
        for (uint256 below; below < 2; ++below) {
            bytes memory auth = _direct(w, address(validator), _pks(CAROL_PK), calls, below == 1);
            vm.prank(relayer);
            vm.expectRevert();
            IWebWallet(w).execute(AUTHORIZED_MODE, _data(calls, auth));
        }
        assertEq(_nonce(w, address(validator)), n, "nonce");
        assertTrue(validator.isLinked(w, _bob()), "Bob removed");
        assertEq(validator.sessionOf(w, _key(BOB_PK)).identity, _bob(), "Bob's admin revoked");
        _runsBy(w, _one(_hitX()), _pks(ALICE_PK, CAROL_PK));
    }
}

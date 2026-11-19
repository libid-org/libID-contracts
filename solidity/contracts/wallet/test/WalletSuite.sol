// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IEntryPoint, PackedUserOperation} from "@openzeppelin/contracts/interfaces/IERC4337.sol";
import {Execution} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";

import {CeremonyProfile} from "../../ceremony/CeremonyProfile.sol";
import {IPlatformVerifier} from "../../ceremony/IPlatformVerifier.sol";
import {NATIVE_TOKEN} from "../../escrow/HandleEscrow.sol";
import {StubPlatformVerifier} from "../../identity/test/StubPlatformVerifier.sol";
import {AUTHORIZED_MODE, IWebWallet} from "../IWebWallet.sol";
import {CallTarget, IUserOpHash, WalletBase} from "./WalletBase.sol";

/// An ERC-7913 verifier that accepts every signature.
contract AcceptingVerifier {
    function verify(bytes calldata, bytes32, bytes calldata) external pure returns (bytes4) {
        return AcceptingVerifier.verify.selector;
    }
}

/// The stub's claim, from another OAuth client.
contract OtherClientVerifier is IPlatformVerifier {
    StubPlatformVerifier private immutable STUB;
    bytes public lastClient;

    constructor(StubPlatformVerifier stub) {
        STUB = stub;
    }

    function verify(bytes calldata payload) external payable returns (VerifiedClaim memory c) {
        c = STUB.verify(payload);
        c.clientIdentifier = "another-app";
        lastClient = c.clientIdentifier;
    }

    function quote() external view returns (uint256) {
        return STUB.quote();
    }

    function platformId() external view returns (bytes32) {
        return STUB.platformId();
    }
}

/// @notice WalletBase plus the builders of the suites ported from 0e2721f: Merkle trees, policies, signed batches
///         and UserOperations at release 1, ERC-1271 forms, and wallets with linked identities.
abstract contract WalletSuite is WalletBase {
    bytes32 internal constant GOOGLE = CeremonyProfile.PLATFORM_GOOGLE;
    bytes32 internal constant CAROL = keccak256("carol's Google id node");
    // cast keccak "libid.webwallet.remove-sessions", "libid.operations", "libid.bind"
    bytes32 internal constant REMOVE = 0x7cabdd831000d819c7b2ae4f79b4d6b566aa21992764e735f944b1459cb43c1b;
    bytes32 internal constant OPERATIONS = 0x60b329d7366897b03545eb9f63f4a707253258ee2e1cd0ba3a8973aa4959e967;
    bytes32 internal constant BIND = 0x4d59cd4487de0a5957f8c83addaac7a1238175aa5c29eeea2fbef57a8f5165ac;
    bytes32 internal constant MAIL = keccak256("a Mail");
    string internal constant MAIL_TYPE = "Mail(address to)";
    bytes32 internal constant PROBE = 0x7739773977397739773977397739773977397739773977397739773977397739;
    bytes4 internal constant MAGIC = 0x1626ba7e;
    uint256 internal constant APP_PK = 0xA99;
    uint256 internal constant CAROL_PK = 0xCA401;
    uint256 internal constant NEW_PK = 0x4E3;
    bytes4 internal constant NOT_SIGNED = IWebWallet.ExecutionNotSigned.selector;
    bytes4 internal constant NOT_ALLOWED = IWebWallet.ExecutionNotAllowed.selector;
    bytes4 internal constant OUTSIDE_WINDOW = IWebWallet.ExecutionOutsideWindow.selector;

    StubPlatformVerifier internal googleStub;
    /// The `msg.value` the helpers' batches sign for, and are sent with.
    uint256 internal signedValue;

    function setUp() public virtual override {
        super.setUp();
        googleStub = new StubPlatformVerifier(GOOGLE, 0);
        vm.prank(owner);
        proofVerifier.setVerifier(GOOGLE, V1, IPlatformVerifier(address(googleStub)));
    }

    function _stub(bytes32 platformId) internal view override returns (StubPlatformVerifier) {
        return platformId == GOOGLE ? googleStub : super._stub(platformId);
    }

    // ─── Trees ──────────────────────────────────────────────────────

    function _leaf(address t, bytes4 selector, uint256 maxValue) internal pure returns (bytes32) {
        return keccak256(bytes.concat(keccak256(abi.encode(t, selector, maxValue))));
    }

    function _domainLeaf(bytes32 separator) internal pure returns (bytes32) {
        return keccak256(bytes.concat(keccak256(abi.encode(separator))));
    }

    function _paymasterLeaf(address paymaster) internal pure returns (bytes32) {
        return keccak256(bytes.concat(keccak256(abi.encode(paymaster))));
    }

    /// The root of `leaves` and the proof of leaf `index`: sorted pairs, an odd last node rises a level.
    function _tree(bytes32[] memory leaves, uint256 index)
        internal
        pure
        returns (bytes32 root, bytes32[] memory proof)
    {
        uint256 n = leaves.length;
        bytes32[] memory level = new bytes32[](n);
        for (uint256 i; i < n; ++i) {
            level[i] = leaves[i];
        }
        bytes32[] memory path = new bytes32[](16);
        uint256 depth;
        while (n > 1) {
            if ((index ^ 1) < n) path[depth++] = level[index ^ 1];
            for (uint256 i; i < n; i += 2) {
                (bytes32 a, bytes32 b) = (level[i], i + 1 < n ? level[i + 1] : level[i]);
                level[i / 2] = i + 1 == n ? a : a < b ? keccak256(abi.encode(a, b)) : keccak256(abi.encode(b, a));
            }
            n = (n + 1) / 2;
            index /= 2;
        }
        proof = new bytes32[](depth);
        for (uint256 i; i < depth; ++i) {
            proof[i] = path[i];
        }
        return (level[0], proof);
    }

    // ─── Policies ───────────────────────────────────────────────────

    function _noRules() internal pure returns (IWebWallet.Rules memory r) {
        r.allowances = new IWebWallet.Allowance[](0);
    }

    function _app() internal pure returns (IWebWallet.Policy memory p) {
        p.rules = _noRules();
    }

    function _hitScope() internal view returns (bytes32) {
        return _leaf(address(target), CallTarget.hit.selector, 0);
    }

    /// `_hitOnly` with a lifetime NATIVE allowance of 1 ether to pay its operations' gas.
    function _hitGas() internal view returns (IWebWallet.Policy memory p) {
        p = _hitOnly();
        p.rules.allowances = new IWebWallet.Allowance[](1);
        p.rules.allowances[0] = IWebWallet.Allowance({token: NATIVE_TOKEN, amount: 1 ether, period: 0});
    }

    /// The proofs of `n` executions of `hit()` under `_hitScope()`: each empty.
    function _hitProofs(uint256 n) internal pure returns (IWebWallet.CallProof[] memory p) {
        p = new IWebWallet.CallProof[](n);
        for (uint256 i; i < n; ++i) {
            p[i].proof = new bytes32[](0);
        }
    }

    // ─── Signatures ─────────────────────────────────────────────────

    function _pks(uint256 a, uint256 b) internal pure returns (uint256[] memory r) {
        r = new uint256[](2);
        (r[0], r[1]) = (a, b);
    }

    function _belowQuorum(bytes32 h, uint48 at, bytes memory governingKey) internal pure returns (bytes32) {
        return keccak256(abi.encode(h, at, keccak256(governingKey)));
    }

    /// An `Authorization` of `pks` each signing `h`.
    function _auth(
        uint256[] memory pks,
        bytes32 h,
        uint48 at,
        IWebWallet.CallProof[] memory calls,
        bytes32[] memory domainProof
    ) internal pure returns (bytes memory) {
        IWebWallet.SessionSignature[] memory s = new IWebWallet.SessionSignature[](pks.length);
        for (uint256 i; i < pks.length; ++i) {
            (uint8 v, bytes32 r, bytes32 sv) = vm.sign(pks[i], h);
            s[i] = IWebWallet.SessionSignature({key: _key(pks[i]), signature: abi.encodePacked(r, sv, v)});
        }
        return abi.encode(
            IWebWallet.Authorization({
                signatures: s, at: at, calls: calls, domainProof: domainProof, paymasterProof: new bytes32[](0)
            })
        );
    }

    /// `pks` signing `h` at the block time, with no proofs.
    function _sigs(uint256[] memory pks, bytes32 h) internal view returns (bytes memory) {
        return _auth(pks, h, uint48(_now()), new IWebWallet.CallProof[](0), new bytes32[](0));
    }

    function _wrap(IWebWallet.SessionSignature[] memory s) internal view returns (bytes memory) {
        return abi.encode(
            IWebWallet.Authorization({
                signatures: s,
                at: uint48(_now()),
                calls: new IWebWallet.CallProof[](0),
                domainProof: new bytes32[](0),
                paymasterProof: new bytes32[](0)
            })
        );
    }

    // ─── UserOperations ─────────────────────────────────────────────

    function _exec(address to, bytes memory data) internal pure returns (bytes memory) {
        return abi.encodeCall(IWebWallet.execute, (MODE_SINGLE, abi.encodePacked(to, uint256(0), data)));
    }

    /// `_op` at nonce `n` of key 0.
    function _opN(address w, uint256 n, bytes memory callData) internal view returns (PackedUserOperation memory op) {
        op = _op(w, callData);
        op.nonce = n;
    }

    /// What a wallet's sessions sign for the EntryPoint hash `h`: nested under release 1's domain.
    function _signable(address w, bytes32 h) internal view returns (bytes32) {
        return _typed(w, 1, keccak256(abi.encode(USER_OP_TYPEHASH, h)));
    }

    function _signed(PackedUserOperation memory op, uint256[] memory pks)
        internal
        view
        returns (PackedUserOperation memory)
    {
        op.signature = _sigs(pks, _signable(op.sender, IUserOpHash(EP).getUserOpHash(op)));
        return op;
    }

    /// Below quorum, at the block time, with a scope proof per execution.
    function _signedWith(PackedUserOperation memory op, uint256[] memory pks, IWebWallet.CallProof[] memory calls)
        internal
        view
        returns (PackedUserOperation memory)
    {
        _signBelow(op, pks, calls, uint48(_now()));
        return op;
    }

    function _signBelow(
        PackedUserOperation memory op,
        uint256[] memory pks,
        IWebWallet.CallProof[] memory calls,
        uint48 at
    ) internal view {
        bytes32 h = _signable(op.sender, IUserOpHash(EP).getUserOpHash(op));
        op.signature = _auth(pks, _belowQuorum(h, at, _key(pks[0])), at, calls, new bytes32[](0));
    }

    /// What the EntryPoint takes before execution: the gas limits at the max fee.
    function _prefund(PackedUserOperation memory op) internal pure returns (uint256) {
        uint256 limits = uint256(op.accountGasLimits);
        return ((limits >> 128) + uint128(limits) + op.preVerificationGas) * uint128(uint256(op.gasFees));
    }

    /// Funds the sender with 1 ether of value on top of the prefund, and handles `op`.
    function _handle(PackedUserOperation memory op) internal {
        vm.deal(op.sender, 1 ether + _prefund(op));
        vm.prank(bundler, bundler);
        IEntryPoint(EP).handleOps(_ops(op), payable(bundler));
    }

    /// `handleOps` refuses `op` in validation, which answered failure without reverting.
    function _refused(PackedUserOperation memory op, string memory why) internal {
        vm.deal(op.sender, 1 ether + _prefund(op));
        vm.prank(bundler, bundler);
        try IEntryPoint(EP).handleOps(_ops(op), payable(bundler)) {
            fail(string.concat("accepted: ", why));
        } catch (bytes memory err) {
            assertEq(bytes4(err), IEntryPoint.FailedOp.selector, string.concat("not a validation failure: ", why));
        }
    }

    /// `handleOps` refuses `op` with `FailedOp(0, reason)`.
    function _refusedWith(PackedUserOperation memory op, string memory reason) internal {
        vm.deal(op.sender, 1 ether + _prefund(op));
        vm.prank(bundler, bundler);
        try IEntryPoint(EP).handleOps(_ops(op), payable(bundler)) {
            fail(string.concat("accepted: ", reason));
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, reason), reason);
        }
    }

    /// The wallet's answer for `op`, asked by the EntryPoint.
    function _answer(PackedUserOperation memory op) internal returns (uint256) {
        bytes32 h = IUserOpHash(EP).getUserOpHash(op);
        vm.prank(EP);
        return IWebWallet(op.sender).validateUserOp(op, h, 0);
    }

    /// `op` refused and `control`, the guarded part fixed, accepted from the same state.
    function _refusedFor(PackedUserOperation memory op, PackedUserOperation memory control, string memory why)
        internal
    {
        uint256 state = vm.snapshotState();
        assertEq(_answer(op), 1, why);
        vm.revertToState(state);
        assertNotEq(_answer(control), 1, string.concat("control: ", why));
        vm.revertToStateAndDelete(state);
    }

    /// The wallet's answer for `callData` signed by `pks` at quorum over a made-up hash.
    function _validate(address w, bytes memory callData, uint256[] memory pks) internal returns (uint256) {
        PackedUserOperation memory op = _opN(w, 0, callData);
        bytes32 h = keccak256(abi.encode("user op", callData));
        op.signature = _sigs(pks, _signable(w, h));
        vm.prank(EP);
        return IWebWallet(w).validateUserOp(op, h, 0);
    }

    function _window(uint48 validAfter, uint48 validUntil) internal pure returns (uint256) {
        return (uint256(validAfter) << 208) | (uint256(validUntil) << 160);
    }

    // ─── ERC-1271 ───────────────────────────────────────────────────

    /// The ERC-7739 PersonalSign hash of `h` under `w`'s domain.
    function _wrapped(address w, bytes32 h) internal view returns (bytes32) {
        return _typed(w, 1, keccak256(abi.encode(PERSONAL_SIGN, h)));
    }

    function _isValid1271(address w, bytes32 h, uint256 pk, bytes32 signed) internal view returns (bool) {
        return IWebWallet(w).isValidSignature(h, _sigs(_pks(pk), signed)) == MAGIC;
    }

    /// `pks`' `TypedDataSign` below quorum of the fixed Mail for the app separator `app`, with `domainProof`.
    function _typedSigBy(address w, uint256[] memory pks, bytes32 app, bytes32[] memory domainProof)
        internal
        view
        returns (bytes32 h, bytes memory sig)
    {
        bytes32 signed = _belowQuorum(_typedHash(w, app), 0, _key(pks[0]));
        return _typedSigOf(app, _auth(pks, signed, 0, new IWebWallet.CallProof[](0), domainProof));
    }

    /// The hash a `TypedDataSign` of the fixed Mail for `app` signs, nested under `w`'s domain.
    function _typedHash(address w, bytes32 app) internal view returns (bytes32) {
        (, string memory name, string memory version, uint256 chainId, address verifying, bytes32 salt,) =
            IWebWallet(w).eip712Domain();
        bytes32 typehash = keccak256(
            abi.encodePacked(
                "TypedDataSign(Mail contents,string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)",
                MAIL_TYPE
            )
        );
        bytes32 structHash = keccak256(
            abi.encode(typehash, MAIL, keccak256(bytes(name)), keccak256(bytes(version)), chainId, verifying, salt)
        );
        return keccak256(abi.encodePacked(hex"1901", app, structHash));
    }

    /// `auth` as a `TypedDataSign` of the fixed Mail for `app`, and the app's hash it answers.
    function _typedSigOf(bytes32 app, bytes memory auth) internal pure returns (bytes32 h, bytes memory sig) {
        h = keccak256(abi.encodePacked(hex"1901", app, MAIL));
        sig = abi.encodePacked(auth, app, MAIL, MAIL_TYPE, uint16(bytes(MAIL_TYPE).length));
    }

    // ─── AUTHORIZED batches ─────────────────────────────────────────

    function _execDigestGas(
        address w,
        bytes32 mode,
        bytes memory calls,
        uint48 at,
        uint256 n,
        uint48 deadline,
        uint256 callGas
    ) internal view returns (bytes32) {
        return _typed(
            w, 1, keccak256(abi.encode(EXECUTE_TYPEHASH, mode, keccak256(calls), signedValue, at, n, deadline, callGas))
        );
    }

    function _execDigest(address w, bytes32 mode, bytes memory calls, uint48 at, uint256 n, uint48 deadline)
        internal
        view
        returns (bytes32)
    {
        return _execDigestGas(w, mode, calls, at, n, deadline, CALL_GAS);
    }

    /// The signed envelope: `abi.encode(Authorization, uint48 deadline, uint256 callGas)`.
    function _env(IWebWallet.Authorization memory a, uint48 deadline) internal pure returns (bytes memory) {
        return abi.encode(a, deadline, CALL_GAS);
    }

    /// `AUTHORIZED_MODE`'s data for `calls` and the envelope `env`.
    function _data(bytes memory calls, bytes memory env) internal view returns (bytes memory) {
        (IWebWallet.Authorization memory a, uint48 deadline, uint256 callGas) =
            abi.decode(env, (IWebWallet.Authorization, uint48, uint256));
        return abi.encode(calls, signedValue, deadline, callGas, abi.encode(a));
    }

    function _authOf(uint256[] memory pks, bytes32 h, uint48 at, bool below, IWebWallet.CallProof[] memory p)
        internal
        pure
        returns (IWebWallet.Authorization memory)
    {
        bytes32 signed = below ? _belowQuorum(h, at, _key(pks[0])) : h;
        return abi.decode(_auth(pks, signed, at, p, new bytes32[](0)), (IWebWallet.Authorization));
    }

    /// `pks` sign `calls` for `w`'s next nonce, at the block time, valid for an hour.
    function _direct(address w, uint256[] memory pks, bytes memory calls, bool below)
        internal
        view
        returns (bytes memory)
    {
        uint256 n = below ? abi.decode(calls, (Execution[])).length : 0;
        return _directAt(w, pks, calls, _nonce(w), uint48(_now()), below, _hitProofs(n));
    }

    function _directAt(
        address w,
        uint256[] memory pks,
        bytes memory calls,
        uint256 n,
        uint48 at,
        bool below,
        IWebWallet.CallProof[] memory p
    ) internal view returns (bytes memory) {
        uint48 deadline = uint48(_now() + 1 hours);
        return _env(_authOf(pks, _execDigest(w, AUTHORIZED_MODE, calls, at, n, deadline), at, below, p), deadline);
    }

    /// Alice, at quorum, signs the digest `h` at `at`.
    function _alice(bytes32 h, uint48 at, uint48 deadline) internal pure returns (bytes memory) {
        return _env(_authOf(_pks(ALICE_PK), h, at, false, _hitProofs(0)), deadline);
    }

    function _aliceFor(address w, bytes memory calls, uint256 n) internal view returns (bytes memory) {
        return _directAt(w, _pks(ALICE_PK), calls, n, uint48(_now()), false, _hitProofs(0));
    }

    /// `a`, then a `hit()` that shows whether the batch ran.
    function _then(Execution memory a) internal view returns (bytes memory) {
        return _two(a, _hitX());
    }

    function _run(address w, bytes memory calls, bytes memory env) internal {
        vm.prank(relayer);
        IWebWallet(w).execute{value: signedValue}(AUTHORIZED_MODE, _data(calls, env));
    }

    function _refuses(address w, bytes memory calls, bytes memory env, bytes4 err) internal {
        _refuses(w, calls, env, err, "");
    }

    /// The batch reverts with `err`, leaves the nonce and does not hit `target`.
    function _refuses(address w, bytes memory calls, bytes memory env, bytes4 err, string memory why) internal {
        uint256 n = _nonce(w);
        uint256 hits = target.calls();
        vm.deal(relayer, signedValue);
        vm.prank(relayer);
        vm.expectPartialRevert(err);
        IWebWallet(w).execute{value: signedValue}(AUTHORIZED_MODE, _data(calls, env));
        assertEq(_nonce(w), n, string.concat(why, ": a refused batch used the nonce"));
        assertEq(target.calls(), hits, string.concat(why, ": a refused batch's call stayed"));
    }

    /// `_run`, and `target` was hit from `w`.
    function _runs(address w, bytes memory calls, bytes memory env) internal {
        uint256 hits = target.calls();
        vm.deal(relayer, signedValue);
        _run(w, calls, env);
        assertGt(target.calls(), hits, "the batch did not run");
        assertEq(target.last(), w, "not from the wallet");
    }

    function _refusesBy(address w, bytes memory calls, uint256[] memory pks, bytes4 err) internal {
        _refuses(w, calls, _direct(w, pks, calls, false), err);
    }

    function _runsBy(address w, bytes memory calls, uint256[] memory pks) internal {
        _runs(w, calls, _direct(w, pks, calls, false));
    }

    // ─── Wallets ────────────────────────────────────────────────────

    /// Alice's wallet whose genesis bootstrap added her session under `p`.
    function _claimWith(IWebWallet.Policy memory p) internal returns (address w) {
        vm.prank(relayer);
        w = factory.createWallet(X, ALICE, 0);
        bytes memory data = _signed(w, _pks(ALICE_PK), _one(_linkX(w, X, ALICE, _key(ALICE_PK), p)));
        vm.prank(relayer);
        IWebWallet(w).execute(AUTHORIZED_MODE, data);
        vm.deal(w, 1 ether);
    }

    /// `w` links `(platformId, idNode)`, then adds `key` under `p` unless it is empty.
    function _link(address w, bytes32 platformId, bytes32 idNode, bytes memory key, IWebWallet.Policy memory p)
        internal
    {
        IWebWallet.Policy memory none;
        bytes memory payload = _linkPayload(w, platformId, idNode, "", none);
        vm.prank(w);
        IWebWallet(w).linkIdentity(platformId, V1, payload, "", none);
        if (key.length == 0) return;
        vm.prank(w);
        IWebWallet(w).addSession(_identity(platformId, idNode), key, p);
    }

    function _addSession(address w, bytes32 identity, bytes memory key, IWebWallet.Policy memory p) internal {
        vm.prank(w);
        IWebWallet(w).addSession(identity, key, p);
    }

    function _revoke(address w, bytes memory key) internal {
        vm.prank(w);
        IWebWallet(w).revokeSession(key);
    }

    function _addByLogin(
        address submitter,
        bytes32 platformId,
        bytes32 idNode,
        address w,
        bytes memory key,
        IWebWallet.Policy memory p
    ) internal {
        bytes memory payload = _loginPayload(w, platformId, idNode, key, p);
        vm.prank(submitter);
        IWebWallet(w).addSessionByLogin(platformId, V1, payload, "", p);
    }

    function _queueW(address w, bytes memory data) internal returns (bytes32) {
        vm.prank(w);
        return IWebWallet(w).queueRoot(data);
    }

    /// `w` queues `data`, 48 hours pass, and anyone executes it.
    function _rootW(address w, bytes memory data) internal {
        bytes32 id = _queueW(w, data);
        vm.warp(_now() + 48 hours);
        IWebWallet(w).executeRoot(id);
    }

    function _rootReverts(address w, bytes memory data, bytes memory err) internal {
        bytes32 id = _queueW(w, data);
        vm.warp(_now() + 48 hours);
        vm.expectRevert(err);
        IWebWallet(w).executeRoot(id);
    }

    function _threshold(address w, uint8 t) internal {
        _rootW(w, abi.encodeCall(IWebWallet.setThreshold, (t)));
    }

    function _raise() internal pure returns (bytes memory) {
        return abi.encodeCall(IWebWallet.setRootDelay, (72 hours));
    }

    /// The wallet's call queueing a root delay of 72 hours.
    function _queueRaise(address w) internal pure returns (Execution memory) {
        return _x(w, 0, abi.encodeCall(IWebWallet.queueRoot, (_raise())));
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IEntryPoint, PackedUserOperation} from "@openzeppelin/contracts/interfaces/IERC4337.sol";
import {Execution, IERC7579Execution} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";

import {IPlatformVerifier} from "../../ceremony/IPlatformVerifier.sol";
import {StubPlatformVerifier} from "../../identity/test/StubPlatformVerifier.sol";
import {NATIVE_TOKEN} from "../../NativeToken.sol";
import {IExecutionCheck, IIdentityValidator} from "../IIdentityValidator.sol";
import {IWalletRegistry} from "../IWalletRegistry.sol";
import {AUTHORIZED_MODE, IWebWallet} from "../IWebWallet.sol";
import {CallTarget, IUserOpHash, WalletTestBase} from "./WalletTestBase.sol";

/// EntryPoint v0.9's `incrementNonce`, which OpenZeppelin's interface leaves out.
interface INonceIncrement {
    function incrementNonce(uint192 key) external;
}

/// Reverts until opened.
contract Gate {
    bool public open;

    function openUp() external {
        open = true;
    }

    function pass() external view {
        require(open, "closed");
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

/// Called from a batch, submits another direct batch to the wallet; a failure bubbles.
contract Reenter {
    function go(address w, bytes calldata data) external {
        IWebWallet(w).execute(AUTHORIZED_MODE, data);
    }
}

/// @notice The direct path's builders: the `Execute` digest by hand, the authorization envelope, and wallets
///         whose genesis link added their first session.
abstract contract ExecuteBase is WalletTestBase {
    // cast keccak "Execute(bytes32 mode,bytes executionCalldata,uint48 at,uint256 nonce,uint48 deadline,uint256 callGas)"
    bytes32 internal constant EXECUTE_V2_TYPEHASH = 0x760f5de560082c6a0b40515f572ed0ff64b687ebb82b54045a3a595299961f27;
    /// The gas the helpers' batches sign for.
    uint256 internal constant CALL_GAS = 200_000;
    uint256 internal constant NEW_PK = 0x4E3;
    bytes4 internal constant NOT_AUTHORIZED = IExecutionCheck.ExecutionNotAuthorized.selector;

    /// Alice's wallet, holding 1 ether, whose genesis link added her admin session.
    function _fresh() internal returns (address w) {
        w = factory.createWallet(X, ALICE);
        _link(w, X, ALICE, w, _key(ALICE_PK), _admin());
        vm.deal(w, 1 ether);
    }

    /// The EntryPoint nonce key of `v`, and its full next nonce for `w`.
    function _nonceKey(address v) internal pure returns (uint192) {
        return uint192(uint160(v)) << 32;
    }

    function _nonce(address w, address v) internal view returns (uint256) {
        return IEntryPoint(EP).getNonce(w, _nonceKey(v));
    }

    /// `w`'s EIP-712 domain separator, written from the spec: it need not exist yet.
    function _domain(address w) internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("WebWallet"),
                keccak256("1"),
                vm.getChainId(),
                w
            )
        );
    }

    function _execDigest(address w, bytes32 mode, bytes memory calls, uint48 at, uint256 n, uint48 deadline)
        internal
        view
        returns (bytes32)
    {
        return _execDigestGas(w, mode, calls, at, n, deadline, CALL_GAS);
    }

    function _execDigestGas(
        address w,
        bytes32 mode,
        bytes memory calls,
        uint48 at,
        uint256 n,
        uint48 deadline,
        uint256 callGas
    ) internal view returns (bytes32) {
        bytes32 s = keccak256(abi.encode(EXECUTE_V2_TYPEHASH, mode, keccak256(calls), at, n, deadline, callGas));
        return keccak256(abi.encodePacked(hex"1901", _domain(w), s));
    }

    /// The helpers' signed envelope: `abi.encode(Authorization, uint48 deadline, uint256 callGas)`.
    function _env(IIdentityValidator.Authorization memory a, uint48 deadline) internal pure returns (bytes memory) {
        return abi.encode(a, deadline, CALL_GAS);
    }

    /// `AUTHORIZED_MODE`'s `data` for `calls` and the envelope `env`:
    /// `abi.encode(bytes executionCalldata, uint48 deadline, uint256 callGas, bytes authorization)`.
    function _data(bytes memory calls, bytes memory env) internal pure returns (bytes memory) {
        (IIdentityValidator.Authorization memory a, uint48 deadline, uint256 callGas) =
            abi.decode(env, (IIdentityValidator.Authorization, uint48, uint256));
        return abi.encode(calls, deadline, callGas, abi.encode(a));
    }

    /// `pks` sign `h` (below quorum, bound to `at` and the first key), as an `Authorization`.
    function _authOf(uint256[] memory pks, bytes32 h, uint48 at, bool below, IIdentityValidator.CallProof[] memory p)
        internal
        pure
        returns (IIdentityValidator.Authorization memory)
    {
        bytes32 signed = below ? _belowQuorum(h, at, _key(pks[0])) : h;
        return abi.decode(_auth(pks, signed, at, p, new bytes32[](0)), (IIdentityValidator.Authorization));
    }

    /// `pks` sign `calls` for `w` under `v`'s next nonce, at the block time, valid for an hour.
    function _direct(address w, address v, uint256[] memory pks, bytes memory calls, bool below)
        internal
        view
        returns (bytes memory)
    {
        return _directAt(w, pks, calls, _nonce(w, v), uint48(_now()), below, _hitProofs(below ? _count(calls) : 0));
    }

    function _directAt(
        address w,
        uint256[] memory pks,
        bytes memory calls,
        uint256 n,
        uint48 at,
        bool below,
        IIdentityValidator.CallProof[] memory p
    ) internal view returns (bytes memory) {
        uint48 deadline = uint48(_now() + 1 hours);
        bytes32 h = _execDigest(w, AUTHORIZED_MODE, calls, at, n, deadline);
        return _env(_authOf(pks, h, at, below, p), deadline);
    }

    /// Alice, at quorum, signs the digest `h` at `at`, as the envelope with `deadline`.
    function _alice(bytes32 h, uint48 at, uint48 deadline) internal pure returns (bytes memory) {
        return _env(_authOf(_pks(ALICE_PK), h, at, false, _hitProofs(0)), deadline);
    }

    /// Alice, at quorum, signs `calls` for `w`'s nonce `n` at the block time.
    function _aliceFor(address w, bytes memory calls, uint256 n) internal view returns (bytes memory) {
        return _directAt(w, _pks(ALICE_PK), calls, n, uint48(_now()), false, _hitProofs(0));
    }

    function _count(bytes memory calls) private pure returns (uint256) {
        return abi.decode(calls, (Execution[])).length;
    }

    function _x(address to, uint256 value, bytes memory data) internal pure returns (Execution memory) {
        return Execution({target: to, value: value, callData: data});
    }

    function _hitX() internal view returns (Execution memory) {
        return _x(address(target), 0, abi.encodeCall(CallTarget.hit, ()));
    }

    function _one(Execution memory a) internal pure returns (bytes memory) {
        Execution[] memory x = new Execution[](1);
        x[0] = a;
        return abi.encode(x);
    }

    /// `a`, then a `hit()` that shows whether the batch ran.
    function _then(Execution memory a) internal view returns (bytes memory) {
        Execution[] memory x = new Execution[](2);
        (x[0], x[1]) = (a, _hitX());
        return abi.encode(x);
    }

    function _run(address w, bytes memory calls, bytes memory auth) internal {
        vm.prank(relayer);
        IWebWallet(w).execute(AUTHORIZED_MODE, _data(calls, auth));
    }

    /// The batch reverts (with selector `err` unless zero), leaves `validator`'s nonce and does not hit `target`.
    function _refuses(address w, bytes memory calls, bytes memory auth, bytes4 err) internal {
        uint256 n = _nonce(w, address(validator));
        uint256 hits = target.calls();
        vm.prank(relayer);
        if (err == bytes4(0)) vm.expectRevert();
        else vm.expectPartialRevert(err);
        IWebWallet(w).execute(AUTHORIZED_MODE, _data(calls, auth));
        assertEq(_nonce(w, address(validator)), n, "a refused batch used the nonce");
        assertEq(target.calls(), hits, "a refused batch's call stayed");
    }

    /// `_run`, and `target` was hit from `w`.
    function _runs(address w, bytes memory calls, bytes memory auth) internal {
        uint256 hits = target.calls();
        _run(w, calls, auth);
        assertGt(target.calls(), hits, "the batch did not run");
        assertEq(target.last(), w, "not from the wallet");
    }
}

/// @notice The direct `execute(AUTHORIZED_MODE, data)`: any caller, checked at the end.
contract DirectExecuteTest is ExecuteBase {
    bytes4 internal constant OUT_OF_PERIOD = IExecutionCheck.ExecutionOutsidePeriod.selector;

    /// Alice's wallet at threshold 2: her X admin and Bob's GitHub admin, both active.
    function _twoOfTwo() internal returns (address w) {
        w = _fresh();
        _link(w, GITHUB, BOB, w, _key(BOB_PK), _admin());
        _root(w, address(validator), abi.encodeCall(IIdentityValidator.setThreshold, (2)));
        assertEq(validator.threshold(w), 2, "threshold");
    }

    // ─── Acceptance ─────────────────────────────────────────────────

    /// A stranger submits; the digest is the spec's, and the nonce is the EntryPoint's under the validator's key.
    function test_aStrangerSubmitsAnAdminSignedBatch() public {
        address w = _fresh();
        uint256 n = uint256(uint160(address(validator))) << 96;
        assertEq(_nonce(w, address(validator)), n, "the nonce key");
        _runs(w, _one(_hitX()), _aliceFor(w, _one(_hitX()), n));
        assertEq(_nonce(w, address(validator)), n + 1, "the nonce was not consumed");
    }

    // ─── The invariant table: no writer helps its own batch's check ──

    function test_aSessionAddedInTheBatchCannotSignIt() public {
        address w = _twoOfTwo();
        bytes32 bob = _identity(GITHUB, BOB);
        bytes memory add = abi.encodeCall(IIdentityValidator.addSession, (bob, _key(NEW_PK), _admin()));
        bytes memory calls = _then(_x(address(validator), 0, add));
        _refuses(w, calls, _direct(w, address(validator), _pks(ALICE_PK, NEW_PK), calls, false), bytes4(0));

        vm.prank(w);
        validator.addSession(bob, _key(NEW_PK), _admin());
        assertEq(validator.sessionOf(w, _key(NEW_PK)).activeAt, _now(), "activeAt is not the block time");
        bytes memory hit = _one(_hitX());
        _refuses(w, hit, _direct(w, address(validator), _pks(ALICE_PK, NEW_PK), hit, false), bytes4(0));
        vm.warp(_now() + 1);
        _runs(w, hit, _direct(w, address(validator), _pks(ALICE_PK, NEW_PK), hit, false));
    }

    function test_anIdentityLinkedInTheBatchCannotSignIt() public {
        address w = _twoOfTwo();
        bytes memory payload = _payload(GOOGLE, CAROL, LINK, _txData(w, _key(CAROL_PK), _ph(_admin())));
        bytes memory link = abi.encodeCall(IWalletRegistry.linkIdentity, (GOOGLE, V1, payload, _admin()));
        bytes memory calls = _then(_x(address(registry), 0, link));
        _refuses(w, calls, _direct(w, address(validator), _pks(ALICE_PK, CAROL_PK), calls, false), bytes4(0));
        assertFalse(validator.isLinked(w, _identity(GOOGLE, CAROL)), "the link stayed");

        _link(w, GOOGLE, CAROL, w, _key(CAROL_PK), _admin());
        assertEq(validator.sessionOf(w, _key(CAROL_PK)).activeAt, _now(), "activeAt is not the block time");
        vm.warp(_now() + 1);
        bytes memory hit = _one(_hitX());
        _runs(w, hit, _direct(w, address(validator), _pks(ALICE_PK, CAROL_PK), hit, false));
    }

    /// Signed as if Alice alone were at quorum: true only once the batch's own `executeRoot` ran.
    function test_executingSetThresholdInTheBatchDoesNotLowerItsCheck() public {
        address w = _twoOfTwo();
        bytes memory one = abi.encodeCall(IIdentityValidator.setThreshold, (1));
        vm.prank(w);
        validator.queueRoot(address(validator), one);
        vm.warp(_now() + 48 hours);
        bytes memory exec = abi.encodeCall(IIdentityValidator.executeRoot, (w, address(validator), one));
        bytes memory calls = _then(_x(address(validator), 0, exec));
        _refuses(w, calls, _direct(w, address(validator), _pks(ALICE_PK), calls, false), bytes4(0));
        assertEq(validator.threshold(w), 2, "the threshold changed");

        validator.executeRoot(w, address(validator), one);
        bytes memory hit = _one(_hitX());
        _runs(w, hit, _direct(w, address(validator), _pks(ALICE_PK), hit, false));
    }

    /// The end check runs against the entry-time validator: the new install's session cannot sign the batch
    /// that executes the migration, while the old validator's admin can.
    function test_executingAMigrationInTheBatchDoesNotHelpIt() public {
        address w = _fresh();
        (IIdentityValidator v2, bytes memory up) = _upgrade(abi.encode(X, ALICE, _key(NEW_PK), _admin()));
        vm.prank(w);
        validator.queueRoot(w, up);
        vm.warp(_now() + 48 hours);
        bytes memory calls =
            _then(_x(address(validator), 0, abi.encodeCall(IIdentityValidator.executeRoot, (w, w, up))));
        _refuses(w, calls, _direct(w, address(validator), _pks(NEW_PK), calls, false), bytes4(0));
        _refuses(w, calls, _direct(w, address(v2), _pks(NEW_PK), calls, false), bytes4(0));
        assertFalse(IWebWallet(w).isModuleInstalled(1, address(v2), ""), "migrated");

        _runs(w, calls, _direct(w, address(validator), _pks(ALICE_PK), calls, false));
        assertTrue(IWebWallet(w).isModuleInstalled(1, address(v2), ""), "not migrated");
        assertEq(v2.sessionOf(w, _key(NEW_PK)).activeAt, _now(), "the install session's start");
        vm.warp(_now() + 1);
        bytes memory hit = _one(_hitX());
        _runs(w, hit, _direct(w, address(v2), _pks(NEW_PK), hit, false));
    }

    /// The nonce carries the validator's key: a signature for V1, unused, does not run after migrating to V2.
    function test_aV1SignatureDoesNotReplayAfterMigration() public {
        address w = _fresh();
        (IIdentityValidator v2, bytes memory up) = _upgrade(abi.encode(X, ALICE, _key(ALICE_PK), _admin()));
        vm.prank(w);
        validator.queueRoot(w, up);
        vm.warp(_now() + 48 hours);
        // Signed for V1's sequence 0, which V2's sequence 0 matches but for the key.
        bytes memory hit = _one(_hitX());
        bytes memory used = _direct(w, address(validator), _pks(ALICE_PK), hit, false);
        _runs(w, hit, used);
        validator.executeRoot(w, w, up);
        vm.warp(_now() + 1);
        assertEq(_nonce(w, address(v2)), uint256(uint160(address(v2))) << 96, "V2's sequence");
        _refuses(w, hit, used, NOT_AUTHORIZED);
        _runs(w, hit, _direct(w, address(v2), _pks(ALICE_PK), hit, false));
    }

    function test_queueingAndExecutingSetThresholdInOneBatchFails() public {
        address w = _twoOfTwo();
        bytes memory one = abi.encodeCall(IIdentityValidator.setThreshold, (1));
        Execution[] memory x = new Execution[](3);
        x[0] = _x(address(validator), 0, abi.encodeCall(IIdentityValidator.queueRoot, (address(validator), one)));
        x[1] = _x(address(validator), 0, abi.encodeCall(IIdentityValidator.executeRoot, (w, address(validator), one)));
        x[2] = _hitX();
        bytes memory calls = abi.encode(x);
        _refuses(w, calls, _direct(w, address(validator), _pks(ALICE_PK), calls, false), bytes4(0));
        // Even at quorum: a root operation matures no earlier than the next second.
        _refuses(
            w,
            calls,
            _direct(w, address(validator), _pks(ALICE_PK, BOB_PK), calls, false),
            IIdentityValidator.RootNotReady.selector
        );
        assertEq(validator.threshold(w), 2, "the threshold changed");
        bytes memory hit = _one(_hitX());
        _runs(w, hit, _direct(w, address(validator), _pks(ALICE_PK, BOB_PK), hit, false));
    }

    function test_revokingAnAdminInTheBatchDoesNotHelpIt() public {
        address w = _twoOfTwo();
        bytes memory calls =
            _then(_x(address(validator), 0, abi.encodeCall(IIdentityValidator.revokeSession, (_key(BOB_PK)))));
        _refuses(w, calls, _direct(w, address(validator), _pks(ALICE_PK), calls, false), bytes4(0));
        assertEq(validator.sessionOf(w, _key(BOB_PK)).identity, _identity(GITHUB, BOB), "Bob's session revoked");
        bytes memory hit = _one(_hitX());
        _runs(w, hit, _direct(w, address(validator), _pks(ALICE_PK, BOB_PK), hit, false));
    }

    // ─── The first-session exception ────────────────────────────────

    function test_theFirstSessionSignsAtOnce() public {
        address w = _fresh();
        assertEq(validator.sessionOf(w, _key(ALICE_PK)).activeAt, 0, "the first session is pending");
        bytes memory hit = _one(_hitX());
        _runs(w, hit, _direct(w, address(validator), _pks(ALICE_PK), hit, false));
    }

    /// The first session comes from any OAuth client's proof.
    function test_aFirstSessionFromAnyClientSignsAtOnce() public {
        OtherClientVerifier other = new OtherClientVerifier(xStub);
        vm.prank(owner);
        proofVerifier.setVerifier(X, V1, other);
        address w = factory.createWallet(X, ALICE);
        _link(w, X, ALICE, w, _key(ALICE_PK), _admin());
        assertEq(other.lastClient(), "another-app", "not the other client's proof");
        assertEq(validator.sessionOf(w, _key(ALICE_PK)).activeAt, 0, "the first session is pending");
        vm.deal(w, 1 ether);
        bytes memory hit = _one(_hitX());
        _runs(w, hit, _direct(w, address(validator), _pks(ALICE_PK), hit, false));
    }

    // Without each of the genesis identity, a wallet that never had a session and an admin policy, a session
    // added (if at all) cannot sign in its own second.

    function test_theExceptionNeedsTheGenesis() public {
        address w = factory.createWallet(X, ALICE);
        _tryLink(w, GITHUB, BOB, BOB_PK, _admin());
        bytes memory hit = _one(_hitX());
        _refuses(w, hit, _direct(w, address(validator), _pks(BOB_PK), hit, false), bytes4(0));
    }

    function test_theExceptionNeedsAWalletThatNeverHadASession() public {
        address w = _fresh();
        _link(w, X, ALICE, w, _key(NEW_PK), _admin());
        assertEq(validator.sessionOf(w, _key(NEW_PK)).activeAt, _now(), "activeAt is not the block time");
        bytes memory hit = _one(_hitX());
        _refuses(w, hit, _direct(w, address(validator), _pks(NEW_PK), hit, false), bytes4(0));
    }

    function test_theExceptionNeedsAnAdmin() public {
        address w = factory.createWallet(X, ALICE);
        _tryLink(w, X, ALICE, APP_PK, _hitOnly());
        bytes memory hit = _one(_hitX());
        _refuses(w, hit, _direct(w, address(validator), _pks(APP_PK), hit, true), bytes4(0));
    }

    function _tryLink(address w, bytes32 platformId, bytes32 idNode, uint256 pk, IIdentityValidator.Policy memory p)
        internal
    {
        bytes memory payload = _payload(platformId, idNode, LINK, _txData(w, _key(pk), _ph(p)));
        vm.prank(w);
        try registry.linkIdentity(platformId, V1, payload, p) {} catch {}
    }

    /// Only the wallet's own batch gives a fresh wallet its first session.
    function test_aFreshWalletsFirstSessionComesOnlyFromItsOwnBatch() public {
        address w = factory.createWallet(X, ALICE);
        bytes memory link = _payload(X, ALICE, LINK, _txData(w, _key(MALLORY_PK), _ph(_admin())));
        vm.prank(mallory);
        vm.expectRevert(abi.encodeWithSelector(IWalletRegistry.NotWallet.selector, w, mallory));
        registry.linkIdentity(X, V1, link, _admin());
        bytes memory add = _payload(X, ALICE, ADD, _txData(w, _key(MALLORY_PK), _ph(_admin())));
        vm.prank(mallory);
        vm.expectRevert();
        registry.addSessionByProof(X, V1, add, _admin());
        assertFalse(validator.hadSession(w), "a stranger gave the wallet a session");

        // Once the wallet had a session, a proof add is accepted, pending for the recovery delay.
        _link(w, X, ALICE, w, _key(ALICE_PK), _admin());
        _addByProof(mallory, X, ALICE, w, _key(MALLORY_PK), _admin());
        IIdentityValidator.Session memory s = validator.sessionOf(w, _key(MALLORY_PK));
        assertTrue(s.byProof, "no session by proof");
        assertEq(s.activeAt, _now() + validator.recoveryDelay(w), "not pending for the recovery delay");
    }

    function test_migrateRefusesAnEmptyKey() public {
        address w = _fresh();
        (, bytes memory bare) = _upgrade(abi.encode(X, ALICE));
        vm.prank(w);
        validator.queueRoot(w, bare);
        vm.warp(_now() + 48 hours);
        vm.expectRevert();
        validator.executeRoot(w, w, bare);

        (IIdentityValidator v2, bytes memory keyed) = _upgrade(abi.encode(X, ALICE, _key(ALICE_PK), _admin()));
        _root(w, w, keyed);
        assertTrue(IWebWallet(w).isModuleInstalled(1, address(v2), ""), "the keyed migration failed");
    }

    /// A second stack, and the root upgrade that migrates to it with `installData`.
    function _upgrade(bytes memory installData) internal returns (IIdentityValidator v2, bytes memory up) {
        IWalletRegistry r2 = _newRegistry(address(factory));
        v2 = IIdentityValidator(r2.identityValidator());
        address impl2 = deployCode("WebWallet.sol:WebWallet", abi.encode(address(v2)));
        up = abi.encodeCall(IWebWallet.upgradeToAndCall, (impl2, abi.encodeCall(IWebWallet.migrate, (installData))));
    }

    // ─── The nonce ──────────────────────────────────────────────────

    function test_theNonceIsSharedWithUserOperations() public {
        address w = _fresh();
        bytes memory hit = _one(_hitX());
        _runs(w, hit, _direct(w, address(validator), _pks(ALICE_PK), hit, false));
        _refused(_signed(_op(w, 0, _hit()), _pks(ALICE_PK)), "a UserOperation reused the direct nonce");
        _handle(_signed(_op(w, 1, _hit()), _pks(ALICE_PK)));
        assertEq(target.calls(), 2, "the next UserOperation did not run");

        uint256 n1 = (uint256(uint160(address(validator))) << 96) | 1;
        bytes memory stale = _aliceFor(w, hit, n1);
        _refuses(w, hit, stale, NOT_AUTHORIZED);
        _runs(w, hit, _direct(w, address(validator), _pks(ALICE_PK), hit, false));
    }

    /// Signed for the nonce after next, the batch cannot spend the next one itself.
    function test_aBatchCallingIncrementNonceDoesNotHelp() public {
        address w = _fresh();
        uint256 n = _nonce(w, address(validator));
        bytes memory calls =
            _then(_x(EP, 0, abi.encodeCall(INonceIncrement.incrementNonce, (_nonceKey(address(validator))))));
        _refuses(w, calls, _aliceFor(w, calls, n + 1), bytes4(0));
        _runs(w, calls, _aliceFor(w, calls, n));
        assertEq(_nonce(w, address(validator)), n + 2, "nonce");
    }

    function test_aRevertedBatchLeavesItsNonce() public {
        address w = _fresh();
        Gate gate = new Gate();
        bytes memory calls = _then(_x(address(gate), 0, abi.encodeCall(Gate.pass, ())));
        bytes memory auth = _direct(w, address(validator), _pks(ALICE_PK), calls, false);
        _refuses(w, calls, auth, bytes4(0));
        gate.openUp();
        _runs(w, calls, auth);
    }

    /// The submitter cannot run the signed batch with less than the signed `callGas`.
    function test_tooLittleGasRevertsBeforeAnyCall() public {
        address w = _fresh();
        uint48 at = uint48(_now());
        uint48 deadline = at + 1 hours;
        bytes memory calls = _one(_hitX());
        uint256 n = _nonce(w, address(validator));
        bytes32 h = _execDigestGas(w, AUTHORIZED_MODE, calls, at, n, deadline, 5_000_000);
        bytes memory data = abi.encode(
            calls, deadline, uint256(5_000_000), abi.encode(_authOf(_pks(ALICE_PK), h, at, false, _hitProofs(0)))
        );
        vm.prank(relayer);
        vm.expectRevert();
        IWebWallet(w).execute{gas: 1_000_000}(AUTHORIZED_MODE, data);
        assertEq(target.calls(), 0, "a call ran");
        assertEq(_nonce(w, address(validator)), n, "nonce");
        vm.prank(relayer);
        IWebWallet(w).execute{gas: 6_000_000}(AUTHORIZED_MODE, data);
        assertEq(target.calls(), 1, "control");
    }

    // ─── Reentry ────────────────────────────────────────────────────

    /// The inner batch is signed for the nonce the outer one leaves: only the lock refuses it.
    function test_theLockRefusesReentryFromTheDirectPath() public {
        address w = _fresh();
        Reenter re = new Reenter();
        uint256 n = _nonce(w, address(validator));
        bytes memory inner = _one(_hitX());
        bytes memory innerAuth = _aliceFor(w, inner, n + 1);
        bytes memory outer = _one(_x(address(re), 0, abi.encodeCall(Reenter.go, (w, _data(inner, innerAuth)))));
        _refuses(w, outer, _aliceFor(w, outer, n), ReentrancyGuardTransient.ReentrancyGuardReentrantCall.selector);

        bytes memory self = _then(_x(w, 0, abi.encodeCall(IERC7579Execution.execute, (MODE_BATCH, inner))));
        _refuses(w, self, _direct(w, address(validator), _pks(ALICE_PK), self, false), bytes4(0));
        _runs(w, inner, _direct(w, address(validator), _pks(ALICE_PK), inner, false));
    }

    function test_theLockRefusesReentryFromTheEntryPoint() public {
        address w = _fresh();
        Reenter re = new Reenter();
        uint256 n = _nonce(w, address(validator));
        bytes memory inner = _one(_hitX());
        bytes memory innerAuth = _aliceFor(w, inner, n + 1);
        bytes memory outer = _then(_x(address(re), 0, abi.encodeCall(Reenter.go, (w, _data(inner, innerAuth)))));
        _handle(_signed(_op(w, 0, abi.encodeCall(IERC7579Execution.execute, (MODE_BATCH, outer))), _pks(ALICE_PK)));
        assertEq(target.calls(), 0, "the reentered batch ran");
        assertEq(_nonce(w, address(validator)), n + 1, "the UserOperation's nonce");
        _runs(w, inner, innerAuth);
    }

    // ─── Periods below quorum ───────────────────────────────────────

    /// Value is charged to NATIVE, gas is not, and only the period holding the block time is accepted.
    function test_belowQuorumTheSignedPeriodMustBeNow() public {
        address w = _fresh();
        IIdentityValidator.Policy memory p = _app();
        p.rules.scopeRoot = _leaf(address(target), CallTarget.hit.selector, 1 ether);
        p.rules.allowances = new IIdentityValidator.Allowance[](1);
        p.rules.allowances[0] = IIdentityValidator.Allowance({token: NATIVE_TOKEN, amount: 1 ether, period: 1 days});
        vm.prank(w);
        validator.addSession(_identity(X, ALICE), _key(APP_PK), p);
        vm.warp(_now() + 1);

        bytes memory calls = _one(_x(address(target), 0.1 ether, abi.encodeCall(CallTarget.hit, ())));
        IIdentityValidator.CallProof[] memory proofs = _hitProofs(1);
        proofs[0].maxValue = 1 ether;
        uint256 n = _nonce(w, address(validator));
        uint48 t = uint48(_now());
        _refuses(w, calls, _directAt(w, _pks(APP_PK), calls, n, t + 1 days, true, proofs), OUT_OF_PERIOD);
        _refuses(w, calls, _directAt(w, _pks(APP_PK), calls, n, t - 1 days, true, proofs), OUT_OF_PERIOD);
        _runs(w, calls, _directAt(w, _pks(APP_PK), calls, n, t, true, proofs));
        assertEq(address(target).balance, 0.1 ether, "value");
        assertEq(validator.allowanceOf(w, _key(APP_PK), NATIVE_TOKEN).spent, 0.1 ether, "NATIVE charge");
    }

    // ─── Replay ─────────────────────────────────────────────────────

    function test_aDirectSignatureIsNotAUserOperationSignature() public {
        address w = _fresh();
        bytes memory calls = _one(_hitX());
        uint48 at = uint48(_now());
        bytes32 h = _execDigest(w, AUTHORIZED_MODE, calls, at, _nonce(w, address(validator)), at + 1 hours);
        PackedUserOperation memory op = _op(w, 0, abi.encodeCall(IERC7579Execution.execute, (MODE_BATCH, calls)));
        op.signature = abi.encode(_authOf(_pks(ALICE_PK), h, at, false, _hitProofs(0)));
        _refused(op, "a direct signature as a UserOperation");
        op.signature = _direct(w, address(validator), _pks(ALICE_PK), calls, false);
        _refused(op, "a direct authorization as a UserOperation");
        _handle(_signed(op, _pks(ALICE_PK)));
        assertEq(target.calls(), 1, "control");
    }

    function test_aUserOperationSignatureIsNotADirectSignature() public {
        address w = _fresh();
        bytes memory calls = _one(_hitX());
        PackedUserOperation memory op = _op(w, 0, abi.encodeCall(IERC7579Execution.execute, (MODE_BATCH, calls)));
        uint48 at = uint48(_now());
        bytes32 h = IUserOpHash(EP).getUserOpHash(op);
        _refuses(w, calls, _alice(h, at, at + 1 hours), NOT_AUTHORIZED);
        _runs(w, calls, _direct(w, address(validator), _pks(ALICE_PK), calls, false));
    }

    function test_erc1271AndTheDirectPathShareNoSignature() public {
        address w = _fresh();
        bytes memory calls = _one(_hitX());
        uint48 at = uint48(_now());
        uint48 deadline = at + 1 hours;
        bytes32 d = _execDigest(w, AUTHORIZED_MODE, calls, at, _nonce(w, address(validator)), deadline);
        assertFalse(_isValid1271(w, d, ALICE_PK, d), "a direct signature passed ERC-1271");
        assertTrue(_isValid1271(w, d, ALICE_PK, _wrapped(w, d)), "control: ERC-1271");
        bytes memory as1271 = _alice(_wrapped(w, d), at, deadline);
        _refuses(w, calls, as1271, NOT_AUTHORIZED);
        _runs(w, calls, _alice(d, at, deadline));
    }

    function test_aChangedBatchModeDeadlineOrChainIsRefused() public {
        address w = _fresh();
        bytes memory calls = _one(_hitX());
        uint256 n = _nonce(w, address(validator));
        uint48 at = uint48(_now());
        uint48 deadline = at + 1 hours;
        IIdentityValidator.Authorization memory a =
            _authOf(_pks(ALICE_PK), _execDigest(w, AUTHORIZED_MODE, calls, at, n, deadline), at, false, _hitProofs(0));

        Execution[] memory two = new Execution[](2);
        (two[0], two[1]) = (_hitX(), _hitX());
        _refuses(w, abi.encode(two), _env(a, deadline), NOT_AUTHORIZED);
        _refuses(w, calls, abi.encode(a, deadline + 1, CALL_GAS), NOT_AUTHORIZED);
        _refuses(w, calls, abi.encode(a, deadline, CALL_GAS - 1), NOT_AUTHORIZED);

        bytes32 otherMode = AUTHORIZED_MODE | bytes32(uint256(1));
        bytes32 h = _execDigest(w, otherMode, calls, at, n, deadline);
        _refuses(w, calls, _alice(h, at, deadline), NOT_AUTHORIZED);

        uint48 past = at - 1;
        h = _execDigest(w, AUTHORIZED_MODE, calls, at, n, past);
        bytes memory expired = _alice(h, at, past);
        _refuses(w, calls, expired, IExecutionCheck.ExecutionExpired.selector);
        h = _execDigest(w, AUTHORIZED_MODE, calls, at, n, 0);
        _refuses(w, calls, _alice(h, at, uint48(0)), bytes4(0));

        uint256 chain = vm.getChainId();
        vm.chainId(chain + 1);
        _refuses(w, calls, _env(a, deadline), NOT_AUTHORIZED);
        vm.chainId(chain);
        _runs(w, calls, _env(a, deadline));
    }
}

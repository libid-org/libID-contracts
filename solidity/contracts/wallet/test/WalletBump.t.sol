// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/IERC4337.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

import {IWalletFactory} from "../IWalletFactory.sol";
import {AUTHORIZED_MODE, IIdentityAdmin, IWalletCore, IWebWallet} from "../IWebWallet.sol";
import {WalletBase} from "./WalletBase.sol";

/// A release whose data step records, from `RECORD` in the wallet's storage: calls, `from`, caller, and the
/// flags lock | entryPointBlocked << 1 | dataStep << 2.
contract StepRecorder {
    uint64 public immutable VERSION;
    address public immutable FACTORY;
    address public immutable REGISTRY;
    bytes32 public constant RECORD = keccak256("test.step-recorder");
    bytes32 private constant LOCK = 0xc9e10f29671c1e91671796ae10cf0910e186e77a658823020379090d44874400;
    bytes32 private constant BLOCKED = 0xd9893535c4c4b5cd665ca764f2da4f77d7dc5ab6d2372696ca69936a0c362100;
    bytes32 private constant STEP = 0x634693ff7eb334934b2860ed0d3d3a4ad5bfbd5aa7959baa8bf9f0bcd8c88000;

    constructor(address factory, address registry, uint64 version) {
        (FACTORY, REGISTRY, VERSION) = (factory, registry, version);
    }

    function runDataSteps(uint64 from) external {
        (bytes32 r, bytes32 l, bytes32 b, bytes32 s) = (RECORD, LOCK, BLOCKED, STEP);
        assembly {
            let flags :=
                or(or(iszero(iszero(tload(l))), shl(1, iszero(iszero(tload(b))))), shl(2, iszero(iszero(tload(s)))))
            sstore(r, add(sload(r), 1))
            sstore(add(r, 1), from)
            sstore(add(r, 2), caller())
            sstore(add(r, 3), flags)
        }
    }
}

/// A factory upgrade whose `release(lie)` names `liar`.
contract RogueFactory is UUPSUpgradeable {
    uint64 private immutable LIE;
    address private immutable LIAR;
    address private immutable R1;
    address private immutable R2;

    constructor(uint64 lie, address liar, address r1, address r2) {
        (LIE, LIAR, R1, R2) = (lie, liar, r1, r2);
    }

    function release(uint64 v) external view returns (address) {
        if (v == LIE) return LIAR;
        return v == 1 ? R1 : v == 2 ? R2 : address(0);
    }

    function _authorizeUpgrade(address) internal override {}
}

/// @notice Publishing releases, and the root-executed bump between them.
contract WalletBumpTest is WalletBase {
    address internal w;
    address internal impl2;

    function setUp() public override {
        super.setUp();
        w = _claim();
        impl2 = _publish(2);
    }

    function _bump(uint64 v) internal pure returns (bytes memory) {
        return abi.encodeCall(IIdentityAdmin.bump, (v));
    }

    /// Acceptance 7.
    function test_publishRefusals() public {
        address eoa = makeAddr("eoa");
        address other = makeAddr("another factory");
        address otherRegistry = makeAddr("another registry");
        address[6] memory impls = [
            _releaseFor(address(factory), 3),
            eoa,
            _releaseFor(address(factory), 4),
            _releaseFor(address(factory), 2),
            _releaseFor(other, 3),
            deployCode(
                "WebWallet.sol:WebWallet",
                abi.encode(address(factory), otherRegistry, uint64(3), identityAdmin, sessionRules)
            )
        ];
        address[6] memory callers = [mallory, owner, owner, owner, owner, owner];
        bytes[6] memory errs = [
            abi.encodeWithSignature("OwnableUnauthorizedAccount(address)", mallory),
            abi.encodeWithSelector(IWalletFactory.ImplementationWithoutCode.selector, eoa),
            abi.encodeWithSelector(IWalletFactory.WrongReleaseVersion.selector, 3, 4),
            abi.encodeWithSelector(IWalletFactory.WrongReleaseVersion.selector, 3, 2),
            abi.encodeWithSelector(IWalletFactory.WrongReleaseFactory.selector, other),
            abi.encodeWithSelector(IWalletFactory.WrongReleaseRegistry.selector, otherRegistry)
        ];
        for (uint256 i; i < impls.length; ++i) {
            vm.prank(callers[i]);
            vm.expectRevert(errs[i]);
            factory.publish(impls[i]);
        }
        (address latest, uint64 version) = factory.latest();
        assertEq(abi.encode(latest, version), abi.encode(impl2, uint64(2)), "latest moved");
        assertEq(factory.release(2), impl2, "release 2 overwritten");
        assertEq(factory.release(3), address(0), "release 3 published");
        vm.prank(owner);
        factory.publish(impls[0]);
        assertEq(factory.release(3), impls[0], "control: the next release");
    }

    /// `bump(0)` resolves to the latest at queue time, and the operation names its implementation; the bump keeps the wallet's state and voids the roots
    /// queued under the old version.
    function test_bumpMovesTheReleaseAndKeepsTheWalletState() public {
        (bytes32 p, bytes32 n, uint256 s) = IWebWallet(w).genesisIdentity();
        bytes32 epoch = IWebWallet(w).epoch();
        bytes32 delay = _queue(w, abi.encodeCall(IIdentityAdmin.setRootDelay, (72 hours)));
        bytes32 id = _queue(w, _bump(0));
        IIdentityAdmin.RootOperation memory op = IWebWallet(w).rootOperation(id);
        assertEq(
            abi.encode(op.version, op.data, op.implementation),
            abi.encode(uint64(1), _bump(2), impl2),
            "not resolved at queue time"
        );
        _publish(3);
        _mature(w);
        vm.expectEmit(w);
        emit IWebWallet.Bumped(1, 2, impl2);
        IWebWallet(w).executeRoot(id);
        (address impl, uint64 version) = IWebWallet(w).release();
        assertEq(abi.encode(impl, version), abi.encode(impl2, uint64(2)), "release");
        assertEq(IWebWallet(w).VERSION(), 2, "not running release 2");
        (,, string memory domainVersion,,,,) = IWebWallet(w).eip712Domain();
        assertEq(domainVersion, "2", "domain version");
        (bytes32 p2, bytes32 n2, uint256 s2) = IWebWallet(w).genesisIdentity();
        assertEq(abi.encode(p2, n2, s2), abi.encode(p, n, s), "the genesis did not survive");
        assertEq(IWebWallet(w).epoch(), epoch, "a bump moved the epoch");
        assertEq(IWebWallet(w).sessionOf(_key(ALICE_PK)).identity, _identity(X, ALICE), "the session did not survive");
        assertEq(IWebWallet(w).rootReadyAt(delay), 0, "a void root reads as pending");
        uint32 before = IWebWallet(w).rootDelay();
        vm.expectRevert(abi.encodeWithSelector(IWebWallet.RootOperationVoid.selector, delay));
        IWebWallet(w).executeRoot(delay);
        assertEq(IWebWallet(w).rootDelay(), before, "a void root ran");
    }

    function test_bumpRefusals() public {
        bytes memory notAbove =
            _signed(w, _pks(ALICE_PK), _one(_x(w, 0, abi.encodeCall(IIdentityAdmin.queueRoot, (_bump(1))))));
        vm.expectPartialRevert(IWebWallet.ReleaseNotAbove.selector);
        IWebWallet(w).execute(AUTHORIZED_MODE, notAbove);
        bytes memory unpublished =
            _signed(w, _pks(ALICE_PK), _one(_x(w, 0, abi.encodeCall(IIdentityAdmin.queueRoot, (_bump(3))))));
        vm.expectRevert(abi.encodeWithSelector(IWebWallet.ReleaseMismatch.selector, 3));
        IWebWallet(w).execute(AUTHORIZED_MODE, unpublished);

        // The factory upgraded under a queued bump: `release(2)` with no code, `release(1)`, and `release(2)` naming
        // another release 2 with code no longer match.
        uint64[3] memory lies = [uint64(2), 1, 2];
        address[3] memory liars = [address(0xbad), address(0xbad), _releaseFor(address(factory), 2)];
        for (uint256 i; i < lies.length; ++i) {
            uint256 snap = vm.snapshotState();
            bytes32 id = _queue(w, _bump(2));
            _mature(w);
            address rogue = address(new RogueFactory(lies[i], liars[i], impl1, impl2));
            vm.prank(owner);
            UUPSUpgradeable(address(factory)).upgradeToAndCall(rogue, "");
            vm.expectRevert(abi.encodeWithSelector(IWebWallet.ReleaseMismatch.selector, lies[i]));
            IWebWallet(w).executeRoot(id);
            (, uint64 version) = IWebWallet(w).release();
            assertEq(version, 1, "bumped on a mismatch");
            vm.revertToStateAndDelete(snap);
        }
    }

    /// `Execute`, ERC-1271 and UserOperation signatures under release 1's domain die with the bump.
    /// @dev Isolated, so the control operation runs in a transaction after the bump's.
    /// forge-config: default.isolate = true
    function test_signaturesUnderTheOldDomainAreRefused() public {
        bytes32 id = _queue(w, _bump(2));
        _mature(w);
        bytes memory batch = _one(_hitX());
        bytes memory oldExec = _signedAt(w, 1, _pks(ALICE_PK), batch, false);
        PackedUserOperation memory oldOp = _signOp(_op(w, _hitCall()), 1, _pks(ALICE_PK));
        bytes32 h = keccak256("a message");
        assertTrue(_valid1271(w, 1, ALICE_PK, h), "control: release 1 signature");
        IWebWallet(w).executeRoot(id);

        vm.prank(relayer);
        vm.expectPartialRevert(IWebWallet.ExecutionNotSigned.selector);
        IWebWallet(w).execute(AUTHORIZED_MODE, oldExec);
        assertFalse(_valid1271(w, 1, ALICE_PK, h), "ERC-1271 under the old domain");
        assertTrue(_valid1271(w, 2, ALICE_PK, h), "ERC-1271 under the new domain");
        _refusedOp(oldOp);

        _handle(_ops(_signOp(_op(w, _hitCall()), 2, _pks(ALICE_PK))));
        assertEq(target.calls(), 1, "control: a release 2 operation");
        _run(w, batch);
        assertEq(target.calls(), 2, "control: a release 2 batch");
    }

    /// A UserOperation validated before a bump in the same bundle does not execute after it.
    function test_entryPointExecuteIsBlockedAfterTheBump() public {
        address b = _claimAs(GITHUB, BOB, 0, BOB_PK);
        bytes32 id = _queue(w, _bump(2));
        _mature(w);
        PackedUserOperation[] memory ops = new PackedUserOperation[](2);
        bytes memory bumpIt = abi.encodeCall(
            IWalletCore.execute,
            (MODE_SINGLE, abi.encodePacked(w, uint256(0), abi.encodeCall(IIdentityAdmin.executeRoot, (id))))
        );
        ops[0] = _signOp(_op(b, bumpIt), IWebWallet(b).VERSION(), _pks(BOB_PK));
        ops[1] = _signOp(_op(w, _hitCall()), 1, _pks(ALICE_PK));
        _handle(ops);
        (, uint64 version) = IWebWallet(w).release();
        assertEq(version, 2, "the bump did not run");
        assertEq(target.calls(), 0, "the stale operation executed");
    }

    /// A wallet skipping release 2 runs the data steps once, from its own version, inside the bump only.
    function test_dataStepsRunOnceAcrossSkippedVersions() public {
        StepRecorder impl3 = new StepRecorder(address(factory), address(registry), 3);
        vm.prank(owner);
        factory.publish(address(impl3));
        uint64[2] memory via = [uint64(0), 2];
        for (uint256 i; i < via.length; ++i) {
            uint256 snap = vm.snapshotState();
            if (via[i] != 0) _root(w, _bump(via[i]));
            _root(w, _bump(3));
            uint256 r = uint256(impl3.RECORD());
            assertEq(uint256(vm.load(w, bytes32(r))), 1, "steps ran more than once");
            assertEq(uint256(vm.load(w, bytes32(r + 1))), via[i] == 0 ? 1 : via[i], "from");
            assertEq(vm.load(w, bytes32(r + 2)), bytes32(uint256(uint160(w))), "not a self-call");
            assertEq(uint256(vm.load(w, bytes32(r + 3))), 7, "lock, entryPointBlocked and dataStep not all set");
            vm.revertToStateAndDelete(snap);
        }
    }

    /// Outside a bump, `runDataSteps` refuses a stranger and the wallet's own call.
    function test_dataStepsAreRefusedOutsideABump() public {
        vm.expectRevert(IWebWallet.DataStepRefused.selector);
        IWebWallet(w).runDataSteps(1);
        bytes memory data =
            _signed(w, _pks(ALICE_PK), _one(_x(w, 0, abi.encodeCall(IWalletCore.runDataSteps, (uint64(1))))));
        vm.expectRevert(IWebWallet.DataStepRefused.selector);
        IWebWallet(w).execute(AUTHORIZED_MODE, data);
    }
}

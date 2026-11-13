// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Account as OzAccount} from "@openzeppelin/contracts/account/Account.sol";
import {ERC7579Utils} from "@openzeppelin/contracts/account/utils/draft-ERC7579Utils.sol";
import {IEntryPoint} from "@openzeppelin/contracts/interfaces/IERC4337.sol";
import {Execution, IERC7579Execution, IERC7579Validator} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";

import {IIdentityValidator} from "../IIdentityValidator.sol";
import {AUTHORIZED_MODE, IWebWallet} from "../IWebWallet.sol";
import {CallTarget} from "./WalletTestBase.sol";
import {ExecuteBase} from "./DirectExecute.t.sol";

/// Records an account's EntryPoint nonce when called.
contract NonceProbe {
    uint256 public seen;

    function look(address ep, address account, uint192 key) external {
        seen = IEntryPoint(ep).getNonce(account, key);
    }
}

/// @notice The direct path's modes, changed batches and signers out of their window, and the default mode
///         and `executeFromExecutor` that only the EntryPoint, or nobody, calls.
contract DirectExecuteEdgesTest is ExecuteBase {
    uint256 internal constant OTHER_PK = 0x07E4;

    address internal w;

    function setUp() public override {
        super.setUp();
        w = _fresh();
    }

    /// Alice signs `calls` under `mode` for the next nonce.
    function _signedFor(bytes32 mode, bytes memory calls) internal view returns (bytes memory) {
        uint48 at = uint48(_now());
        uint48 deadline = at + 1 hours;
        bytes32 h = _execDigest(w, mode, calls, at, _nonce(w, address(validator)), deadline);
        return _alice(h, at, deadline);
    }

    function _hits(uint256 n) internal view returns (Execution[] memory x) {
        x = new Execution[](n);
        for (uint256 i; i < n; ++i) {
            x[i] = _hitX();
        }
    }

    /// Only the exact `AUTHORIZED_MODE` word is the direct path. Its variants, another selector and delegatecall are
    /// other modes: only the EntryPoint sends them, and it is refused too.
    function test_otherModesRevert() public {
        bytes memory batch = _one(_hitX());
        bytes32[4] memory modes = [
            AUTHORIZED_MODE | bytes32(uint256(0x01) << 240),
            AUTHORIZED_MODE ^ bytes32(uint256(0x01) << 248),
            AUTHORIZED_MODE | bytes32(uint256(1)),
            MODE_BATCH | bytes32(uint256(0xdeadbeef) << 176)
        ];
        for (uint256 i; i < modes.length; ++i) {
            bytes memory data = _data(batch, _signedFor(modes[i], batch));
            vm.prank(relayer);
            vm.expectRevert(abi.encodeWithSelector(OzAccount.AccountUnauthorized.selector, relayer));
            IWebWallet(w).execute(modes[i], data);
            vm.prank(EP);
            vm.expectPartialRevert(IWebWallet.UnsupportedModeSelector.selector);
            IWebWallet(w).execute(modes[i], data);
        }
        bytes memory delegate = abi.encodePacked(address(target), abi.encodeCall(CallTarget.hit, ()));
        vm.prank(EP);
        vm.expectPartialRevert(ERC7579Utils.ERC7579UnsupportedCallType.selector);
        IWebWallet(w).execute(MODE_DELEGATE, delegate);
        assertEq(target.calls(), 0, "a refused mode ran");
    }

    /// Signed for one batch, submitted as another.
    function test_aChangedBatchIsRefused() public {
        CallTarget other = new CallTarget();
        Execution[] memory x = _hits(2);
        x[1].value = 0.1 ether;
        bytes memory auth = _signedFor(AUTHORIZED_MODE, abi.encode(x));

        Execution[][6] memory changed;
        for (uint256 i; i < 6; ++i) {
            changed[i] = _hits(2);
            changed[i][1].value = 0.1 ether;
        }
        changed[0][0].target = address(other);
        changed[1][1].value = 0.2 ether;
        changed[2][0].callData = abi.encodeWithSelector(CallTarget.hit.selector, uint256(1));
        (changed[3][0], changed[3][1]) = (x[1], x[0]);
        changed[4] = _hits(3);
        changed[4][1].value = 0.1 ether;
        changed[5] = _hits(1);
        for (uint256 i; i < changed.length; ++i) {
            _refuses(w, abi.encode(changed[i]), auth, NOT_AUTHORIZED);
        }
        _refuses(w, bytes.concat(abi.encode(x), hex"00"), auth, bytes4(0));
        _runs(w, abi.encode(x), auth);
    }

    /// Pending, expired, not yet valid, revoked and unlinked admin sessions sign nothing.
    function test_signersOutsideTheirWindowAreRefused() public {
        bytes32 alice = _identity(X, ALICE);
        _link(w, GITHUB, BOB, w, _key(BOB_PK), _admin());
        _root(w, address(validator), abi.encodeCall(IIdentityValidator.unlink, (_identity(GITHUB, BOB))));

        _addByProof(relayer, X, ALICE, w, _key(ALICE2_PK), _admin());
        IIdentityValidator.Policy memory p = _admin();
        p.validUntil = uint48(_now() + 1 hours);
        vm.startPrank(w);
        validator.addSession(alice, _key(CAROL_PK), p);
        p.validUntil = 0;
        p.validAfter = uint48(_now() + 3 hours);
        validator.addSession(alice, _key(MALLORY_PK), p);
        validator.addSession(alice, _key(OTHER_PK), _admin());
        validator.revokeSession(_key(OTHER_PK));
        vm.stopPrank();
        vm.warp(_now() + 2 hours);

        bytes memory hit = _one(_hitX());
        uint256[5] memory pks = [ALICE2_PK, CAROL_PK, MALLORY_PK, OTHER_PK, BOB_PK];
        for (uint256 i; i < pks.length; ++i) {
            _refuses(w, hit, _direct(w, address(validator), _pks(pks[i]), hit, false), NOT_AUTHORIZED);
        }
        _runs(w, hit, _direct(w, address(validator), _pks(ALICE_PK), hit, false));
    }

    function test_theEntryPointRefusesNonZeroSelectorsInValidation() public {
        bytes memory hits = _one(_hitX());
        bytes32 unknown = MODE_BATCH | bytes32(uint256(0xdeadbeef) << 176);
        _refused(
            _signed(_op(w, 0, abi.encodeCall(IERC7579Execution.execute, (unknown, hits))), _pks(ALICE_PK)),
            "an unknown selector through the EntryPoint"
        );
        bytes memory data = _data(hits, _signedFor(AUTHORIZED_MODE, hits));
        _refused(
            _signed(_op(w, 0, abi.encodeCall(IERC7579Execution.execute, (AUTHORIZED_MODE, data))), _pks(ALICE_PK)),
            "AUTHORIZED_MODE through the EntryPoint"
        );
        _handle(_signed(_op(w, 0, abi.encodeCall(IERC7579Execution.execute, (MODE_BATCH, hits))), _pks(ALICE_PK)));
        assertEq(target.calls(), 1, "the default selector");
    }

    /// The default mode takes neither a stranger nor the wallet itself, outside any batch.
    function test_onlyTheEntryPointCallsTheDefaultMode() public {
        address[2] memory callers = [mallory, w];
        bytes32[2] memory modes = [MODE_BATCH, MODE_SINGLE];
        bytes memory single = abi.encodePacked(address(target), uint256(0), abi.encodeCall(CallTarget.hit, ()));
        bytes[2] memory calls = [_one(_hitX()), single];
        for (uint256 i; i < callers.length; ++i) {
            for (uint256 j; j < modes.length; ++j) {
                vm.prank(callers[i]);
                vm.expectRevert(abi.encodeWithSelector(OzAccount.AccountUnauthorized.selector, callers[i]));
                IERC7579Execution(w).execute(modes[j], calls[j]);
            }
        }
        assertEq(target.calls(), 0, "a call ran");
    }

    /// No executor module exists: `executeFromExecutor` has no caller.
    function test_executeFromExecutorAlwaysReverts() public {
        assertFalse(IWebWallet(w).supportsModule(2), "executor modules supported");
        address[4] memory callers = [mallory, EP, w, address(validator)];
        bytes memory single = abi.encodePacked(address(target), uint256(0), abi.encodeCall(CallTarget.hit, ()));
        for (uint256 i; i < callers.length; ++i) {
            vm.prank(callers[i]);
            vm.expectRevert();
            IERC7579Execution(w).executeFromExecutor(MODE_SINGLE, single);
        }
    }

    /// The deadline's own second still runs.
    function test_theDeadlineSecondRuns() public {
        bytes memory hit = _one(_hitX());
        uint48 at = uint48(_now());
        _runs(w, hit, _alice(_execDigest(w, AUTHORIZED_MODE, hit, at, _nonce(w, address(validator)), at), at, at));
    }

    /// The nonce is spent before the calls run: the batch sees the next one.
    function test_theBatchSeesItsNonceSpent() public {
        NonceProbe probe = new NonceProbe();
        uint256 n = _nonce(w, address(validator));
        bytes memory look = abi.encodeCall(NonceProbe.look, (EP, w, _nonceKey(address(validator))));
        bytes memory calls = _then(_x(address(probe), 0, look));
        _runs(w, calls, _aliceFor(w, calls, n));
        assertEq(probe.seen(), n + 1, "the batch saw its nonce unspent");
    }

    /// A validator that reverts answers the ERC-1271 failure value: neither success nor a revert.
    function test_aRevertingValidatorAnswersFailure() public {
        bytes32 probe = 0x7739773977397739773977397739773977397739773977397739773977397739;
        assertEq(IWebWallet(w).isValidSignature(probe, ""), bytes4(0x77390001), "control: the ERC-7739 probe");
        vm.mockCallRevert(
            address(validator), abi.encodeWithSelector(IERC7579Validator.isValidSignatureWithSender.selector), ""
        );
        assertEq(IWebWallet(w).isValidSignature(probe, ""), bytes4(0xffffffff), "a reverting validator");
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Test.sol";
import {Execution} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Base64} from "@openzeppelin/contracts/utils/Base64.sol";
import {P256} from "@openzeppelin/contracts/utils/cryptography/P256.sol";
import {WebAuthn} from "@openzeppelin/contracts/utils/cryptography/WebAuthn.sol";
import {ERC7913P256Verifier} from "@openzeppelin/contracts/utils/cryptography/verifiers/ERC7913P256Verifier.sol";
import {
    ERC7913WebAuthnVerifier
} from "@openzeppelin/contracts/utils/cryptography/verifiers/ERC7913WebAuthnVerifier.sol";

import {NATIVE_TOKEN} from "../../common/Constants.sol";
import {TestERC20} from "../../escrow/test/EscrowMocks.sol";
import {AUTHORIZED_MODE, IIdentityAdmin, IWalletCore, IWebWallet} from "../IWebWallet.sol";
import {WalletSuite} from "./WalletSuite.sol";

/// @notice What a relayer's simulation of a batch with dummy signatures leaves out: each further signer's check in
///         `_verify`, by key kind, the run after a valid `_verify`, and the rules check below quorum: a refund's, and
///         each further call's.
contract WalletVerifyGasTest is WalletSuite {
    uint256 internal constant P256_PK = 0x9A55;
    /// Etched before the test's transaction, so cold in it, and at fixed addresses, so no deployer's nonce moves.
    address internal p256 = makeAddr("P-256 verifier");
    address internal webAuthn = makeAddr("WebAuthn verifier");

    function setUp() public override {
        super.setUp();
        vm.etch(p256, type(ERC7913P256Verifier).runtimeCode);
        vm.etch(webAuthn, type(ERC7913WebAuthnVerifier).runtimeCode);
    }

    /// Alice's wallet, at quorum alone, signs one `hit()` with a further signer of each kind, its verifier cold.
    /// `verify(tail)` is a run Alice signs less one where another key signs for her: from her `_signedBy`'s return
    /// to `execute`'s, less from it to the `ExecutionNotSigned` revert. `verify(kind)` is the same difference with
    /// the kind's valid signature second, less `verify(tail)`: its iteration of `_verify`'s second loop.
    function test_verify() public {
        (uint256 qx, uint256 qy) = vm.publicKeyP256(P256_PK);
        bytes[3] memory keys = [_key(NEW_PK), abi.encodePacked(p256, qx, qy), abi.encodePacked(webAuthn, qx, qy)];
        address w = _claim();
        for (uint256 i; i < keys.length; ++i) {
            _addSession(w, _identity(X, ALICE), keys[i], _admin());
        }
        vm.warp(_now() + 1);
        bytes memory calls = _one(_hitX());
        bytes32 h = _execDigest(w, AUTHORIZED_MODE, calls, uint48(_now()), _nonce(w), uint48(_now() + 1 hours));

        IWalletCore.SessionSignature memory none;
        uint256 tail = _signedLessUnsigned(w, calls, h, none);
        vm.snapshotValue("wallet-verify", "verify(tail)", tail);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(NEW_PK, h);
        _further("verify(ECDSA)", w, calls, h, keys[0], abi.encodePacked(r, s, v), tail);
        (r, s) = _signP256(h);
        _further("verify(P-256)", w, calls, h, keys[1], abi.encodePacked(r, s), tail);
        bytes memory authenticatorData =
            abi.encodePacked(bytes32(0), WebAuthn.AUTH_DATA_FLAGS_UP | WebAuthn.AUTH_DATA_FLAGS_UV, bytes4(0));
        string memory clientDataJSON =
            string.concat('{"type":"webauthn.get","challenge":"', Base64.encodeURL(abi.encodePacked(h)), '"}');
        (r, s) = _signP256(sha256(abi.encodePacked(authenticatorData, sha256(bytes(clientDataJSON)))));
        _further(
            "verify(WebAuthn)", w, calls, h, keys[2], abi.encode(r, s, 23, 1, authenticatorData, clientDataJSON), tail
        );
    }

    /// forge-config: gas.isolate = true
    function test_rulesOfARefund() public {
        vm.snapshotValue("wallet-verify", "rules(refund)", _rules(false));
    }

    /// forge-config: gas.isolate = true
    function test_rulesPerCall() public {
        uint256 refund = _rules(false);
        vm.snapshotValue("wallet-verify", "rules(per call)", _rules(true) - refund);
    }

    /// `name`: the runs with `key`'s `signature` second, signed less unsigned, less `tail`.
    function _further(
        string memory name,
        address w,
        bytes memory calls,
        bytes32 h,
        bytes memory key,
        bytes memory signature,
        uint256 tail
    ) internal {
        IWalletCore.SessionSignature memory more = IWalletCore.SessionSignature({key: key, signature: signature});
        uint256 checked = _signedLessUnsigned(w, calls, h, more);
        vm.snapshotValue("wallet-verify", name, checked - tail);
    }

    /// The run Alice signs less the run another key signs for her.
    function _signedLessUnsigned(address w, bytes memory calls, bytes32 h, IWalletCore.SessionSignature memory more)
        internal
        returns (uint256)
    {
        return _gas(w, calls, h, ALICE_PK, more) - _gas(w, calls, h, BOT_PK, more);
    }

    /// The gas `w` spends on `calls` with `pk`'s signature over `h` in Alice's name, then `more` unless its key is
    /// empty, from one state: a run's writes and accesses are reverted after it.
    function _gas(address w, bytes memory calls, bytes32 h, uint256 pk, IWalletCore.SessionSignature memory more)
        internal
        returns (uint256 used)
    {
        IWalletCore.SessionSignature[] memory sigs = new IWalletCore.SessionSignature[](more.key.length == 0 ? 1 : 2);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, h);
        sigs[0] = IWalletCore.SessionSignature({key: _key(ALICE_PK), signature: abi.encodePacked(r, s, v)});
        if (sigs.length == 2) sigs[1] = more;
        IWalletCore.Authorization memory a = abi.decode(_wrap(sigs), (IWalletCore.Authorization));
        bytes memory input =
            abi.encodeCall(IWalletCore.execute, (AUTHORIZED_MODE, _data(calls, _env(a, uint48(_now() + 1 hours)))));
        uint256 state = vm.snapshotState();
        bool ok;
        bytes4 err;
        vm.prank(relayer);
        used = gasleft();
        // No return data copied before the second read: the test's memory grows from run to run.
        assembly ("memory-safe") {
            ok := call(gas(), w, 0, add(input, 0x20), mload(input), 0, 0)
        }
        used -= gasleft();
        assembly ("memory-safe") {
            if gt(returndatasize(), 3) {
                returndatacopy(0, 0, 4)
                err := mload(0)
            }
        }
        if (pk == ALICE_PK) assertTrue(ok, "a signed run");
        else assertEq(err, NOT_SIGNED, "an unsigned run");
        vm.revertToState(state);
    }

    function _signP256(bytes32 h) internal pure returns (bytes32 r, bytes32 s) {
        (r, s) = vm.signP256(P256_PK, h);
        if (uint256(s) > P256.N / 2) s = bytes32(P256.N - uint256(s));
    }

    /// The rules check of a batch that refunds the relayer, after an ERC-20 `transfer` when `transfer`: Bot's session
    /// below quorum less Alice's admin at quorum, from the same state. Each call has a depth-4 proof, in a 16-leaf scope, and charges its
    /// allowance's first spend in a fresh period, from cold slots.
    function _rules(bool transfer) internal returns (uint256 gas) {
        uint256 fresh = vm.snapshotState();
        TestERC20 token = new TestERC20();
        bytes32[] memory leaves = new bytes32[](16);
        for (uint256 i = 4; i < 16; ++i) {
            leaves[i] = _leaf(address(uint160(i)), bytes4(0), 0);
        }
        leaves[0] = _hitScope();
        leaves[1] = _leaf(relayer, bytes4(0), 1 ether);
        leaves[2] = _leaf(address(token), IERC20.transfer.selector, 0);
        leaves[3] = _leaf(address(token), IERC20.approve.selector, 0);
        IIdentityAdmin.Policy memory p;
        (p.rules.scopeRoot,) = _tree(leaves, 0);
        p.rules.allowances = new IIdentityAdmin.Allowance[](2);
        (address a, address b) =
            address(token) < NATIVE_TOKEN ? (address(token), NATIVE_TOKEN) : (NATIVE_TOKEN, address(token));
        p.rules.allowances[0] = IIdentityAdmin.Allowance({token: a, amount: 1 ether, period: 1 days});
        p.rules.allowances[1] = IIdentityAdmin.Allowance({token: b, amount: 1 ether, period: 1 days});
        address w = _claim();
        _addSession(w, _identity(X, ALICE), _key(BOT_PK), p);
        vm.deal(w, 1 ether);
        token.mint(w, 1 ether);
        vm.warp(_now() + 1);

        uint256 n = transfer ? 2 : 1;
        Execution[] memory x = new Execution[](n);
        IWalletCore.CallProof[] memory proofs = new IWalletCore.CallProof[](n);
        if (transfer) {
            x[0] = _x(address(token), 0, abi.encodeCall(IERC20.transfer, (relayer, 1)));
            (, proofs[0].proof) = _tree(leaves, 2);
        }
        x[n - 1] = _x(relayer, 0.01 ether, "");
        (, proofs[n - 1].proof) = _tree(leaves, 1);
        proofs[n - 1].maxValue = 1 ether;
        bytes memory calls = abi.encode(x);

        uint256 state = vm.snapshotState();
        uint256 quorum = _batchGas(w, ALICE_PK, false, calls, new IWalletCore.CallProof[](0));
        vm.revertToState(state);
        gas = _batchGas(w, BOT_PK, true, calls, proofs) - quorum;
        IIdentityAdmin.AllowanceState memory spent = IWebWallet(w).allowanceOf(_key(BOT_PK), NATIVE_TOKEN);
        assertTrue(spent.spent == 0.01 ether && spent.periodStart != 0, "the refund's first spend");
        if (transfer) assertEq(IWebWallet(w).allowanceOf(_key(BOT_PK), address(token)).spent, 1, "the transfer");
        vm.revertToState(fresh);
    }

    /// A whole transaction's gas used, less the refund.
    function _batchGas(address w, uint256 pk, bool below, bytes memory calls, IWalletCore.CallProof[] memory proofs)
        internal
        returns (uint256)
    {
        bytes memory data = _data(calls, _directAt(w, _pks(pk), calls, _nonce(w), uint48(_now()), below, proofs));
        uint256 balance = relayer.balance;
        vm.prank(relayer, relayer);
        IWebWallet(w).execute(AUTHORIZED_MODE, data);
        Vm.Gas memory used = vm.lastFrameGas();
        assertEq(relayer.balance, balance + 0.01 ether, "the refund");
        // forge-lint: disable-next-line(unsafe-typecast)
        return used.gasTotalUsed - uint64(used.gasRefunded);
    }
}

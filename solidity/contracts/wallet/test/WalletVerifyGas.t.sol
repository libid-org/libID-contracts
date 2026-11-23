// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Test.sol";
import {Execution} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Base64} from "@openzeppelin/contracts/utils/Base64.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {P256} from "@openzeppelin/contracts/utils/cryptography/P256.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {WebAuthn} from "@openzeppelin/contracts/utils/cryptography/WebAuthn.sol";
import {ERC7913P256Verifier} from "@openzeppelin/contracts/utils/cryptography/verifiers/ERC7913P256Verifier.sol";
import {
    ERC7913WebAuthnVerifier
} from "@openzeppelin/contracts/utils/cryptography/verifiers/ERC7913WebAuthnVerifier.sol";

import {NATIVE_TOKEN} from "../../common/Constants.sol";
import {TestERC20} from "../../escrow/test/EscrowMocks.sol";
import {AUTHORIZED_MODE, IIdentityAdmin, IWalletCore, IWebWallet} from "../IWebWallet.sol";
import {WalletSuite} from "./WalletSuite.sol";

/// @notice What a relayer's simulation of a batch with dummy signatures leaves out: each signer's signature check,
///         by key kind, and the rules check below quorum: a refund's, and each further call's.
contract WalletVerifyGasTest is WalletSuite {
    uint256 internal constant P256_PK = 0x9A55;
    bytes32 internal constant HASH = keccak256("a digest");

    /// The check `WebWallet._signedBy` runs for one valid signature, its ERC-7913 verifier cold.
    function test_verify() public {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PK, HASH);
        bytes memory signature = abi.encodePacked(r, s, v);
        vm.startSnapshotGas("wallet-verify", "verify(ECDSA)");
        (address signer, ECDSA.RecoverError err,) = ECDSA.tryRecover(HASH, signature);
        vm.stopSnapshotGas();
        assertTrue(err == ECDSA.RecoverError.NoError && signer == vm.addr(ALICE_PK), "ECDSA");

        (r, s) = _signP256(HASH);
        _measure("verify(P-256)", address(new ERC7913P256Verifier()), abi.encodePacked(r, s));

        bytes memory authenticatorData =
            abi.encodePacked(bytes32(0), WebAuthn.AUTH_DATA_FLAGS_UP | WebAuthn.AUTH_DATA_FLAGS_UV, bytes4(0));
        string memory clientDataJSON =
            string.concat('{"type":"webauthn.get","challenge":"', Base64.encodeURL(abi.encodePacked(HASH)), '"}');
        (r, s) = _signP256(sha256(abi.encodePacked(authenticatorData, sha256(bytes(clientDataJSON)))));
        _measure(
            "verify(WebAuthn)",
            address(new ERC7913WebAuthnVerifier()),
            abi.encode(r, s, 23, 1, authenticatorData, clientDataJSON)
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

    /// `verifier`'s P-256 key checks `signature`.
    function _measure(string memory name, address verifier, bytes memory signature) internal {
        (uint256 qx, uint256 qy) = vm.publicKeyP256(P256_PK);
        bytes memory key = abi.encodePacked(verifier, qx, qy);
        vm.cool(verifier);
        vm.startSnapshotGas("wallet-verify", name);
        bool valid = SignatureChecker.isValidSignatureNow(key, HASH, signature);
        vm.stopSnapshotGas();
        assertTrue(valid, name);
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

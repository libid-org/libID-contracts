// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Test.sol";
import {Execution} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {Base64} from "@openzeppelin/contracts/utils/Base64.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {P256} from "@openzeppelin/contracts/utils/cryptography/P256.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {WebAuthn} from "@openzeppelin/contracts/utils/cryptography/WebAuthn.sol";
import {ERC7913P256Verifier} from "@openzeppelin/contracts/utils/cryptography/verifiers/ERC7913P256Verifier.sol";
import {
    ERC7913WebAuthnVerifier
} from "@openzeppelin/contracts/utils/cryptography/verifiers/ERC7913WebAuthnVerifier.sol";

import {AUTHORIZED_MODE, IWebWallet} from "../IWebWallet.sol";
import {WalletSuite} from "./WalletSuite.sol";

/// @notice What a relayer's simulation of a batch with dummy signatures leaves out: each signer's signature check,
///         by key kind, and the rules check below quorum, by number of calls.
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
    function test_rulesOfOneCall() public {
        _measureRules(1, "rules(1 call)");
    }

    /// forge-config: gas.isolate = true
    function test_rulesOfThreeCalls() public {
        _measureRules(3, "rules(3 calls)");
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

    /// The same `n` hits, by Bot's session below quorum less by Alice's admin at quorum, from the same state: the
    /// rules check, and the call proofs it reads.
    function _measureRules(uint256 n, string memory name) internal {
        address w = _claim();
        _addSession(w, _identity(X, ALICE), _key(BOT_PK), _hitGas());
        vm.warp(_now() + 1);
        uint256 state = vm.snapshotState();
        uint256 quorum = _batchGas(w, ALICE_PK, false, n);
        vm.revertToState(state);
        uint256 below = _batchGas(w, BOT_PK, true, n);
        vm.snapshotValue("wallet-verify", name, below - quorum);
    }

    /// A whole transaction's gas used, less the refund.
    function _batchGas(address w, uint256 pk, bool below, uint256 n) internal returns (uint256) {
        bytes memory data = _batch(w, pk, below, n);
        vm.prank(relayer, relayer);
        IWebWallet(w).execute(AUTHORIZED_MODE, data);
        Vm.Gas memory used = vm.lastFrameGas();
        assertEq(target.calls(), n, "hit() did not run");
        // forge-lint: disable-next-line(unsafe-typecast)
        return used.gasTotalUsed - uint64(used.gasRefunded);
    }

    /// `pk` signs `n` hits for `w`.
    function _batch(address w, uint256 pk, bool below, uint256 n) internal view returns (bytes memory) {
        bytes memory calls = _hits(n);
        return _data(calls, _directAt(w, _pks(pk), calls, _nonce(w), uint48(_now()), below, _hitProofs(below ? n : 0)));
    }

    function _hits(uint256 n) internal view returns (bytes memory) {
        Execution[] memory hits = new Execution[](n);
        for (uint256 i; i < n; ++i) {
            hits[i] = _hitX();
        }
        return abi.encode(hits);
    }
}

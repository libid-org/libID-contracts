// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/IERC4337.sol";
import {Base64} from "@openzeppelin/contracts/utils/Base64.sol";
import {P256} from "@openzeppelin/contracts/utils/cryptography/P256.sol";
import {WebAuthn} from "@openzeppelin/contracts/utils/cryptography/WebAuthn.sol";
import {
    ERC7913WebAuthnVerifier
} from "@openzeppelin/contracts/utils/cryptography/verifiers/ERC7913WebAuthnVerifier.sol";

import {IIdentityValidator} from "../IIdentityValidator.sol";
import {IWebWallet} from "../IWebWallet.sol";
import {IUserOpHash, WalletTestBase} from "./WalletTestBase.sol";

/// @notice D21: a WebAuthn P-256 key as an ERC-7913 admin session.
contract PasskeyTest is WalletTestBase {
    uint256 internal constant PASSKEY_PK = 0x9A55;
    bytes internal passkey;

    function setUp() public override {
        super.setUp();
        (uint256 qx, uint256 qy) = vm.publicKeyP256(PASSKEY_PK);
        passkey = abi.encodePacked(address(new ERC7913WebAuthnVerifier()), qx, qy);
    }

    /// A WebAuthn assertion over `h`, with user presence and verification, as a session signature list.
    function _passkeySigs(bytes32 h) internal view returns (bytes memory) {
        bytes memory authenticatorData =
            abi.encodePacked(bytes32(0), WebAuthn.AUTH_DATA_FLAGS_UP | WebAuthn.AUTH_DATA_FLAGS_UV, bytes4(0));
        string memory clientDataJSON =
            string.concat('{"type":"webauthn.get","challenge":"', Base64.encodeURL(abi.encodePacked(h)), '"}');
        (bytes32 r, bytes32 s) =
            vm.signP256(PASSKEY_PK, sha256(abi.encodePacked(authenticatorData, sha256(bytes(clientDataJSON)))));
        if (uint256(s) > P256.N / 2) s = bytes32(P256.N - uint256(s));
        // The verifier reads WebAuthnAuth's fields as a bare tuple, with no leading offset word.
        bytes memory auth = abi.encode(r, s, 23, 1, authenticatorData, clientDataJSON);
        IIdentityValidator.SessionSignature[] memory sigs = new IIdentityValidator.SessionSignature[](1);
        sigs[0] = IIdentityValidator.SessionSignature({key: passkey, signature: auth});
        return _wrap(sigs);
    }

    function _withPasskey() internal returns (address w) {
        w = _claim();
        vm.prank(w);
        validator.addSession(_identity(X, ALICE), passkey, _admin());
    }

    /// A passkey-signed `addSession` is an ordinary admin operation: active at once, no proof.
    function test_passkeyAdminAddsASessionThroughTheEntryPoint() public {
        address w = _withPasskey();
        bytes memory callData = _exec(
            address(validator),
            abi.encodeCall(IIdentityValidator.addSession, (_identity(X, ALICE), _key(ALICE2_PK), _admin()))
        );
        PackedUserOperation memory op = _op(w, 0, callData);
        op.signature = _passkeySigs(IUserOpHash(EP).getUserOpHash(op));
        _handle(op);
        IIdentityValidator.Session memory added = validator.sessionOf(w, _key(ALICE2_PK));
        assertEq(added.identity, _identity(X, ALICE), "no session added");
        assertEq(added.activeAt, 0, "the new session waits");

        // The validator's own answer, and its cost with OZ's Solidity P-256 (no precompile under cancun).
        bytes32 h = keccak256("user op");
        op.signature = _passkeySigs(h);
        vm.prank(w);
        uint256 before = gasleft();
        uint256 result = validator.validateUserOp(op, h);
        emit log_named_uint("validateUserOp gas, passkey", before - gasleft());
        assertEq(result, 0, "passkey refused");
        op.signature = _passkeySigs(keccak256("another op"));
        vm.prank(w);
        assertEq(validator.validateUserOp(op, h), 1, "a signature over another hash passed");
    }

    function test_passkeySignsErc1271() public {
        address w = _withPasskey();
        vm.warp(_now() + 1);
        bytes32 h = keccak256("a message");
        bytes memory sig = abi.encodePacked(address(validator), _passkeySigs(_wrapped(w, h)));
        assertEq(IWebWallet(w).isValidSignature(h, sig), bytes4(0x1626ba7e), "passkey ERC-1271 refused");
        sig = abi.encodePacked(address(validator), _passkeySigs(h));
        assertEq(IWebWallet(w).isValidSignature(h, sig), bytes4(0xffffffff), "unwrapped hash accepted");
    }
}

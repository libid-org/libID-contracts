// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IIdentityValidator} from "../IIdentityValidator.sol";
import {IWebWallet} from "../IWebWallet.sol";
import {WalletTestBase} from "./WalletTestBase.sol";

/// A session added by proof to a wallet that had one acts only with signers that reach the threshold.
contract QuorumByProofTest is WalletTestBase {
    /// An admin policy whose rules allow `hit()` below quorum.
    function _adminHitOnly() internal view returns (IIdentityValidator.Policy memory p) {
        p = _hitOnly();
        p.admin = true;
    }

    /// Alice's wallet, her session allowed `hit()` below quorum, with Bob's GitHub identity linked
    /// and a threshold of 2.
    function _twoPlatforms() internal returns (address w) {
        w = _claimWith(_adminHitOnly());
        _link(w, GITHUB, BOB, w, "", _admin());
        _root(w, address(validator), abi.encodeCall(IIdentityValidator.setThreshold, (2)));
    }

    function _isValid1271By(address w, bytes32 h, uint256[] memory pks) internal view returns (bool) {
        bytes memory sig = abi.encodePacked(address(validator), _sigs(pks, _wrapped(w, h)));
        return IWebWallet(w).isValidSignature(h, sig) == bytes4(0x1626ba7e);
    }

    function test_aProofSessionAloneIsBelowTheThreshold() public {
        address w = _twoPlatforms();
        _addByProof(mallory, GITHUB, BOB, w, _key(BOB_PK), _adminHitOnly());
        vm.warp(_now() + 48 hours + 1);
        assertTrue(validator.sessionOf(w, _key(BOB_PK)).byProof, "not marked");
        assertFalse(validator.sessionOf(w, _key(ALICE_PK)).byProof, "the genesis session is marked");

        _refused(_signed(_op(w, 0, _hit()), _pks(BOB_PK)), "an ordinary call by one proof session");
        _refused(_signedWith(_op(w, 0, _hit()), _pks(BOB_PK), _hitProofs(1)), "a proof session within its rules");
        bytes32 h = keccak256("message");
        assertFalse(
            _isValid1271(w, h, BOB_PK, _belowQuorum(_wrapped(w, h), 0, _key(BOB_PK))), "ERC-1271 by one proof session"
        );

        // The genesis session is not marked: it still calls alone, within its rules.
        _handle(_signedWith(_op(w, 0, _hit()), _pks(ALICE_PK), _hitProofs(1)));
        assertEq(target.calls(), 1, "the genesis session's call");

        _addByProof(mallory, X, ALICE, w, _key(ALICE2_PK), _admin());
        vm.warp(_now() + 48 hours + 1);
        _handle(_signed(_op(w, 1, _hit()), _pks(BOB_PK, ALICE2_PK)));
        assertEq(target.calls(), 2, "two proof sessions reach the threshold");
        assertTrue(_isValid1271By(w, h, _pks(BOB_PK, ALICE2_PK)), "ERC-1271 by two proof sessions");
    }

    function test_atThresholdOneAProofSessionHasFullControl() public {
        address w = _claim();
        _addByProof(mallory, X, ALICE, w, _key(ALICE2_PK), _admin());
        vm.warp(_now() + 48 hours + 1);

        _handle(_signed(_op(w, 0, _hit()), _pks(ALICE2_PK)));
        assertEq(target.calls(), 1, "an ordinary call");
        bytes memory raise = _exec(address(validator), abi.encodeCall(IIdentityValidator.setRecoveryDelay, (72 hours)));
        _handle(_signed(_op(w, 1, raise), _pks(ALICE2_PK)));
        assertEq(validator.recoveryDelay(w), 72 hours, "an admin operation");
        bytes32 h = keccak256("message");
        assertTrue(_isValid1271(w, h, ALICE2_PK, _wrapped(w, h)), "ERC-1271");
    }
}

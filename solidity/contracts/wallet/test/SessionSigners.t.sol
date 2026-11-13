// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/IERC4337.sol";

import {IIdentityValidator} from "../IIdentityValidator.sol";
import {IWebWallet} from "../IWebWallet.sol";
import {WalletTestBase} from "./WalletTestBase.sol";

/// Below quorum, the first signer's `signers` is how many distinct platforms sign.
contract SessionSignersTest is WalletTestBase {
    bytes32 internal constant APP = keccak256("app A");
    address internal w;

    /// Alice's wallet with Bob's GitHub identity linked and an app session of each.
    function setUp() public override {
        super.setUp();
        w = _claim();
        _link(w, GITHUB, BOB, w, "", _admin());
        vm.prank(w);
        validator.addSession(_identity(GITHUB, BOB), _key(BOB_PK), _app());
    }

    /// An app session of Alice's allowed `hit()` and app `APP`, needing `signers`.
    function _governing(uint8 signers) internal {
        IIdentityValidator.Policy memory p = _hitOnly();
        p.signers = signers;
        p.rules.domainsRoot = _domainLeaf(APP);
        vm.prank(w);
        validator.addSession(_identity(X, ALICE), _key(APP_PK), p);
    }

    function _hitBy(uint64 seq, uint256[] memory pks) internal view returns (PackedUserOperation memory) {
        return _signedWith(_op(w, seq, _hit()), pks, _hitProofs(1));
    }

    function _pks(uint256 a, uint256 b, uint256 c) internal pure returns (uint256[] memory r) {
        r = new uint256[](3);
        (r[0], r[1], r[2]) = (a, b, c);
    }

    function test_twoSignersNeedTwoPlatforms() public {
        _governing(2);
        assertEq(validator.sessionOf(w, _key(APP_PK)).signers, 2, "signers");
        _refused(_hitBy(0, _pks(APP_PK)), "one signer of two");
        _refused(_hitBy(0, _pks(BOB_PK, APP_PK)), "Bob's session governs, needing one");
        // Bob's app session has no scope: Alice's rules govern.
        _handle(_hitBy(0, _pks(APP_PK, BOB_PK)));
        assertEq(target.calls(), 1, "two platforms");
    }

    function test_aSecondSignerOnTheSamePlatformDoesNotCount() public {
        _governing(2);
        vm.prank(w);
        validator.addSession(_identity(X, ALICE), _key(ALICE2_PK), _app());
        _refused(_hitBy(0, _pks(APP_PK, ALICE2_PK)), "two X sessions");
        _refused(_hitBy(0, _pks(APP_PK, ALICE2_PK, BOB_PK)), "three signers for two");
    }

    function test_aSessionByProofNeverCounts() public {
        _governing(2);
        _addByProof(mallory, GITHUB, BOB, w, _key(MALLORY_PK), _app());
        vm.warp(_now() + 48 hours + 1);
        assertTrue(validator.sessionOf(w, _key(MALLORY_PK)).byProof, "not by proof");
        _refused(_hitBy(0, _pks(APP_PK, MALLORY_PK)), "a GitHub session by proof");
        _handle(_hitBy(0, _pks(APP_PK, BOB_PK)));
        assertEq(target.calls(), 1, "control");
    }

    function test_oneSignerActsAlone() public {
        for (uint8 signers; signers <= 1; ++signers) {
            uint256 state = vm.snapshotState();
            _governing(signers);
            _refused(_hitBy(0, _pks(APP_PK, BOB_PK)), "a second signer");
            _handle(_hitBy(0, _pks(APP_PK)));
            assertEq(target.calls(), 1, "alone");
            vm.revertToStateAndDelete(state);
        }
    }

    function test_erc1271TakesTheSameSigners() public {
        _governing(2);
        vm.warp(_now() + 1);
        (bytes32 h, bytes memory sig) = _typedSigBy(w, _pks(APP_PK), APP, new bytes32[](0));
        assertEq(IWebWallet(w).isValidSignature(h, sig), bytes4(0xffffffff), "one signer of two");
        (h, sig) = _typedSigBy(w, _pks(APP_PK, BOB_PK), APP, new bytes32[](0));
        assertEq(IWebWallet(w).isValidSignature(h, sig), bytes4(0x1626ba7e), "two platforms");
    }
}

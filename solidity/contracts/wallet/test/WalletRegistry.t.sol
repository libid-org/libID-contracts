// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IPlatformVerifier} from "../../ceremony/IPlatformVerifier.sol";
import {StubPlatformVerifier} from "../../identity/test/StubPlatformVerifier.sol";
import {IIdentityValidator} from "../IIdentityValidator.sol";
import {IWalletRegistry} from "../IWalletRegistry.sol";
import {WalletTestBase} from "./WalletTestBase.sol";

/// @notice The two `libid.webwallet.*` domains: encoding, chain, submitter, spending, and the 48 h rule.
contract WalletRegistryTest is WalletTestBase {
    function test_domainsAreTheSpecStrings() public view {
        assertEq(registry.LINK_IDENTITY_DOMAIN(), LINK);
        assertEq(registry.ADD_SESSION_DOMAIN(), ADD);
    }

    function test_genesisLinkByAnyoneCarriesTheFirstSession() public {
        vm.prank(relayer);
        address w = factory.createWallet(X, ALICE, 0);
        bytes memory payload = _payload(X, ALICE, LINK, _txData(w, _key(ALICE_PK), _ph(_admin())));
        vm.expectEmit(true, true, true, false, address(registry));
        emit IWalletRegistry.IdentityLinked(w, X, ALICE, bytes32(0));
        vm.prank(mallory);
        registry.linkIdentity(X, V1, payload, _admin());

        bytes32 alice = _identity(X, ALICE);
        assertTrue(validator.isLinked(w, alice), "not linked");
        IIdentityValidator.Session memory s = validator.sessionOf(w, _key(ALICE_PK));
        assertEq(s.identity, alice, "session identity");
        assertTrue(s.policy.admin, "first session is not admin");
        assertLe(s.activeAt, _now(), "the first session waits");
        assertTrue(validator.hadSession(w), "flag not set");
        assertTrue(registry.digestSpent(xStub.lastDigest()), "digest not spent");
    }

    function test_linkOnlyAddsNoSession() public {
        address w = factory.createWallet(X, ALICE, 0);
        _link(relayer, X, ALICE, w, "", _admin());
        assertTrue(validator.isLinked(w, _identity(X, ALICE)), "not linked");
        assertFalse(validator.hadSession(w), "a session was added");
    }

    function test_otherIdentitiesLinkOnlyFromTheWallet() public {
        address w = _claim();
        bytes memory payload = _payload(GITHUB, BOB, LINK, _txData(w, "", bytes32(0)));
        vm.prank(mallory);
        vm.expectRevert(abi.encodeWithSelector(IWalletRegistry.NotWallet.selector, w, mallory));
        registry.linkIdentity(GITHUB, V1, payload, _admin());

        vm.prank(w);
        registry.linkIdentity(GITHUB, V1, payload, _admin());
        assertTrue(validator.isLinked(w, _identity(GITHUB, BOB)), "bob not linked");
    }

    /// R5: a phished link to another wallet does not keep the canonical wallet from linking.
    function test_phishedLinkDoesNotSquat() public {
        address canonical = factory.walletAddress(X, ALICE, 0);
        address theirs = factory.createWallet(X, MALLORY, 0);
        _link(theirs, X, ALICE, theirs, "", _admin());
        assertTrue(validator.isLinked(theirs, _identity(X, ALICE)), "the phished link failed");

        address w = _claim();
        assertEq(w, canonical, "canonical address moved");
        assertTrue(validator.isLinked(w, _identity(X, ALICE)), "canonical wallet could not link");
    }

    function test_aDigestIsSpentOnce() public {
        address w = factory.createWallet(X, ALICE, 0);
        bytes memory payload = _payload(X, ALICE, LINK, _txData(w, "", bytes32(0)));
        registry.linkIdentity(X, V1, payload, _admin());
        bytes32 digest = xStub.lastDigest();
        vm.expectRevert(abi.encodeWithSelector(IWalletRegistry.DigestAlreadySpent.selector, digest));
        registry.linkIdentity(X, V1, payload, _admin());
    }

    function test_foreignDomainsAreRefused() public {
        address w = _claim();
        bytes memory data = _txData(w, _key(ALICE2_PK), _ph(_admin()));
        bytes32[3] memory domains = [ADD, BIND, keccak256("libid.operations")];
        for (uint256 i; i < domains.length; ++i) {
            bytes memory payload = _payload(X, ALICE, domains[i], data);
            vm.expectRevert(abi.encodeWithSelector(IWalletRegistry.ForeignOperationDomain.selector, domains[i]));
            registry.linkIdentity(X, V1, payload, _admin());
        }
        bytes memory linkPayload = _payload(X, ALICE, LINK, data);
        vm.expectRevert(abi.encodeWithSelector(IWalletRegistry.ForeignOperationDomain.selector, LINK));
        registry.addSessionByProof(X, V1, linkPayload, _admin());
    }

    function test_crossChainReplayIsRefused() public {
        address w = factory.createWallet(X, ALICE, 0);
        bytes memory base = abi.encode(uint256(8453), w, bytes(""), bytes32(0));
        bytes memory payload = _payload(X, ALICE, LINK, base);
        vm.expectRevert(abi.encodeWithSelector(IWalletRegistry.WrongChain.selector, 8453));
        registry.linkIdentity(X, V1, payload, _admin());

        payload = _payload(X, ALICE, LINK, _txData(w, "", bytes32(0)));
        uint256 here = block.chainid;
        vm.chainId(8453);
        vm.expectRevert(abi.encodeWithSelector(IWalletRegistry.WrongChain.selector, here));
        registry.linkIdentity(X, V1, payload, _admin());
    }

    /// REQ-COMMON-01F: exactly the canonical `abi.encode(chainId, wallet, key, policyHash)`.
    function test_transactionDataMustBeCanonical() public {
        address w = factory.createWallet(X, ALICE, 0);
        bytes memory key = _key(ALICE_PK);
        bytes32 ph = _ph(_admin());
        bytes memory good = _txData(w, key, ph);
        assertEq(good.length, 192, "reference length");

        bytes[] memory bad = new bytes[](6);
        bad[0] = abi.encodePacked(good, bytes1(0)); // trailing byte
        bad[1] = abi.encodePacked(good, bytes32(0)); // trailing word
        bad[2] = abi.encodePacked(block.chainid, uint256(uint160(w)), uint256(0xa0), ph, bytes32(0), uint256(20));
        bad[2] = abi.encodePacked(bad[2], key, bytes12(0)); // a gap before the key
        bad[3] = abi.encode(block.chainid, w, hex"00112233445566778899aabbccddeeff001122", ph); // 19-byte key
        bad[4] = abi.encode(block.chainid, w, bytes(""), ph); // link only, with a policy hash
        bad[5] = abi.encodePacked(good); // key padding not zero
        bad[5][191] = 0x01;
        for (uint256 i; i < bad.length; ++i) {
            bytes memory payload = _payload(X, ALICE, LINK, bad[i]);
            vm.expectPartialRevert(IWalletRegistry.BadTransactionData.selector);
            registry.linkIdentity(X, V1, payload, _admin());
        }
        // Rows abi.decode itself rejects: any revert.
        bytes[] memory undecodable = new bytes[](2);
        undecodable[0] = abi.encodePacked(block.chainid, uint256(uint160(w)) | (1 << 200), uint256(0x80), ph);
        undecodable[0] = abi.encodePacked(undecodable[0], uint256(20), key, bytes12(0)); // dirty address bits
        undecodable[1] = abi.encodePacked(block.chainid, uint256(uint160(w)), uint256(0x80), ph, uint256(64));
        undecodable[1] = abi.encodePacked(undecodable[1], key, bytes12(0)); // length runs past the data
        for (uint256 i; i < undecodable.length; ++i) {
            bytes memory payload = _payload(X, ALICE, LINK, undecodable[i]);
            vm.expectRevert();
            registry.linkIdentity(X, V1, payload, _admin());
        }

        bytes memory addPayload = _payload(X, ALICE, ADD, abi.encodePacked(good, bytes1(0)));
        vm.expectPartialRevert(IWalletRegistry.BadTransactionData.selector);
        registry.addSessionByProof(X, V1, addPayload, _admin());
    }

    function test_policyMustMatchTheCommitment() public {
        address w = factory.createWallet(X, ALICE, 0);
        bytes memory payload = _payload(X, ALICE, LINK, _txData(w, _key(ALICE_PK), _ph(_admin())));
        vm.expectRevert(abi.encodeWithSelector(IWalletRegistry.PolicyMismatch.selector, _ph(_admin()), _ph(_app())));
        registry.linkIdentity(X, V1, payload, _app());
    }

    function test_aProofWithoutAnIdIsRefused() public {
        address w = _claim();
        bytes memory payload = _payload(X, bytes32(0), LINK, _txData(w, "", bytes32(0)));
        vm.prank(w);
        vm.expectRevert(IWalletRegistry.NoId.selector);
        registry.linkIdentity(X, V1, payload, _admin());
    }

    function test_valueIsExactlyTheQuote() public {
        StubPlatformVerifier paid = new StubPlatformVerifier(GITHUB, 5);
        vm.prank(owner);
        proofVerifier.setVerifier(GITHUB, 2, IPlatformVerifier(address(paid)));
        assertEq(registry.quote(GITHUB, 2), 5, "quote");
        address w = _claim();
        vm.deal(w, 1 ether);
        paid.setNodes(BOB, keccak256("h"));
        bytes memory payload = abi.encode(
            StubPlatformVerifier.StubPayload({
                ceremonyVersion: 1,
                operationDomain: LINK,
                authorizationNonce: keccak256("paid"),
                transactionData: _txData(w, "", bytes32(0))
            })
        );
        for (uint256 v = 4; v <= 6; v += 2) {
            vm.prank(w);
            vm.expectRevert(abi.encodeWithSelector(IWalletRegistry.WrongValue.selector, 5, v));
            registry.linkIdentity{value: v}(GITHUB, 2, payload, _admin());
        }
        vm.prank(w);
        registry.linkIdentity{value: 5}(GITHUB, 2, payload, _admin());
        assertEq(paid.lastValue(), 5, "the verifier was not paid");
    }

    // ─── Sessions by proof (R4) ─────────────────────────────────────

    function test_addSessionNeedsALinkedIdentity() public {
        address w = _claim();
        bytes memory payload = _payload(GITHUB, BOB, ADD, _txData(w, _key(BOB_PK), _ph(_admin())));
        vm.expectRevert(abi.encodeWithSelector(IIdentityValidator.NotLinked.selector, w, _identity(GITHUB, BOB)));
        registry.addSessionByProof(GITHUB, V1, payload, _admin());

        payload = _payload(X, ALICE, ADD, _txData(w, "", bytes32(0)));
        vm.expectPartialRevert(IWalletRegistry.BadTransactionData.selector);
        registry.addSessionByProof(X, V1, payload, _admin());
    }

    function test_aWalletThatNeverHadASessionSkipsTheWait() public {
        address w = factory.createWallet(X, ALICE, 0);
        _link(relayer, X, ALICE, w, "", _admin());
        _addByProof(mallory, X, ALICE, w, _key(ALICE_PK), _admin());
        assertLe(validator.sessionOf(w, _key(ALICE_PK)).activeAt, _now(), "first session waits");
        assertTrue(validator.hadSession(w), "flag not set");
    }

    function test_aSessionByProofWaitsAndIsAnnounced() public {
        address w = _claim();
        uint48 due = uint48(_now() + 48 hours);
        bytes memory payload = _payload(X, ALICE, ADD, _txData(w, _key(ALICE2_PK), _ph(_admin())));
        vm.expectEmit(true, true, false, true, address(validator));
        emit IIdentityValidator.SessionPending(w, _identity(X, ALICE), _key(ALICE2_PK), _ph(_admin()), due);
        vm.prank(mallory);
        registry.addSessionByProof(X, V1, payload, _admin());
        assertEq(validator.sessionOf(w, _key(ALICE2_PK)).activeAt, due, "not pending for 48 h");
    }

    /// The review's dormant-wallet case: expired admins do not switch the wait off.
    function test_aDormantWalletStillWaits() public {
        address w =
            _claimWith(IIdentityValidator.Policy({validAfter: 0, validUntil: uint48(_now() + 1 days), admin: true}));
        vm.warp(_now() + 30 days);
        _addByProof(mallory, X, ALICE, w, _key(MALLORY_PK), _admin());
        assertEq(validator.sessionOf(w, _key(MALLORY_PK)).activeAt, _now() + 48 hours, "dormant wallet skipped wait");
    }

    function test_aNewerPendingSessionReplacesTheOlder() public {
        address w = _claim();
        _addByProof(relayer, X, ALICE, w, _key(MALLORY_PK), _admin());
        vm.warp(_now() + 1 hours);
        _addByProof(relayer, X, ALICE, w, _key(ALICE2_PK), _admin());

        assertEq(validator.sessionOf(w, _key(MALLORY_PK)).identity, bytes32(0), "older pending kept");
        vm.warp(_now() + 48 hours);
        assertEq(_validate(w, _hit(), _pks(MALLORY_PK)), 1, "replaced session still signs");
        assertEq(validator.sessionOf(w, _key(ALICE2_PK)).activeAt, _now(), "newer not pending");
    }
}

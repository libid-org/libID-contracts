// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

import {AttestationBuilder} from "./AttestationBuilder.sol";
import {CeremonyAttestation} from "../CeremonyAttestation.sol";
import {INotaryService} from "../INotaryService.sol";
import {NotaryService} from "../NotaryService.sol";
import {GoogleJwtRoots} from "../GoogleJwtRoots.sol";
import {JwtRootsBase} from "../JwtRootsBase.sol";
import {JwtRootsTestBase} from "./JwtRootsBase.t.sol";

/// The `google/v1` profile's trust list, fed by a notarized reading of
/// Google's JWKS endpoint. Google's real body is a fixture.
contract GoogleJwtRootsTest is JwtRootsTestBase {
    bytes32 constant AUTHORITY = keccak256("www.googleapis.com");

    /// Google's real body, fetched 2026-09-03: pretty-printed, two keys.
    string constant GOOGLE_JWKS = "contracts/ceremony/test/fixtures/google-jwks.json";
    string constant GOOGLE_KID_1 = "943a3a5d7d919625a454e489b75c29adab57acba";
    string constant GOOGLE_KID_2 = "f10f87405a979c1df36df26606734f33cd85c271";

    /// The keeper's limb-hash vector. The keeper's `decision::modulus_hash` and
    /// `_splitLimbs` must agree on it, or the verifier refuses keys the keeper trusts.
    string constant KEEPER_MODULUS =
        "BAsSGSAnLjU8Q0pRWF9mbXR7gomQl56lrLO6wcjP1t3k6_L5BQwTGiEoLzY9REtSWWBnbnV8g4qRmJ-mrbS7wsnQ197l7PP6Bg0UGyIpMDc-RUxTWmFob3Z9hIuSmaCnrrW8w8rR2N_m7fT7Bw4VHCMqMTg_Rk1UW2JpcHd-hYyTmqGor7a9xMvS2eDn7vUBCA8WHSQrMjlAR05VXGNqcXh_ho2Um6KpsLe-xczT2uHo7_YCCRAXHiUsMzpBSE9WXWRrcnmAh46VnKOqsbi_xs3U2-Lp8PcDChEYHyYtNDtCSVBXXmVsc3qBiI-WnaSrsrnAx87V3OPq8fgECxIZIA";
    bytes32 constant KEEPER_MODULUS_HASH = 0xc5c1457ba4adf8bb84324e8595bf883639aa7ebd7aa7e7626a0b51f90e6838bc;

    /// The request the keeper's prover sends. The User-Agent is not read on chain.
    bytes constant REQUEST = "GET /oauth2/v3/certs HTTP/1.1\r\n" "host: www.googleapis.com\r\n" "connection: close\r\n"
        "accept: application/json\r\n" "user-agent: libid-keeper/0.1.0\r\n" "\r\n";

    function _implementation() internal override returns (JwtRootsBase) {
        return new GoogleJwtRoots();
    }

    function _authority() internal pure override returns (bytes32) {
        return AUTHORITY;
    }

    function _request() internal pure override returns (bytes memory) {
        return REQUEST;
    }

    // ─── What it accepts ────────────────────────────────────────────

    function test_aContentLengthFramedReadingInstallsTheKeys() public {
        uint64 at = _now();
        _rotate(_reading(_twoKeys("kid-1", "one", "kid-2", "two")));

        bytes32 first = _hash("one");
        bytes32 second = _hash("two");
        assertTrue(first != second, "distinct keys");
        _assertGeneration(_current(), at, _two(first, second), "current");
        _assertEmpty(_previous(), "nothing precedes the first reading");
        assertEq(roots.trustedHashExpiresAt(first), at + roots.READING_LIFETIME());
        assertEq(roots.trustedHashExpiresAt(second), at + roots.READING_LIFETIME());
    }

    /// Google serves the key set chunked; 100-byte chunks cut the first modulus three times.
    /// The same body under `Content-Length` then refreshes the set rather than rotating it.
    function test_aChunkedReadingInstallsTheKeys() public {
        bytes memory body = _oneKey("kid-1", "one");
        _rotate(_attest(REQUEST, _chunked(body, 100), _now()));
        assertEq(_current().moduli, _one(_hash("one")), "installed through chunked framing");

        vm.warp(block.timestamp + 1);
        _rotate(_reading(body));
        assertEq(_current().moduli, _one(_hash("one")), "framing changed the key");
        _assertEmpty(_previous(), "framing changed the key");
    }

    /// Google's real body, pretty-printed, in Google's chunked framing.
    function test_googlesRealBodyIsAccepted() public {
        bytes memory body = bytes(vm.readFile(GOOGLE_JWKS));
        assertEq(string(_slice(body, 0, 13)), "{\n  \"keys\": [", "the fixture is Google's pretty-printed body");

        vm.recordLogs();
        _rotate(_attest(REQUEST, _chunked(body, 512), _now()));

        (, string[] memory kids, bytes32[] memory moduli) = _lastRotation();
        assertEq(kids, _names(GOOGLE_KID_1, GOOGLE_KID_2), "both Google kids, in Google's order");
        assertTrue(moduli[0] != moduli[1], "two distinct keys");
        assertEq(_current().moduli, moduli);
        assertFalse(roots.needsRotation());
    }

    /// Cross-language pin: the keeper's `decision::modulus_hash` gives this hash for
    /// this modulus. `_hash` uses the same hasher.
    function test_theLimbHashMatchesTheKeeper() public {
        assertEq(hasher.hashOfB64url(KEEPER_MODULUS), KEEPER_MODULUS_HASH);
        _rotate(_reading(_body(_jwk("keeper", KEEPER_MODULUS))));
        assertEq(_current().moduli, _one(KEEPER_MODULUS_HASH));
        assertGt(roots.trustedHashExpiresAt(KEEPER_MODULUS_HASH), 0);
    }

    /// Anyone may submit a reading: the notary's signature is its authority.
    function test_anybodyMaySubmitARotation() public {
        bytes memory attested = _reading(_oneKey("kid-1", "one"));
        bytes memory sig = AttestationBuilder.sign(NOTARY_KEY, attested);
        vm.prank(keeper);
        roots.rotate{value: FEE}(attested, sig);
        assertEq(_current().moduli, _one(_hash("one")));
    }

    /// A rotation pays the Notary Fee, which accrues on the Notary Service.
    function test_theRotationPaysTheNotaryFee() public {
        assertEq(roots.quoteRotation(), FEE);
        _install("kid-1", "one");
        assertEq(address(notary).balance, FEE, "the fee reached the Notary Service");
        assertEq(address(roots).balance, 0, "nothing stays with the list");
    }

    // ─── Which readings count ───────────────────────────────────────

    /// Re-applying the reading in force fails with `NotNewer`, returns the fee,
    /// and leaves the list and the lifetime unchanged.
    function test_replayingTheReadingInForceIsRefused() public {
        uint64 at = _now();
        bytes memory attested = _reading(_oneKey("kid-1", "one"));
        _rotate(attested);

        vm.warp(block.timestamp + 30 minutes); // still inside the window
        _refuses(attested, abi.encodeWithSelector(JwtRootsBase.NotNewer.selector, at, at));

        assertEq(address(notary).balance, FEE, "the refused replay paid a fee");
        _assertGeneration(_current(), at, _one(_hash("one")), "current");
        _assertEmpty(_previous(), "a replay shifted the list");
        assertEq(
            roots.trustedHashExpiresAt(_hash("one")), at + roots.READING_LIFETIME(), "replay restarted the lifetime"
        );
    }

    /// A second reading dated the same second is refused whatever it carries.
    function test_aReadingDatedTheSameSecondIsRefused() public {
        uint64 at = _now();
        _rotate(_readingAt(_oneKey("kid-1", "one"), at));

        _refuses(
            _readingAt(_oneKey("kid-1", "two"), at), abi.encodeWithSelector(JwtRootsBase.NotNewer.selector, at, at)
        );

        _assertGeneration(_current(), at, _one(_hash("one")), "current");
        _assertEmpty(_previous(), "the same second shifted the list");
        assertEq(roots.trustedHashExpiresAt(_hash("two")), 0, "the same second installed a key");
    }

    /// A genuinely signed older reading, replayed after a newer one, fails with
    /// `NotNewer` carrying both clocks.
    function test_aGenuinelySignedOlderReadingIsRefused() public {
        uint64 dated = _now() - 30 minutes;
        bytes memory older = _readingAt(_oneKey("kid-1", "retired"), dated);
        uint64 at = _now();
        bytes32 live = _install("kid-1", "live");

        _refuses(older, abi.encodeWithSelector(JwtRootsBase.NotNewer.selector, dated, at));

        _assertGeneration(_current(), at, _one(live), "older reading rolled the set back");
        _assertEmpty(_previous(), "older reading shifted the list");
        assertEq(roots.trustedHashExpiresAt(_hash("retired")), 0, "older reading installed a retired key");
        assertEq(roots.trustedHashExpiresAt(live), at + roots.READING_LIFETIME(), "live key lost trust");
    }

    /// A stranger landing the keeper's reading first costs the keeper only gas:
    /// the fee returns and its next reading lands.
    function test_aFrontRunKeeperLosesGasOnly() public {
        uint64 at = _now();
        bytes memory attested = _reading(_oneKey("kid-1", "one"));
        bytes memory sig = AttestationBuilder.sign(NOTARY_KEY, attested);
        address stranger = makeAddr("stranger");
        vm.deal(stranger, 1 ether);
        vm.prank(stranger);
        roots.rotate{value: FEE}(attested, sig);

        uint256 funds = keeper.balance;
        vm.prank(keeper);
        vm.expectRevert(abi.encodeWithSelector(JwtRootsBase.NotNewer.selector, at, at));
        roots.rotate{value: FEE}(attested, sig);
        assertEq(keeper.balance, funds, "the refused reading kept the keeper's fee");
        assertEq(address(notary).balance, FEE, "one fee reached the service: the stranger's");

        vm.warp(at + 1 minutes);
        bytes memory next = _reading(_oneKey("kid-1", "one"));
        sig = AttestationBuilder.sign(NOTARY_KEY, next);
        vm.prank(keeper);
        roots.rotate{value: FEE}(next, sig);
        assertEq(roots.freshestObservedAt(), at + 1 minutes, "the keeper's next reading landed");
        assertEq(address(notary).balance, 2 * FEE);
    }

    /// A newer reading of the current set restarts its lifetime without shifting;
    /// key order is immaterial.
    function test_aNewerReadingOfTheSameSetRefreshesWithoutShifting() public {
        uint64 first = _now();
        _rotate(_readingAt(_twoKeys("kid-1", "one", "kid-2", "two"), first));
        bytes32[] memory set = _two(_hash("one"), _hash("two"));

        vm.warp(first + 20 minutes);
        uint64 second = first + 10 minutes;
        vm.expectEmit(false, false, false, true);
        emit JwtRootsBase.ReadingRefreshed(second);
        _rotate(_readingAt(_twoKeys("kid-2", "two", "kid-1", "one"), second)); // the same set, reversed

        _assertGeneration(_current(), second, set, "refreshed in place, original order kept");
        _assertEmpty(_previous(), "a refresh shifted the list");
        assertEq(roots.trustedHashExpiresAt(_hash("one")), second + roots.READING_LIFETIME(), "lifetime restarted");
        assertEq(roots.trustedHashExpiresAt(_hash("two")), second + roots.READING_LIFETIME(), "lifetime restarted");
        assertEq(roots.freshestObservedAt(), second);
    }

    /// A newer reading of a different set moves current to previous; the event
    /// lists the keys in Google's order.
    function test_aNewerReadingOfADifferentSetRotates() public {
        uint64 first = _now();
        bytes32 old = _install("kid-a", "a");

        vm.warp(first + 20 minutes);
        uint64 second = first + 10 minutes;
        bytes32[] memory incoming = _two(_hash("b"), _hash("c"));
        vm.expectEmit(false, false, false, true);
        emit JwtRootsBase.KeysRotated(second, _names("kid-b", "kid-c"), incoming);
        _rotate(_readingAt(_twoKeys("kid-b", "b", "kid-c", "c"), second));

        _assertGeneration(_current(), second, incoming, "current");
        _assertGeneration(_previous(), first, _one(old), "previous");
        assertEq(roots.trustedHashExpiresAt(old), first + roots.READING_LIFETIME(), "the old set keeps its own stamp");
        assertEq(roots.trustedHashExpiresAt(_hash("b")), second + roots.READING_LIFETIME());
        assertEq(roots.trustedHashExpiresAt(_hash("c")), second + roots.READING_LIFETIME());
        assertEq(roots.freshestObservedAt(), second);
    }

    /// A third distinct set drops the oldest, whose keys stop being trusted.
    function test_aThirdSetDropsTheOldest() public {
        uint64 first = _now();
        bytes32 a = _install("kid-a", "a");
        vm.warp(first + 1 minutes);
        uint64 second = _now();
        bytes32 b = _install("kid-b", "b");
        vm.warp(second + 1 minutes);
        uint64 third = _now();
        bytes32 c = _install("kid-c", "c");

        _assertGeneration(_current(), third, _one(c), "current");
        _assertGeneration(_previous(), second, _one(b), "previous");
        assertEq(roots.trustedHashExpiresAt(a), 0, "the oldest set is still trusted");
        assertEq(roots.trustedHashExpiresAt(b), second + roots.READING_LIFETIME());
        assertEq(roots.trustedHashExpiresAt(c), third + roots.READING_LIFETIME());
    }

    /// Google's sets overlap; a key in both generations carries the current one's stamp.
    function test_aKeyInBothGenerationsCarriesTheCurrentStamp() public {
        uint64 first = _now();
        _rotate(_readingAt(_twoKeys("kid-1", "one", "kid-2", "two"), first));
        vm.warp(first + 1 minutes);
        uint64 second = _now();
        _rotate(_readingAt(_twoKeys("kid-2", "two", "kid-3", "three"), second));

        assertEq(roots.trustedHashExpiresAt(_hash("two")), second + roots.READING_LIFETIME(), "in both: current stamp");
        assertEq(roots.trustedHashExpiresAt(_hash("one")), first + roots.READING_LIFETIME(), "previous only");
        assertEq(roots.trustedHashExpiresAt(_hash("three")), second + roots.READING_LIFETIME(), "current only");
    }

    /// Trust lapses at `createdAt + READING_LIFETIME`, by the notary's clock,
    /// with no further transaction.
    function test_trustLapsesByTheReadingsOwnClockWithNoCall() public {
        uint64 observedAt = _now() - 30 minutes;
        _rotate(_readingAt(_oneKey("kid-1", "one"), observedAt));
        uint256 stamp = observedAt + roots.READING_LIFETIME();
        assertEq(roots.trustedHashExpiresAt(_hash("one")), stamp, "anchored to the reading, not the block");
        assertTrue(stamp < block.timestamp + roots.READING_LIFETIME(), "block time did not stretch it");

        vm.warp(stamp);
        assertEq(roots.trustedHashExpiresAt(_hash("one")), stamp, "nothing rewrote the stamp");
        assertTrue(roots.trustedHashExpiresAt(_hash("one")) <= block.timestamp, "expired by time alone");
        assertTrue(roots.needsRotation());
        _assertGeneration(_current(), observedAt, _one(_hash("one")), "the generation is still what was read");
    }

    /// `freshestObservedAt` is the current generation's clock: a refresh or a rotation
    /// moves it forward, and an older reading is refused against it.
    function test_freshestObservedAtIsTheReadingInForce() public {
        assertEq(roots.freshestObservedAt(), 0);
        uint64 first = _now();
        _rotate(_readingAt(_oneKey("kid-1", "one"), first));
        assertEq(roots.freshestObservedAt(), first);

        _refuses(
            _readingAt(_oneKey("kid-1", "one"), first - 10 minutes),
            abi.encodeWithSelector(JwtRootsBase.NotNewer.selector, first - 10 minutes, first)
        );
        assertEq(roots.freshestObservedAt(), first, "an older reading moved the mark");

        vm.warp(first + 20 minutes);
        _rotate(_readingAt(_oneKey("kid-1", "one"), first + 10 minutes)); // same set: refresh
        assertEq(roots.freshestObservedAt(), first + 10 minutes, "a refresh must move the mark");
        _rotate(_readingAt(_oneKey("kid-2", "two"), first + 15 minutes)); // different set: rotation
        assertEq(roots.freshestObservedAt(), first + 15 minutes, "a rotation must move the mark");
    }

    // ─── What a keeper reads ────────────────────────────────────────

    function test_currentKeysStartsEmpty() public view {
        _assertEmpty(_current(), "current");
        _assertEmpty(_previous(), "previous");
        assertEq(roots.freshestObservedAt(), 0);
        assertTrue(roots.needsRotation());
    }

    /// True until the first rotation, then again once less than RENEWAL_MARGIN
    /// of trust remains.
    function test_needsRotationTracksTheTrustedRunway() public {
        assertTrue(roots.needsRotation(), "an empty list needs a rotation");
        // A chain younger than the lifetime still asks for its first reading.
        vm.warp(1);
        assertTrue(roots.needsRotation(), "an empty list needs a rotation at any block time");
        vm.warp(T0 + 10);

        uint64 at = _now();
        _install("kid-1", "one");
        assertFalse(roots.needsRotation(), "a fresh rotation buys quiet");

        uint256 stamp = at + roots.READING_LIFETIME();
        vm.warp(stamp - roots.RENEWAL_MARGIN() - 1);
        assertFalse(roots.needsRotation(), "still a second of margin to spare");
        vm.warp(stamp - roots.RENEWAL_MARGIN());
        assertTrue(roots.needsRotation(), "the margin should trip before expiry does");
    }

    /// The event carries the reading's kids and limb hashes in Google's order,
    /// stamped with the notary's clock.
    function test_aRotationAnnouncesTheKeysInReadingOrder() public {
        uint64 provenAt = _now() - 10 minutes;

        vm.recordLogs();
        _rotate(_readingAt(_manyKeys(3), provenAt));

        (uint64 observedAt, string[] memory kids, bytes32[] memory moduli) = _lastRotation();
        assertEq(observedAt, provenAt, "observedAt is the notary's clock");
        assertEq(kids.length, 3);
        assertEq(moduli.length, 3);
        for (uint256 i = 0; i < 3; ++i) {
            string memory kid = string.concat("kid-", vm.toString(i));
            assertEq(kids[i], kid, "kid in reading order");
            assertEq(moduli[i], _hash(kid), "modulus in reading order");
        }
        assertEq(_current().moduli, moduli, "the event is what was stored");
    }

    // ─── Administration ─────────────────────────────────────────────

    /// Pointing at another Notary Service moves the list under its keys and fee.
    function test_theOwnerCanPointAtAnotherNotaryService() public {
        uint256 otherKey = 0xC0FFEE;
        NotaryService otherImpl = new NotaryService();
        NotaryService other = NotaryService(
            address(
                new ERC1967Proxy(
                    address(otherImpl), abi.encodeCall(NotaryService.initialize, (OWNER, vm.addr(otherKey), 2 * FEE))
                )
            )
        );

        vm.prank(OWNER);
        vm.expectEmit(false, false, false, true);
        emit JwtRootsBase.NotaryServiceChanged(address(other));
        roots.setNotaryService(INotaryService(address(other)));

        assertEq(roots.notaryService(), address(other));
        assertEq(roots.quoteRotation(), 2 * FEE);

        // The old service's key is refused,
        bytes memory attested = _reading(_oneKey("kid-1", "one"));
        bytes memory oldSig = AttestationBuilder.sign(NOTARY_KEY, attested);
        vm.expectRevert(abi.encodeWithSelector(NotaryService.UntrustedNotary.selector, vm.addr(NOTARY_KEY)));
        roots.rotate{value: 2 * FEE}(attested, oldSig);

        // and the new one's is accepted at the new fee.
        roots.rotate{value: 2 * FEE}(attested, AttestationBuilder.sign(otherKey, attested));
        assertEq(_current().moduli, _one(_hash("one")));
        assertEq(address(other).balance, 2 * FEE);
    }

    function test_onlyTheOwnerSetsTheNotaryService() public {
        vm.prank(keeper);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, keeper));
        roots.setNotaryService(INotaryService(address(0xD00D)));
    }

    function test_aZeroNotaryServiceIsRefused() public {
        vm.prank(OWNER);
        vm.expectRevert(JwtRootsBase.ZeroAddress.selector);
        roots.setNotaryService(INotaryService(address(0)));

        GoogleJwtRoots impl = new GoogleJwtRoots();
        vm.expectRevert(JwtRootsBase.ZeroAddress.selector);
        new ERC1967Proxy(address(impl), abi.encodeCall(JwtRootsBase.initialize, (OWNER, INotaryService(address(0)))));
    }

    /// Renouncing would freeze the list while Google's keys expire, halting Google claims.
    function test_renouncingIsDisabled() public {
        vm.prank(OWNER);
        vm.expectRevert(bytes("renounce disabled"));
        roots.renounceOwnership();
    }

    // ─── Clearing the keys ──────────────────────────────────────────

    /// Keys read under a notary key the Notary Service has since removed stay
    /// trusted until the owner clears the list; then neither generation is.
    function test_clearingTheKeysUntrustsBothGenerations() public {
        bytes32 older = _install("kid-1", "older");
        vm.warp(_now() + 1 hours);
        bytes32 newer = _install("kid-2", "newer");
        _replaceTheNotaryKey();
        assertGt(roots.trustedHashExpiresAt(older), _now(), "previous is trusted before the clear");
        assertGt(roots.trustedHashExpiresAt(newer), _now(), "current is trusted before the clear");

        vm.prank(OWNER);
        vm.expectEmit(false, false, false, true);
        emit JwtRootsBase.KeysCleared();
        roots.clearKeys();

        _assertEmpty(_current(), "current");
        _assertEmpty(_previous(), "previous");
        assertEq(roots.trustedHashExpiresAt(older), 0, "previous still trusted");
        assertEq(roots.trustedHashExpiresAt(newer), 0, "current still trusted");
        assertEq(roots.freshestObservedAt(), 0, "the stamp survived");
        assertTrue(roots.needsRotation(), "a cleared list asks for a reading");
    }

    /// The next reading the Notary Service accepts refills the list, even one
    /// dated the second the cleared reading was.
    function test_aReadingAfterTheClearRestoresTheList() public {
        uint64 at = _now();
        bytes32 cleared = _install("kid-1", "cleared");
        _replaceTheNotaryKey();
        _clearKeys();

        _rotateUnder(NEXT_NOTARY_KEY, _readingAt(_oneKey("kid-2", "restored"), at));

        _assertGeneration(_current(), at, _one(_hash("restored")), "current");
        _assertEmpty(_previous(), "previous");
        assertEq(roots.trustedHashExpiresAt(_hash("restored")), at + roots.READING_LIFETIME(), "restored key");
        assertEq(roots.trustedHashExpiresAt(cleared), 0, "the cleared key came back");
    }

    /// Clearing does not stand in for removing the notary key: a reading under
    /// the removed key is still refused, and the list stays empty.
    function test_aRemovedNotaryKeyStaysRefusedAfterTheClear() public {
        _install("kid-1", "cleared");
        _replaceTheNotaryKey();
        _clearKeys();

        vm.warp(_now() + 1);
        bytes memory attested = _reading(_oneKey("kid-1", "cleared"));
        bytes memory sig = AttestationBuilder.sign(NOTARY_KEY, attested);
        vm.expectRevert(abi.encodeWithSelector(NotaryService.UntrustedNotary.selector, vm.addr(NOTARY_KEY)));
        roots.rotate{value: FEE}(attested, sig);

        _assertEmpty(_current(), "current");
        _assertEmpty(_previous(), "previous");
    }

    /// The clear drops the stamp with the keys, so an older reading still
    /// inside the freshness window lands afterwards. It installs the set it was
    /// read with, dated by its own clock.
    function test_anOlderReadingLandsAfterTheClearWithItsOwnSet() public {
        uint64 dated = _now();
        bytes memory older = _readingAt(_oneKey("kid-1", "older"), dated);
        vm.warp(_now() + 30 minutes);
        bytes32 newer = _install("kid-2", "newer");
        _clearKeys();

        _rotate(older);

        _assertGeneration(_current(), dated, _one(_hash("older")), "current");
        _assertEmpty(_previous(), "previous");
        assertEq(roots.trustedHashExpiresAt(_hash("older")), dated + roots.READING_LIFETIME(), "older key");
        assertEq(roots.trustedHashExpiresAt(newer), 0, "the cleared key came back");
    }

    function test_onlyTheOwnerClearsTheKeys() public {
        bytes32 installed = _install("kid-1", "one");

        vm.prank(keeper);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, keeper));
        roots.clearKeys();

        _assertGeneration(_current(), _now(), _one(installed), "current");
    }

    // ─── What it refuses: the fee and the notary ────────────────────

    /// Only the exact fee is accepted; an overpayment fails too, so nothing needs refunding.
    function test_refusesAnyValueOtherThanTheFee() public {
        bytes memory attested = _reading(_oneKey("kid-1", "one"));
        bytes memory sig = AttestationBuilder.sign(NOTARY_KEY, attested);

        vm.expectRevert(abi.encodeWithSelector(JwtRootsBase.WrongValue.selector, FEE, FEE - 1));
        roots.rotate{value: FEE - 1}(attested, sig);

        vm.expectRevert(abi.encodeWithSelector(JwtRootsBase.WrongValue.selector, FEE, FEE + 1));
        roots.rotate{value: FEE + 1}(attested, sig);

        vm.expectRevert(abi.encodeWithSelector(JwtRootsBase.WrongValue.selector, FEE, 0));
        roots.rotate(attested, sig);
    }

    /// A reading signed by a key the Notary Service does not trust is refused.
    function test_refusesAnUntrustedNotaryKey() public {
        uint256 stranger = 0xB0B;
        bytes memory attested = _reading(_oneKey("kid-1", "one"));
        bytes memory sig = AttestationBuilder.sign(stranger, attested);
        vm.expectRevert(abi.encodeWithSelector(NotaryService.UntrustedNotary.selector, vm.addr(stranger)));
        roots.rotate{value: FEE}(attested, sig);
    }

    /// One edited byte changes the digest, so the signature recovers an untrusted address.
    function test_refusesATamperedAttestedByte() public {
        bytes memory attested = _reading(_oneKey("kid-1", "one"));
        bytes memory sig = AttestationBuilder.sign(NOTARY_KEY, attested);
        attested[attested.length - 40] = bytes1(uint8(attested[attested.length - 40]) ^ 0x01);
        vm.expectPartialRevert(NotaryService.UntrustedNotary.selector);
        roots.rotate{value: FEE}(attested, sig);
    }

    function test_refusesAMalformedSignature() public {
        bytes memory attested = _reading(_oneKey("kid-1", "one"));
        vm.expectRevert(NotaryService.MalformedSignature.selector);
        roots.rotate{value: FEE}(attested, hex"1234");
    }

    /// A rejected rotation leaves no fee behind.
    function test_aRejectedRotationDeliversNoFee() public {
        bytes memory attested = _reading(_oneKey("kid-1", "one"));
        vm.expectRevert(NotaryService.MalformedSignature.selector);
        roots.rotate{value: FEE}(attested, hex"1234");
        assertEq(address(notary).balance, 0, "a rejection kept the fee");
        assertEq(address(roots).balance, 0);
    }

    // ─── What it refuses: the session ───────────────────────────────

    /// A reading signed for another host is refused before the transcript is read.
    function test_refusesAnotherAuthority() public {
        bytes32 other = keccak256("storage.googleapis.com");
        bytes memory attested =
            AttestationBuilder.encode(other, _now(), _whole(REQUEST), _whole(_contentLength(_oneKey("kid-1", "one"))));
        _refuses(attested, abi.encodeWithSelector(JwtRootsBase.WrongAuthority.selector, AUTHORITY, other));
    }

    function test_refusesAReadingFromTheFuture() public {
        uint64 ahead = _now() + uint64(roots.CLOCK_SKEW_GRACE()) + 1;
        _refuses(_readingAt(_oneKey("kid-1", "one"), ahead), JwtRootsBase.FutureProof.selector);
        // One exactly at the grace is accepted.
        _rotate(_readingAt(_oneKey("kid-1", "one"), ahead - 1));
    }

    /// A reading older than FRESHNESS_WINDOW is refused.
    function test_refusesAStaleReading() public {
        uint64 provenAt = _now();
        bytes memory attested = _readingAt(_oneKey("kid-1", "one"), provenAt);
        vm.warp(provenAt + roots.FRESHNESS_WINDOW() + 1);
        _refuses(attested, JwtRootsBase.StaleProof.selector);
    }

    /// Both directions must tile the signed length.
    function test_refusesACoverageGapInTheRequest() public {
        uint32 len = uint32(REQUEST.length);
        AttestationBuilder.Direction memory sent = AttestationBuilder.Direction({
            revealed: AttestationBuilder.one(AttestationBuilder.Range({start: 0, value: _slice(REQUEST, 0, len - 1)})),
            commitments: AttestationBuilder.none(),
            length: len
        });
        bytes memory attested =
            AttestationBuilder.encode(AUTHORITY, _now(), sent, _whole(_contentLength(_oneKey("kid-1", "one"))));
        _refuses(attested, abi.encodeWithSelector(CeremonyAttestation.CoverageGap.selector, len - 1, len));
    }

    function test_refusesACoverageGapInTheResponse() public {
        bytes memory response = _contentLength(_oneKey("kid-1", "one"));
        uint32 len = uint32(response.length);
        AttestationBuilder.Direction memory received = AttestationBuilder.Direction({
            revealed: AttestationBuilder.one(AttestationBuilder.Range({start: 1, value: _slice(response, 1, len)})),
            commitments: AttestationBuilder.none(),
            length: len
        });
        bytes memory attested = AttestationBuilder.encode(AUTHORITY, _now(), _whole(REQUEST), received);
        _refuses(attested, abi.encodeWithSelector(CeremonyAttestation.CoverageGap.selector, 0, 1));
    }

    /// A commitment passes coverage but hides bytes, so it is refused.
    function test_refusesAHiddenByteInTheRequest() public {
        uint32 len = uint32(REQUEST.length);
        AttestationBuilder.Direction memory sent = AttestationBuilder.Direction({
            revealed: AttestationBuilder.one(AttestationBuilder.Range({start: 0, value: REQUEST})),
            commitments: AttestationBuilder.one(
                AttestationBuilder.Commitment({start: len, end: len + 4, value: bytes32(uint256(0x7777))})
            ),
            length: len + 4
        });
        bytes memory attested =
            AttestationBuilder.encode(AUTHORITY, _now(), sent, _whole(_contentLength(_oneKey("kid-1", "one"))));
        _refuses(attested, JwtRootsBase.HiddenBytes.selector);
    }

    function test_refusesAHiddenByteInTheResponse() public {
        bytes memory response = _contentLength(_oneKey("kid-1", "one"));
        uint32 len = uint32(response.length);
        AttestationBuilder.Direction memory received = AttestationBuilder.Direction({
            revealed: AttestationBuilder.one(AttestationBuilder.Range({start: 0, value: response})),
            commitments: AttestationBuilder.one(
                AttestationBuilder.Commitment({start: len, end: len + 4, value: bytes32(uint256(0x7777))})
            ),
            length: len + 4
        });
        bytes memory attested = AttestationBuilder.encode(AUTHORITY, _now(), _whole(REQUEST), received);
        _refuses(attested, JwtRootsBase.HiddenBytes.selector);
    }

    /// An empty direction passes coverage against a zero length and is refused by name.
    function test_refusesAnEmptyRequest() public {
        bytes memory attested =
            AttestationBuilder.encode(AUTHORITY, _now(), _empty(), _whole(_contentLength(_oneKey("kid-1", "one"))));
        _refuses(attested, abi.encodeWithSelector(JwtRootsBase.RequestLineNotAtOrigin.selector, type(uint32).max));
    }

    function test_refusesAnEmptyResponse() public {
        bytes memory attested = AttestationBuilder.encode(AUTHORITY, _now(), _whole(REQUEST), _empty());
        _refuses(attested, abi.encodeWithSelector(JwtRootsBase.RequestLineNotAtOrigin.selector, type(uint32).max));
    }

    // ─── What it refuses: the request ───────────────────────────────

    function _withRequest(bytes memory request) private view returns (bytes memory) {
        return _attest(request, _contentLength(_oneKey("kid-1", "one")), _now());
    }

    function test_refusesAPostRequestLine() public {
        bytes memory request =
            abi.encodePacked("POST /oauth2/v3/certs HTTP/1.1\r\n", _slice(REQUEST, 31, REQUEST.length));
        _refuses(_withRequest(request), JwtRootsBase.WrongRequestLine.selector);
    }

    function test_refusesAnotherPath() public {
        bytes memory request =
            abi.encodePacked("GET /oauth2/v3/certs2 HTTP/1.1\r\n", _slice(REQUEST, 31, REQUEST.length));
        _refuses(_withRequest(request), JwtRootsBase.WrongRequestLine.selector);
    }

    /// A query is another document: `?callback=<name>` returns a JSONP body that
    /// starts with bytes the requester chose. The whole request line is pinned.
    function test_refusesAQueryInTheRequestTarget() public {
        bytes memory request =
            abi.encodePacked("GET /oauth2/v3/certs?callback=foo HTTP/1.1\r\n", _slice(REQUEST, 31, REQUEST.length));
        _refuses(_withRequest(request), JwtRootsBase.WrongRequestLine.selector);
    }

    /// Only the origin-form request target is accepted.
    function test_refusesAnAbsoluteFormRequestTarget() public {
        bytes memory request = abi.encodePacked(
            "GET https://www.googleapis.com/oauth2/v3/certs HTTP/1.1\r\n", _slice(REQUEST, 31, REQUEST.length)
        );
        _refuses(_withRequest(request), JwtRootsBase.WrongRequestLine.selector);
    }

    /// googleapis.com serves many hosts under one certificate, so exactly one `Host` is accepted.
    function test_refusesASecondHostHeader() public {
        bytes memory request = abi.encodePacked(
            "GET /oauth2/v3/certs HTTP/1.1\r\n",
            "host: www.googleapis.com\r\n",
            "host: storage.googleapis.com\r\n",
            "connection: close\r\n\r\n"
        );
        _refuses(_withRequest(request), abi.encodeWithSelector(JwtRootsBase.NotOneHostHeader.selector, 2));
    }

    /// Field names are case-insensitive and the colon admits whitespace, so
    /// the count runs over normalized bytes.
    function test_refusesASecondHostHeaderEvadingCaseAndWhitespace() public {
        bytes memory request = abi.encodePacked(
            "GET /oauth2/v3/certs HTTP/1.1\r\n",
            "host: www.googleapis.com\r\n",
            "HOST\t : storage.googleapis.com\r\n",
            "connection: close\r\n\r\n"
        );
        _refuses(_withRequest(request), abi.encodeWithSelector(JwtRootsBase.NotOneHostHeader.selector, 2));
    }

    /// Google's front end honours a `Host` after a bare LF, which a CRLF-anchored
    /// count misses. The bare LF is refused at its offset before hosts are counted.
    function test_refusesASecondHostHeaderBehindABareLineFeed() public {
        bytes memory request = abi.encodePacked(
            "GET /oauth2/v3/certs HTTP/1.1\r\n",
            "x-a: b\nhost: storage.googleapis.com\r\n",
            "host: www.googleapis.com\r\n",
            "connection: close\r\n\r\n"
        );
        _refuses(_withRequest(request), abi.encodeWithSelector(CeremonyAttestation.BareLineFeed.selector, 37));
    }

    /// An obsolete line fold normalizes to `\r\nhost:` and would count as the one
    /// `Host`. It is refused at the CRLF that starts it.
    function test_refusesAnObsoleteLineFoldInTheRequest() public {
        bytes memory request = abi.encodePacked(
            "GET /oauth2/v3/certs HTTP/1.1\r\n", "x-a: b\r\n host: www.googleapis.com\r\n", "connection: close\r\n\r\n"
        );
        _refuses(_withRequest(request), abi.encodeWithSelector(CeremonyAttestation.ObsoleteLineFold.selector, 37));

        // A folded right host over a bare-LF wrong one: the fold is named first.
        request = abi.encodePacked(
            "GET /oauth2/v3/certs HTTP/1.1\r\n",
            "x-a: b\r\n host: www.googleapis.com\r\n",
            "x-b: c\nhost: storage.googleapis.com\r\n",
            "connection: close\r\n\r\n"
        );
        _refuses(_withRequest(request), abi.encodeWithSelector(CeremonyAttestation.ObsoleteLineFold.selector, 37));
    }

    /// A `Host` after the blank line is body bytes and does not count.
    function test_aHostInTheRequestBodyDoesNotCount() public {
        bytes memory request = abi.encodePacked(
            "GET /oauth2/v3/certs HTTP/1.1\r\n", "connection: close\r\n\r\n", "host: www.googleapis.com\r\n"
        );
        _refuses(_withRequest(request), abi.encodeWithSelector(JwtRootsBase.NotOneHostHeader.selector, 0));
    }

    function test_refusesARequestWhoseHeadNeverEnds() public {
        bytes memory request = "GET /oauth2/v3/certs HTTP/1.1\r\nhost: www.googleapis.com\r\n";
        _refuses(_withRequest(request), JwtRootsBase.NoHeadBoundary.selector);
    }

    function test_refusesARequestWithoutAHostHeader() public {
        bytes memory request = "GET /oauth2/v3/certs HTTP/1.1\r\nconnection: close\r\n\r\n";
        _refuses(_withRequest(request), abi.encodeWithSelector(JwtRootsBase.NotOneHostHeader.selector, 0));
    }

    /// The TLS authority names the certificate and `Host` picks the backend; both
    /// must be Google's JWKS host.
    function test_refusesAnotherGoogleHost() public {
        bytes memory request =
            "GET /oauth2/v3/certs HTTP/1.1\r\nhost: storage.googleapis.com\r\nconnection: close\r\n\r\n";
        _refuses(_withRequest(request), JwtRootsBase.WrongHost.selector);
    }

    /// A host that is a prefix of the right one, or the right one followed by
    /// more, is another host.
    function test_refusesAHostThatMerelyContainsTheRightOne() public {
        bytes memory request =
            "GET /oauth2/v3/certs HTTP/1.1\r\nhost: www.googleapis.com.evil\r\nconnection: close\r\n\r\n";
        _refuses(_withRequest(request), JwtRootsBase.WrongHost.selector);
        request = "GET /oauth2/v3/certs HTTP/1.1\r\nhost: www.googleapis.co\r\nconnection: close\r\n\r\n";
        _refuses(_withRequest(request), JwtRootsBase.WrongHost.selector);
    }

    // ─── What it refuses: the response ──────────────────────────────

    function _withResponse(bytes memory response) private view returns (bytes memory) {
        return _attest(REQUEST, response, _now());
    }

    /// Only a 200 is accepted; a redirect's body is not the key set.
    function test_refusesARedirect() public {
        bytes memory response =
            abi.encodePacked("HTTP/1.1 302 Found\r\nlocation: /elsewhere\r\ncontent-length: 0\r\n\r\n");
        _refuses(_withResponse(response), JwtRootsBase.WrongStatusLine.selector);
    }

    function test_refusesAResponseWithoutAHeadBoundary() public {
        bytes memory response = abi.encodePacked(STATUS_OK, CONTENT_TYPE, "content-length: 2\r\n", "{}");
        _refuses(_withResponse(response), JwtRootsBase.NoHeadBoundary.selector);
    }

    /// The prover negotiates no compression, so a `Content-Encoding` is refused by
    /// name before the framing is read.
    function test_refusesAnEncodedBody() public {
        bytes memory body = _oneKey("kid-1", "one");
        bytes memory response = abi.encodePacked(
            STATUS_OK,
            CONTENT_TYPE,
            "content-encoding: gzip\r\n",
            "content-length: ",
            vm.toString(body.length),
            "\r\n\r\n",
            body
        );
        _refuses(_withResponse(response), JwtRootsBase.EncodedBody.selector);
    }

    /// Every deviation from strict chunked framing fails with `BadChunkFraming`.
    function test_refusesBadChunkFraming() public {
        bytes memory head = abi.encodePacked(STATUS_OK, CONTENT_TYPE, "transfer-encoding: chunked\r\n\r\n");
        bytes memory body = _oneKey("kid-1", "one");
        bytes memory sizeLine = abi.encodePacked(_hex(body.length), "\r\n");

        // A size that is not hex.
        _refuses(
            _withResponse(abi.encodePacked(head, "zz\r\n", body, "\r\n0\r\n\r\n")),
            JwtRootsBase.BadChunkFraming.selector
        );
        // A chunk extension.
        _refuses(
            _withResponse(abi.encodePacked(head, _hex(body.length), ";ext=1\r\n", body, "\r\n0\r\n\r\n")),
            JwtRootsBase.BadChunkFraming.selector
        );
        // No terminating zero chunk.
        _refuses(_withResponse(abi.encodePacked(head, sizeLine, body, "\r\n")), JwtRootsBase.BadChunkFraming.selector);
        // Trailers after the zero chunk.
        _refuses(
            _withResponse(abi.encodePacked(head, sizeLine, body, "\r\n0\r\nx-trailer: 1\r\n\r\n")),
            JwtRootsBase.BadChunkFraming.selector
        );
        // Nine hex digits.
        _refuses(
            _withResponse(abi.encodePacked(head, "000000001\r\n", body, "\r\n0\r\n\r\n")),
            JwtRootsBase.BadChunkFraming.selector
        );
        // Chunk data not followed by CRLF.
        _refuses(
            _withResponse(abi.encodePacked(head, sizeLine, body, "0\r\n\r\n")), JwtRootsBase.BadChunkFraming.selector
        );
        // A size past the end of the body.
        _refuses(
            _withResponse(abi.encodePacked(head, "ffff\r\n", body, "\r\n0\r\n\r\n")),
            JwtRootsBase.BadChunkFraming.selector
        );
        // Bytes after the final CRLF.
        _refuses(
            _withResponse(abi.encodePacked(head, sizeLine, body, "\r\n0\r\n\r\n\r\n")),
            JwtRootsBase.BadChunkFraming.selector
        );
        // And the strict form of the same body is accepted.
        _rotate(_withResponse(abi.encodePacked(head, sizeLine, body, "\r\n0\r\n\r\n")));
    }

    function test_refusesAContentLengthThatIsNotTheBody() public {
        bytes memory body = _oneKey("kid-1", "one");
        bytes memory response = abi.encodePacked(
            STATUS_OK, CONTENT_TYPE, "content-length: ", vm.toString(body.length + 1), "\r\n\r\n", body
        );
        _refuses(
            _withResponse(response),
            abi.encodeWithSelector(JwtRootsBase.ContentLengthMismatch.selector, body.length + 1, body.length)
        );

        // A value that is not a decimal declares no length any body matches.
        response = abi.encodePacked(STATUS_OK, CONTENT_TYPE, "content-length: 4x\r\n\r\n", body);
        _refuses(
            _withResponse(response), abi.encodeWithSelector(JwtRootsBase.ContentLengthMismatch.selector, 4, body.length)
        );
    }

    /// With neither framing header, `connection: close` delimits and the body
    /// is what follows the head.
    function test_acceptsABodyDelimitedByConnectionClose() public {
        bytes memory response = abi.encodePacked(STATUS_OK, CONTENT_TYPE, "\r\n", _oneKey("kid-1", "one"));
        _rotate(_withResponse(response));
        assertEq(_current().moduli, _one(_hash("one")));
    }

    // ─── What it refuses: the key set ───────────────────────────────

    function _withBody(bytes memory body) private view returns (bytes memory) {
        return _reading(body);
    }

    function test_refusesABodyWithoutKeys() public {
        _refuses(
            _withBody(abi.encodePacked('{"kyes":[', _jwk("kid-1", _modulus("one")), "]}")),
            abi.encodeWithSelector(JwtRootsBase.MissingMember.selector, "keys")
        );
        // Present, but not an array.
        _refuses(
            _withBody(abi.encodePacked('{"keys":', _jwk("kid-1", _modulus("one")), "}")),
            abi.encodeWithSelector(JwtRootsBase.MissingMember.selector, "keys")
        );
    }

    /// Two `keys` members are ambiguous.
    function test_refusesADecoyKeysMember() public {
        bytes memory body = abi.encodePacked(
            '{"keys":[', _jwk("kid-1", _modulus("one")), '],"keys":[', _jwk("kid-2", _modulus("two")), "]}"
        );
        _refuses(_withBody(body), abi.encodeWithSelector(JwtRootsBase.AmbiguousMember.selector, "keys"));
    }

    function test_refusesAKeyWithoutAModulus() public {
        bytes memory body = _body('{"kty":"RSA","kid":"kid-1","e":"AQAB"}');
        _refuses(_withBody(body), abi.encodeWithSelector(JwtRootsBase.MissingMember.selector, "n"));
    }

    function test_refusesAKeyWithoutAKid() public {
        bytes memory body = _body(abi.encodePacked('{"kty":"RSA","n":"', _modulus("one"), '","e":"AQAB"}'));
        _refuses(_withBody(body), abi.encodeWithSelector(JwtRootsBase.MissingMember.selector, "kid"));
    }

    /// The circuit verifies RS256 under 65537 only and the verifier trusts a modulus
    /// alone, so any other exponent is refused.
    function test_refusesAnotherExponent() public {
        bytes memory body = _body(abi.encodePacked('{"kid":"kid-1","n":"', _modulus("one"), '","e":"AQAC"}'));
        _refuses(_withBody(body), abi.encodeWithSelector(JwtRootsBase.WrongExponent.selector, bytes("AQAC")));
        // 65537 padded is not the pinned token either.
        body = _body(abi.encodePacked('{"kid":"kid-1","n":"', _modulus("one"), '","e":"AQAB="}'));
        _refuses(_withBody(body), abi.encodeWithSelector(JwtRootsBase.WrongExponent.selector, bytes("AQAB=")));
    }

    function test_refusesAKeyWithoutAnExponent() public {
        bytes memory body = _body(abi.encodePacked('{"kty":"RSA","kid":"kid-1","n":"', _modulus("one"), '"}'));
        _refuses(_withBody(body), abi.encodeWithSelector(JwtRootsBase.MissingMember.selector, "e"));
    }

    /// A duplicate `kid` is ambiguous: parsers pick different ones.
    function test_refusesADuplicateKidMember() public {
        bytes memory body = _body(abi.encodePacked('{"kid":"kid-1","kid":"kid-2","n":"', _modulus("one"), '"}'));
        _refuses(_withBody(body), abi.encodeWithSelector(JwtRootsBase.AmbiguousMember.selector, "kid"));
    }

    /// The `}` is inside the unterminated string, so the key never closes.
    function test_refusesAnUnterminatedKid() public {
        bytes memory body = _body(abi.encodePacked('{"n":"', _modulus("one"), '","kid":"kid-1}'));
        _refuses(_withBody(body), abi.encodeWithSelector(JwtRootsBase.UnterminatedMember.selector, "keys"));
    }

    function test_refusesAnUnterminatedKeysArray() public {
        _refuses(
            _withBody(abi.encodePacked('{"keys":[', _jwk("kid-1", _modulus("one")))),
            abi.encodeWithSelector(JwtRootsBase.UnterminatedMember.selector, "keys")
        );
        // An element that is not an object.
        _refuses(
            _withBody(abi.encodePacked('{"keys":[', _jwk("kid-1", _modulus("one")), ',"x"]}')),
            abi.encodeWithSelector(JwtRootsBase.UnterminatedMember.selector, "keys")
        );
        // An object with no closing brace.
        _refuses(
            _withBody(abi.encodePacked('{"keys":[{"kid":"kid-1","n":"', _modulus("one"), '"')),
            abi.encodeWithSelector(JwtRootsBase.UnterminatedMember.selector, "keys")
        );
    }

    /// A backslash is refused: kids and base64url moduli need no escapes, and the
    /// parser does not unescape.
    function test_refusesAnEscapedValue() public {
        bytes memory body = _body(abi.encodePacked('{"kid":"kid\\"1","n":"', _modulus("one"), '"}'));
        _refuses(_withBody(body), abi.encodeWithSelector(JwtRootsBase.EscapedValue.selector, "kid"));
    }

    /// A member array of plain strings is stepped over unread; an object, or an
    /// array holding an object or array, is refused.
    function test_refusesANestedObject() public {
        bytes memory body = _body(abi.encodePacked('{"kid":"kid-1","inner":{},"n":"', _modulus("one"), '"}'));
        _refuses(_withBody(body), JwtRootsBase.UnexpectedNesting.selector);
        body = _body(abi.encodePacked('{"kid":"kid-1","x5c":["a",{}],"n":"', _modulus("one"), '"}'));
        _refuses(_withBody(body), JwtRootsBase.UnexpectedNesting.selector);
        body = _body(abi.encodePacked('{"kid":"kid-1","x5c":[["a"]],"n":"', _modulus("one"), '"}'));
        _refuses(_withBody(body), JwtRootsBase.UnexpectedNesting.selector);
    }

    function test_acceptsAFlatStringArrayInAKey() public {
        _rotate(
            _reading(
                _body(abi.encodePacked('{"kid":"kid-1","x5c":["MIIC", "x"],"n":"', _modulus("one"), '","e":"AQAB"}'))
            )
        );
        assertEq(_current().moduli, _one(_hash("one")));
    }

    /// A `]` inside an array's string does not close it, an array may close the
    /// key, and a key without `kty` is read. A backslash in an array is refused.
    function test_arrayStringsAndAnUntypedKey() public {
        _rotate(_reading(_body(abi.encodePacked('{"kid":"k","n":"', _modulus("one"), '","e":"AQAB","x5c":["]{["]}'))));
        assertEq(_current().moduli, _one(_hash("one")));
        bytes memory body = _body(abi.encodePacked('{"kid":"k","x5c":["a\\b"],"n":"', _modulus("one"), '","e":"AQAB"}'));
        _refuses(_withBody(body), JwtRootsBase.UnexpectedNesting.selector);
    }

    /// The list names Google's JWKS host.
    function test_namesItsHost() public view {
        assertEq(roots.AUTHORITY(), AUTHORITY);
    }

    /// A request shorter than its line is refused by name.
    function test_aShortRequestIsTheWrongLine() public {
        _refuses(_withRequest("GET /oauth2/v3/certs\r\n\r\n"), JwtRootsBase.WrongRequestLine.selector);
    }

    /// One reading carries at most MAX_KEYS keys, and the refusal names how
    /// many it carried. The cap itself is accepted.
    function test_refusesNineKeys() public {
        uint256 max = roots.MAX_KEYS();
        assertEq(max, 8);
        _refuses(_withBody(_manyKeys(max + 1)), abi.encodeWithSelector(JwtRootsBase.TooManyKeys.selector, max + 1));
        _rotate(_withBody(_manyKeys(max)));
        assertEq(_current().moduli.length, max, "the cap itself is a valid reading");
    }

    /// Brackets and braces inside a JWK's strings are string bytes, and an
    /// escaped quote does not end one.
    function test_bracketsInsideStringsDoNotNest() public {
        bytes memory body = _body(
            abi.encodePacked('{"kty":"RSA","use":"a\\"[","kid":"a[","n":"', _modulus("one"), '","e":"AQAB","x":"}{"}')
        );
        _rotate(_withBody(body));
        assertEq(_current().moduli, _one(_hash("one")));
    }

    /// Skipped keys count toward MAX_KEYS too.
    function test_refusesTooManyNonRsaKeys() public {
        uint256 max = roots.MAX_KEYS();
        bytes memory list = '{"kty":"EC","kid":"0"}';
        for (uint256 i = 1; i <= max; ++i) {
            list = abi.encodePacked(list, ',{"kty":"EC","kid":"', vm.toString(i), '"}');
        }
        _refuses(_withBody(_body(list)), abi.encodeWithSelector(JwtRootsBase.TooManyKeys.selector, max + 1));
    }

    /// The same modulus twice is not a set.
    function test_refusesADuplicateModulus() public {
        bytes memory body = _twoKeys("kid-1", "one", "kid-2", "one");
        _refuses(_withBody(body), abi.encodeWithSelector(JwtRootsBase.DuplicateKey.selector, _hash("one")));
    }

    function test_refusesTrailingBytes() public {
        bytes memory body = _oneKey("kid-1", "one");
        _refuses(_withBody(abi.encodePacked(body, "x")), JwtRootsBase.TrailingBytes.selector);
        _refuses(_withBody(abi.encodePacked(body, "{}")), JwtRootsBase.TrailingBytes.selector);
        // No closing brace at all.
        _refuses(_withBody(_slice(body, 0, body.length - 1)), JwtRootsBase.TrailingBytes.selector);
        // Trailing whitespace, as Google sends, is accepted.
        _rotate(_withBody(abi.encodePacked(body, "\n")));
    }

    /// The circuit takes a 2048-bit modulus and nothing else.
    function test_refusesAShortModulus() public {
        bytes memory body = _body(_jwk("kid-1", string(_b64url(_bytes("short", 255)))));
        _refuses(_withBody(body), JwtRootsBase.InvalidModulusLength.selector);
    }

    function test_refusesANonBase64urlCharacter() public {
        bytes memory body = _body(_jwk("kid-1", "AAA+"));
        _refuses(_withBody(body), JwtRootsBase.InvalidB64Char.selector);
    }

    function test_refusesAnImpossibleBase64Length() public {
        bytes memory body = _body(_jwk("kid-1", "AAAAA"));
        _refuses(_withBody(body), JwtRootsBase.InvalidB64Length.selector);
    }

    /// A reading with no keys is refused; it would shift the live set into `previous`.
    function test_refusesAnEmptyKeySet() public {
        _refuses(_withBody('{"keys":[]}'), JwtRootsBase.EmptyKeySet.selector);
        _refuses(_withBody('{"keys": [ ]}'), JwtRootsBase.EmptyKeySet.selector);
    }

    /// A framing header that appears twice, or both framings at once, is refused.
    function test_refusesDuplicateOrConflictingFramingHeaders() public {
        bytes memory body = _oneKey("kid-1", "one");
        bytes memory length = abi.encodePacked("content-length: ", vm.toString(body.length), "\r\n");
        _refuses(
            _withResponse(abi.encodePacked(STATUS_OK, CONTENT_TYPE, length, length, "\r\n", body)),
            abi.encodeWithSelector(JwtRootsBase.DuplicateFramingHeader.selector, "content-length", 2)
        );
        bytes memory chunked = "transfer-encoding: chunked\r\n";
        _refuses(
            _withResponse(
                abi.encodePacked(
                    STATUS_OK, CONTENT_TYPE, chunked, "Transfer-Encoding: identity\r\n", "\r\n", _chunks(body, 64)
                )
            ),
            abi.encodeWithSelector(JwtRootsBase.DuplicateFramingHeader.selector, "transfer-encoding", 2)
        );
        _refuses(
            _withResponse(abi.encodePacked(STATUS_OK, CONTENT_TYPE, chunked, length, "\r\n", _chunks(body, 64))),
            JwtRootsBase.ConflictingFraming.selector
        );
        // A coding other than chunked frames a body this contract cannot locate.
        _refuses(
            _withResponse(abi.encodePacked(STATUS_OK, CONTENT_TYPE, "transfer-encoding: gzip\r\n", "\r\n", body)),
            JwtRootsBase.BadChunkFraming.selector
        );
    }

    // ─── Helpers ────────────────────────────────────────────────────

    function _slice(bytes memory data, uint256 from, uint256 to) private pure returns (bytes memory out) {
        out = new bytes(to - from);
        for (uint256 i = 0; i < out.length; ++i) {
            out[i] = data[from + i];
        }
    }
}

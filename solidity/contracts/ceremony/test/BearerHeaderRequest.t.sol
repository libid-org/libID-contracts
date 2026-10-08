// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {CeremonyAttestation} from "../CeremonyAttestation.sol";

/// @notice The identity-session request checks of REQ-COMMON-35, -39 and -40,
///         exercised against the attacks each one exists to stop.
/// @dev Mirrors `libid-rs/crates/libid-ceremony/src/attestation.rs`.
contract BearerHeaderRequestTest is Test {
    bytes constant BEARER = "AAAAbbbbCCCCdddd";

    function run(CeremonyAttestation.DirectionBlock memory block_, uint32 length)
        external
        pure
        returns (CeremonyAttestation.RangeCommitment memory commitment)
    {
        (commitment,) = CeremonyAttestation.requireBearerHeaderRequest(block_, length);
    }

    /// A real `/2/users/me` request: the bearer committed, every other byte
    /// revealed, tiled exactly.
    function _request(string memory extraHeader, string memory bearerPrefix)
        private
        pure
        returns (CeremonyAttestation.DirectionBlock memory block_, uint32 length)
    {
        return _request(extraHeader, bearerPrefix, "\r\nconnection: close\r\n\r\n");
    }

    /// The same, with `tail` revealed after the committed bearer.
    function _request(string memory extraHeader, string memory bearerPrefix, bytes memory tail)
        private
        pure
        returns (CeremonyAttestation.DirectionBlock memory block_, uint32 length)
    {
        bytes memory head = abi.encodePacked(
            "GET /2/users/me HTTP/1.1\r\naccept: application/json\r\nhost: api.x.com\r\n", extraHeader, bearerPrefix
        );
        uint32 start = uint32(head.length);
        uint32 end = start + uint32(BEARER.length);
        length = end + uint32(tail.length);

        block_.revealed = new CeremonyAttestation.RevealedRange[](2);
        block_.revealed[0] = CeremonyAttestation.RevealedRange({start: 0, end: start, value: head});
        block_.revealed[1] = CeremonyAttestation.RevealedRange({start: end, end: length, value: tail});
        block_.commitments = new CeremonyAttestation.RangeCommitment[](1);
        block_.commitments[0] =
            CeremonyAttestation.RangeCommitment({start: start, end: end, commitment: bytes32(uint256(5))});
    }

    function _honest() private pure returns (CeremonyAttestation.DirectionBlock memory block_, uint32 length) {
        return _request("", "authorization: Bearer ");
    }

    /// @dev The prover picks where the reveals are cut. Cutting one through the
    ///      middle of a second `\r\nauthorization:` used to make neither half
    ///      contain the needle -- two header lines, a count of one, and the
    ///      platform answering to whichever bearer it honoured. The count runs
    ///      over the concatenation for exactly this.
    function test_rejectsANeedleSplitAcrossAdjacentRanges() public {
        bytes memory head = "GET /2/users/me HTTP/1.1\r\nhost: api.x.com";
        bytes memory victim = "\r\nauthorization: Bearer VICTIMTOKENVICTIM";
        bytes memory own = "\r\nauthorization: Bearer ";
        bytes memory tail = "\r\nconnection: close\r\n\r\n";

        // The cut falls six bytes into the victim's needle.
        uint32 cut = uint32(head.length + 6);
        bytes memory a = abi.encodePacked(head, _slice(victim, 0, 6));
        bytes memory b = abi.encodePacked(_slice(victim, 6, victim.length), own);
        uint32 bearerStart = uint32(a.length + b.length);
        uint32 bearerEnd = bearerStart + 16;
        uint32 total = bearerEnd + uint32(tail.length);

        CeremonyAttestation.RevealedRange[] memory rev = new CeremonyAttestation.RevealedRange[](3);
        rev[0] = CeremonyAttestation.RevealedRange({start: 0, end: cut, value: a});
        rev[1] = CeremonyAttestation.RevealedRange({start: cut, end: bearerStart, value: b});
        rev[2] = CeremonyAttestation.RevealedRange({start: bearerEnd, end: total, value: tail});
        CeremonyAttestation.RangeCommitment[] memory com = new CeremonyAttestation.RangeCommitment[](1);
        com[0] =
            CeremonyAttestation.RangeCommitment({start: bearerStart, end: bearerEnd, commitment: bytes32(uint256(1))});

        vm.expectPartialRevert(CeremonyAttestation.NotOneAuthorizationHeader.selector);
        this.run(CeremonyAttestation.DirectionBlock({revealed: rev, commitments: com}), total);
    }

    function _slice(bytes memory d, uint256 f, uint256 t) private pure returns (bytes memory o) {
        o = new bytes(t - f);
        for (uint256 i = 0; i < o.length; ++i) {
            o[i] = d[f + i];
        }
    }

    function test_acceptsAnHonestIdentityRequest() public view {
        (CeremonyAttestation.DirectionBlock memory b, uint32 len) = _honest();
        CeremonyAttestation.RangeCommitment memory c = this.run(b, len);
        assertEq(c.commitment, bytes32(uint256(5)));
    }

    function test_rejectsASecondAuthorizationHeader() public {
        (CeremonyAttestation.DirectionBlock memory b, uint32 len) =
            _request("authorization: Bearer stolen\r\n", "authorization: Bearer ");
        vm.expectRevert(abi.encodeWithSelector(CeremonyAttestation.NotOneAuthorizationHeader.selector, 2));
        this.run(b, len);
    }

    /// @dev Field names and the scheme token are case-insensitive and the colon
    ///      admits whitespace, so a literal search would miss this one.
    function test_rejectsACaseAndWhitespaceEvadedSecondHeader() public {
        (CeremonyAttestation.DirectionBlock memory b, uint32 len) =
            _request("AuThOrIzAtIoN:\tBeArEr stolen\r\n", "authorization: Bearer ");
        vm.expectRevert(abi.encodeWithSelector(CeremonyAttestation.NotOneAuthorizationHeader.selector, 2));
        this.run(b, len);
    }

    /// @dev The gap a security review found. `authorization:\r\n Bearer x`
    ///      normalizes to `authorization:\r\nbearer`, so the needle does not
    ///      match and the header is never counted.
    function test_rejectsAnObsoleteLineFold() public {
        (CeremonyAttestation.DirectionBlock memory b, uint32 len) =
            _request("authorization:\r\n Bearer stolen\r\n", "authorization: Bearer ");
        vm.expectPartialRevert(CeremonyAttestation.ObsoleteLineFold.selector);
        this.run(b, len);
    }

    function test_rejectsARequestWithNoAuthorizationHeader() public {
        (CeremonyAttestation.DirectionBlock memory b, uint32 len) = _request("", "x-other: ");
        vm.expectRevert(abi.encodeWithSelector(CeremonyAttestation.NotOneAuthorizationHeader.selector, 0));
        this.run(b, len);
    }

    /// @dev Why the three are one call: open a gap and the hidden bytes are
    ///      never scanned at all.
    function test_rejectsAGapTheScanWouldNeverRead() public {
        (CeremonyAttestation.DirectionBlock memory b, uint32 len) = _honest();
        b.revealed[0].end -= 1;
        bytes memory v = b.revealed[0].value;
        assembly ("memory-safe") {
            mstore(v, sub(mload(v), 1))
        }
        vm.expectPartialRevert(CeremonyAttestation.CoverageGap.selector);
        this.run(b, len);
    }

    /// @dev Framing alone: the authorization header is whole and revealed, so
    ///      the needle counts once and coverage is exact, but the committed
    ///      range sits in the `host` header instead.
    function test_rejectsACommitmentThatIsNotTheHeaderValue() public {
        bytes memory head =
            "GET /2/users/me HTTP/1.1\r\naccept: application/json\r\nauthorization: Bearer TOKEN123\r\nhost: ";
        bytes memory committed = "api.";
        bytes memory tail = "x.com\r\nconnection: close\r\n\r\n";
        uint32 start = uint32(head.length);
        uint32 end = start + uint32(committed.length);
        uint32 len = end + uint32(tail.length);

        CeremonyAttestation.DirectionBlock memory b;
        b.revealed = new CeremonyAttestation.RevealedRange[](2);
        b.revealed[0] = CeremonyAttestation.RevealedRange({start: 0, end: start, value: head});
        b.revealed[1] = CeremonyAttestation.RevealedRange({start: end, end: len, value: tail});
        b.commitments = new CeremonyAttestation.RangeCommitment[](1);
        b.commitments[0] =
            CeremonyAttestation.RangeCommitment({start: start, end: end, commitment: bytes32(uint256(5))});

        vm.expectRevert(CeremonyAttestation.BadBearerFraming.selector);
        this.run(b, len);
    }

    /// @dev Several commitments would leave the framed range and the range the
    ///      circuit opens unrelated.
    function test_rejectsMoreThanOneCommitment() public {
        (CeremonyAttestation.DirectionBlock memory b, uint32 len) = _honest();
        CeremonyAttestation.RangeCommitment[] memory two = new CeremonyAttestation.RangeCommitment[](2);
        two[0] = CeremonyAttestation.RangeCommitment({start: 0, end: 1, commitment: bytes32(uint256(6))});
        two[1] = b.commitments[0];
        b.commitments = two;
        vm.expectRevert(abi.encodeWithSelector(CeremonyAttestation.NotOneCommitment.selector, 2));
        this.run(b, len);
    }

    // ─── One request ────────────────────────────────────────────────

    function _withTail(bytes memory tail) private pure returns (CeremonyAttestation.DirectionBlock memory, uint32) {
        return _request("", "authorization: Bearer ", tail);
    }

    /// @dev The session carries one request, as the token session does: a
    ///      second head after the first is refused, whatever it carries.
    function test_rejectsASecondRequestAfterTheFirst() public {
        (CeremonyAttestation.DirectionBlock memory b, uint32 len) =
            _withTail("\r\nconnection: close\r\n\r\nGET /2/users/me HTTP/1.1\r\nhost: api.x.com\r\n\r\n");
        vm.expectRevert(abi.encodeWithSelector(CeremonyAttestation.NotOneRequest.selector, 2));
        this.run(b, len);
    }

    /// @dev Including one with an authorization header of its own: the one
    ///      request is required before any header is counted.
    function test_rejectsASecondRequestCarryingItsOwnAuthorization() public {
        (CeremonyAttestation.DirectionBlock memory b, uint32 len) = _withTail(
            "\r\n\r\nGET /2/users/me HTTP/1.1\r\nhost: api.x.com\r\nauthorization: Bearer OTHERTOKENOTHERT\r\n\r\n"
        );
        vm.expectRevert(abi.encodeWithSelector(CeremonyAttestation.NotOneRequest.selector, 2));
        this.run(b, len);
    }

    /// @dev A GET has no body, so nothing may follow its head.
    function test_rejectsBytesAfterTheHead() public {
        (CeremonyAttestation.DirectionBlock memory b, uint32 len) = _withTail("\r\nconnection: close\r\n\r\nGET");
        vm.expectRevert(abi.encodeWithSelector(CeremonyAttestation.BytesAfterRequest.selector, 3));
        this.run(b, len);
    }

    function test_rejectsARequestWithNoHeadEnd() public {
        (CeremonyAttestation.DirectionBlock memory b, uint32 len) = _withTail("\r\nconnection: close\r\n");
        vm.expectRevert(abi.encodeWithSelector(CeremonyAttestation.NotOneRequest.selector, 0));
        this.run(b, len);
    }

    /// @dev A head end cut across two revealed ranges is still one, counted
    ///      over the join: the honest request verifies however it is cut.
    function test_acceptsAHeadEndCutAcrossTwoRanges() public view {
        (CeremonyAttestation.DirectionBlock memory b, uint32 len) = _honest();
        this.run(_cutLast(b, 2), len);
    }

    /// @dev And a second head end cut that way is still counted.
    function test_rejectsASecondHeadEndCutAcrossTwoRanges() public {
        (CeremonyAttestation.DirectionBlock memory b, uint32 len) =
            _withTail("\r\n\r\nGET /2/users/me HTTP/1.1\r\n\r\n");
        vm.expectRevert(abi.encodeWithSelector(CeremonyAttestation.NotOneRequest.selector, 2));
        this.run(_cutLast(b, 3), len);
    }

    /// @dev A committed range after the last revealed byte is bytes after the
    ///      head too, read off the signed length rather than the join.
    function test_rejectsACommittedRangeAfterTheHead() public {
        (CeremonyAttestation.DirectionBlock memory b, uint32 len) = _honest();
        CeremonyAttestation.RangeCommitment[] memory com = new CeremonyAttestation.RangeCommitment[](2);
        com[0] = b.commitments[0];
        com[1] = CeremonyAttestation.RangeCommitment({start: len, end: len + 7, commitment: bytes32(uint256(6))});
        b.commitments = com;
        bytes memory revealed = CeremonyAttestation.concatRevealed(b);
        vm.expectRevert(abi.encodeWithSelector(CeremonyAttestation.BytesAfterRequest.selector, 7));
        this.oneRequest(b, revealed, len + 7);
    }

    function oneRequest(CeremonyAttestation.DirectionBlock memory block_, bytes memory revealed, uint32 length)
        external
        pure
    {
        CeremonyAttestation.requireOneBodilessRequest(block_, revealed, length);
    }

    /// `b` with its last revealed range cut in two, `back` bytes from its end.
    function _cutLast(CeremonyAttestation.DirectionBlock memory b, uint256 back)
        private
        pure
        returns (CeremonyAttestation.DirectionBlock memory)
    {
        uint256 n = b.revealed.length;
        CeremonyAttestation.RevealedRange memory last = b.revealed[n - 1];
        uint256 at = last.value.length - back;
        // forge-lint: disable-next-line(unsafe-typecast)
        uint32 cut = last.start + uint32(at);
        CeremonyAttestation.RevealedRange[] memory rev = new CeremonyAttestation.RevealedRange[](n + 1);
        for (uint256 i = 0; i + 1 < n; ++i) {
            rev[i] = b.revealed[i];
        }
        rev[n - 1] = CeremonyAttestation.RevealedRange({start: last.start, end: cut, value: _slice(last.value, 0, at)});
        rev[n] = CeremonyAttestation.RevealedRange({
            start: cut, end: last.end, value: _slice(last.value, at, last.value.length)
        });
        b.revealed = rev;
        return b;
    }
}

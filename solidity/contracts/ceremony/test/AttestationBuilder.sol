// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";

import {ICeremony} from "../ICeremony.sol";

/// @notice Builds platform-ceremonies section 4.1 attested data, for tests only.
///
/// @dev The inverse of `CeremonyAttestation.decode`. Rust-versus-Solidity
///      agreement on these bytes is proven separately, by the pinned fixture in
///      `CeremonyAttestation.t.sol`; this exists so a test can vary one field of
///      a session and watch a verifier refuse it.
library AttestationBuilder {
    Vm private constant VM = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    /// @dev No `end`: a revealed range's length is its bytes, and the encoder
    ///      writes that length. A separate `end` would be a field a test could
    ///      set and watch do nothing.
    struct Range {
        uint32 start;
        bytes value;
    }

    struct Commitment {
        uint32 start;
        uint32 end;
        bytes32 value;
    }

    struct Direction {
        Range[] revealed;
        Commitment[] commitments;
        uint32 length;
    }

    function encode(bytes32 authorityId, uint64 createdAt, Direction memory sent, Direction memory received)
        internal
        pure
        returns (bytes memory out)
    {
        out = abi.encodePacked(authorityId, createdAt, sent.length, received.length);
        out = abi.encodePacked(out, _direction(sent), _direction(received));
    }

    function _direction(Direction memory d) private pure returns (bytes memory out) {
        out = abi.encodePacked(uint64(d.revealed.length));
        for (uint256 i = 0; i < d.revealed.length; ++i) {
            out = abi.encodePacked(out, d.revealed[i].start, uint64(d.revealed[i].value.length), d.revealed[i].value);
        }
        out = abi.encodePacked(out, uint64(d.commitments.length));
        for (uint256 i = 0; i < d.commitments.length; ++i) {
            out = abi.encodePacked(out, d.commitments[i].start, d.commitments[i].end, d.commitments[i].value);
        }
    }

    function one(Range memory r) internal pure returns (Range[] memory out) {
        out = new Range[](1);
        out[0] = r;
    }

    function two(Range memory a, Range memory b) internal pure returns (Range[] memory out) {
        out = new Range[](2);
        out[0] = a;
        out[1] = b;
    }

    function one(Commitment memory c) internal pure returns (Commitment[] memory out) {
        out = new Commitment[](1);
        out[0] = c;
    }

    function three(Range memory a, Range memory b, Range memory c) internal pure returns (Range[] memory out) {
        out = new Range[](3);
        out[0] = a;
        out[1] = b;
        out[2] = c;
    }

    function three(Commitment memory a, Commitment memory b, Commitment memory c)
        internal
        pure
        returns (Commitment[] memory out)
    {
        out = new Commitment[](3);
        out[0] = a;
        out[1] = b;
        out[2] = c;
    }

    function none() internal pure returns (Commitment[] memory out) {
        out = new Commitment[](0);
    }

    function two(Commitment memory a, Commitment memory b) internal pure returns (Commitment[] memory out) {
        out = new Commitment[](2);
        out[0] = a;
        out[1] = b;
    }

    /// @dev Appends `value` to `d` as a revealed range; returns `d` to chain.
    function reveal(Direction memory d, bytes memory value) internal pure returns (Direction memory) {
        Range[] memory grown = new Range[](d.revealed.length + 1);
        for (uint256 i = 0; i < d.revealed.length; ++i) {
            grown[i] = d.revealed[i];
        }
        grown[d.revealed.length] = Range({start: d.length, value: value});
        d.revealed = grown;
        d.length += uint32(value.length);
        return d;
    }

    /// @dev `value` committed under `commitment` at the end of `d`. The
    ///      bytes themselves are not recorded, only how many there are.
    function commit(Direction memory d, bytes memory value, bytes32 commitment)
        internal
        pure
        returns (Direction memory)
    {
        Commitment[] memory grown = new Commitment[](d.commitments.length + 1);
        for (uint256 i = 0; i < d.commitments.length; ++i) {
            grown[i] = d.commitments[i];
        }
        uint32 end = d.length + uint32(value.length);
        grown[d.commitments.length] = Commitment({start: d.length, end: end, value: commitment});
        d.commitments = grown;
        d.length = end;
        return d;
    }

    /// @dev `attested` signed by `key` as the Notary Service checks it: an
    ///      EIP-191 signature over `keccak256(attested)`, as `r || s || v`.
    function sign(uint256 key, bytes memory attested) internal pure returns (bytes memory) {
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(attested)));
        (uint8 v, bytes32 r, bytes32 s) = VM.sign(key, ethHash);
        return abi.encodePacked(r, s, v);
    }

    /// @dev The attestation at `key` (`.token`, `.identity`) of a libid-rs
    ///      session fixture.
    function fixtureSession(string memory json, string memory key)
        internal
        pure
        returns (ICeremony.Attestation memory)
    {
        return ICeremony.Attestation({
            attestedData: VM.parseJsonBytes(json, string.concat(key, ".attested_data")),
            proof: VM.parseJsonBytes(json, string.concat(key, ".notary_signature"))
        });
    }

    /// @dev The 32-byte node a circuit writes into its public inputs as two
    ///      16-byte halves, `[high, low]`, at `i` and `i + 1`.
    function nodeAt(bytes32[] memory inputs, uint256 i) internal pure returns (bytes32) {
        return bytes32((uint256(inputs[i]) << 128) | uint256(inputs[i + 1]));
    }

    /// @dev The offset of the first `needle` in `haystack`, or `max`.
    function indexOf(bytes memory haystack, bytes memory needle) internal pure returns (uint256) {
        if (needle.length > haystack.length) return type(uint256).max;
        for (uint256 i = 0; i + needle.length <= haystack.length; ++i) {
            bool same = true;
            for (uint256 j = 0; j < needle.length && same; ++j) {
                same = haystack[i + j] == needle[j];
            }
            if (same) return i;
        }
        return type(uint256).max;
    }

    function contains(bytes memory haystack, bytes memory needle) internal pure returns (bool) {
        return indexOf(haystack, needle) != type(uint256).max;
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Turns a handle a caller typed into the one form the identity
///         circuits hash into a node.
///
/// @dev The transform is closed and refuses rather than repairs: A-Z fold to
///      a-z, and nothing is trimmed or stripped. It reads bytes, it does not
///      fold Unicode, and it never consults a table outside this file.
///
///      The circuit is what keys a binding: it folds the handle the platform
///      sent and outputs its node. This copy serves the plaintext a caller
///      hands the registry -- a disclosure, a lookup -- and must agree with
///      the circuit byte for byte, or a disclosed name would not hash to the
///      node it names. Every rule below is exercised by the vector table in
///      `contracts/handles/handles.json`, which the circuits, Rust and
///      TypeScript run too.
library HandleNormalizer {
    /// Nothing is left after the transform.
    error EmptyHandle();
    /// More bytes than the platform allows.
    error HandleTooLong();
    /// A byte the platform does not allow.
    error BadCharacter();
    /// Allowed bytes in an arrangement the platform does not allow.
    error BadShape();

    /// @notice What one platform accepts. Each platform's rules are a
    ///         `HandleVectors` constant generated from `handles.json`, the
    ///         table its circuit folds handles with; a new platform is a
    ///         `handles.json` entry and a circuit of its own.
    ///
    /// @param maxLength       Bytes allowed.
    /// @param isEmail         Validate as an address instead of a bare handle.
    /// @param allowUnderscore Allowed by X, not by GitHub.
    /// @param allowHyphen     Allowed by GitHub, not by X. A hyphen may not
    ///                        start or end the handle, and two may not touch.
    struct Rules {
        uint16 maxLength;
        bool isEmail;
        bool allowUnderscore;
        bool allowHyphen;
    }

    /// @notice What was wrong with a handle, for the readers that answer rather
    ///         than revert.
    enum Problem {
        None,
        Empty,
        TooLong,
        BadChar,
        Shape
    }

    /// @notice The normalized handle, or a revert naming what was wrong.
    ///
    /// @dev The disclosure path. A name a holder asks to publish that does not
    ///      normalize can name no node, and failing loudly is right.
    function normalize(string memory raw, Rules memory rules) internal pure returns (string memory out) {
        Problem problem;
        (problem, out) = tryNormalize(raw, rules);
        if (problem == Problem.Empty) revert EmptyHandle();
        if (problem == Problem.TooLong) revert HandleTooLong();
        if (problem == Problem.BadChar) revert BadCharacter();
        if (problem == Problem.Shape) revert BadShape();
    }

    /// @notice The same transform, reporting instead of reverting.
    ///
    /// @dev The read path. A resolver is asked "who holds this text", and text
    ///      nobody could hold answers "nobody". A caller resolving whatever
    ///      was typed must be able to tell that from a platform it cannot
    ///      reach, and a stray space in a recipient field must not revert the
    ///      transaction around it.
    function tryNormalize(string memory raw, Rules memory rules)
        internal
        pure
        returns (Problem problem, string memory normalized)
    {
        bytes memory input = bytes(raw);
        uint256 length = input.length;
        if (length == 0) return (Problem.Empty, "");
        if (length > rules.maxLength) return (Problem.TooLong, "");

        bytes memory out = new bytes(length);
        for (uint256 i = 0; i < length; i++) {
            bytes1 c = input[i];
            // Fold A-Z down. Nothing else changes, so two addresses that differ
            // in more than case stay two identities.
            if (c >= 0x41 && c <= 0x5A) {
                c = bytes1(uint8(c) + 0x20);
            }
            if (!_allowed(c, rules)) return (Problem.BadChar, "");
            out[i] = c;
        }

        if (rules.isEmail) {
            if (!_hasEmailShape(out)) return (Problem.Shape, "");
        } else if (rules.allowHyphen) {
            if (!_hasHyphenShape(out)) return (Problem.Shape, "");
        }
        return (Problem.None, string(out));
    }

    /// @dev One byte, after folding. Anything outside the platform's set is a
    ///      `BadCharacter`, including every byte above 0x7f, so a multi-byte
    ///      character can never reach a node.
    function _allowed(bytes1 c, Rules memory rules) private pure returns (bool) {
        if (c >= 0x61 && c <= 0x7A) return true; // a-z
        if (c >= 0x30 && c <= 0x39) return true; // 0-9
        if (rules.isEmail) {
            // The set a Google address uses. The dot, the plus and the tag stay
            // exactly as proved: this transform must never map two addresses to
            // one identity.
            return c == 0x2E || c == 0x2B || c == 0x2D || c == 0x5F || c == 0x40;
        }
        if (rules.allowUnderscore && c == 0x5F) return true;
        if (rules.allowHyphen && c == 0x2D) return true;
        return false;
    }

    /// @dev Exactly one `@`, and not at either edge.
    function _hasEmailShape(bytes memory value) private pure returns (bool) {
        uint256 at = type(uint256).max;
        for (uint256 i = 0; i < value.length; i++) {
            if (value[i] == 0x40) {
                if (at != type(uint256).max) return false; // a second one
                at = i;
            }
        }
        if (at == type(uint256).max) return false; // none
        return at != 0 && at != value.length - 1; // an empty side
    }

    /// @dev A hyphen may not start or end the handle, and two may not touch.
    function _hasHyphenShape(bytes memory value) private pure returns (bool) {
        if (value[0] == 0x2D || value[value.length - 1] == 0x2D) return false;
        for (uint256 i = 1; i < value.length; i++) {
            if (value[i] == 0x2D && value[i - 1] == 0x2D) return false;
        }
        return true;
    }

    /// @notice A disclosed handle, normalized, and the node it names:
    ///         `SHA256(tag || normalized)`, the node the platform's circuit
    ///         outputs for that handle.
    ///
    /// @dev The one disclosure computation, for the Platform Verifier checking
    ///      a handle against its proof and the registry checking one a holder
    ///      publishes later. Reverts as `normalize` does.
    function nodeOf(string memory raw, Rules memory rules, bytes memory tag)
        internal
        pure
        returns (string memory normalized, bytes32 handleNode)
    {
        normalized = normalize(raw, rules);
        handleNode = node(tag, normalized);
    }

    /// @notice `SHA256(tag || normalized)`: the node a normalized handle is
    ///         bound under. The one place this contract set writes the
    ///         formula the circuits compute.
    function node(bytes memory tag, string memory normalized) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(tag, normalized));
    }
}

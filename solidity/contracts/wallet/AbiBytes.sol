// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC7579Utils, Execution} from "@openzeppelin/contracts/account/utils/draft-ERC7579Utils.sol";

import {IWebWallet} from "./IWebWallet.sol";

/// The `bytes` member of the ABI tuple `data` whose offset is the head word at `head`.
function bytesAt(bytes calldata data, uint256 head) pure returns (bytes calldata) {
    uint256 offset = uint256(bytes32(data[head:head + 32]));
    uint256 length = uint256(bytes32(data[offset:offset + 32]));
    return data[offset + 32:offset + 32 + length];
}

/// The batch `executionCalldata` decodes to, and whether it is exactly that batch's `abi.encode`: only then is
/// no call read from outside these bytes, so every decoder of them reads the same calls.
function canonicalBatch(bytes calldata executionCalldata) pure returns (Execution[] calldata batch, bool canonical) {
    batch = ERC7579Utils.decodeBatch(executionCalldata);
    uint256 free;
    assembly ("memory-safe") {
        free := mload(0x40)
    }
    canonical = keccak256(abi.encode(batch)) == keccak256(executionCalldata);
    // The encoding's memory is released.
    assembly ("memory-safe") {
        mstore(0x40, free)
    }
}

/// `signature` as an `Authorization`, and whether it is one: every offset and length inside its bytes and `at`
/// 48 bits wide, so the decoder cannot revert. A malformed one decodes to none.
function decodeAuthorization(bytes calldata signature) pure returns (bool ok, IWebWallet.Authorization memory auth) {
    if (!_authorizationFits(signature)) return (false, auth);
    return (true, abi.decode(signature, (IWebWallet.Authorization)));
}

function _authorizationFits(bytes calldata s) pure returns (bool) {
    (bool ok, uint256 t) = _tail(s, 0, 0, 160);
    if (!ok || _wordAt(s, t + 32) >> 48 != 0) return false;
    // signatures: (bytes key, bytes signature)[]
    (bool fits, uint256 heads, uint256 n) = _array(s, t, t, 32);
    if (!fits) return false;
    for (uint256 i; i < n; ++i) {
        (bool found, uint256 e) = _tail(s, heads + 32 * i, heads, 64);
        if (!found || !_bytesFit(s, e, e) || !_bytesFit(s, e + 32, e)) return false;
    }
    // calls: (uint256 maxValue, bytes32[] proof)[]
    (fits, heads, n) = _array(s, t + 64, t, 32);
    if (!fits) return false;
    for (uint256 i; i < n; ++i) {
        (bool found, uint256 e) = _tail(s, heads + 32 * i, heads, 64);
        if (!found || !_array32Fits(s, e + 32, e)) return false;
    }
    return _array32Fits(s, t + 96, t) && _array32Fits(s, t + 128, t);
}

/// The position `base` plus the offset at `head`, when `size` bytes from there are inside `s`.
function _tail(bytes calldata s, uint256 head, uint256 base, uint256 size) pure returns (bool, uint256) {
    if (head + 32 > s.length) return (false, 0);
    uint256 offset = uint256(_wordAt(s, head));
    if (offset > s.length) return (false, 0);
    uint256 at = base + offset;
    return (at + size <= s.length, at);
}

/// The array the offset at `head` points to: where its elements start, and its length, when its `size`-byte
/// heads are inside `s`.
function _array(bytes calldata s, uint256 head, uint256 base, uint256 size) pure returns (bool, uint256, uint256) {
    (bool ok, uint256 at) = _tail(s, head, base, 32);
    if (!ok) return (false, 0, 0);
    uint256 n = uint256(_wordAt(s, at));
    return (n <= s.length && at + 32 + n * size <= s.length, at + 32, n);
}

function _array32Fits(bytes calldata s, uint256 head, uint256 base) pure returns (bool ok) {
    (ok,,) = _array(s, head, base, 32);
}

function _bytesFit(bytes calldata s, uint256 head, uint256 base) pure returns (bool ok) {
    (ok,,) = _array(s, head, base, 1);
}

function _wordAt(bytes calldata s, uint256 at) pure returns (bytes32) {
    return bytes32(s[at:at + 32]);
}

/// Whether `b` has the heads, lengths and clean addresses `abi.encode(Execution[])` gives it, so decoding it cannot
/// revert. Its padding is left to the caller's re-encoding.
function executionsFit(bytes memory b) pure returns (bool) {
    uint256 length = b.length;
    if (length < 64 || _mwordAt(b, 0) != 0x20) return false;
    uint256 n = _mwordAt(b, 32);
    if (n > length / 32) return false;
    uint256 at = 64 + 32 * n;
    for (uint256 i; i < n; ++i) {
        if (
            at + 128 > length || _mwordAt(b, 64 + 32 * i) != at - 64 || _mwordAt(b, at) >> 160 != 0
                || _mwordAt(b, at + 64) != 0x60
        ) return false;
        uint256 size = _mwordAt(b, at + 96);
        if (size > length) return false;
        at += 128 + (size + 31) / 32 * 32;
    }
    return at == length;
}

function _mwordAt(bytes memory b, uint256 at) pure returns (uint256 w) {
    assembly ("memory-safe") {
        w := mload(add(add(b, 0x20), at))
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IWebWallet} from "./IWebWallet.sol";

/// An identity: `keccak256(abi.encode(platformId, idNode))`.
function identityOf(bytes32 platformId, bytes32 idNode) pure returns (bytes32) {
    return keccak256(abi.encode(platformId, idNode));
}

/// A rule set's hash, stored with the session and keying its allowance counters.
function rulesHashOf(IWebWallet.Rules memory rules) pure returns (bytes32) {
    return keccak256(abi.encode(rules.scopeRoot, rules.domainsRoot, rules.paymastersRoot, rules.allowances));
}

/// A policy's hash, as a proof commits it.
function policyHashOf(IWebWallet.Policy memory policy) pure returns (bytes32) {
    return keccak256(
        abi.encode(policy.validAfter, policy.validUntil, policy.admin, policy.signers, rulesHashOf(policy.rules))
    );
}

/// @title WalletStorage - the wallet's state, shared by WebWallet and the targets it delegates to.
/// @dev Namespace `erc7201:libid.webwallet.state`: the epoch, then each epoch's state. Moving the epoch drops
///      everything; only a data step that moves it copies the genesis forward.
library WalletStorage {
    uint32 internal constant MAX_ROOT_DELAY = 365 days;

    /// A linked identity: its platform, the generation its live sessions carry, and its admin sessions.
    struct Link {
        bool linked;
        uint32 generation;
        uint32 adminSessions;
        bytes32 platformId;
    }

    /// A platform's linked identities and admin sessions.
    struct PlatformCount {
        uint32 links;
        uint32 admins;
    }

    /// A session; dead once `generation` is not its identity's.
    struct SessionRecord {
        bytes32 identity;
        bytes32 policyHash;
        bytes32 rulesHash;
        bytes32 scopeRoot;
        bytes32 domainsRoot;
        bytes32 paymastersRoot;
        uint48 validAfter;
        uint48 validUntil;
        uint48 activeAt;
        uint32 generation;
        bool admin;
        bool byProof;
        uint8 signers;
    }

    /// A session's counter for one token; `listed` marks a token its rules give an allowance.
    struct Counter {
        uint128 amount;
        uint48 period;
        uint48 periodStart;
        bool listed;
        uint128 spent;
    }

    /// A queued root operation, void once the version or the root epoch moved.
    struct Root {
        bytes data;
        uint64 version;
        uint48 readyAt;
        uint32 rootEpoch;
    }

    /// Everything of one epoch.
    struct EpochState {
        bytes32 platformId;
        bytes32 idNode;
        uint256 salt;
        uint8 threshold;
        bool hadSession;
        uint32 rootDelay;
        uint32 rootEpoch;
        uint32 adminSessions;
        uint32 platforms;
        uint32 adminPlatforms;
        mapping(bytes32 keyHash => SessionRecord) sessions;
        mapping(bytes32 identity => Link) links;
        mapping(bytes32 platformId => PlatformCount) platformCounts;
        mapping(bytes32 counterId => Counter) counters;
        mapping(bytes32 id => Root) roots;
        mapping(bytes32 identity => bytes32[]) appLists;
    }

    /// @custom:storage-location erc7201:libid.webwallet.state
    struct WalletState {
        bytes32 epoch;
        mapping(bytes32 epoch => EpochState) epochs;
    }

    /// What `_verify` found: whether every signature holds, the distinct platforms of its signers and of the
    /// admin sessions among them, the window they share, the latest second a signer was added in, whether any is
    /// by proof, and the first signer's key hash and `signers`.
    struct Verified {
        bool ok;
        uint48 activeAt;
        uint256 platforms;
        uint256 adminPlatforms;
        uint48 validAfter;
        uint48 validUntil;
        bool byProof;
        bytes32 keyHash;
        uint8 signers;
    }

    // cast index-erc7201 libid.webwallet.state
    bytes32 internal constant SLOT = 0x2fefcc1cd2f12f011dc78ce30301455eb7a4a027395fa8fbcaed6284d99cf200;

    function wallet() internal pure returns (WalletState storage $) {
        assembly ("memory-safe") {
            $.slot := SLOT
        }
    }

    /// The current epoch's state.
    function state() internal view returns (EpochState storage) {
        WalletState storage w = wallet();
        return w.epochs[w.epoch];
    }

    function session(bytes32 keyHash) internal view returns (SessionRecord storage) {
        return state().sessions[keyHash];
    }

    /// The counter of key `keyHash` under rules `rulesHash` for `token`.
    function counter(bytes32 keyHash, bytes32 rulesHash, address token) internal view returns (Counter storage) {
        return state().counters[keccak256(abi.encode(keyHash, rulesHash, token))];
    }

    /// Distinct admin platforms an admin operation needs; 1 by default.
    function threshold() internal view returns (uint8) {
        uint8 t = state().threshold;
        return t == 0 ? 1 : t;
    }

    /// Links `identity` of `platformId`; a linked identity stays as it is.
    function link(bytes32 platformId, bytes32 identity) internal {
        EpochState storage s = state();
        Link storage l = s.links[identity];
        if (l.linked) return;
        (l.linked, l.platformId) = (true, platformId);
        if (++s.platformCounts[platformId].links == 1) ++s.platforms;
        emit IWebWallet.IdentityLinked(identity);
    }

    /// Whether the session exists and belongs to its identity's current link.
    function live(SessionRecord storage s) internal view returns (bool) {
        bytes32 identity = s.identity;
        return identity != 0 && s.generation == state().links[identity].generation;
    }

    /// Narrows `v`'s window to `(validAfter, validUntil]`; `validUntil == 0` is unbounded.
    function narrow(Verified memory v, uint48 validAfter, uint48 validUntil) internal pure {
        if (validAfter > v.validAfter) v.validAfter = validAfter;
        if (validUntil != 0 && (v.validUntil == 0 || validUntil < v.validUntil)) v.validUntil = validUntil;
    }

    /// An OpenZeppelin double-hashed Merkle leaf.
    function leaf(bytes memory encoded) internal pure returns (bytes32) {
        return keccak256(bytes.concat(keccak256(encoded)));
    }

    /// The first four bytes: zero for data shorter than four bytes.
    function selectorOf(bytes calldata data) internal pure returns (bytes4) {
        // forge-lint: disable-next-line(unsafe-typecast)
        return data.length < 4 ? bytes4(0) : bytes4(data);
    }
}

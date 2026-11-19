// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IIdentityAdmin, IWebWallet} from "./IWebWallet.sol";

/// An identity: `keccak256(abi.encode(platformId, idNode))`.
function identityOf(bytes32 platformId, bytes32 idNode) pure returns (bytes32) {
    return keccak256(abi.encode(platformId, idNode));
}

/// A rule set's hash, stored with the session and keying its allowance counters.
function rulesHashOf(IIdentityAdmin.Rules memory rules) pure returns (bytes32) {
    return keccak256(abi.encode(rules.scopeRoot, rules.domainsRoot, rules.paymastersRoot, rules.allowances));
}

/// A policy's hash, as a proof commits it.
function policyHashOf(IIdentityAdmin.Policy memory policy) pure returns (bytes32) {
    return policyHashFrom(policy.validAfter, policy.validUntil, policy.admin, policy.signers, rulesHashOf(policy.rules));
}

/// `policyHashOf` from a policy's fields and its rules' hash.
function policyHashFrom(uint48 validAfter, uint48 validUntil, bool admin, uint8 signers, bytes32 rulesHash)
    pure
    returns (bytes32)
{
    return keccak256(abi.encode(validAfter, validUntil, admin, signers, rulesHash));
}

/// @title WalletStorage - the wallet's state, shared by WebWallet and the targets it delegates to.
/// @dev Namespace `erc7201:libid.webwallet.state`: the epoch, then each epoch's state. Moving the epoch drops
///      everything; only a data step that moves it copies the genesis forward.
library WalletStorage {
    uint32 internal constant MAX_ROOT_DELAY = 365 days;

    /// An identity's link, at the index it keeps for the epoch: whether it is linked, the generation its live
    /// sessions carry, its admin sessions and its platform's index, in the one slot validation reads.
    struct Link {
        bool linked;
        uint32 generation;
        uint32 adminSessions;
        uint32 platform;
        bytes32 platformId;
    }

    /// A platform's linked identities and admin sessions, and its index for the epoch.
    struct PlatformCount {
        uint32 links;
        uint32 admins;
        uint32 index;
    }

    /// A session; dead once `generation` is not its link's. Validation at quorum reads only the first slot.
    struct SessionRecord {
        uint48 validAfter;
        uint48 validUntil;
        uint48 activeAt;
        uint32 generation;
        bool admin;
        bool byProof;
        uint8 signers;
        uint32 link;
        bytes32 identity;
        bytes32 rulesHash;
        bytes32 scopeRoot;
        bytes32 domainsRoot;
        bytes32 paymastersRoot;
    }

    /// A session's counter for one token; `listed` marks a token its rules give an allowance.
    struct Counter {
        uint128 amount;
        uint48 period;
        uint48 periodStart;
        bool listed;
        uint128 spent;
    }

    /// A queued root operation, void once the version or the root epoch moved. `implementation`: a bump's.
    struct Root {
        bytes data;
        address implementation;
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
        uint32 linkCount;
        uint32 platformCount;
        mapping(bytes32 keyHash => SessionRecord) sessions;
        mapping(uint32 index => Link) links;
        mapping(bytes32 platformId => PlatformCount) platformCounts;
        mapping(bytes32 counterId => Counter) counters;
        mapping(bytes32 id => Root) roots;
        mapping(bytes32 identity => bytes32[]) appLists;
        mapping(bytes32 identity => uint32) linkIndex;
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

    /// `identity`'s link index and link; index 0, never written, for an identity never linked in this epoch.
    function indexedLinkOf(bytes32 identity) internal view returns (uint32 i, Link storage l) {
        EpochState storage s = state();
        i = s.linkIndex[identity];
        l = s.links[i];
    }

    function linkOf(bytes32 identity) internal view returns (Link storage l) {
        (, l) = indexedLinkOf(identity);
    }

    /// Links `identity` of `platformId`; a linked identity stays as it is. Indices start at 1 and are never
    /// reused, so an unlinked identity's generation persists.
    function link(bytes32 platformId, bytes32 identity) internal {
        EpochState storage s = state();
        uint32 i = s.linkIndex[identity];
        if (i != 0 && s.links[i].linked) return;
        PlatformCount storage p = s.platformCounts[platformId];
        if (i == 0) {
            s.linkIndex[identity] = i = ++s.linkCount;
            if (p.index == 0) p.index = ++s.platformCount;
            (s.links[i].platform, s.links[i].platformId) = (p.index, platformId);
        }
        s.links[i].linked = true;
        if (++p.links == 1) ++s.platforms;
        emit IWebWallet.IdentityLinked(identity);
    }

    /// Whether the session exists and belongs to its link's current generation.
    function live(SessionRecord storage s) internal view returns (bool ok) {
        (ok,) = liveLink(state(), s);
    }

    /// `live`, and the link of `s` in `st`: one slot of the session and one of the link.
    function liveLink(EpochState storage st, SessionRecord storage s) internal view returns (bool, Link storage l) {
        uint32 i = s.link;
        l = st.links[i];
        return (i != 0 && s.generation == l.generation, l);
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

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IIdentityValidator} from "./IIdentityValidator.sol";

/// @title IdentityValidatorState - IdentityValidator's storage, and the helpers its own code and the
///        SessionRules it delegates to share.
/// @dev Every slot validation reads or writes has the account as its innermost mapping key (ERC-7562).
abstract contract IdentityValidatorState {
    /// One install's settings for one account.
    struct AccountState {
        bytes32 platformId;
        bytes32 idNode;
        uint48 recoveryDelay;
        uint8 threshold;
        bool hadSession;
        uint32 adminSessions;
        uint32 identities;
        uint32 rootEpoch;
        uint32 platforms;
    }

    /// What `_verify` found: whether every signature holds, the distinct platforms of its signers and
    /// of its admin sessions, the window they share, whether any signer is a session by proof, and the
    /// first signer's key hash and `signers`.
    struct Verified {
        bool ok;
        uint256 platforms;
        uint256 adminPlatforms;
        uint48 validAfter;
        uint48 validUntil;
        bool byProof;
        bytes32 keyHash;
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

    /// A queued root operation: when it matures, and the root epoch it was queued in.
    struct Root {
        uint48 readyAt;
        uint32 epoch;
    }

    /// @dev Keyed by install, then by item, then by account.
    /// @custom:storage-location erc7201:libid.storage.IdentityValidator
    struct IdentityValidatorStorage {
        mapping(address account => uint256) installs;
        mapping(uint256 install => mapping(address account => AccountState)) accounts;
        mapping(
            uint256 install => mapping(bytes32 keyHash => mapping(address account => IIdentityValidator.Session))
        ) sessions;
        mapping(uint256 install => mapping(bytes32 identity => mapping(address account => bool))) links;
        mapping(uint256 install => mapping(bytes32 identity => mapping(address account => bytes))) pendingKeys;
        mapping(uint256 install => mapping(bytes32 opId => mapping(address account => Root))) roots;
        mapping(uint256 install => mapping(bytes32 identity => mapping(address account => uint32))) generations;
        mapping(uint256 install => mapping(bytes32 identity => mapping(address account => uint32))) adminSessions;
        mapping(uint256 install => mapping(bytes32 identity => mapping(address account => bytes32))) platformOf;
        mapping(uint256 install => mapping(bytes32 platformId => mapping(address account => uint32))) platformLinks;
        mapping(uint256 install => mapping(bytes32 identity => mapping(address account => bool))) recoveryFrozen;
        mapping(uint256 install => mapping(bytes32 counterId => mapping(address account => Counter))) counters;
    }

    // cast index-erc7201 libid.storage.IdentityValidator
    bytes32 private constant IDENTITY_VALIDATOR_STORAGE =
        0x873011f05c4a0f65dcb571f9747866179ce051ed2f0788dad77cc90e91439700;

    function _s() internal pure returns (IdentityValidatorStorage storage $) {
        assembly {
            $.slot := IDENTITY_VALIDATOR_STORAGE
        }
    }

    function _install(address account) internal view returns (uint256) {
        return _s().installs[account];
    }

    function _account(address account) internal view returns (AccountState storage) {
        return _s().accounts[_install(account)][account];
    }

    function _sessions(address account, bytes32 keyHash)
        internal
        view
        returns (mapping(address => IIdentityValidator.Session) storage)
    {
        return _s().sessions[_install(account)][keyHash];
    }

    function _session(address account, bytes memory key) internal view returns (IIdentityValidator.Session storage) {
        return _sessions(account, keccak256(key))[account];
    }

    /// The counter of key `keyHash` under rules `rulesHash` for `token`.
    function _counter(address account, bytes32 keyHash, bytes32 rulesHash, address token)
        internal
        view
        returns (Counter storage)
    {
        return _s().counters[_install(account)][keccak256(abi.encode(keyHash, rulesHash, token))][account];
    }

    function _roots(address account, bytes32 opId) internal view returns (mapping(address => Root) storage) {
        return _s().roots[_install(account)][opId];
    }

    function _generations(address account, bytes32 identity)
        internal
        view
        returns (mapping(address => uint32) storage)
    {
        return _s().generations[_install(account)][identity];
    }

    /// The identity's own admin sessions; `AccountState.adminSessions` counts the account's.
    function _identityAdmins(address account, bytes32 identity)
        internal
        view
        returns (mapping(address => uint32) storage)
    {
        return _s().adminSessions[_install(account)][identity];
    }

    function _platformOf(address account, bytes32 identity) internal view returns (bytes32) {
        return _s().platformOf[_install(account)][identity][account];
    }

    /// The platform's linked identities; `AccountState.platforms` counts the platforms with any.
    function _platformLinks(address account, bytes32 platformId)
        internal
        view
        returns (mapping(address => uint32) storage)
    {
        return _s().platformLinks[_install(account)][platformId];
    }

    /// Narrows `v`'s window to `(validAfter, validUntil]`; `validUntil == 0` is unbounded.
    function _narrow(Verified memory v, uint48 validAfter, uint48 validUntil) internal pure {
        if (validAfter > v.validAfter) v.validAfter = validAfter;
        if (validUntil != 0 && (v.validUntil == 0 || validUntil < v.validUntil)) v.validUntil = validUntil;
    }

    /// An OpenZeppelin double-hashed Merkle leaf.
    function _leaf(bytes memory encoded) internal pure returns (bytes32) {
        return keccak256(bytes.concat(keccak256(encoded)));
    }

    /// The first four bytes: zero for data shorter than four bytes.
    function _selector(bytes calldata data) internal pure returns (bytes4) {
        // forge-lint: disable-next-line(unsafe-typecast)
        return data.length < 4 ? bytes4(0) : bytes4(data);
    }
}

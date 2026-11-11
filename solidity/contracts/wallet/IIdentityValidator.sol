// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC7579Validator} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";

/// An identity: `keccak256(abi.encode(platformId, idNode))`.
function identityOf(bytes32 platformId, bytes32 idNode) pure returns (bytes32) {
    return keccak256(abi.encode(platformId, idNode));
}

/// @title IIdentityValidator - identities, sessions and root operations of ERC-7579 accounts.
/// @notice Constructor: `IdentityValidator(address walletRegistry)`. Immutable, no owner.
/// @dev State is per account and per install: an uninstall drops it.
///      An identity is `identityOf(platformId, idNode)`.
///      A session key is an ERC-7913 signer: a 20-byte address, or `verifier || key`.
///      A policy hash is `keccak256(abi.encode(policy))`.
///      `userOp.signature`, and the ERC-1271 signature after the validator's
///      address, are `abi.encode(SessionSignature[])`. A UserOperation signs
///      `userOpHash`; an ERC-1271 signature signs the ERC-7739 `PersonalSign`
///      hash under the account's `eip712Domain()`.
///      Fresh install data is `abi.encode(platformId, idNode)`: the genesis identity.
interface IIdentityValidator is IERC7579Validator {
    /// @dev `validUntil == 0` never expires. Only admin sessions may change the account.
    struct Policy {
        uint48 validAfter;
        uint48 validUntil;
        bool admin;
    }

    /// @dev `identity == 0`: no such session. `activeAt` is the end of a pending wait.
    ///      A session whose `generation` is not its identity's current one, bumped by each unlink, is dead.
    struct Session {
        bytes32 identity;
        Policy policy;
        uint48 activeAt;
        uint32 generation;
    }

    struct SessionSignature {
        bytes key;
        bytes signature;
    }

    event SessionAdded(address indexed account, bytes32 indexed identity, bytes key, bytes32 policyHash);
    event SessionPending(
        address indexed account, bytes32 indexed identity, bytes key, bytes32 policyHash, uint48 activeAt
    );
    event SessionRevoked(address indexed account, bytes32 indexed identity, bytes key);
    event RootQueued(address indexed account, bytes32 indexed opId, address target, bytes data, uint48 readyAt);
    event RootCancelled(address indexed account, bytes32 indexed opId);
    event RootExecuted(address indexed account, bytes32 indexed opId);
    event IdentityUnlinked(address indexed account, bytes32 indexed identity);

    /// A registry-only entry was called by someone else.
    error NotRegistry(address caller);
    /// The identity is not linked to the account.
    error NotLinked(address account, bytes32 identity);
    /// The change must be queued with `queueRoot`.
    error RootOperationRequired();
    /// No matured root operation with this id.
    error RootNotReady(bytes32 opId);
    /// The recovery delay may only grow, and never below the floor.
    error RecoveryDelayTooShort(uint48 delay);
    /// The recovery delay may not exceed `MAX_RECOVERY_DELAY`.
    error RecoveryDelayTooLong(uint48 delay);
    /// The threshold may not exceed the number of linked identities.
    error ThresholdTooHigh(uint8 threshold, uint32 identities);
    /// An account keeps at least one linked identity.
    error LastIdentity(bytes32 identity);
    /// The unlink would leave the account no admin session.
    error LastAdmin(bytes32 identity);
    /// An unlink ran after the root operation was queued.
    error RootSuperseded(bytes32 opId);
    /// A session key is a 20-byte address or `verifier || key`.
    error InvalidKey(bytes key);
    error SessionExists(bytes key);
    error NoSession(bytes key);
    /// A policy bound reaches bit 47, which EntryPoint v0.9 reads as a block-number flag.
    error PolicyOutOfRange(uint48 validAfter, uint48 validUntil);
    /// A root operation targets the account, or this validator's `setThreshold`, `revokeSession` or `unlink`.
    error BadRootOperation(address target);

    /// The floor of the wait for sessions added by proof.
    function MIN_RECOVERY_DELAY() external view returns (uint48);
    /// The floor of the wait between `queueRoot` and `executeRoot`, which is the account's `recoveryDelay`.
    function ROOT_DELAY() external view returns (uint48);
    /// Ceiling of `recoveryDelay`.
    function MAX_RECOVERY_DELAY() external view returns (uint48);
    function walletRegistry() external view returns (address);

    function genesisIdentity(address account) external view returns (bytes32 platformId, bytes32 idNode);
    function isLinked(address account, bytes32 identity) external view returns (bool);
    function sessionOf(address account, bytes calldata key) external view returns (Session memory);
    /// The identity's current generation: a session of any other is dead.
    function generationOf(address account, bytes32 identity) external view returns (uint32);
    /// Distinct admin identities an admin operation needs. Defaults to 1.
    function threshold(address account) external view returns (uint8);
    function recoveryDelay(address account) external view returns (uint48);
    /// One-way: set once the account has had any session.
    function hadSession(address account) external view returns (bool);
    /// `keccak256(abi.encode(account, target, data))` once queued, else 0; also 0 once an unlink supersedes it.
    function rootReadyAt(address account, bytes32 opId) external view returns (uint48);

    // Registry only.
    function link(address account, bytes32 platformId, bytes32 idNode) external;
    /// Active at once while the account never had a session, else pending for `recoveryDelay`.
    /// A newer pending session of the same identity replaces the older one.
    function addSessionByProof(address account, bytes32 identity, bytes calldata key, Policy calldata policy)
        external
        returns (uint48 activeAt);
    /// Active at once: the account itself submitted the proof.
    function addSessionByAccount(address account, bytes32 identity, bytes calldata key, Policy calldata policy) external;

    // The account itself (an admin operation, under the threshold).
    /// Active at once. The identity must be linked. A dead session's key may be reused.
    function addSession(bytes32 identity, bytes calldata key, Policy calldata policy) external;
    /// Revokes an active or pending session. Removing the last admin session, counting pending and expired ones, is a root operation.
    function revokeSession(bytes calldata key) external;
    function setRecoveryDelay(uint48 delay) external;
    /// Root operation only: reverts `RootOperationRequired` when the account calls it.
    function setThreshold(uint8 threshold_) external;
    /// Root operation only. Every session of the identity, active or pending, stops validating for good,
    /// and every root operation queued before it stops executing.
    /// Refused for an identity not linked, the last one, one the threshold still needs,
    /// or when the account would be left with no admin session.
    function unlink(bytes32 identity) external;
    /// `target` is the account (install, uninstall, upgrade) or this validator
    /// (`setThreshold`, `unlink`, `revokeSession` of the last admin). Ready after `recoveryDelay`.
    function queueRoot(address target, bytes calldata data) external returns (bytes32 opId);
    function cancelRoot(bytes32 opId) external;

    /// Anyone, once `rootReadyAt` has passed, unless an unlink ran since it was queued.
    function executeRoot(address account, address target, bytes calldata data) external;
}

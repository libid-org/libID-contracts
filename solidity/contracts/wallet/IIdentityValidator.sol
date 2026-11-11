// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC7579Validator} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";

/// An identity: `keccak256(abi.encode(platformId, idNode))`.
function identityOf(bytes32 platformId, bytes32 idNode) pure returns (bytes32) {
    return keccak256(abi.encode(platformId, idNode));
}

/// A policy's hash, as a proof commits it.
function policyHashOf(IIdentityValidator.Policy memory policy) pure returns (bytes32) {
    return keccak256(abi.encode(policy));
}

/// @title IIdentityValidator - identities, sessions and root operations of ERC-7579 accounts.
/// @notice Constructor: `IdentityValidator(address walletRegistry)`, deployed by the WalletRegistry's
///         own constructor. Immutable, no owner.
/// @dev State is per account and per install: an uninstall drops it.
///      An identity is `identityOf(platformId, idNode)`.
///      A session key is an ERC-7913 signer: a 20-byte address, or `verifier || key`.
///      A policy hash is `policyHashOf(policy)`.
///      `userOp.signature` is `abi.encode(SessionSignature[])` over `userOpHash`.
///      The ERC-1271 signature after the validator's address is an ERC-7739 nested signature
///      under the account's `eip712Domain()`: `PersonalSign`, or `TypedDataSign` followed by the
///      app separator, contents hash and contents type. Its signature part is `abi.encode(SessionSignature[])`.
///      `isValidSignatureWithSender(_, 0x7739…7739, "")` answers `0x77390001` (ERC-7739 detection).
///      Fresh install data is `abi.encode(platformId, idNode)`: the genesis identity.
///      `onInstall` and `onUninstall` run only from the account's own install and uninstall:
///      they revert while the account has this validator installed.
///      `onUninstall` expects the account to remove the module before it calls the hook, the order
///      of OpenZeppelin's `AccountERC7579`: an account that calls the hook first cannot uninstall.
///      Revoking an active admin session, or unlinking an identity, voids every root operation
///      queued before it: a queued change does not outlive the sessions that could have queued it.
interface IIdentityValidator is IERC7579Validator {
    /// @dev `validUntil == 0` never expires. Only admin sessions may change the account.
    struct Policy {
        uint48 validAfter;
        uint48 validUntil;
        bool admin;
    }

    /// @dev `identity == 0`: no such session. `activeAt` is the end of a pending wait.
    ///      A session whose `generation` is not its identity's current one, bumped by each unlink, is dead.
    ///      `byProof`: added by proof to an account that already had a session. Its operations, ordinary
    ///      calls and ERC-1271 signatures included, need signers that reach the threshold.
    ///      A non-admin session by proof counts toward no platform, so it never acts alone.
    struct Session {
        bytes32 identity;
        Policy policy;
        uint48 activeAt;
        uint32 generation;
        bool byProof;
    }

    struct SessionSignature {
        bytes key;
        bytes signature;
    }

    /// A session added by the account itself.
    event SessionAdded(address indexed account, bytes32 indexed identity, bytes key, Policy policy);
    /// A session added by proof, the event to alert on: `activeAt != 0` is pending until then.
    event SessionAddedByProof(
        address indexed account, bytes32 indexed identity, bytes key, Policy policy, uint48 activeAt
    );
    event SessionRevoked(address indexed account, bytes32 indexed identity, bytes key);
    event RootQueued(address indexed account, bytes32 indexed opId, address target, bytes data, uint48 readyAt);
    event RootCancelled(address indexed account, bytes32 indexed opId);
    event RootExecuted(address indexed account, bytes32 indexed opId);
    event IdentityUnlinked(address indexed account, bytes32 indexed identity);

    /// The account still has this validator installed: its hooks run only from the account's own
    /// install and uninstall.
    error InstallLive(address account);
    /// The account has no install of this validator to end.
    error NotInstalled(address account);
    /// A registry-only entry was called by someone else.
    error NotRegistry(address caller);
    /// The identity is not linked to the account.
    error NotLinked(address account, bytes32 identity);
    /// The change must be queued with `queueRoot`.
    error RootOperationRequired();
    /// No matured root operation with this id.
    error RootNotReady(bytes32 opId);
    /// The recovery delay may not go below `MIN_RECOVERY_DELAY`.
    error RecoveryDelayTooShort(uint48 delay);
    /// The recovery delay may not exceed `MAX_RECOVERY_DELAY`.
    error RecoveryDelayTooLong(uint48 delay);
    /// The threshold may not exceed the number of platforms with a linked identity.
    error ThresholdTooHigh(uint8 threshold, uint32 platforms);
    /// An account keeps at least one linked identity.
    error LastIdentity(bytes32 identity);
    /// The unlink would leave the account no admin session.
    error LastAdmin(bytes32 identity);
    /// The genesis identity stays linked: it names the wallet's factory address.
    error GenesisIdentity(bytes32 identity);
    /// An unlink or an active admin session's revoke ran after the root operation was queued.
    error RootSuperseded(bytes32 opId);
    /// A session key is a 20-byte address or `verifier || key`.
    error InvalidKey(bytes key);
    error SessionExists(bytes key);
    error NoSession(bytes key);
    /// A policy bound reaches bit 47, which EntryPoint v0.9 reads as a block-number flag.
    error PolicyOutOfRange(uint48 validAfter, uint48 validUntil);
    /// A root operation targets the account, or this validator's `setThreshold`, `revokeSession`,
    /// `unlink`, `setRecoveryDelay` or `setRecoveryFrozen`.
    error BadRootOperation(address target);
    /// The account froze recovery by proof for this identity.
    error RecoveryFrozen(bytes32 identity);

    /// Floor of `recoveryDelay`.
    function MIN_RECOVERY_DELAY() external view returns (uint48);
    /// Ceiling of `recoveryDelay`.
    function MAX_RECOVERY_DELAY() external view returns (uint48);
    function walletRegistry() external view returns (address);

    function genesisIdentity(address account) external view returns (bytes32 platformId, bytes32 idNode);
    function isLinked(address account, bytes32 identity) external view returns (bool);
    function sessionOf(address account, bytes calldata key) external view returns (Session memory);
    /// The identity's current generation: a session of any other is dead.
    function generationOf(address account, bytes32 identity) external view returns (uint32);
    /// Distinct platforms with at least one linked identity: the most `threshold` can be.
    function linkedPlatforms(address account) external view returns (uint32);
    /// Distinct platforms an admin operation's admin sessions need: two identities on one platform count once.
    /// Defaults to 1.
    function threshold(address account) external view returns (uint8);
    /// The account's wait for sessions added by proof and for root operations (see `rootReadyAt`).
    function recoveryDelay(address account) external view returns (uint48);
    /// One-way: set once the account has had any session.
    function hadSession(address account) external view returns (bool);
    /// Whether `addSessionByProof` refuses the identity. The flag survives an unlink and a relink.
    function recoveryFrozen(address account, bytes32 identity) external view returns (bool);
    /// `keccak256(abi.encode(account, target, data))` once queued, else 0; also 0 once an unlink or an admin revoke supersedes it.
    function rootReadyAt(address account, bytes32 opId) external view returns (uint48);

    // Registry only.
    function link(address account, bytes32 platformId, bytes32 idNode) external;
    /// Active at once while the account never had a session, else pending for `recoveryDelay` and `byProof`.
    /// A newer pending session of the same identity replaces the older one.
    /// Refused while the identity's recovery is frozen.
    function addSessionByProof(address account, bytes32 identity, bytes calldata key, Policy calldata policy)
        external
        returns (uint48 activeAt);
    /// Active at once: the account itself submitted the proof.
    function addSessionByAccount(address account, bytes32 identity, bytes calldata key, Policy calldata policy) external;

    // The account itself (an admin operation, under the threshold).
    /// Active at once. The identity must be linked. A dead session's key may be reused.
    function addSession(bytes32 identity, bytes calldata key, Policy calldata policy) external;
    /// Revokes an active or pending session. Removing the last admin session, counting pending and expired ones, is a root operation.
    /// Revoking an active admin session voids every root operation queued before it.
    function revokeSession(bytes calldata key) external;
    /// Raises the delay at once. Lowering it, never below `MIN_RECOVERY_DELAY`, is a root operation:
    /// the account reverts `RootOperationRequired`.
    function setRecoveryDelay(uint48 delay) external;
    /// Root operation only: reverts `RootOperationRequired` when the account calls it.
    function setThreshold(uint8 threshold_) external;
    /// Root operation only. Every session of the identity, active or pending, stops validating for good,
    /// and every root operation queued before it stops executing.
    /// Refused for an identity not linked, the last one, the last of a platform the threshold still needs,
    /// the genesis identity, or when the account would be left with no admin session.
    function unlink(bytes32 identity) external;
    /// Root operation only. While frozen, `addSessionByProof` refuses the identity; its active sessions
    /// keep working. Freezing revokes the identity's latest session by proof while it is still pending.
    function setRecoveryFrozen(bytes32 identity, bool frozen) external;
    /// `target` is the account (install, uninstall, upgrade) or this validator
    /// (`setThreshold`, `unlink`, `setRecoveryFrozen`, `revokeSession` of the last admin, a lower
    /// `setRecoveryDelay`).
    /// Ready after `recoveryDelay`.
    function queueRoot(address target, bytes calldata data) external returns (bytes32 opId);
    function cancelRoot(bytes32 opId) external;

    /// Anyone, once `rootReadyAt` has passed, unless an unlink or an admin revoke superseded it.
    function executeRoot(address account, address target, bytes calldata data) external;
}

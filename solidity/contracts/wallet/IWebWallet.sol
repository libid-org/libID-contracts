// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/IERC4337.sol";

// The mode of a signed batch anyone may submit: batch call type, default exec type, and mode selector
// `bytes4(keccak256("libid.webwallet.authorized"))`.
bytes32 constant AUTHORIZED_MODE = 0x01000000000018f4a5a900000000000000000000000000000000000000000000;
// The gas between the wallet's `callGas` check before each `AUTHORIZED_MODE` call and the call, which gets 63/64 of
// what is left.
uint256 constant CALL_OVERHEAD = 20_000;

/// EntryPoint v0.9's `incrementNonce`, which OpenZeppelin's interface leaves out.
interface INonceIncrement {
    function incrementNonce(uint192 key) external;
}

/// @title IWebWallet
/// @notice Every external of the WebWallet implementation and of the selectors it routes to its targets.
interface IWebWallet {
    struct Allowance {
        address token;
        uint128 amount;
        uint48 period;
    }

    struct Rules {
        bytes32 scopeRoot;
        bytes32 domainsRoot;
        bytes32 paymastersRoot;
        Allowance[] allowances;
    }

    struct Policy {
        uint48 validAfter;
        uint48 validUntil;
        bool admin;
        uint8 signers;
        Rules rules;
    }

    struct Session {
        bytes32 identity;
        bytes32 policyHash;
        uint48 activeAt;
        bool admin;
        bool byProof;
        uint8 signers;
    }

    struct SessionSignature {
        bytes key;
        bytes signature;
    }

    struct CallProof {
        uint256 maxValue;
        bytes32[] proof;
    }

    /// What signs a batch, a UserOperation or an ERC-1271 hash.
    struct Authorization {
        SessionSignature[] signatures;
        uint48 at;
        CallProof[] calls;
        bytes32[] domainProof;
        bytes32[] paymasterProof;
    }

    /// A live session's raw counter for one token.
    struct AllowanceState {
        uint128 amount;
        uint48 period;
        uint48 periodStart;
        uint128 spent;
    }

    struct RootOperation {
        bytes data;
        /// A bump's implementation, read from the factory at queue time; zero for the others.
        address implementation;
        uint64 version;
        uint48 readyAt;
    }

    event RootQueued(bytes32 indexed id, uint64 version, uint48 readyAt, bytes data);
    event RootCancelled(bytes32 indexed id);
    event RootExecuted(bytes32 indexed id);
    event IdentityLinked(bytes32 indexed identity);
    event IdentityUnlinked(bytes32 indexed identity);
    /// `byProof`: added by a login, the event to alert on.
    event SessionAdded(bytes32 indexed identity, bytes key, bytes32 policyHash, uint48 activeAt, bool byProof);
    event SessionRevoked(bytes32 indexed identity, bytes key);
    event SessionsRemovedByLogin(bytes32 indexed identity);
    event AppListSet(bytes32 indexed identity, bytes32[] apps);
    /// `reset` moved the epoch: every earlier session, link and root operation is gone.
    event EpochReset(bytes32 epoch);
    /// The release slot moved from version `from` to `to`, run by `implementation`.
    event Bumped(uint64 from, uint64 to, address implementation);
    /// The effective threshold, as `threshold()` reads it.
    event ThresholdSet(uint8 threshold);
    event RootDelaySet(uint32 delay);
    /// A call of a batch under the try exec type failed.
    event ERC7579TryExecuteFail(uint256 batchExecutionIndex, bytes returndata);

    error RootOperationRequired();
    error RootOperationNotAllowed(bytes4 selector);
    error RootOperationUnknown(bytes32 id);
    error RootOperationNotReady(bytes32 id);
    error RootOperationVoid(bytes32 id);
    error ReleaseNotAbove(uint64 current, uint64 version);
    error ReleaseMismatch(uint64 version);
    error Locked();
    error EntryPointBlocked();
    /// The EntryPoint has no code on this chain.
    error EntryPointMissing(address entryPoint);
    error ResetRefused();
    error InitializeRefused();
    error DataStepRefused();
    error NotDelegated();
    /// Only the wallet's own call.
    error OnlySelf();
    error FirstSessionRefused();
    error LinkSessionRefused();
    error NotLinked(bytes32 identity);
    /// `app` is `keccak256(clientIdentifier)`.
    error AppNotListed(bytes32 app);
    error ExecutionNotSigned();
    error ExecutionNotAllowed();
    error ExecutionOutsideWindow();
    /// The batch is not `abi.encode(Execution[])` of the calls it decodes to.
    error NoncanonicalBatch();
    /// `msg.value` is not the signed `value`.
    error WrongBatchValue(uint256 value, uint256 sent);
    /// The gas left before a call would give it less than the signed `callGas`.
    error InsufficientCallGas(uint256 callGas, uint256 left);
    /// The signed `deadline` is zero or has passed.
    error ExecutionExpired(uint48 deadline);
    /// A mode other than `AUTHORIZED_MODE` or a single or batch call with selector 0.
    error UnsupportedMode(bytes32 mode);
    /// A session key is a 20-byte address or `verifier || key`.
    error InvalidKey(bytes key);
    error SessionExists(bytes key);
    error NoSession(bytes key);
    /// A policy bound reaches bit 47, which EntryPoint v0.9 reads as a block-number flag.
    error PolicyOutOfRange(uint48 validAfter, uint48 validUntil);
    /// An admin session never expires: its `validUntil` is 0.
    error AdminSessionExpires(uint48 validUntil);
    /// An allowance's token does not sort after the one before it, or its period reaches bit 47.
    error BadAllowance(address token);
    error RootDelayTooLong(uint32 delay);
    /// The threshold would exceed the platforms holding an admin session, while some do.
    error ThresholdTooHigh(uint8 threshold, uint32 adminPlatforms);
    /// The genesis identity stays linked: it names the wallet's address.
    error GenesisIdentity(bytes32 identity);
    /// The default mode from neither the EntryPoint nor an EIP-7702 account's own key.
    error AccountUnauthorized(address sender);
    /// A call of a batch reverted with no data.
    error FailedCall();
    /// `executionCalldata` is not a well-formed batch.
    error ERC7579DecodingError();
    /// OpenZeppelin's mode decoder declares it; a 32-byte mode never raises it.
    error OutOfRangeAccess();

    // ─── Account ────────────────────────────────────────────────────

    function entryPoint() external view returns (address);
    function getNonce() external view returns (uint256);
    function getNonce(uint192 key) external view returns (uint256);
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        returns (uint256);
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4);
    function eip712Domain()
        external
        view
        returns (
            bytes1 fields,
            string memory name,
            string memory version,
            uint256 chainId,
            address verifyingContract,
            bytes32 salt,
            uint256[] memory extensions
        );
    function execute(bytes32 mode, bytes calldata executionCalldata) external payable;
    function supportsInterface(bytes4 interfaceId) external view returns (bool);
    function onERC721Received(address operator, address from, uint256 tokenId, bytes calldata data)
        external
        returns (bytes4);
    function onERC1155Received(address operator, address from, uint256 id, uint256 value, bytes calldata data)
        external
        returns (bytes4);
    function onERC1155BatchReceived(
        address operator,
        address from,
        uint256[] calldata ids,
        uint256[] calldata values,
        bytes calldata data
    ) external returns (bytes4);

    // ─── Setup and releases ─────────────────────────────────────────

    function VERSION() external view returns (uint64);
    function FACTORY() external view returns (address);
    function REGISTRY() external view returns (address);
    function initialize(bytes32 platformId, bytes32 idNode, uint256 salt) external;
    function reset(bytes calldata executionCalldata) external payable;
    function release() external view returns (address implementation, uint64 version);
    function epoch() external view returns (bytes32);
    function genesisIdentity() external view returns (bytes32 platformId, bytes32 idNode, uint256 salt);
    function runDataSteps(uint64 from) external;

    // ─── Identities and sessions ────────────────────────────────────

    function linkIdentity(
        bytes32 platformId,
        uint16 verifierVersion,
        bytes calldata payload,
        bytes calldata data,
        Policy calldata policy
    ) external payable;
    function addSessionByLogin(
        bytes32 platformId,
        uint16 verifierVersion,
        bytes calldata payload,
        bytes calldata data,
        Policy calldata policy
    ) external payable;
    function removeSessionsByLogin(
        bytes32 platformId,
        uint16 verifierVersion,
        bytes calldata payload,
        bytes calldata data,
        Policy calldata policy
    ) external payable;
    function addSession(bytes32 identity, bytes calldata key, Policy calldata policy) external;
    function revokeSession(bytes calldata key) external;
    /// Self only: the apps, each `keccak256(clientIdentifier)`, whose logins may add `identity`'s sessions;
    /// empty admits any.
    function setAppList(bytes32 identity, bytes32[] calldata apps) external;
    function sessionOf(bytes calldata key) external view returns (Session memory);
    function isLinked(bytes32 identity) external view returns (bool);
    function appList(bytes32 identity) external view returns (bytes32[] memory);
    /// The live session `key`'s counter for `token`; zero without one. `spent` holds only while
    /// `at - at % period == periodStart`.
    function allowanceOf(bytes calldata key, address token) external view returns (AllowanceState memory);
    /// The identity's current generation: a session of any other is dead.
    function generationOf(bytes32 identity) external view returns (uint32);
    /// Distinct platforms with a linked identity.
    function linkedPlatforms() external view returns (uint32);
    /// Whether the wallet ever had a session in this epoch.
    function hadSession() external view returns (bool);

    // ─── Root operations ────────────────────────────────────────────

    function queueRoot(bytes calldata data) external returns (bytes32 id);
    function cancelRoot(bytes32 id) external;
    function executeRoot(bytes32 id) external;
    function rootOperation(bytes32 id) external view returns (RootOperation memory);
    /// When the queued operation `id` matures; 0 when unknown or void.
    function rootReadyAt(bytes32 id) external view returns (uint48);
    function threshold() external view returns (uint8);
    function rootDelay() external view returns (uint32);
    function bump(uint64 version) external;
    function setThreshold(uint8 threshold) external;
    function setRootDelay(uint32 delay) external;
    function unlink(bytes32 identity) external;
}

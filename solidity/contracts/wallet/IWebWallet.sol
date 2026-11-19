// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/IERC4337.sol";

// The mode of a signed batch anyone may submit: batch call type, default exec type, and mode selector
// `bytes4(keccak256("libid.webwallet.authorized"))`.
bytes32 constant AUTHORIZED_MODE = 0x01000000000018f4a5a900000000000000000000000000000000000000000000;

/// @title IWebWallet
/// @notice Every external of the WebWallet implementation and of the selectors it routes to its targets.
interface IWebWallet {
    struct Allowance {
        address token;
        uint256 amount;
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

    struct RootOperation {
        bytes data;
        uint64 version;
        uint48 readyAt;
    }

    event RootQueued(bytes32 indexed id, uint64 version, uint48 readyAt, bytes data);

    error RootOperationRequired();
    error RootOperationNotAllowed(bytes4 selector);
    error RootOperationUnknown(bytes32 id);
    error RootOperationNotReady(bytes32 id);
    error RootOperationVoid(bytes32 id);
    error ReleaseNotAbove(uint64 current, uint64 version);
    error ReleaseMismatch(uint64 version);
    error Locked();
    error EntryPointBlocked();
    error ResetRefused();
    error InitializeRefused();
    error DataStepRefused();
    error NotDelegated();
    error FirstSessionRefused();
    error LinkSessionRefused();
    error NotLinked(bytes32 identity);
    error AppNotListed(bytes app);
    error ExecutionNotSigned();
    error ExecutionNotAllowed();
    error ExecutionOutsideWindow();

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
        bytes calldata data
    ) external payable;
    function addSession(bytes32 identity, bytes calldata key, Policy calldata policy) external;
    function revokeSession(bytes calldata key) external;
    function setAppList(bytes32 platformId, bytes[] calldata apps) external;
    function sessionOf(bytes calldata key) external view returns (Session memory);
    function isLinked(bytes32 identity) external view returns (bool);
    function appList(bytes32 platformId) external view returns (bytes[] memory);

    // ─── Root operations ────────────────────────────────────────────

    function queueRoot(bytes calldata data) external returns (bytes32 id);
    function cancelRoot(bytes32 id) external;
    function executeRoot(bytes32 id) external;
    function rootOperation(bytes32 id) external view returns (RootOperation memory);
    function threshold() external view returns (uint8);
    function rootDelay() external view returns (uint32);
    function bump(uint64 version) external;
    function setThreshold(uint8 threshold) external;
    function setRootDelay(uint32 delay) external;
    function unlink(bytes32 identity) external;
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/IERC4337.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {
    IERC7579Execution,
    IERC7579Module,
    MODULE_TYPE_VALIDATOR
} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {ERC4337Utils} from "@openzeppelin/contracts/account/utils/ERC4337Utils.sol";
import {CallType, ERC7579Utils, Execution, Mode} from "@openzeppelin/contracts/account/utils/draft-ERC7579Utils.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

import {IIdentityValidator, identityOf} from "./IIdentityValidator.sol";

/// @title IdentityValidator - the one ERC-7579 validator of every WebWallet.
/// @notice Holds each account's linked identities, sessions, threshold and root operations.
/// @dev Every slot read in validation has the account as its innermost mapping key (ERC-7562),
///      and validation reads no clock: windows go back to the EntryPoint packed.
contract IdentityValidator is IIdentityValidator {
    using ERC7579Utils for bytes;
    using ERC7579Utils for Mode;

    uint48 public constant MIN_RECOVERY_DELAY = 48 hours;
    uint48 public constant ROOT_DELAY = MIN_RECOVERY_DELAY;
    uint48 public constant MAX_RECOVERY_DELAY = 365 days;

    address private immutable REGISTRY;

    /// What `callData` asks of the account.
    enum Scope {
        Call,
        Admin,
        Refused
    }

    /// One install's settings for one account.
    struct AccountState {
        bytes32 platformId;
        bytes32 idNode;
        uint48 recoveryDelay;
        uint8 threshold;
        bool hadSession;
        uint32 adminSessions;
        uint32 identities;
        uint32 unlinkEpoch;
    }

    /// A queued root operation: when it matures, and the unlink epoch it was queued in.
    struct Root {
        uint48 readyAt;
        uint32 epoch;
    }

    /// @dev Keyed by install, then by item, then by account.
    /// @custom:storage-location erc7201:libid.storage.IdentityValidator
    struct IdentityValidatorStorage {
        mapping(address account => uint256) installs;
        mapping(uint256 install => mapping(address account => AccountState)) accounts;
        mapping(uint256 install => mapping(bytes32 keyHash => mapping(address account => Session))) sessions;
        mapping(uint256 install => mapping(bytes32 identity => mapping(address account => bool))) links;
        mapping(uint256 install => mapping(bytes32 identity => mapping(address account => bytes))) pendingKeys;
        mapping(uint256 install => mapping(bytes32 opId => mapping(address account => Root))) roots;
        mapping(uint256 install => mapping(bytes32 identity => mapping(address account => uint32))) generations;
        mapping(uint256 install => mapping(bytes32 identity => mapping(address account => uint32))) adminSessions;
    }

    // cast index-erc7201 libid.storage.IdentityValidator
    bytes32 private constant IDENTITY_VALIDATOR_STORAGE =
        0x873011f05c4a0f65dcb571f9747866179ce051ed2f0788dad77cc90e91439700;

    function _s() private pure returns (IdentityValidatorStorage storage $) {
        assembly {
            $.slot := IDENTITY_VALIDATOR_STORAGE
        }
    }

    function _install(address account) private view returns (uint256) {
        return _s().installs[account];
    }

    function _account(address account) private view returns (AccountState storage) {
        return _s().accounts[_install(account)][account];
    }

    function _session(address account, bytes memory key) private view returns (Session storage) {
        return _s().sessions[_install(account)][keccak256(key)][account];
    }

    function _generations(address account, bytes32 identity) private view returns (mapping(address => uint32) storage) {
        return _s().generations[_install(account)][identity];
    }

    function _adminSessions(address account, bytes32 identity)
        private
        view
        returns (mapping(address => uint32) storage)
    {
        return _s().adminSessions[_install(account)][identity];
    }

    modifier onlyRegistry() {
        if (msg.sender != REGISTRY) revert NotRegistry(msg.sender);
        _;
    }

    constructor(address walletRegistry_) {
        REGISTRY = walletRegistry_;
    }

    // ─── ERC-7579 module ────────────────────────────────────────────

    function isModuleType(uint256 moduleTypeId) external pure returns (bool) {
        return moduleTypeId == MODULE_TYPE_VALIDATOR;
    }

    /// @dev Starts a fresh install: nothing of an earlier one is visible.
    function onInstall(bytes calldata data) external {
        (bytes32 platformId, bytes32 idNode) = abi.decode(data, (bytes32, bytes32));
        AccountState storage a = _s().accounts[++_s().installs[msg.sender]][msg.sender];
        a.platformId = platformId;
        a.idNode = idNode;
    }

    function onUninstall(bytes calldata) external {
        ++_s().installs[msg.sender];
    }

    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash) external view returns (uint256) {
        Scope scope = _scope(msg.sender, userOp.callData);
        if (scope == Scope.Refused) return ERC4337Utils.SIG_VALIDATION_FAILED;
        (bool ok, uint256 admins, uint48 validAfter, uint48 validUntil) =
            _verify(msg.sender, userOpHash, userOp.signature);
        if (!ok || (scope == Scope.Admin && admins < threshold(msg.sender))) {
            return ERC4337Utils.SIG_VALIDATION_FAILED;
        }
        return (uint256(validAfter) << 208) | (uint256(validUntil) << 160);
    }

    /// @dev The account has already wrapped `hash` as ERC-7739 `PersonalSign` under its domain.
    function isValidSignatureWithSender(address, bytes32 hash, bytes calldata signature)
        external
        view
        returns (bytes4)
    {
        (bool ok, uint256 admins, uint48 validAfter, uint48 validUntil) = _verify(msg.sender, hash, signature);
        bool live = validAfter < block.timestamp && (validUntil == 0 || block.timestamp <= validUntil);
        return ok && admins != 0 && live ? IERC1271.isValidSignature.selector : bytes4(0xffffffff);
    }

    // ─── Views ──────────────────────────────────────────────────────

    function walletRegistry() external view returns (address) {
        return REGISTRY;
    }

    function genesisIdentity(address account) external view returns (bytes32 platformId, bytes32 idNode) {
        AccountState storage a = _account(account);
        return (a.platformId, a.idNode);
    }

    function isLinked(address account, bytes32 identity) public view returns (bool) {
        return _s().links[_install(account)][identity][account];
    }

    function sessionOf(address account, bytes calldata key) external view returns (Session memory) {
        return _session(account, key);
    }

    function threshold(address account) public view returns (uint8) {
        uint8 t = _account(account).threshold;
        return t == 0 ? 1 : t;
    }

    function recoveryDelay(address account) public view returns (uint48) {
        uint48 d = _account(account).recoveryDelay;
        return d == 0 ? MIN_RECOVERY_DELAY : d;
    }

    function hadSession(address account) external view returns (bool) {
        return _account(account).hadSession;
    }

    function generationOf(address account, bytes32 identity) external view returns (uint32) {
        return _generations(account, identity)[account];
    }

    function rootReadyAt(address account, bytes32 opId) external view returns (uint48) {
        return _s().roots[_install(account)][opId][account].readyAt;
    }

    // ─── Registry ───────────────────────────────────────────────────

    function link(address account, bytes32 platformId, bytes32 idNode) external onlyRegistry {
        mapping(address => bool) storage linked = _s().links[_install(account)][identityOf(platformId, idNode)];
        if (linked[account]) return;
        linked[account] = true;
        ++_account(account).identities;
    }

    function addSessionByProof(address account, bytes32 identity, bytes calldata key, Policy calldata policy)
        external
        onlyRegistry
        returns (uint48 activeAt)
    {
        if (_account(account).hadSession) {
            activeAt = _maturity(account);
            _replacePending(account, identity, key);
        }
        _add(account, identity, key, policy, activeAt);
    }

    function addSessionByAccount(address account, bytes32 identity, bytes calldata key, Policy calldata policy)
        external
        onlyRegistry
    {
        _add(account, identity, key, policy, 0);
    }

    // ─── The account ────────────────────────────────────────────────

    function addSession(bytes32 identity, bytes calldata key, Policy calldata policy) external {
        _add(msg.sender, identity, key, policy, 0);
    }

    function revokeSession(bytes calldata key) external {
        _revoke(msg.sender, key, false);
    }

    function setRecoveryDelay(uint48 delay) external {
        if (delay < recoveryDelay(msg.sender)) revert RecoveryDelayTooShort(delay);
        if (delay > MAX_RECOVERY_DELAY) revert RecoveryDelayTooLong(delay);
        _account(msg.sender).recoveryDelay = delay;
    }

    /// Decodes a signature list; external so a malformed one fails validation instead of reverting it.
    function decodeSignatures(bytes calldata signature) external pure returns (SessionSignature[] memory) {
        return abi.decode(signature, (SessionSignature[]));
    }

    function setThreshold(uint8) external pure {
        revert RootOperationRequired();
    }

    function unlink(bytes32) external pure {
        revert RootOperationRequired();
    }

    function queueRoot(address target, bytes calldata data) external returns (bytes32 opId) {
        bytes4 selector = _selector(data);
        bool own = target == address(this)
            && (selector == this.setThreshold.selector
                || selector == this.revokeSession.selector
                || selector == this.unlink.selector);
        if (target != msg.sender && !own) revert BadRootOperation(target);
        opId = _rootId(msg.sender, target, data);
        uint48 readyAt = _maturity(msg.sender);
        _s().roots[_install(msg.sender)][opId][msg.sender] =
            Root({readyAt: readyAt, epoch: _account(msg.sender).unlinkEpoch});
        emit RootQueued(msg.sender, opId, target, data, readyAt);
    }

    function cancelRoot(bytes32 opId) external {
        mapping(address => Root) storage root = _s().roots[_install(msg.sender)][opId];
        if (root[msg.sender].readyAt == 0) revert RootNotReady(opId);
        delete root[msg.sender];
        emit RootCancelled(msg.sender, opId);
    }

    function executeRoot(address account, address target, bytes calldata data) external {
        bytes32 opId = _rootId(account, target, data);
        mapping(address => Root) storage root = _s().roots[_install(account)][opId];
        Root memory r = root[account];
        if (r.readyAt == 0 || block.timestamp < r.readyAt) revert RootNotReady(opId);
        if (r.epoch != _account(account).unlinkEpoch) revert RootSuperseded(opId);
        delete root[account];
        emit RootExecuted(account, opId);

        if (target == account) {
            Address.functionCall(account, data);
        } else if (_selector(data) == this.setThreshold.selector) {
            AccountState storage a = _account(account);
            uint8 t = abi.decode(data[4:], (uint8));
            if (t > a.identities) revert ThresholdTooHigh(t, a.identities);
            a.threshold = t;
        } else if (_selector(data) == this.unlink.selector) {
            _unlink(account, abi.decode(data[4:], (bytes32)));
        } else {
            _revoke(account, abi.decode(data[4:], (bytes)), true);
        }
    }

    // ─── Internals ──────────────────────────────────────────────────

    function _add(address account, bytes32 identity, bytes memory key, Policy memory policy, uint48 activeAt) private {
        if (!isLinked(account, identity)) revert NotLinked(account, identity);
        if (key.length < 20) revert InvalidKey(key);
        if ((policy.validAfter | policy.validUntil | activeAt) >= 1 << 47) {
            revert PolicyOutOfRange(policy.validAfter, policy.validUntil);
        }
        Session storage s = _session(account, key);
        if (_live(account, s)) revert SessionExists(key);
        s.identity = identity;
        s.policy = policy;
        s.activeAt = activeAt;
        s.generation = _generations(account, identity)[account];

        AccountState storage a = _account(account);
        a.hadSession = true;
        if (policy.admin) {
            ++a.adminSessions;
            ++_adminSessions(account, identity)[account];
        }

        bytes32 policyHash = keccak256(abi.encode(policy));
        if (activeAt == 0) emit SessionAdded(account, identity, key, policyHash);
        else emit SessionPending(account, identity, key, policyHash, activeAt);
    }

    function _revoke(address account, bytes memory key, bool root) private {
        Session storage s = _session(account, key);
        bytes32 identity = s.identity;
        if (identity == 0) revert NoSession(key);
        // A dead session's admin count went with its unlink.
        if (s.policy.admin && _live(account, s)) {
            AccountState storage a = _account(account);
            if (a.adminSessions == 1 && !root) revert RootOperationRequired();
            --a.adminSessions;
            --_adminSessions(account, identity)[account];
        }
        delete s.identity;
        delete s.policy;
        delete s.activeAt;
        delete s.generation;
        emit SessionRevoked(account, identity, key);
    }

    function _unlink(address account, bytes32 identity) private {
        mapping(address => bool) storage linked = _s().links[_install(account)][identity];
        if (!linked[account]) revert NotLinked(account, identity);
        AccountState storage a = _account(account);
        uint32 left = a.identities - 1;
        if (left == 0) revert LastIdentity(identity);
        if (a.threshold > left) revert ThresholdTooHigh(a.threshold, left);
        mapping(address => uint32) storage admins = _adminSessions(account, identity);
        if (admins[account] == a.adminSessions) revert LastAdmin(identity);
        a.adminSessions -= admins[account];
        delete admins[account];
        delete linked[account];
        ++_generations(account, identity)[account];
        a.identities = left;
        ++a.unlinkEpoch;
        emit IdentityUnlinked(account, identity);
    }

    /// Whether the session exists and belongs to its identity's current link.
    function _live(address account, Session storage s) private view returns (bool) {
        bytes32 identity = s.identity;
        return identity != 0 && s.generation == _generations(account, identity)[account];
    }

    function _rootId(address account, address target, bytes calldata data) private pure returns (bytes32) {
        return keccak256(abi.encode(account, target, data));
    }

    /// When a wait of the account's recovery delay, started now, ends.
    function _maturity(address account) private view returns (uint48) {
        // forge-lint: disable-next-line(unsafe-typecast)
        return uint48(block.timestamp) + recoveryDelay(account);
    }

    /// Drops the identity's earlier session by proof while it is still pending.
    function _replacePending(address account, bytes32 identity, bytes memory key) private {
        mapping(address => bytes) storage pending = _s().pendingKeys[_install(account)][identity];
        bytes memory old = pending[account];
        if (old.length != 0) {
            Session storage o = _session(account, old);
            if (o.identity == identity && o.activeAt > block.timestamp) _revoke(account, old, true);
        }
        pending[account] = key;
    }

    /// Whether every signature is by a session of its identity's current link, the distinct admin identities among them,
    /// and the window they all share.
    function _verify(address account, bytes32 hash, bytes calldata signature)
        private
        view
        returns (bool ok, uint256 admins, uint48 validAfter, uint48 validUntil)
    {
        SessionSignature[] memory sigs;
        try this.decodeSignatures(signature) returns (SessionSignature[] memory decoded) {
            sigs = decoded;
        } catch {
            return (false, 0, 0, 0);
        }
        if (sigs.length == 0) return (false, 0, 0, 0);
        bytes32[] memory adminIds = new bytes32[](sigs.length);
        for (uint256 i; i < sigs.length; ++i) {
            Session storage s = _session(account, sigs[i].key);
            bytes32 identity = s.identity;
            if (!_live(account, s) || !_signedBy(sigs[i].key, hash, sigs[i].signature)) return (false, 0, 0, 0);
            Policy memory p = s.policy;
            (validAfter, validUntil) = _narrow(validAfter, validUntil, p, s.activeAt);
            if (p.admin && !_contains(adminIds, admins, identity)) adminIds[admins++] = identity;
        }
        return (true, admins, validAfter, validUntil);
    }

    /// The window narrowed to one session's: its policy window, starting no earlier than `activeAt`.
    function _narrow(uint48 validAfter, uint48 validUntil, Policy memory p, uint48 activeAt)
        private
        pure
        returns (uint48, uint48)
    {
        uint48 start = p.validAfter > activeAt ? p.validAfter : activeAt;
        if (start > validAfter) validAfter = start;
        if (p.validUntil != 0 && (validUntil == 0 || p.validUntil < validUntil)) validUntil = p.validUntil;
        return (validAfter, validUntil);
    }

    /// @dev A 20-byte key is recovered with ECDSA, never asked through ERC-1271:
    ///      validation may not read a codeless address's code size (ERC-7562).
    function _signedBy(bytes memory key, bytes32 hash, bytes memory signature) private view returns (bool) {
        if (key.length != 20) return SignatureChecker.isValidSignatureNow(key, hash, signature);
        (address signer, ECDSA.RecoverError err,) = ECDSA.tryRecover(hash, signature);
        // forge-lint: disable-next-line(unsafe-typecast)
        return err == ECDSA.RecoverError.NoError && signer == address(bytes20(key));
    }

    function _contains(bytes32[] memory ids, uint256 n, bytes32 id) private pure returns (bool) {
        for (uint256 i; i < n; ++i) {
            if (ids[i] == id) return true;
        }
        return false;
    }

    /// `execute` of single or batch calls to outside targets is an ordinary call. A call to
    /// the account, this validator or the registry is an admin operation. Anything else, and
    /// `onInstall`/`onUninstall` called directly, is refused.
    function _scope(address account, bytes calldata callData) private view returns (Scope scope) {
        if (_selector(callData) != IERC7579Execution.execute.selector) return Scope.Refused;
        (CallType callType,,,) = Mode.wrap(bytes32(callData[4:36])).decodeMode();
        bytes calldata executionCalldata = _executionCalldata(callData);
        if (callType == ERC7579Utils.CALLTYPE_SINGLE) {
            (address target,, bytes calldata data) = executionCalldata.decodeSingle();
            return _targetScope(account, target, data);
        }
        if (callType == ERC7579Utils.CALLTYPE_BATCH) {
            Execution[] calldata batch = executionCalldata.decodeBatch();
            for (uint256 i; i < batch.length; ++i) {
                Scope s = _targetScope(account, batch[i].target, batch[i].callData);
                if (s > scope) scope = s;
            }
            return scope;
        }
        return Scope.Refused;
    }

    function _targetScope(address account, address target, bytes calldata data) private view returns (Scope) {
        if (target == address(this)) {
            bytes4 selector = _selector(data);
            bool module =
                selector == IERC7579Module.onInstall.selector || selector == IERC7579Module.onUninstall.selector;
            return module ? Scope.Refused : Scope.Admin;
        }
        // The account executes a call to address(0) on itself.
        if (target == account || target == address(0) || target == REGISTRY) return Scope.Admin;
        return Scope.Call;
    }

    /// The first four bytes, zero-padded.
    function _selector(bytes calldata data) private pure returns (bytes4) {
        // forge-lint: disable-next-line(unsafe-typecast)
        return bytes4(data);
    }

    /// The `bytes` argument of `execute(bytes32, bytes)`, as the account's ABI decoder reads it.
    function _executionCalldata(bytes calldata callData) private pure returns (bytes calldata) {
        bytes calldata args = callData[4:];
        uint256 offset = uint256(bytes32(args[32:64]));
        uint256 length = uint256(bytes32(args[offset:offset + 32]));
        return args[offset + 32:offset + 32 + length];
    }
}

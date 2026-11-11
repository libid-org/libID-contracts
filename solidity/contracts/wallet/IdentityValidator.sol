// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/IERC4337.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {IERC5267} from "@openzeppelin/contracts/interfaces/IERC5267.sol";
import {
    IERC7579Execution,
    IERC7579Module,
    MODULE_TYPE_VALIDATOR
} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {ERC4337Utils} from "@openzeppelin/contracts/account/utils/ERC4337Utils.sol";
import {CallType, ERC7579Utils, Execution, Mode} from "@openzeppelin/contracts/account/utils/draft-ERC7579Utils.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {ERC7739Utils} from "@openzeppelin/contracts/utils/cryptography/draft-ERC7739Utils.sol";

import {IIdentityValidator, identityOf} from "./IIdentityValidator.sol";

/// @title IdentityValidator - the one ERC-7579 validator of every WebWallet.
/// @notice Holds each account's linked identities, sessions, threshold and root operations.
/// @dev Every slot read in validation has the account as its innermost mapping key (ERC-7562),
///      and validation reads no clock: windows go back to the EntryPoint packed.
contract IdentityValidator is IIdentityValidator {
    using ERC7579Utils for bytes;
    using ERC7579Utils for Mode;
    using ERC7739Utils for *;
    using MessageHashUtils for bytes32;

    uint48 public constant MIN_RECOVERY_DELAY = 48 hours;
    uint48 public constant ROOT_DELAY = MIN_RECOVERY_DELAY;
    uint48 public constant MAX_RECOVERY_DELAY = 365 days;

    address private immutable REGISTRY;

    /// The ERC-7739 detection hash: with an empty signature, it answers `0x77390001`.
    bytes32 private constant ERC7739_PROBE = 0x7739773977397739773977397739773977397739773977397739773977397739;
    bytes32 private constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

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

    /// What `_verify` found: whether every signature holds, the distinct admin identities among them,
    /// the window they share, and the hash of the first signature's key.
    struct Verified {
        bool ok;
        uint256 admins;
        uint48 validAfter;
        uint48 validUntil;
        bytes32 keyHash;
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
        return _sessionAt(account, keccak256(key));
    }

    function _sessionAt(address account, bytes32 keyHash) private view returns (Session storage) {
        return _s().sessions[_install(account)][keyHash][account];
    }

    function _roots(address account, bytes32 opId) private view returns (mapping(address => Root) storage) {
        return _s().roots[_install(account)][opId];
    }

    function _generations(address account, bytes32 identity) private view returns (mapping(address => uint32) storage) {
        return _s().generations[_install(account)][identity];
    }

    /// The identity's own admin sessions; `AccountState.adminSessions` counts the account's.
    function _identityAdmins(address account, bytes32 identity)
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
        (Scope scope,) = _scope(msg.sender, userOp.callData);
        if (scope == Scope.Refused) return ERC4337Utils.SIG_VALIDATION_FAILED;
        Verified memory v = _verify(msg.sender, userOpHash, userOp.signature);
        if (!v.ok || (scope == Scope.Admin && v.admins < threshold(msg.sender))) {
            return ERC4337Utils.SIG_VALIDATION_FAILED;
        }
        return (uint256(v.validAfter) << 208) | (uint256(v.validUntil) << 160);
    }

    /// @dev Only admin sessions sign, inside their window.
    function isValidSignatureWithSender(address, bytes32 hash, bytes calldata signature)
        external
        view
        returns (bytes4)
    {
        if (hash == ERC7739_PROBE && signature.length == 0) return bytes4(0x77390001);
        (bytes32 signed, bytes calldata sigs) = _unnest(hash, signature);
        Verified memory v = _verify(msg.sender, signed, sigs);
        bool live = v.validAfter < block.timestamp && (v.validUntil == 0 || block.timestamp <= v.validUntil);
        return v.ok && v.admins != 0 && live ? IERC1271.isValidSignature.selector : bytes4(0xffffffff);
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
        Root memory r = _roots(account, opId)[account];
        return _superseded(account, r) ? 0 : r.readyAt;
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
        _roots(msg.sender, opId)[msg.sender] = Root({readyAt: readyAt, epoch: _account(msg.sender).unlinkEpoch});
        emit RootQueued(msg.sender, opId, target, data, readyAt);
    }

    function cancelRoot(bytes32 opId) external {
        mapping(address => Root) storage root = _roots(msg.sender, opId);
        if (root[msg.sender].readyAt == 0) revert RootNotReady(opId);
        delete root[msg.sender];
        emit RootCancelled(msg.sender, opId);
    }

    function executeRoot(address account, address target, bytes calldata data) external {
        bytes32 opId = _rootId(account, target, data);
        mapping(address => Root) storage root = _roots(account, opId);
        Root memory r = root[account];
        if (r.readyAt == 0 || block.timestamp < r.readyAt) revert RootNotReady(opId);
        if (_superseded(account, r)) revert RootSuperseded(opId);
        delete root[account];
        emit RootExecuted(account, opId);

        bytes4 selector = _selector(data);
        if (target == account) {
            Address.functionCall(account, data);
        } else if (selector == this.setThreshold.selector) {
            _setThreshold(account, abi.decode(data[4:], (uint8)));
        } else if (selector == this.unlink.selector) {
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
            ++_identityAdmins(account, identity)[account];
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
            --_identityAdmins(account, identity)[account];
        }
        delete s.identity;
        delete s.policy;
        delete s.activeAt;
        delete s.generation;
        emit SessionRevoked(account, identity, key);
    }

    function _setThreshold(address account, uint8 t) private {
        AccountState storage a = _account(account);
        if (t > a.identities) revert ThresholdTooHigh(t, a.identities);
        a.threshold = t;
    }

    function _unlink(address account, bytes32 identity) private {
        mapping(address => bool) storage linked = _s().links[_install(account)][identity];
        if (!linked[account]) revert NotLinked(account, identity);
        AccountState storage a = _account(account);
        uint32 left = a.identities - 1;
        if (left == 0) revert LastIdentity(identity);
        if (a.threshold > left) revert ThresholdTooHigh(a.threshold, left);
        mapping(address => uint32) storage admins = _identityAdmins(account, identity);
        if (admins[account] == a.adminSessions) revert LastAdmin(identity);
        a.adminSessions -= admins[account];
        delete admins[account];
        delete linked[account];
        ++_generations(account, identity)[account];
        a.identities = left;
        ++a.unlinkEpoch;
        emit IdentityUnlinked(account, identity);
    }

    /// Whether an unlink ran after the root operation was queued.
    function _superseded(address account, Root memory r) private view returns (bool) {
        return r.epoch != _account(account).unlinkEpoch;
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

    /// Checks that every signature is by a session of its identity's current link.
    function _verify(address account, bytes32 hash, bytes calldata signature) private view returns (Verified memory v) {
        SessionSignature[] memory sigs;
        try this.decodeSignatures(signature) returns (SessionSignature[] memory decoded) {
            sigs = decoded;
        } catch {
            return v;
        }
        if (sigs.length == 0) return v;
        bytes32[] memory adminIds = new bytes32[](sigs.length);
        for (uint256 i; i < sigs.length; ++i) {
            bytes32 keyHash = keccak256(sigs[i].key);
            Session storage s = _sessionAt(account, keyHash);
            bytes32 identity = s.identity;
            if (!_live(account, s) || !_signedBy(sigs[i].key, hash, sigs[i].signature)) {
                return Verified(false, 0, 0, 0, 0);
            }
            Policy memory p = s.policy;
            (v.validAfter, v.validUntil) = _narrow(v.validAfter, v.validUntil, p, s.activeAt);
            if (p.admin && !_contains(adminIds, v.admins, identity)) adminIds[v.admins++] = identity;
            if (i == 0) v.keyHash = keyHash;
        }
        v.ok = true;
    }

    /// The hash an ERC-7739 nested signature signs, and its signature list.
    /// @dev The account's domain is OpenZeppelin `EIP712`'s: name, version, chainId and verifyingContract.
    function _unnest(bytes32 hash, bytes calldata signature) private view returns (bytes32, bytes calldata) {
        (, string memory name, string memory version, uint256 chainId, address verifying, bytes32 salt,) =
            IERC5267(msg.sender).eip712Domain();
        (bytes calldata inner, bytes32 appSeparator, bytes32 contentsHash, string calldata descr) =
            signature.decodeTypedDataSig();
        bytes memory domain = abi.encode(keccak256(bytes(name)), keccak256(bytes(version)), chainId, verifying, salt);
        // Zero for an empty or malformed contents type, which binds nothing.
        bytes32 structHash = descr.typedDataSignStructHash(contentsHash, domain);
        if (structHash != 0 && hash == appSeparator.toTypedDataHash(contentsHash)) {
            return (appSeparator.toTypedDataHash(structHash), inner);
        }
        bytes32 separator = keccak256(
            abi.encode(DOMAIN_TYPEHASH, keccak256(bytes(name)), keccak256(bytes(version)), chainId, verifying)
        );
        return (separator.toTypedDataHash(hash.personalSignStructHash()), signature);
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
    /// the account, this validator or the registry is an admin operation. Any other target is
    /// outside, the ClaimExecutor included: anyone may call its entries. Anything but `execute`,
    /// and this validator's `onInstall`/`onUninstall` called directly, is refused.
    /// Also returns the decoded executions.
    function _scope(address account, bytes calldata callData)
        private
        view
        returns (Scope scope, Execution[] memory executions)
    {
        if (_selector(callData) != IERC7579Execution.execute.selector) return (Scope.Refused, executions);
        (CallType callType,,,) = Mode.wrap(bytes32(callData[4:36])).decodeMode();
        bytes calldata executionCalldata = _executionCalldata(callData);
        if (callType == ERC7579Utils.CALLTYPE_SINGLE) {
            (address target, uint256 value, bytes calldata data) = executionCalldata.decodeSingle();
            executions = new Execution[](1);
            executions[0] = Execution({target: target, value: value, callData: data});
            return (_targetScope(account, target, data), executions);
        }
        if (callType == ERC7579Utils.CALLTYPE_BATCH) {
            Execution[] calldata batch = executionCalldata.decodeBatch();
            for (uint256 i; i < batch.length; ++i) {
                Scope s = _targetScope(account, batch[i].target, batch[i].callData);
                if (s > scope) scope = s;
            }
            return (scope, batch);
        }
        return (Scope.Refused, executions);
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

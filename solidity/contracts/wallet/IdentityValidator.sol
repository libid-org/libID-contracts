// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/IERC4337.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {IERC5267} from "@openzeppelin/contracts/interfaces/IERC5267.sol";
import {IERC7579ModuleConfig, MODULE_TYPE_VALIDATOR} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {ERC4337Utils} from "@openzeppelin/contracts/account/utils/ERC4337Utils.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {ERC7739Utils} from "@openzeppelin/contracts/utils/cryptography/draft-ERC7739Utils.sol";

import {IIdentityValidator, identityOf, rulesHashOf} from "./IIdentityValidator.sol";
import {IdentityValidatorState} from "./IdentityValidatorState.sol";
import {IWalletFactory} from "./IWalletFactory.sol";
import {SessionRules} from "./SessionRules.sol";

/// @title IdentityValidator - the one ERC-7579 validator of every WebWallet.
/// @notice Holds each account's linked identities, sessions, threshold and root operations.
///         The threshold counts distinct admin platforms.
/// @dev Every slot validation reads or writes has the account as its innermost mapping key (ERC-7562),
///      and validation reads no clock: windows go back to the EntryPoint packed. What an operation may
///      do runs in SessionRules, deployed by the constructor and called through DELEGATECALL.
contract IdentityValidator is IIdentityValidator, IdentityValidatorState {
    using ERC7739Utils for *;
    using MessageHashUtils for bytes32;

    uint48 public constant MIN_RECOVERY_DELAY = 48 hours;
    uint48 public constant MAX_RECOVERY_DELAY = 365 days;

    address private immutable REGISTRY;
    address private immutable FACTORY;
    address private immutable RULES;

    /// The ERC-7739 detection hash: with an empty signature, it answers `0x77390001`.
    bytes32 private constant ERC7739_PROBE = 0x7739773977397739773977397739773977397739773977397739773977397739;

    bytes32 private constant EXECUTE_TYPEHASH = keccak256(
        "Execute(bytes32 mode,bytes executionCalldata,uint48 at,uint256 nonce,uint48 deadline,uint256 callGas)"
    );

    /// What a root operation does: a call by the account to itself, or one of this validator's own.
    enum RootAction {
        AccountCall,
        SetThreshold,
        RevokeSession,
        Unlink,
        SetRecoveryDelay,
        SetRecoveryFrozen
    }

    modifier onlyRegistry() {
        if (msg.sender != REGISTRY) revert NotRegistry(msg.sender);
        _;
    }

    constructor(address walletRegistry_, address walletFactory_) {
        REGISTRY = walletRegistry_;
        FACTORY = walletFactory_;
        RULES = address(new SessionRules());
    }

    // ─── ERC-7579 module ────────────────────────────────────────────

    function isModuleType(uint256 moduleTypeId) external pure returns (bool) {
        return moduleTypeId == MODULE_TYPE_VALIDATOR;
    }

    /// @dev Starts a fresh install: nothing of an earlier one is visible. Only the factory's wallet of the
    ///      genesis identity installs it, so a migration keeps the genesis.
    ///      `installs` is odd while an install is live.
    function onInstall(bytes calldata data) external {
        uint256 install = _install(msg.sender);
        if (install % 2 == 1) revert InstallLive(msg.sender);
        (bytes32 platformId, bytes32 idNode) = abi.decode(data[:64], (bytes32, bytes32));
        address wallet = IWalletFactory(FACTORY).walletAddress(platformId, idNode);
        if (wallet != msg.sender) revert NotFactoryWallet(msg.sender, wallet);
        _s().installs[msg.sender] = ++install;
        AccountState storage a = _s().accounts[install][msg.sender];
        a.platformId = platformId;
        a.idNode = idNode;
        _link(msg.sender, platformId, idNode);
        if (data.length == 64) return;
        (,, bytes memory key, Policy memory policy) = abi.decode(data, (bytes32, bytes32, bytes, Policy));
        if (!policy.admin) revert InstallSessionNotAdmin();
        _addNow(msg.sender, identityOf(platformId, idNode), key, policy);
    }

    /// @dev The account removes the module before it calls this hook, as OpenZeppelin's `AccountERC7579` does.
    function onUninstall(bytes calldata) external {
        uint256 install = _install(msg.sender);
        if (install % 2 == 0) revert NotInstalled(msg.sender);
        if (IERC7579ModuleConfig(msg.sender).isModuleInstalled(MODULE_TYPE_VALIDATOR, address(this), "")) {
            revert InstallLive(msg.sender);
        }
        _s().installs[msg.sender] = install + 1;
    }

    /// @dev Below quorum, charges the session's allowances: a refused operation's charges are
    ///      reverted with the EntryPoint's call.
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash) external returns (uint256) {
        Authorization memory auth = _decode(userOp.signature);
        uint8 quorum = threshold(msg.sender);
        (bool ok, bool below, Verified memory v) = _signers(userOpHash, auth, quorum);
        if (!ok) return ERC4337Utils.SIG_VALIDATION_FAILED;
        (ok, v) = _rules(abi.encodeCall(SessionRules.allowed, (msg.sender, REGISTRY, v, userOp, below)));
        if (!ok) return ERC4337Utils.SIG_VALIDATION_FAILED;
        return (uint256(v.validAfter) << 208) | (uint256(v.validUntil) << 160);
    }

    /// @dev Inside the signers' window; below quorum, signers `_cosigned` signing `TypedDataSign` for an
    ///      app the first one lists, bound to it at `at` 0.
    function isValidSignatureWithSender(address, bytes32 hash, bytes calldata signature)
        external
        view
        returns (bytes4)
    {
        if (hash == ERC7739_PROBE && signature.length == 0) return bytes4(0x77390001);
        (bytes32 signed, bytes calldata inner, bytes32 app) = _unnest(hash, signature);
        Authorization memory auth = _decode(inner);
        uint8 quorum = threshold(msg.sender);
        Verified memory v = _verify(msg.sender, signed, auth.signatures, quorum, 0);
        bool live = _inWindow(v);
        bool allowed = v.adminPlatforms >= quorum
            || (_cosigned(v, auth.signatures.length)
                && app != 0
                && MerkleProof.verify(
                    auth.domainProof, _sessions(msg.sender, v.keyHash)[msg.sender].domainsRoot, _leaf(abi.encode(app))
                ));
        return v.ok && live && allowed ? IERC1271.isValidSignature.selector : bytes4(0xffffffff);
    }

    // ─── Direct execution ─────────────────────────────────────────

    /// @dev Signers and rules as `validateUserOp`'s at `quorum`, charging after the calls ran; the window
    ///      is checked once the charges narrowed it.
    function checkExecution(
        bytes32 mode,
        bytes calldata executionCalldata,
        uint48 deadline,
        uint256 callGas,
        bytes calldata authorization,
        uint256 nonce,
        uint8 quorum,
        bytes32 domainSeparator
    ) external {
        Authorization memory auth = abi.decode(authorization, (Authorization));
        if (deadline == 0 || block.timestamp > deadline) revert ExecutionExpired(deadline);
        bytes32 digest = domainSeparator.toTypedDataHash(
            keccak256(
                abi.encode(EXECUTE_TYPEHASH, mode, keccak256(executionCalldata), auth.at, nonce, deadline, callGas)
            )
        );
        (bool ok, bool below, Verified memory v) = _signers(digest, auth, quorum);
        if (!ok || !_inWindow(v)) revert ExecutionNotAuthorized();
        (ok, v) = _rules(
            abi.encodeCall(
                SessionRules.allowedExecution, (msg.sender, REGISTRY, v, mode, executionCalldata, auth, below)
            )
        );
        if (!ok) revert ExecutionNotAuthorized();
        if (!_inWindow(v)) revert ExecutionOutsidePeriod(auth.at);
    }

    // ─── Views ──────────────────────────────────────────────────────

    function walletRegistry() external view returns (address) {
        return REGISTRY;
    }

    function walletFactory() external view returns (address) {
        return FACTORY;
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

    function linkedPlatforms(address account) external view returns (uint32) {
        return _account(account).platforms;
    }

    function allowanceOf(address account, bytes calldata key, address token)
        external
        view
        returns (AllowanceState memory state)
    {
        Session storage s = _session(account, key);
        Counter storage c = _counter(account, keccak256(key), s.rulesHash, token);
        if (_live(account, s) && c.listed) state = AllowanceState(c.amount, c.period, c.periodStart, c.spent);
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

    function recoveryFrozen(address account, bytes32 identity) public view returns (bool) {
        return _s().recoveryFrozen[_install(account)][identity][account];
    }

    function rootReadyAt(address account, bytes32 opId) external view returns (uint48) {
        Root memory r = _roots(account, opId)[account];
        return _superseded(account, r) ? 0 : r.readyAt;
    }

    // ─── Registry ───────────────────────────────────────────────────

    function link(address account, bytes32 platformId, bytes32 idNode) external onlyRegistry {
        _link(account, platformId, idNode);
    }

    function addSessionByProof(address account, bytes32 identity, bytes calldata key, Policy calldata policy)
        external
        onlyRegistry
        returns (uint48 activeAt)
    {
        if (recoveryFrozen(account, identity)) revert RecoveryFrozen(identity);
        if (!_account(account).hadSession) revert FirstSessionRefused(account);
        activeAt = _maturity(account);
        _replacePending(account, identity, key);
        _add(account, identity, key, policy, activeAt, true);
        emit SessionAddedByProof(account, identity, key, policy, activeAt);
    }

    /// @dev The first session is the one add active at once.
    function addSessionByAccount(address account, bytes32 identity, bytes calldata key, Policy calldata policy)
        external
        onlyRegistry
    {
        AccountState storage a = _account(account);
        if (a.hadSession) return _addNow(account, identity, key, policy);
        if (!policy.admin || identity != identityOf(a.platformId, a.idNode)) {
            revert FirstSessionRefused(account);
        }
        _add(account, identity, key, policy, 0, false);
        emit SessionAdded(account, identity, key, policy);
    }

    // ─── The account ────────────────────────────────────────────────

    function addSession(bytes32 identity, bytes calldata key, Policy calldata policy) external {
        _addNow(msg.sender, identity, key, policy);
    }

    function revokeSession(bytes calldata key) external {
        _revoke(msg.sender, key, false);
    }

    function setRecoveryDelay(uint48 delay) external {
        if (delay < recoveryDelay(msg.sender)) revert RootOperationRequired();
        _setRecoveryDelay(msg.sender, delay);
    }

    /// Decodes an `Authorization`; external so a malformed one fails validation instead of reverting it.
    function decodeAuthorization(bytes calldata signature) external pure returns (Authorization memory) {
        return abi.decode(signature, (Authorization));
    }

    function setThreshold(uint8) external pure {
        revert RootOperationRequired();
    }

    function unlink(bytes32) external pure {
        revert RootOperationRequired();
    }

    function setRecoveryFrozen(bytes32, bool) external pure {
        revert RootOperationRequired();
    }

    function queueRoot(address target, bytes calldata data) external returns (bytes32 opId) {
        _rootAction(msg.sender, target, data);
        opId = _rootId(msg.sender, target, data);
        uint48 readyAt = _maturity(msg.sender);
        _roots(msg.sender, opId)[msg.sender] = Root({readyAt: readyAt, epoch: _account(msg.sender).rootEpoch});
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

        RootAction action = _rootAction(account, target, data);
        if (action == RootAction.AccountCall) {
            Address.functionCall(account, data);
        } else if (action == RootAction.SetThreshold) {
            _setThreshold(account, abi.decode(data[4:], (uint8)));
        } else if (action == RootAction.RevokeSession) {
            _revoke(account, abi.decode(data[4:], (bytes)), true);
        } else if (action == RootAction.Unlink) {
            _unlink(account, abi.decode(data[4:], (bytes32)));
        } else if (action == RootAction.SetRecoveryDelay) {
            _setRecoveryDelay(account, abi.decode(data[4:], (uint48)));
        } else {
            (bytes32 identity, bool frozen) = abi.decode(data[4:], (bytes32, bool));
            _s().recoveryFrozen[_install(account)][identity][account] = frozen;
            if (frozen) _revokePending(account, identity);
        }
    }

    // ─── Internals ──────────────────────────────────────────────────

    function _link(address account, bytes32 platformId, bytes32 idNode) private {
        bytes32 identity = identityOf(platformId, idNode);
        mapping(address => bool) storage linked = _s().links[_install(account)][identity];
        if (linked[account]) return;
        linked[account] = true;
        _s().platformOf[_install(account)][identity][account] = platformId;
        AccountState storage a = _account(account);
        ++a.identities;
        if (++_platformLinks(account, platformId)[account] == 1) ++a.platforms;
    }

    function _add(
        address account,
        bytes32 identity,
        bytes memory key,
        Policy memory policy,
        uint48 activeAt,
        bool byProof
    ) private {
        if (!isLinked(account, identity)) revert NotLinked(account, identity);
        if (key.length < 20) revert InvalidKey(key);
        if ((policy.validAfter | policy.validUntil | activeAt) >= 1 << 47) {
            revert PolicyOutOfRange(policy.validAfter, policy.validUntil);
        }
        bytes32 keyHash = keccak256(key);
        mapping(address => Session) storage sessions = _sessions(account, keyHash);
        if (_live(account, sessions[account])) revert SessionExists(key);
        Rules memory r = policy.rules;
        bytes32 rulesHash = rulesHashOf(r);
        sessions[account] = Session({
            identity: identity,
            validAfter: policy.validAfter,
            validUntil: policy.validUntil,
            admin: policy.admin,
            activeAt: activeAt,
            generation: _generations(account, identity)[account],
            byProof: byProof,
            signers: policy.signers,
            scopeRoot: r.scopeRoot,
            domainsRoot: r.domainsRoot,
            paymastersRoot: r.paymastersRoot,
            rulesHash: rulesHash
        });
        // A counter of the same key and rules keeps its spend.
        for (uint256 i; i < r.allowances.length; ++i) {
            Allowance memory allowance = r.allowances[i];
            if (allowance.period >= 1 << 47) revert BadAllowance(allowance.token);
            for (uint256 j; j < i; ++j) {
                if (r.allowances[j].token == allowance.token) revert BadAllowance(allowance.token);
            }
            Counter storage c = _counter(account, keyHash, rulesHash, allowance.token);
            (c.amount, c.period, c.listed) = (allowance.amount, allowance.period, true);
        }

        AccountState storage a = _account(account);
        a.hadSession = true;
        if (policy.admin) {
            ++a.adminSessions;
            ++_identityAdmins(account, identity)[account];
        }
    }

    /// Adds a session that signs from the next second.
    function _addNow(address account, bytes32 identity, bytes memory key, Policy memory policy) private {
        // forge-lint: disable-next-line(unsafe-typecast)
        _add(account, identity, key, policy, uint48(block.timestamp), false);
        emit SessionAdded(account, identity, key, policy);
    }

    function _revoke(address account, bytes memory key, bool root) private {
        Session storage s = _session(account, key);
        bytes32 identity = s.identity;
        if (identity == 0) revert NoSession(key);
        // A dead session's admin count went with its unlink.
        if (s.admin && _live(account, s)) {
            AccountState storage a = _account(account);
            if (a.adminSessions == 1 && !root) revert RootOperationRequired();
            --a.adminSessions;
            --_identityAdmins(account, identity)[account];
            // A pending session has signed nothing; one that was active may have queued roots.
            if (s.activeAt < block.timestamp) ++a.rootEpoch;
        }
        delete _sessions(account, keccak256(key))[account];
        emit SessionRevoked(account, identity, key);
    }

    function _setThreshold(address account, uint8 t) private {
        AccountState storage a = _account(account);
        if (t > a.platforms) revert ThresholdTooHigh(t, a.platforms);
        a.threshold = t;
    }

    function _setRecoveryDelay(address account, uint48 delay) private {
        if (delay < MIN_RECOVERY_DELAY) revert RecoveryDelayTooShort(delay);
        if (delay > MAX_RECOVERY_DELAY) revert RecoveryDelayTooLong(delay);
        _account(account).recoveryDelay = delay;
    }

    function _unlink(address account, bytes32 identity) private {
        mapping(address => bool) storage linked = _s().links[_install(account)][identity];
        if (!linked[account]) revert NotLinked(account, identity);
        AccountState storage a = _account(account);
        uint32 left = a.identities - 1;
        if (left == 0) revert LastIdentity(identity);
        mapping(address => uint32) storage platformLinks = _platformLinks(account, _platformOf(account, identity));
        uint32 platformsLeft = platformLinks[account] == 1 ? a.platforms - 1 : a.platforms;
        if (a.threshold > platformsLeft) revert ThresholdTooHigh(a.threshold, platformsLeft);
        mapping(address => uint32) storage admins = _identityAdmins(account, identity);
        if (admins[account] == a.adminSessions) revert LastAdmin(identity);
        if (identity == identityOf(a.platformId, a.idNode)) revert GenesisIdentity(identity);
        a.adminSessions -= admins[account];
        delete admins[account];
        delete linked[account];
        ++_generations(account, identity)[account];
        --platformLinks[account];
        a.identities = left;
        a.platforms = platformsLeft;
        ++a.rootEpoch;
        emit IdentityUnlinked(account, identity);
    }

    /// The root operation's action; reverts `BadRootOperation` for any other target or selector.
    function _rootAction(address account, address target, bytes calldata data) private view returns (RootAction) {
        if (target == account) return RootAction.AccountCall;
        if (target == address(this)) {
            bytes4 selector = _selector(data);
            if (selector == this.setThreshold.selector) return RootAction.SetThreshold;
            if (selector == this.revokeSession.selector) return RootAction.RevokeSession;
            if (selector == this.unlink.selector) return RootAction.Unlink;
            if (selector == this.setRecoveryDelay.selector) return RootAction.SetRecoveryDelay;
            if (selector == this.setRecoveryFrozen.selector) return RootAction.SetRecoveryFrozen;
        }
        revert BadRootOperation(target);
    }

    /// Whether an unlink or an active admin session's revoke ran after the root operation was queued.
    function _superseded(address account, Root memory r) private view returns (bool) {
        return r.epoch != _account(account).rootEpoch;
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
        _revokePending(account, identity);
        _s().pendingKeys[_install(account)][identity][account] = key;
    }

    /// Revokes the identity's latest session by proof while it is still pending.
    function _revokePending(address account, bytes32 identity) private {
        bytes memory old = _s().pendingKeys[_install(account)][identity][account];
        if (old.length != 0) {
            Session storage o = _session(account, old);
            if (o.identity == identity && o.activeAt >= block.timestamp) _revoke(account, old, true);
        }
    }

    /// SessionRules' verdict on `call`, and the signers' window narrowed to the periods it charged.
    function _rules(bytes memory call) private returns (bool, Verified memory) {
        return abi.decode(Address.functionDelegateCall(RULES, call), (bool, Verified));
    }

    /// The `Authorization` in `signature`, or one with no signatures when it is malformed.
    function _decode(bytes calldata signature) private view returns (Authorization memory auth) {
        try this.decodeAuthorization(signature) returns (Authorization memory decoded) {
            auth = decoded;
        } catch {}
    }

    /// Checks that every signature is by a session of its identity's current link, and counts the
    /// distinct platforms of its signers and of the admin sessions among them. Short of `quorum`, every
    /// signature is over `keccak256(abi.encode(hash, at, keccak256(sigs[0].key)))`: the governing session.
    function _verify(address account, bytes32 hash, SessionSignature[] memory sigs, uint8 quorum, uint48 at)
        private
        view
        returns (Verified memory v)
    {
        if (sigs.length == 0) return v;
        bytes32[] memory platforms = new bytes32[](sigs.length);
        bytes32[] memory adminPlatforms = new bytes32[](sigs.length);
        for (uint256 i; i < sigs.length; ++i) {
            bytes32 keyHash = keccak256(sigs[i].key);
            Session storage s = _sessions(account, keyHash)[account];
            if (!_live(account, s)) return v;
            if (s.byProof) v.byProof = true;
            if (i == 0) (v.keyHash, v.signers) = (keyHash, s.signers);
            _narrow(v, s.validAfter > s.activeAt ? s.validAfter : s.activeAt, s.validUntil);
            bytes32 platformId = _platformOf(account, s.identity);
            if (!_contains(platforms, v.platforms, platformId)) platforms[v.platforms++] = platformId;
            if (s.admin && !_contains(adminPlatforms, v.adminPlatforms, platformId)) {
                adminPlatforms[v.adminPlatforms++] = platformId;
            }
        }
        bytes32 signed = v.adminPlatforms < quorum ? keccak256(abi.encode(hash, at, v.keyHash)) : hash;
        for (uint256 i; i < sigs.length; ++i) {
            if (!_signedBy(sigs[i].key, signed, sigs[i].signature)) return v;
        }
        v.ok = true;
    }

    /// `_verify` over `hash` at `auth.at`, whether the signers fall short of `quorum`, and whether
    /// they sign: below it, `_cosigned`.
    function _signers(bytes32 hash, Authorization memory auth, uint8 quorum)
        private
        view
        returns (bool ok, bool below, Verified memory v)
    {
        v = _verify(msg.sender, hash, auth.signatures, quorum, auth.at);
        below = v.adminPlatforms < quorum;
        ok = v.ok && (!below || _cosigned(v, auth.signatures.length));
    }

    /// Below quorum: `n` signatures, by sessions none by proof, of as many distinct platforms as the
    /// first session's `signers`.
    function _cosigned(Verified memory v, uint256 n) private pure returns (bool) {
        uint256 need = v.signers == 0 ? 1 : v.signers;
        return !v.byProof && n == need && v.platforms == need;
    }

    /// The hash an ERC-7739 nested signature signs, its `Authorization`, and the app separator
    /// of a `TypedDataSign`, zero for `PersonalSign`.
    /// @dev Both forms use the account's `eip712Domain()`: `TypedDataSign` all five fields,
    ///      `PersonalSign` the fields it names. A domain with extensions reverts.
    function _unnest(bytes32 hash, bytes calldata signature) private view returns (bytes32, bytes calldata, bytes32) {
        (bytes1 fields, bytes32 nameHash, bytes32 versionHash, uint256 chainId, address verifying, bytes32 salt) =
            _domain(msg.sender);
        (bytes calldata inner, bytes32 appSeparator, bytes32 contentsHash, string calldata descr) =
            signature.decodeTypedDataSig();
        bytes memory domain = abi.encode(nameHash, versionHash, chainId, verifying, salt);
        // Zero for an empty or malformed contents type, which binds nothing.
        bytes32 structHash = descr.typedDataSignStructHash(contentsHash, domain);
        if (structHash != 0 && hash == appSeparator.toTypedDataHash(contentsHash)) {
            return (appSeparator.toTypedDataHash(structHash), inner, appSeparator);
        }
        bytes32 separator = MessageHashUtils.toDomainSeparator(fields, nameHash, versionHash, chainId, verifying, salt);
        return (separator.toTypedDataHash(hash.personalSignStructHash()), signature, 0);
    }

    /// The account's `eip712Domain()`, its name and version hashed.
    function _domain(address account)
        private
        view
        returns (bytes1 fields, bytes32 nameHash, bytes32 versionHash, uint256 chainId, address verifying, bytes32 salt)
    {
        string memory name;
        string memory version;
        (fields, name, version, chainId, verifying, salt,) = IERC5267(account).eip712Domain();
        return (fields, keccak256(bytes(name)), keccak256(bytes(version)), chainId, verifying, salt);
    }

    /// The block's timestamp is inside `v`'s window.
    function _inWindow(Verified memory v) private view returns (bool) {
        return v.validAfter < block.timestamp && (v.validUntil == 0 || block.timestamp <= v.validUntil);
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
}

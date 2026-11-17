// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC7579ModuleConfig, MODULE_TYPE_VALIDATOR} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";

import {IIdentityValidator, identityOf, rulesHashOf} from "./IIdentityValidator.sol";
import {IdentityValidatorState} from "./IdentityValidatorState.sol";
import {IWalletFactory} from "./IWalletFactory.sol";

/// @title IdentityAdmin - IdentityValidator's writes: installs, links, sessions and root operations.
/// @notice Deployed by IdentityValidator's constructor, which forwards each of these entries to it through
///         DELEGATECALL: it reads and writes the validator's storage. Called directly, it reverts.
///         In that frame `msg.sender` is the account or the registry, and `address(this)` the validator.
contract IdentityAdmin is IdentityValidatorState {
    address private immutable SELF = address(this);
    address private immutable REGISTRY;
    address private immutable FACTORY;

    /// What a root operation does: a call by the account to itself, or one of the validator's own.
    enum RootAction {
        AccountCall,
        SetThreshold,
        RevokeSession,
        Unlink,
        SetRootDelay
    }

    modifier delegated() {
        if (address(this) == SELF) revert NotDelegated();
        _;
    }

    modifier onlyRegistry() {
        if (msg.sender != REGISTRY) revert IIdentityValidator.NotRegistry(msg.sender);
        _;
    }

    constructor(address walletRegistry, address walletFactory) {
        REGISTRY = walletRegistry;
        FACTORY = walletFactory;
    }

    // ─── ERC-7579 module ────────────────────────────────────────────

    /// @dev Starts a fresh install: nothing of an earlier one is visible. Only the factory's wallet of the
    ///      genesis identity installs it, so a migration keeps the genesis.
    ///      `installs` is odd while an install is live.
    function onInstall(bytes calldata data) external delegated {
        uint256 install = _install(msg.sender);
        if (install % 2 == 1) revert IIdentityValidator.InstallLive(msg.sender);
        (bytes32 platformId, bytes32 idNode, uint256 salt, bytes memory key, IIdentityValidator.Policy memory policy) =
            abi.decode(data, (bytes32, bytes32, uint256, bytes, IIdentityValidator.Policy));
        address wallet = IWalletFactory(FACTORY).walletAddress(platformId, idNode, salt);
        if (wallet != msg.sender) revert IIdentityValidator.NotFactoryWallet(msg.sender, wallet);
        _s().installs[msg.sender] = ++install;
        AccountState storage a = _s().accounts[install][msg.sender];
        a.platformId = platformId;
        a.idNode = idNode;
        if (salt != 0) a.salt = salt;
        _link(msg.sender, platformId, idNode);
        if (key.length == 0) return;
        if (!policy.admin) revert IIdentityValidator.InstallSessionNotAdmin();
        _add(msg.sender, identityOf(platformId, idNode), key, policy, false, false);
    }

    /// @dev The account removes the module before it calls this hook, as OpenZeppelin's `AccountERC7579` does.
    function onUninstall(bytes calldata) external delegated {
        uint256 install = _install(msg.sender);
        if (install % 2 == 0) revert IIdentityValidator.NotInstalled(msg.sender);
        if (IERC7579ModuleConfig(msg.sender).isModuleInstalled(MODULE_TYPE_VALIDATOR, address(this), "")) {
            revert IIdentityValidator.InstallLive(msg.sender);
        }
        _s().installs[msg.sender] = install + 1;
    }

    // ─── Registry ───────────────────────────────────────────────────

    function link(address account, bytes32 platformId, bytes32 idNode) external delegated onlyRegistry {
        _link(account, platformId, idNode);
    }

    function addSessionByRegistry(
        address account,
        bytes32 identity,
        bytes calldata key,
        IIdentityValidator.Policy calldata policy,
        bool byLogin
    ) external delegated onlyRegistry {
        _add(account, identity, key, policy, byLogin, true);
    }

    function removeByLogin(address account, bytes32 identity) external delegated onlyRegistry {
        _remove(account, identity, true);
        emit IIdentityValidator.SessionsRemovedByLogin(account, identity);
    }

    // ─── The account ────────────────────────────────────────────────

    function addSession(bytes32 identity, bytes calldata key, IIdentityValidator.Policy calldata policy)
        external
        delegated
    {
        _add(msg.sender, identity, key, policy, false, false);
    }

    function revokeSession(bytes calldata key) external delegated {
        _revoke(msg.sender, key, false);
        _keepQuorum(msg.sender);
    }

    function queueRoot(address target, bytes calldata data) external delegated returns (bytes32 opId) {
        _rootAction(msg.sender, target, data);
        opId = _rootId(msg.sender, target, data);
        uint48 delay = _account(msg.sender).rootDelay;
        // A root operation never matures in the second it was queued, so one batch cannot queue and run it.
        // forge-lint: disable-next-line(unsafe-typecast)
        uint48 readyAt = uint48(block.timestamp) + (delay == 0 ? 1 : delay);
        _roots(msg.sender, opId)[msg.sender] = Root({readyAt: readyAt, epoch: _account(msg.sender).rootEpoch});
        emit IIdentityValidator.RootQueued(msg.sender, opId, target, data, readyAt);
    }

    function cancelRoot(bytes32 opId) external delegated {
        mapping(address => Root) storage root = _roots(msg.sender, opId);
        if (root[msg.sender].readyAt == 0) revert IIdentityValidator.RootNotReady(opId);
        delete root[msg.sender];
        emit IIdentityValidator.RootCancelled(msg.sender, opId);
    }

    function executeRoot(address account, address target, bytes calldata data) external delegated {
        bytes32 opId = _rootId(account, target, data);
        mapping(address => Root) storage root = _roots(account, opId);
        Root memory r = root[account];
        if (r.readyAt == 0 || block.timestamp < r.readyAt) revert IIdentityValidator.RootNotReady(opId);
        if (_superseded(account, r)) revert IIdentityValidator.RootSuperseded(opId);
        delete root[account];
        emit IIdentityValidator.RootExecuted(account, opId);

        RootAction action = _rootAction(account, target, data);
        if (action == RootAction.AccountCall) {
            Address.functionCall(account, data);
        } else if (action == RootAction.SetThreshold) {
            _setThreshold(account, abi.decode(data[4:], (uint8)));
        } else if (action == RootAction.RevokeSession) {
            _revoke(account, abi.decode(data[4:], (bytes)), true);
        } else if (action == RootAction.Unlink) {
            _remove(account, abi.decode(data[4:], (bytes32)), false);
        } else {
            _setRootDelay(account, abi.decode(data[4:], (uint48)));
        }
        if (action == RootAction.SetThreshold || action == RootAction.RevokeSession) _keepQuorum(account);
    }

    // ─── Internals ──────────────────────────────────────────────────

    function _link(address account, bytes32 platformId, bytes32 idNode) private {
        bytes32 identity = identityOf(platformId, idNode);
        mapping(address => bool) storage linked = _s().links[_install(account)][identity];
        if (linked[account]) return;
        linked[account] = true;
        _s().platformOf[_install(account)][identity][account] = platformId;
        AccountState storage a = _account(account);
        if (++_platformLinks(account, platformId)[account] == 1) ++a.platforms;
    }

    /// Adds a session that signs from the next second. `byLogin` adds it `byProof`. From the registry, an
    /// account that never had a session takes only its own link's genesis admin session, active at once.
    function _add(
        address account,
        bytes32 identity,
        bytes memory key,
        IIdentityValidator.Policy memory policy,
        bool byLogin,
        bool byRegistry
    ) private {
        if (!_isLinked(account, identity)) {
            revert IIdentityValidator.NotLinked(account, identity);
        }
        AccountState storage a = _account(account);
        // forge-lint: disable-next-line(unsafe-typecast)
        uint48 activeAt = uint48(block.timestamp);
        if (byRegistry && !a.hadSession) {
            if (byLogin || !policy.admin || identity != identityOf(a.platformId, a.idNode)) {
                revert IIdentityValidator.FirstSessionRefused(account);
            }
            activeAt = 0;
        }
        _checkSession(key, policy, activeAt);
        bytes32 keyHash = keccak256(key);
        mapping(address => IIdentityValidator.Session) storage sessions = _sessions(account, keyHash);
        if (_live(account, sessions[account])) revert IIdentityValidator.SessionExists(key);
        IIdentityValidator.Rules memory r = policy.rules;
        bytes32 rulesHash = rulesHashOf(r);
        sessions[account] = IIdentityValidator.Session({
            identity: identity,
            validAfter: policy.validAfter,
            validUntil: policy.validUntil,
            admin: policy.admin,
            activeAt: activeAt,
            generation: _generations(account, identity)[account],
            byProof: byLogin,
            signers: policy.signers,
            scopeRoot: r.scopeRoot,
            domainsRoot: r.domainsRoot,
            paymastersRoot: r.paymastersRoot,
            rulesHash: rulesHash
        });
        _setAllowances(account, keyHash, rulesHash, r.allowances);

        a.hadSession = true;
        if (policy.admin) {
            ++a.adminSessions;
            ++_identityAdmins(account, identity)[account];
            if (++_platformAdmins(account, _platformOf(account, identity))[account] == 1) ++a.adminPlatforms;
        }
        if (byLogin) emit IIdentityValidator.SessionAddedByLogin(account, identity, key, policy, activeAt);
        else emit IIdentityValidator.SessionAdded(account, identity, key, policy);
    }

    function _checkSession(bytes memory key, IIdentityValidator.Policy memory policy, uint48 activeAt) private pure {
        if (key.length < 20) revert IIdentityValidator.InvalidKey(key);
        if ((policy.validAfter | policy.validUntil | activeAt) >= 1 << 47) {
            revert IIdentityValidator.PolicyOutOfRange(policy.validAfter, policy.validUntil);
        }
        if (policy.admin && policy.validUntil != 0) revert IIdentityValidator.AdminSessionExpires(policy.validUntil);
    }

    /// Sets the key's counters under `rulesHash`; one of the same key and rules keeps its spend.
    function _setAllowances(
        address account,
        bytes32 keyHash,
        bytes32 rulesHash,
        IIdentityValidator.Allowance[] memory allowances
    ) private {
        address last;
        for (uint256 i; i < allowances.length; ++i) {
            IIdentityValidator.Allowance memory allowance = allowances[i];
            if (allowance.period >= 1 << 47 || (i != 0 && allowance.token <= last)) {
                revert IIdentityValidator.BadAllowance(allowance.token);
            }
            last = allowance.token;
            Counter storage c = _counter(account, keyHash, rulesHash, allowance.token);
            (c.amount, c.period, c.listed) = (allowance.amount, allowance.period, true);
        }
    }

    function _revoke(address account, bytes memory key, bool root) private {
        IIdentityValidator.Session storage s = _session(account, key);
        bytes32 identity = s.identity;
        if (identity == 0) revert IIdentityValidator.NoSession(key);
        // A dead session's admin count went with its unlink.
        if (s.admin && _live(account, s)) {
            AccountState storage a = _account(account);
            if (a.adminSessions == 1 && !root) revert IIdentityValidator.RootOperationRequired();
            _dropAdmins(account, identity, 1);
            // A session added this second has signed nothing; an older one may have queued roots.
            if (s.activeAt < block.timestamp) ++a.rootEpoch;
        }
        delete _sessions(account, keccak256(key))[account];
        emit IIdentityValidator.SessionRevoked(account, identity, key);
    }

    function _setThreshold(address account, uint8 t) private {
        AccountState storage a = _account(account);
        if (t > a.adminPlatforms) revert IIdentityValidator.ThresholdTooHigh(t, a.adminPlatforms);
        a.threshold = t;
    }

    function _setRootDelay(address account, uint48 delay) private {
        if (delay > MAX_DELAY) revert IIdentityValidator.RootDelayTooLong(delay);
        _account(account).rootDelay = delay;
    }

    /// Kills every session of `identity` and voids every queued root operation. Unlinks it unless it is the
    /// genesis, which a root operation may not name, and lowers the threshold to the platforms left.
    function _remove(address account, bytes32 identity, bool byLogin) private {
        mapping(address => bool) storage linked = _s().links[_install(account)][identity];
        if (!linked[account]) revert IIdentityValidator.NotLinked(account, identity);
        AccountState storage a = _account(account);
        bool genesis = identity == identityOf(a.platformId, a.idNode);
        if (genesis && !byLogin) revert IIdentityValidator.GenesisIdentity(identity);
        _dropAdmins(account, identity, _identityAdmins(account, identity)[account]);
        ++_generations(account, identity)[account];
        ++a.rootEpoch;
        if (genesis) return;
        delete linked[account];
        if (--_platformLinks(account, _platformOf(account, identity))[account] == 0) --a.platforms;
        // forge-lint: disable-next-line(unsafe-typecast)
        if (a.threshold > a.platforms) a.threshold = uint8(a.platforms);
        emit IIdentityValidator.IdentityUnlinked(account, identity);
    }

    /// Takes `n` admin sessions off the identity, its platform and the account.
    function _dropAdmins(address account, bytes32 identity, uint32 n) private {
        AccountState storage a = _account(account);
        a.adminSessions -= n;
        _identityAdmins(account, identity)[account] -= n;
        mapping(address => uint32) storage p = _platformAdmins(account, _platformOf(account, identity));
        if (n != 0 && (p[account] -= n) == 0) --a.adminPlatforms;
    }

    /// Refuses leaving admin sessions on fewer platforms than the threshold; none at all is allowed.
    function _keepQuorum(address account) private view {
        AccountState storage a = _account(account);
        uint32 left = a.adminPlatforms;
        if (left != 0 && left < a.threshold) revert IIdentityValidator.ThresholdTooHigh(a.threshold, left);
    }

    /// The root operation's action; reverts `BadRootOperation` for any other target or selector.
    function _rootAction(address account, address target, bytes calldata data) private view returns (RootAction) {
        if (target == account) return RootAction.AccountCall;
        if (target == address(this)) {
            bytes4 selector = _selector(data);
            if (selector == IIdentityValidator.setThreshold.selector) return RootAction.SetThreshold;
            if (selector == IIdentityValidator.revokeSession.selector) return RootAction.RevokeSession;
            if (selector == IIdentityValidator.unlink.selector) return RootAction.Unlink;
            if (selector == IIdentityValidator.setRootDelay.selector) return RootAction.SetRootDelay;
        }
        revert IIdentityValidator.BadRootOperation(target);
    }

    function _rootId(address account, address target, bytes calldata data) private pure returns (bytes32) {
        return keccak256(abi.encode(account, target, data));
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Bytes} from "@openzeppelin/contracts/utils/Bytes.sol";

import {IWalletFactory} from "./IWalletFactory.sol";
import {ADD_SESSION_DOMAIN, IWalletRegistry, LINK_IDENTITY_DOMAIN, REMOVE_SESSIONS_DOMAIN} from "./IWalletRegistry.sol";
import {IIdentityAdmin, IWebWallet} from "./IWebWallet.sol";
import {WalletRelease} from "./WalletRelease.sol";
import {WalletStorage, identityOf, policyHashFrom, rulesHashOf} from "./WalletStorage.sol";
import {WalletTransient} from "./WalletTransient.sol";

/// @title IdentityAdmin - the wallet's identities, sessions, app lists and root operations.
/// @notice WebWallet routes `IIdentityAdmin` to it through DELEGATECALL: it reads and writes the wallet's storage,
///         and `msg.sender` is the wallet's caller. Called at its own address, it reverts.
contract IdentityAdmin is IIdentityAdmin {
    address private immutable SELF = address(this);

    /// Not at its own address.
    modifier delegated() {
        _delegated();
        _;
    }

    /// The wallet's own call.
    modifier onlySelf() {
        _delegated();
        if (msg.sender != address(this)) revert IWebWallet.OnlySelf();
        _;
    }

    /// Outside `executeRoot`, only an EIP-7702 account's key in its own top-level call; runs under the lock.
    modifier rootOnly() {
        _delegated();
        if (msg.sender != address(this) || tx.origin != address(this) || _locked()) {
            revert IWebWallet.RootOperationRequired();
        }
        WalletTransient.put(WalletTransient.LOCK, true);
        _;
        WalletTransient.put(WalletTransient.LOCK, false);
    }

    // ─── Identities and sessions ────────────────────────────────────

    /// Links the proven identity. Its key becomes a session only at a factory wallet's genesis bootstrap: the
    /// genesis identity's admin session, active at once, while the wallet never had a session.
    function linkIdentity(
        bytes32 platformId,
        uint16 verifierVersion,
        bytes calldata payload,
        IIdentityAdmin.Policy calldata policy
    ) external payable onlySelf {
        (bytes32 rulesHash, bytes32 policyHash) = _hashes(policy);
        IWalletRegistry.Checked memory c =
            _check(LINK_IDENTITY_DOMAIN, platformId, verifierVersion, payload, policyHash);
        WalletStorage.link(platformId, c.identity);
        if (c.key.length == 0) return;
        WalletStorage.EpochState storage s = WalletStorage.state();
        if (s.platformId == 0 || s.hadSession || !policy.admin || c.identity != identityOf(s.platformId, s.idNode)) {
            revert IWebWallet.LinkSessionRefused();
        }
        _add(c.identity, c.key, policy, 0, false, rulesHash, policyHash);
    }

    /// The submitter a login names: the login of a linked identity adds its session, from the next second, or from
    /// this one when the wallet's batch sends it at its head.
    function addSessionByLogin(
        bytes32 platformId,
        uint16 verifierVersion,
        bytes calldata payload,
        IIdentityAdmin.Policy calldata policy
    ) external payable delegated {
        (bytes32 rulesHash, bytes32 policyHash) = _hashes(policy);
        _login(
            _check(ADD_SESSION_DOMAIN, platformId, verifierVersion, payload, policyHash), policy, rulesHash, policyHash
        );
    }

    /// The submitter a login names: the login kills every session of a linked identity and voids every queued root
    /// operation. With no key it unlinks the identity unless it is the genesis; with a key it keeps the link and adds
    /// the key as `addSessionByLogin` does, from the next second.
    function removeSessionsByLogin(
        bytes32 platformId,
        uint16 verifierVersion,
        bytes calldata payload,
        IIdentityAdmin.Policy calldata policy
    ) external payable delegated {
        (bytes32 rulesHash, bytes32 policyHash) = _hashes(policy);
        IWalletRegistry.Checked memory c =
            _check(REMOVE_SESSIONS_DOMAIN, platformId, verifierVersion, payload, policyHash);
        bool keyed = c.key.length != 0;
        _remove(c.identity, true, keyed);
        emit IWebWallet.SessionsRemovedByLogin(c.identity);
        if (keyed) _login(c, policy, rulesHash, policyHash);
    }

    /// Active from the next second, for a linked identity.
    function addSession(bytes32 identity, bytes calldata key, IIdentityAdmin.Policy calldata policy) external onlySelf {
        (bytes32 rulesHash, bytes32 policyHash) = _hashes(policy);
        _add(identity, key, policy, _now(), false, rulesHash, policyHash);
    }

    /// Revoking the last admin session is a root operation.
    function revokeSession(bytes calldata key) external onlySelf {
        _revoke(key, false);
    }

    /// The apps, each `keccak256(clientIdentifier)`, whose logins may add `identity`'s sessions; empty admits any.
    function setAppList(bytes32 identity, bytes32[] calldata apps) external onlySelf {
        WalletStorage.state().appLists[identity] = apps;
        emit IWebWallet.AppListSet(identity, apps);
    }

    /// A live session, else zero.
    function sessionOf(bytes calldata key) external view delegated returns (IIdentityAdmin.Session memory r) {
        WalletStorage.SessionRecord storage s = WalletStorage.session(keccak256(key));
        if (!WalletStorage.live(s)) return r;
        return IIdentityAdmin.Session({
            identity: s.identity,
            policyHash: policyHashFrom(s.validAfter, s.validUntil, s.admin, s.signers, s.rulesHash),
            activeAt: s.activeAt,
            admin: s.admin,
            byProof: s.byProof,
            signers: s.signers
        });
    }

    function isLinked(bytes32 identity) external view delegated returns (bool) {
        return WalletStorage.linkOf(identity).linked;
    }

    function appList(bytes32 identity) external view delegated returns (bytes32[] memory) {
        return WalletStorage.state().appLists[identity];
    }

    function allowanceOf(bytes calldata key, address token)
        external
        view
        delegated
        returns (IIdentityAdmin.AllowanceState memory a)
    {
        bytes32 keyHash = keccak256(key);
        WalletStorage.SessionRecord storage s = WalletStorage.session(keyHash);
        WalletStorage.Counter storage c = WalletStorage.counter(keyHash, s.rulesHash, token);
        if (WalletStorage.live(s) && c.listed) {
            a = IIdentityAdmin.AllowanceState(c.amount, c.period, c.periodStart, c.spent);
        }
    }

    function generationOf(bytes32 identity) external view delegated returns (uint32) {
        return WalletStorage.linkOf(identity).generation;
    }

    function linkedPlatforms() external view delegated returns (uint32) {
        return WalletStorage.state().platforms;
    }

    function hadSession() external view delegated returns (bool) {
        return WalletStorage.state().hadSession;
    }

    function genesisIdentity() external view delegated returns (bytes32 platformId, bytes32 idNode, uint256 salt) {
        WalletStorage.EpochState storage s = WalletStorage.state();
        return (s.platformId, s.idNode, s.salt);
    }

    // ─── Root operations ────────────────────────────────────────────

    /// `bump`, `setThreshold`, `setRootDelay`, `unlink` or `revokeSession`, ready after the root delay and never
    /// in the second it was queued. `bump(0)` is the factory's latest; a bump stores its version's implementation.
    function queueRoot(bytes calldata data) external onlySelf returns (bytes32 id) {
        bytes4 selector = WalletStorage.selectorOf(data);
        (, uint64 current) = WalletRelease.read();
        bytes memory op = data;
        address implementation;
        if (selector == IIdentityAdmin.bump.selector) {
            uint64 version = abi.decode(data[4:], (uint64));
            IWalletFactory factory = IWalletFactory(_factory());
            if (version == 0) (, version) = factory.latest();
            if (version <= current) revert IWebWallet.ReleaseNotAbove(current, version);
            implementation = factory.release(version);
            if (implementation == address(0)) revert IWebWallet.ReleaseMismatch(version);
            op = abi.encodeCall(IIdentityAdmin.bump, (version));
        } else if (
            selector != IIdentityAdmin.setThreshold.selector && selector != IIdentityAdmin.setRootDelay.selector
                && selector != IIdentityAdmin.unlink.selector && selector != IIdentityAdmin.revokeSession.selector
        ) {
            revert IWebWallet.RootOperationNotAllowed(selector);
        }
        id = keccak256(op);
        WalletStorage.EpochState storage s = WalletStorage.state();
        uint32 delay = s.rootDelay;
        uint48 readyAt = _now() + (delay == 0 ? 1 : delay);
        s.roots[id] = WalletStorage.Root({
            data: op, implementation: implementation, version: current, readyAt: readyAt, rootEpoch: s.rootEpoch
        });
        emit IWebWallet.RootQueued(id, current, readyAt, op);
    }

    function cancelRoot(bytes32 id) external onlySelf {
        mapping(bytes32 => WalletStorage.Root) storage roots = WalletStorage.state().roots;
        if (roots[id].readyAt == 0) revert IWebWallet.RootOperationUnknown(id);
        delete roots[id];
        emit IWebWallet.RootCancelled(id);
    }

    /// Anyone, once matured, under the version and root epoch it was queued in; never while the lock is held.
    function executeRoot(bytes32 id) external delegated {
        if (_locked()) revert IWebWallet.Locked();
        WalletTransient.put(WalletTransient.LOCK, true);
        WalletStorage.EpochState storage s = WalletStorage.state();
        WalletStorage.Root storage r = s.roots[id];
        uint48 readyAt = r.readyAt;
        if (readyAt == 0) revert IWebWallet.RootOperationUnknown(id);
        if (_now() < readyAt) revert IWebWallet.RootOperationNotReady(id);
        (, uint64 current) = WalletRelease.read();
        if (r.version != current || r.rootEpoch != s.rootEpoch) revert IWebWallet.RootOperationVoid(id);
        bytes memory data = r.data;
        address implementation = r.implementation;
        delete s.roots[id];
        emit IWebWallet.RootExecuted(id);
        _root(data, implementation);
        WalletTransient.put(WalletTransient.LOCK, false);
    }

    function rootOperation(bytes32 id) external view delegated returns (IIdentityAdmin.RootOperation memory) {
        WalletStorage.Root storage r = WalletStorage.state().roots[id];
        return IIdentityAdmin.RootOperation({
            data: r.data, implementation: r.implementation, version: r.version, readyAt: r.readyAt
        });
    }

    function rootReadyAt(bytes32 id) external view delegated returns (uint48) {
        WalletStorage.EpochState storage s = WalletStorage.state();
        WalletStorage.Root storage r = s.roots[id];
        (, uint64 current) = WalletRelease.read();
        return r.version == current && r.rootEpoch == s.rootEpoch ? r.readyAt : 0;
    }

    function threshold() external view delegated returns (uint8) {
        return WalletStorage.threshold();
    }

    function rootDelay() external view delegated returns (uint32) {
        return WalletStorage.state().rootDelay;
    }

    function rootEpoch() external view delegated returns (uint32) {
        return WalletStorage.state().rootEpoch;
    }

    function bump(uint64 version) external rootOnly {
        _bump(version, IWalletFactory(_factory()).release(version));
    }

    function setThreshold(uint8 threshold_) external rootOnly {
        _setThreshold(threshold_);
    }

    function setRootDelay(uint32 delay) external rootOnly {
        _setRootDelay(delay);
    }

    function unlink(bytes32 identity) external rootOnly {
        _remove(identity, false, false);
    }

    // ─── Internals ──────────────────────────────────────────────────

    function _delegated() private view {
        if (address(this) == SELF) revert IWebWallet.NotDelegated();
    }

    function _locked() private view returns (bool) {
        return WalletTransient.get(WalletTransient.LOCK);
    }

    function _now() private view returns (uint48) {
        // forge-lint: disable-next-line(unsafe-typecast)
        return uint48(block.timestamp);
    }

    function _factory() private view returns (address) {
        return IWebWallet(address(this)).FACTORY();
    }

    /// The policy's rules hash, and its policy hash.
    function _hashes(IIdentityAdmin.Policy calldata policy)
        private
        pure
        returns (bytes32 rulesHash, bytes32 policyHash)
    {
        rulesHash = rulesHashOf(policy.rules);
        policyHash = policyHashFrom(policy.validAfter, policy.validUntil, policy.admin, policy.signers, rulesHash);
    }

    /// The registry's check of a proof for this wallet, submitted by the wallet's caller, forwarding the whole value.
    function _check(
        bytes32 domain,
        bytes32 platformId,
        uint16 verifierVersion,
        bytes calldata payload,
        bytes32 policyHash
    ) private returns (IWalletRegistry.Checked memory) {
        return IWalletRegistry(IWebWallet(address(this)).REGISTRY()).check{value: msg.value}(
            domain, platformId, verifierVersion, payload, msg.sender, policyHash
        );
    }

    /// A login's session: of a linked identity, never the first, from an app on the identity's list.
    function _login(
        IWalletRegistry.Checked memory c,
        IIdentityAdmin.Policy calldata policy,
        bytes32 rulesHash,
        bytes32 policyHash
    ) private {
        WalletStorage.EpochState storage s = WalletStorage.state();
        if (!s.hadSession) revert IWebWallet.FirstSessionRefused();
        bytes32[] storage apps = s.appLists[c.identity];
        uint256 n = apps.length;
        if (n != 0) {
            bytes32 app = keccak256(c.app);
            uint256 i;
            while (i < n && apps[i] != app) ++i;
            if (i == n) revert IWebWallet.AppNotListed(app);
        }
        // A login add the wallet itself sends at the head of its own batch signs that batch: its proof grants now
        // what it grants a second later.
        uint48 activeAt =
            msg.sender == address(this) && WalletTransient.get(WalletTransient.LOGINS_FIRST) ? _now() - 1 : _now();
        _add(c.identity, c.key, policy, activeAt, true, rulesHash, policyHash);
    }

    /// Adds a session that signs after `activeAt`, under `policy` and its hashes.
    function _add(
        bytes32 identity,
        bytes memory key,
        IIdentityAdmin.Policy calldata policy,
        uint48 activeAt,
        bool byProof,
        bytes32 rulesHash,
        bytes32 policyHash
    ) private {
        WalletStorage.EpochState storage s = WalletStorage.state();
        (uint32 index, WalletStorage.Link storage l) = WalletStorage.indexedLinkOf(identity);
        if (!l.linked) revert IWebWallet.NotLinked(identity);
        if (key.length < 20) revert IWebWallet.InvalidKey(key);
        if ((policy.validAfter | policy.validUntil | activeAt) >= 1 << 47) {
            revert IWebWallet.PolicyOutOfRange(policy.validAfter, policy.validUntil);
        }
        if (policy.admin && policy.validUntil != 0) revert IWebWallet.AdminSessionExpires(policy.validUntil);
        bytes32 keyHash = keccak256(key);
        WalletStorage.SessionRecord storage r = s.sessions[keyHash];
        if (WalletStorage.live(r)) revert IWebWallet.SessionExists(key);
        IIdentityAdmin.Rules calldata rules = policy.rules;
        s.sessions[keyHash] = WalletStorage.SessionRecord({
            validAfter: policy.validAfter,
            validUntil: policy.validUntil,
            activeAt: activeAt,
            generation: l.generation,
            admin: policy.admin,
            byProof: byProof,
            signers: policy.signers,
            link: index,
            identity: identity,
            rulesHash: rulesHash,
            scopeRoot: rules.scopeRoot,
            domainsRoot: rules.domainsRoot,
            paymastersRoot: rules.paymastersRoot
        });
        _setAllowances(keyHash, rulesHash, rules.allowances);
        s.hadSession = true;
        if (policy.admin) {
            ++s.adminSessions;
            ++l.adminSessions;
            if (++s.platformCounts[l.platformId].admins == 1) ++s.adminPlatforms;
        }
        emit IWebWallet.SessionAdded(identity, key, policyHash, activeAt, byProof);
    }

    /// Sets the key's counters under `rulesHash`; one of the same key and rules keeps its spend.
    function _setAllowances(bytes32 keyHash, bytes32 rulesHash, IIdentityAdmin.Allowance[] calldata allowances)
        private
    {
        address last;
        for (uint256 i; i < allowances.length; ++i) {
            IIdentityAdmin.Allowance calldata allowance = allowances[i];
            if (allowance.period >= 1 << 47 || (i != 0 && allowance.token <= last)) {
                revert IWebWallet.BadAllowance(allowance.token);
            }
            last = allowance.token;
            WalletStorage.Counter storage c = WalletStorage.counter(keyHash, rulesHash, allowance.token);
            (c.amount, c.period, c.listed) = (allowance.amount, allowance.period, true);
        }
    }

    /// Revoking an active admin session voids every root operation queued before it, and keeps the quorum.
    function _revoke(bytes memory key, bool root) private {
        WalletStorage.EpochState storage s = WalletStorage.state();
        bytes32 keyHash = keccak256(key);
        WalletStorage.SessionRecord storage r = s.sessions[keyHash];
        bytes32 identity = r.identity;
        if (identity == 0) revert IWebWallet.NoSession(key);
        // A dead session's admin count went with its unlink.
        if (r.admin && WalletStorage.live(r)) {
            if (s.adminSessions == 1 && !root) revert IWebWallet.RootOperationRequired();
            _dropAdmins(identity, 1);
            // A session not yet active has signed nothing; an active one may have queued roots.
            if (r.activeAt < block.timestamp) ++s.rootEpoch;
            _keepQuorum();
        }
        delete s.sessions[keyHash];
        emit IWebWallet.SessionRevoked(identity, key);
    }

    /// Kills every session of `identity` and voids every queued root operation. Unlinks it unless it is the
    /// genesis, which only a login names, or `keepLink`, and lowers the threshold to the platforms left.
    function _remove(bytes32 identity, bool byLogin, bool keepLink) private {
        WalletStorage.EpochState storage s = WalletStorage.state();
        WalletStorage.Link storage l = WalletStorage.linkOf(identity);
        if (!l.linked) revert IWebWallet.NotLinked(identity);
        bool genesis = s.platformId != 0 && identity == identityOf(s.platformId, s.idNode);
        if (genesis && !byLogin) revert IWebWallet.GenesisIdentity(identity);
        _dropAdmins(identity, l.adminSessions);
        ++l.generation;
        ++s.rootEpoch;
        if (genesis || keepLink) return;
        l.linked = false;
        if (--s.platformCounts[l.platformId].links == 0) --s.platforms;
        emit IWebWallet.IdentityUnlinked(identity);
        if (s.threshold > s.platforms) {
            // forge-lint: disable-next-line(unsafe-typecast)
            s.threshold = uint8(s.platforms);
            emit IWebWallet.ThresholdSet(WalletStorage.threshold());
        }
    }

    /// Takes `n` admin sessions off the identity, its platform and the wallet.
    function _dropAdmins(bytes32 identity, uint32 n) private {
        if (n == 0) return;
        WalletStorage.EpochState storage s = WalletStorage.state();
        WalletStorage.Link storage l = WalletStorage.linkOf(identity);
        s.adminSessions -= n;
        l.adminSessions -= n;
        if ((s.platformCounts[l.platformId].admins -= n) == 0) --s.adminPlatforms;
    }

    /// Refuses leaving admin sessions on fewer platforms than the threshold; none at all is allowed.
    function _keepQuorum() private view {
        WalletStorage.EpochState storage s = WalletStorage.state();
        uint32 left = s.adminPlatforms;
        if (left != 0 && left < s.threshold) revert IWebWallet.ThresholdTooHigh(s.threshold, left);
    }

    function _setThreshold(uint8 t) private {
        WalletStorage.EpochState storage s = WalletStorage.state();
        if (t > s.adminPlatforms) revert IWebWallet.ThresholdTooHigh(t, s.adminPlatforms);
        // A quorum change voids the root operations queued under the old one.
        if (WalletStorage.threshold() != (t == 0 ? 1 : t)) ++s.rootEpoch;
        s.threshold = t;
        emit IWebWallet.ThresholdSet(WalletStorage.threshold());
    }

    function _setRootDelay(uint32 delay) private {
        if (delay > WalletStorage.MAX_ROOT_DELAY) revert IWebWallet.RootDelayTooLong(delay);
        WalletStorage.state().rootDelay = delay;
        emit IWebWallet.RootDelaySet(delay);
    }

    /// Runs a matured root operation, one of those `queueRoot` admits; a bump's to its queued implementation.
    function _root(bytes memory data, address implementation) private {
        bytes4 selector = bytes4(data);
        bytes memory args = Bytes.slice(data, 4);
        if (selector == IIdentityAdmin.bump.selector) _bump(abi.decode(args, (uint64)), implementation);
        else if (selector == IIdentityAdmin.setThreshold.selector) _setThreshold(abi.decode(args, (uint8)));
        else if (selector == IIdentityAdmin.setRootDelay.selector) _setRootDelay(abi.decode(args, (uint32)));
        else if (selector == IIdentityAdmin.unlink.selector) _remove(abi.decode(args, (bytes32)), false, false);
        else _revoke(abi.decode(args, (bytes)), true);
    }

    /// Moves the release slot to `next`, once the factory still names the current release and names `next` for
    /// `version`. Blocks the EntryPoint's `execute` for the rest of the transaction, then runs the new
    /// release's data steps.
    function _bump(uint64 version, address next) private {
        (address current, uint64 from) = WalletRelease.read();
        if (version <= from) revert IWebWallet.ReleaseNotAbove(from, version);
        IWalletFactory factory = IWalletFactory(_factory());
        if (factory.release(from) != current) revert IWebWallet.ReleaseMismatch(from);
        if (factory.release(version) != next || next.code.length == 0 || IWebWallet(next).VERSION() != version) {
            revert IWebWallet.ReleaseMismatch(version);
        }
        WalletRelease.write(next, version);
        emit IWebWallet.Bumped(from, version, next);
        WalletTransient.put(WalletTransient.ENTRY_POINT_BLOCKED, true);
        WalletTransient.put(WalletTransient.DATA_STEP, true);
        IWebWallet(address(this)).runDataSteps(from);
        WalletTransient.put(WalletTransient.DATA_STEP, false);
    }
}

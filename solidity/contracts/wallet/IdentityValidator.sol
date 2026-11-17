// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/IERC4337.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {IERC5267} from "@openzeppelin/contracts/interfaces/IERC5267.sol";
import {MODULE_TYPE_VALIDATOR} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {ERC4337Utils} from "@openzeppelin/contracts/account/utils/ERC4337Utils.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {ERC7739Utils} from "@openzeppelin/contracts/utils/cryptography/draft-ERC7739Utils.sol";

import {IIdentityValidator} from "./IIdentityValidator.sol";
import {IdentityValidatorState} from "./IdentityValidatorState.sol";
import {IdentityAdmin} from "./IdentityAdmin.sol";
import {SessionRules} from "./SessionRules.sol";

/// @title IdentityValidator - the one ERC-7579 validator of every WebWallet.
/// @notice Holds each account's linked identities, sessions, threshold and root operations.
///         The threshold counts distinct admin platforms, and never exceeds the platforms holding an
///         admin session unless none does.
/// @dev Every slot validation reads or writes has the account as its innermost mapping key (ERC-7562),
///      and validation reads no clock: windows go back to the EntryPoint packed. What an operation may
///      do runs in SessionRules, and every write in IdentityAdmin: both deployed by the constructor and
///      called through DELEGATECALL.
contract IdentityValidator is IIdentityValidator, IdentityValidatorState {
    using ERC7739Utils for *;
    using MessageHashUtils for bytes32;

    uint48 public constant MIN_RECOVERY_DELAY = MIN_DELAY;
    uint48 public constant MAX_RECOVERY_DELAY = MAX_DELAY;

    address private immutable REGISTRY;
    address private immutable FACTORY;
    address private immutable RULES;
    address private immutable ADMIN;

    /// The ERC-7739 detection hash: with an empty signature, it answers `0x77390001`.
    bytes32 private constant ERC7739_PROBE = 0x7739773977397739773977397739773977397739773977397739773977397739;

    bytes32 private constant EXECUTE_TYPEHASH = keccak256(
        "Execute(bytes32 mode,bytes executionCalldata,uint256 value,uint48 at,uint256 nonce,uint48 deadline,uint256 callGas)"
    );

    constructor(address walletRegistry_, address walletFactory_) {
        REGISTRY = walletRegistry_;
        FACTORY = walletFactory_;
        RULES = address(new SessionRules(walletRegistry_));
        ADMIN = address(new IdentityAdmin(walletRegistry_, walletFactory_));
    }

    // ─── ERC-7579 module ────────────────────────────────────────────

    function isModuleType(uint256 moduleTypeId) external pure returns (bool) {
        return moduleTypeId == MODULE_TYPE_VALIDATOR;
    }

    function onInstall(bytes calldata) external {
        _delegate();
    }

    function onUninstall(bytes calldata) external {
        _delegate();
    }

    /// @dev Below quorum, charges the session's allowances: a refused operation's charges are
    ///      reverted with the EntryPoint's call.
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash) external returns (uint256) {
        Authorization memory auth = _decode(userOp.signature);
        uint8 quorum = threshold(msg.sender);
        (bool ok, bool below, Verified memory v) = _signers(userOpHash, auth, quorum);
        if (!ok) return ERC4337Utils.SIG_VALIDATION_FAILED;
        (ok, v) = _rules(abi.encodeCall(SessionRules.allowed, (v, userOp, below)));
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
        uint256 value,
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
                abi.encode(
                    EXECUTE_TYPEHASH, mode, keccak256(executionCalldata), value, auth.at, nonce, deadline, callGas
                )
            )
        );
        (bool ok, bool below, Verified memory v) = _signers(digest, auth, quorum);
        if (!ok) revert ExecutionNotSigned();
        (ok, v) = _rules(abi.encodeCall(SessionRules.allowedExecution, (v, mode, executionCalldata, auth, below)));
        if (!ok) revert ExecutionNotAllowed();
        if (!_inWindow(v)) revert ExecutionOutsideWindow(auth.at);
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

    function isLinked(address account, bytes32 identity) external view returns (bool) {
        return _isLinked(account, identity);
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

    function recoveryDelay(address account) external view returns (uint48) {
        return _recoveryDelay(account);
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

    // ─── Writes, run in IdentityAdmin ───────────────────────────────

    function link(address, bytes32, bytes32) external {
        _delegate();
    }

    function addSessionByProof(address, bytes32, bytes calldata, Policy calldata) external returns (uint48) {
        return abi.decode(_delegate(), (uint48));
    }

    function addSessionByAccount(address, bytes32, bytes calldata, Policy calldata) external {
        _delegate();
    }

    function addSession(bytes32, bytes calldata, Policy calldata) external {
        _delegate();
    }

    function revokeSession(bytes calldata) external {
        _delegate();
    }

    function queueRoot(address, bytes calldata) external returns (bytes32) {
        return abi.decode(_delegate(), (bytes32));
    }

    function cancelRoot(bytes32) external {
        _delegate();
    }

    function executeRoot(address, address, bytes calldata) external {
        _delegate();
    }

    /// Decodes an `Authorization`; external so a malformed one fails validation instead of reverting it.
    function decodeAuthorization(bytes calldata signature) external pure returns (Authorization memory) {
        return abi.decode(signature, (Authorization));
    }

    function setThreshold(uint8) external pure {
        revert RootOperationRequired();
    }

    function setRecoveryDelay(uint48) external pure {
        revert RootOperationRequired();
    }

    function unlink(bytes32) external pure {
        revert RootOperationRequired();
    }

    // ─── Internals ──────────────────────────────────────────────────

    /// Runs this call in IdentityAdmin; a revert bubbles.
    function _delegate() private returns (bytes memory) {
        return Address.functionDelegateCall(ADMIN, msg.data);
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

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {IEntryPoint, PackedUserOperation} from "@openzeppelin/contracts/interfaces/IERC4337.sol";
import {Account} from "@openzeppelin/contracts/account/Account.sol";
import {EIP7702Utils} from "@openzeppelin/contracts/account/utils/EIP7702Utils.sol";
import {ERC4337Utils} from "@openzeppelin/contracts/account/utils/ERC4337Utils.sol";
import {
    CallType,
    ERC7579Utils,
    ExecType,
    Execution,
    Mode,
    ModeSelector
} from "@openzeppelin/contracts/account/utils/draft-ERC7579Utils.sol";
import {Errors} from "@openzeppelin/contracts/utils/Errors.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IERC721Receiver} from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import {ERC721Holder} from "@openzeppelin/contracts/token/ERC721/utils/ERC721Holder.sol";
import {ERC1155Holder} from "@openzeppelin/contracts/token/ERC1155/utils/ERC1155Holder.sol";
import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {ERC7739Utils} from "@openzeppelin/contracts/utils/cryptography/draft-ERC7739Utils.sol";

import {bytesAt, canonicalBatch, decodeAuthorization} from "./AbiBytes.sol";
import {IWalletFactory} from "./IWalletFactory.sol";
import {
    AUTHORIZED_MODE,
    CALL_OVERHEAD,
    IIdentityAdmin,
    INonceIncrement,
    IWalletCore,
    IWebWallet
} from "./IWebWallet.sol";
import {SessionRules} from "./SessionRules.sol";
import {WalletRelease} from "./WalletRelease.sol";
import {WalletStorage, identityOf} from "./WalletStorage.sol";
import {WalletTransient} from "./WalletTransient.sol";

/// @title WebWallet - an ERC-4337 account whose sessions belong to linked platform identities.
/// @notice One numbered release: a factory wallet's WalletProxy, or an EIP-7702 account's WalletForwarder, routes
///         to it by the release slot. Identity and root-operation entries run in IdentityAdmin through DELEGATECALL;
///         what an operation may do runs in SessionRules.
contract WebWallet is Account, ERC721Holder, ERC1155Holder, IWalletCore {
    using ERC7579Utils for Mode;
    using ERC7739Utils for *;
    using MessageHashUtils for bytes32;

    uint64 public immutable VERSION;
    address public immutable FACTORY;
    address public immutable REGISTRY;
    address private immutable ADMIN;
    address private immutable RULES;
    bytes32 private immutable VERSION_HASH;

    bytes32 private constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)");
    bytes32 private constant NAME_HASH = keccak256("WebWallet");
    bytes32 private constant EXECUTE_TYPEHASH = keccak256(
        "Execute(bytes32 mode,bytes executionCalldata,uint256 value,uint48 at,uint256 nonce,uint48 deadline,uint256 callGas)"
    );
    bytes32 private constant USER_OP_TYPEHASH = keccak256("UserOperation(bytes32 userOpHash)");
    /// The ERC-7739 detection hash: with an empty signature, it answers `0x77390001`.
    bytes32 private constant ERC7739_PROBE = 0x7739773977397739773977397739773977397739773977397739773977397739;

    constructor(address factory, address registry, uint64 version, address identityAdmin, address sessionRules) {
        if (identityAdmin.code.length == 0) revert IWebWallet.TargetWithoutCode(identityAdmin);
        if (sessionRules.code.length == 0) revert IWebWallet.TargetWithoutCode(sessionRules);
        (VERSION, FACTORY, REGISTRY, ADMIN, RULES) = (version, factory, registry, identityAdmin, sessionRules);
        VERSION_HASH = keccak256(bytes(Strings.toString(version)));
    }

    /// Routes `IdentityAdmin`'s selectors to it.
    fallback() external payable {
        address target = _target(msg.sig);
        if (target == address(0)) revert IWebWallet.UnknownSelector(msg.sig);
        assembly ("memory-safe") {
            calldatacopy(0, 0, calldatasize())
            let ok := delegatecall(gas(), target, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            if iszero(ok) { revert(0, returndatasize()) }
            return(0, returndatasize())
        }
    }

    // ─── Setup and releases ─────────────────────────────────────────

    /// Only in the construction of the factory's proxy for this genesis; links it and adds no session.
    function initialize(bytes32 platformId, bytes32 idNode, uint256 salt) external {
        if (
            address(this).code.length != 0
                || IWalletFactory(FACTORY).walletAddress(platformId, idNode, salt) != address(this)
        ) revert IWebWallet.InitializeRefused();
        WalletStorage.EpochState storage s = WalletStorage.state();
        (s.platformId, s.idNode, s.salt) = (platformId, idNode, salt);
        WalletStorage.link(platformId, identityOf(platformId, idNode));
    }

    /// An EIP-7702 account's key, in its own top-level transaction: moves the epoch, which drops all state,
    /// points the release slot at the factory's latest, and runs `executionCalldata` as a default batch.
    function reset(bytes calldata executionCalldata) external payable {
        if (msg.sender != address(this) || tx.origin != address(this) || _locked()) revert IWebWallet.ResetRefused();
        WalletTransient.put(WalletTransient.LOCK, true);
        WalletStorage.WalletState storage w = WalletStorage.wallet();
        w.epoch = keccak256(abi.encode(w.epoch, blockhash(block.number - 1), block.timestamp));
        emit IWebWallet.EpochReset(w.epoch);
        (address implementation, uint64 version) = IWalletFactory(FACTORY).latest();
        WalletRelease.write(implementation, version);
        _batch(executionCalldata, false);
        WalletTransient.put(WalletTransient.LOCK, false);
    }

    function release() external view returns (address implementation, uint64 version) {
        return WalletRelease.read();
    }

    function epoch() external view returns (bytes32) {
        return WalletStorage.wallet().epoch;
    }

    /// ERC-5267: name `WebWallet`, this release's version, the chain, this account, and `_salt()`.
    function eip712Domain()
        external
        view
        returns (bytes1, string memory, string memory, uint256, address, bytes32, uint256[] memory)
    {
        return
            (hex"1f", "WebWallet", Strings.toString(VERSION), block.chainid, address(this), _salt(), new uint256[](0));
    }

    /// Runs the data steps after `from` up to this release, only inside a bump. Release 1 has none.
    function runDataSteps(uint64 from) external view {
        from; // Named for the ABI.
        if (msg.sender != address(this) || !WalletTransient.get(WalletTransient.DATA_STEP)) {
            revert IWebWallet.DataStepRefused();
        }
    }

    function supportsInterface(bytes4 interfaceId) public view override(ERC1155Holder, IWalletCore) returns (bool) {
        return interfaceId == type(IERC721Receiver).interfaceId || super.supportsInterface(interfaceId);
    }

    // ─── Externals OpenZeppelin implements ──────────────────────────

    function entryPoint() public view override(Account, IWalletCore) returns (IEntryPoint) {
        return super.entryPoint();
    }

    function getNonce() public view override(Account, IWalletCore) returns (uint256) {
        return super.getNonce();
    }

    function getNonce(uint192 key) public view override(Account, IWalletCore) returns (uint256) {
        return super.getNonce(key);
    }

    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        public
        override(Account, IWalletCore)
        returns (uint256)
    {
        return super.validateUserOp(userOp, userOpHash, missingAccountFunds);
    }

    function onERC721Received(address operator, address from, uint256 tokenId, bytes memory data)
        public
        override(ERC721Holder, IWalletCore)
        returns (bytes4)
    {
        return super.onERC721Received(operator, from, tokenId, data);
    }

    function onERC1155Received(address operator, address from, uint256 id, uint256 value, bytes memory data)
        public
        override(ERC1155Holder, IWalletCore)
        returns (bytes4)
    {
        return super.onERC1155Received(operator, from, id, value, data);
    }

    function onERC1155BatchReceived(
        address operator,
        address from,
        uint256[] memory ids,
        uint256[] memory values,
        bytes memory data
    ) public override(ERC1155Holder, IWalletCore) returns (bytes4) {
        return super.onERC1155BatchReceived(operator, from, ids, values, data);
    }

    // ─── Execution ──────────────────────────────────────────────────

    /// `AUTHORIZED_MODE` from anyone, checked once the calls ran; a single or batch call with mode selector 0 from
    /// the EntryPoint, or from an EIP-7702 account's own key, never a factory wallet's. One lock covers both.
    function execute(bytes32 mode, bytes calldata executionCalldata) external payable {
        if (_locked()) revert IWebWallet.Locked();
        WalletTransient.put(WalletTransient.LOCK, true);
        if (mode == AUTHORIZED_MODE) {
            _executeAuthorized(executionCalldata);
        } else {
            if (msg.sender == address(entryPoint())) {
                if (WalletTransient.get(WalletTransient.ENTRY_POINT_BLOCKED)) revert IWebWallet.EntryPointBlocked();
            } else if (msg.sender != address(this) || EIP7702Utils.fetchDelegate(address(this)) == address(0)) {
                revert AccountUnauthorized(msg.sender);
            }
            (CallType callType, ExecType execType, ModeSelector selector,) = Mode.wrap(mode).decodeMode();
            bool tryExec = execType == ERC7579Utils.EXECTYPE_TRY;
            if (
                ModeSelector.unwrap(selector) != 0 || !(tryExec || execType == ERC7579Utils.EXECTYPE_DEFAULT)
                    || !(callType == ERC7579Utils.CALLTYPE_SINGLE || callType == ERC7579Utils.CALLTYPE_BATCH)
            ) revert IWebWallet.UnsupportedMode(mode);
            if (callType == ERC7579Utils.CALLTYPE_BATCH) {
                _batch(executionCalldata, tryExec);
            } else {
                (address target, uint256 value, bytes calldata data) = ERC7579Utils.decodeSingle(executionCalldata);
                _call(0, target, value, data, tryExec);
            }
        }
        WalletTransient.put(WalletTransient.LOCK, false);
    }

    /// `data` is `abi.encode(bytes executionCalldata, uint256 value, uint48 deadline, uint256 callGas, bytes
    /// authorization)`. Consumes EntryPoint nonce key 0, runs the batch, then checks it was signed.
    function _executeAuthorized(bytes calldata data) private {
        bytes calldata calls = bytesAt(data, 0);
        (Execution[] calldata batch, bool canonical) = canonicalBatch(calls);
        // The signers sign these bytes alone, so no call may be read from outside them.
        if (!canonical) revert IWebWallet.NoncanonicalBatch();
        (uint256 value, uint48 deadline, uint256 callGas) = abi.decode(data[32:128], (uint256, uint48, uint256));
        if (msg.value != value) revert IWebWallet.WrongBatchValue(value, msg.value);
        IEntryPoint ep = entryPoint();
        if (address(ep).code.length == 0) revert IWebWallet.EntryPointMissing(address(ep));
        uint256 nonce = ep.getNonce(address(this), 0);
        INonceIncrement(address(ep)).incrementNonce(0);
        uint8 quorum = WalletStorage.threshold();
        bytes32 domain = _domainSeparator();
        if (deadline == 0 || block.timestamp > deadline) revert IWebWallet.ExecutionExpired(deadline);
        // Each call's data is copied before the gas check, and its memory released after the call.
        for (uint256 i; i < batch.length; ++i) {
            Memory.Pointer free = Memory.getFreeMemoryPointer();
            Execution calldata x = batch[i];
            bytes memory callData = x.callData;
            if (gasleft() * 63 / 64 < callGas + CALL_OVERHEAD) {
                revert IWebWallet.InsufficientCallGas(callGas, gasleft());
            }
            _call(i, x.target, x.value, callData, false);
            Memory.unsafeSetFreeMemoryPointer(free);
        }
        IWalletCore.Authorization memory auth = abi.decode(bytesAt(data, 128), (IWalletCore.Authorization));
        bytes32 digest = domain.toTypedDataHash(
            keccak256(
                abi.encode(
                    EXECUTE_TYPEHASH, AUTHORIZED_MODE, keccak256(calls), value, auth.at, nonce, deadline, callGas
                )
            )
        );
        (bool ok, bool below, WalletStorage.Verified memory v) = _signers(digest, auth, quorum);
        // A session signs only after the second it was added in.
        if (!ok || v.activeAt >= block.timestamp) revert IWebWallet.ExecutionNotSigned();
        // At quorum the rules allow any canonical batch, which this one is.
        if (below) {
            SessionRules.Batch memory b = SessionRules.Batch(calls, auth.at, auth.calls);
            (ok, v) = _rules(abi.encodeCall(SessionRules.allowedExecution, (abi.encode(v, b, _adminTargets()))));
            if (!ok) revert IWebWallet.ExecutionNotAllowed();
        }
        if (!_inWindow(v)) revert IWebWallet.ExecutionOutsideWindow();
    }

    /// A canonical batch, each call as `_call` runs it; each call's memory is released after it.
    function _batch(bytes calldata executionCalldata, bool tryExec) private {
        (Execution[] calldata batch, bool canonical) = canonicalBatch(executionCalldata);
        if (!canonical) revert IWebWallet.NoncanonicalBatch();
        for (uint256 i; i < batch.length; ++i) {
            Memory.Pointer free = Memory.getFreeMemoryPointer();
            Execution calldata x = batch[i];
            _call(i, x.target, x.value, x.callData, tryExec);
            Memory.unsafeSetFreeMemoryPointer(free);
        }
    }

    /// One call; `address(0)` is the wallet. A failure bubbles unwrapped, an empty one as `FailedCall`; under the try
    /// exec type it is reported.
    function _call(uint256 i, address target, uint256 value, bytes memory data, bool tryExec) private {
        (bool ok, bytes memory returned) = (target == address(0) ? address(this) : target).call{value: value}(data);
        if (ok) return;
        if (!tryExec) {
            if (returned.length == 0) revert Errors.FailedCall();
            assembly ("memory-safe") {
                revert(add(returned, 0x20), mload(returned))
            }
        }
        emit ERC7579Utils.ERC7579TryExecuteFail(i, returned);
    }

    // ─── Validation and signatures ──────────────────────────────────

    /// A malformed signature fails. At quorum, the call must be `execute` with mode selector 0, which checks the
    /// rest. Below quorum, SessionRules checks the calls and charges the session's allowances: a refused
    /// operation's charges revert with the EntryPoint's call. Reads only the wallet's own storage, never the clock:
    /// the window goes back to the EntryPoint.
    function _validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, bytes calldata signature)
        internal
        override
        returns (uint256)
    {
        (bool ok, IWalletCore.Authorization memory auth) = decodeAuthorization(signature);
        if (!ok) return ERC4337Utils.SIG_VALIDATION_FAILED;
        bool below;
        WalletStorage.Verified memory v;
        (ok, below, v) = _signers(_signableUserOpHash(userOp, userOpHash), auth, WalletStorage.threshold());
        if (!ok) return ERC4337Utils.SIG_VALIDATION_FAILED;
        if (below) {
            SessionRules.Operation memory op = SessionRules.Operation({
                callData: userOp.callData,
                paymasterAndData: userOp.paymasterAndData,
                accountGasLimits: userOp.accountGasLimits,
                preVerificationGas: userOp.preVerificationGas,
                gasFees: userOp.gasFees,
                at: auth.at,
                calls: auth.calls,
                paymasterProof: auth.paymasterProof
            });
            (ok, v) = _rules(abi.encodeCall(SessionRules.allowed, (abi.encode(v, op, _adminTargets()))));
        } else {
            bytes calldata callData = userOp.callData;
            ok = callData.length >= 36 && WalletStorage.selectorOf(callData) == IWalletCore.execute.selector
                && bytes4(bytes32(callData[4:36]) << 48) == 0;
        }
        if (!ok) return ERC4337Utils.SIG_VALIDATION_FAILED;
        return (uint256(v.validAfter) << 208) | (uint256(v.validUntil) << 160);
    }

    /// `userOpHash` nested under this release's EIP-712 domain.
    function _signableUserOpHash(PackedUserOperation calldata, bytes32 userOpHash)
        internal
        view
        override
        returns (bytes32)
    {
        return _domainSeparator().toTypedDataHash(keccak256(abi.encode(USER_OP_TYPEHASH, userOpHash)));
    }

    /// Unused: `_validateUserOp` checks sessions and rules itself.
    function _rawSignatureValidation(bytes32, bytes calldata) internal pure override returns (bool) {
        return false;
    }

    /// An EIP-7702 account's key signs `hash` with 65-byte ECDSA. Otherwise ERC-7739 under `eip712Domain()`,
    /// `signature` a bare `Authorization` at `at` 0, inside the signers' window; a malformed one answers `0xffffffff`.
    /// Below quorum, signers `_cosigned` signing `TypedDataSign` for an app the first one lists.
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        if (hash == ERC7739_PROBE && signature.length == 0) return bytes4(0x77390001);
        if (signature.length == 65 && EIP7702Utils.fetchDelegate(address(this)) != address(0)) {
            (address signer, ECDSA.RecoverError err,) = ECDSA.tryRecoverCalldata(hash, signature);
            if (err == ECDSA.RecoverError.NoError && signer == address(this)) return this.isValidSignature.selector;
        }
        (bytes32 signed, bytes calldata inner, bytes32 app) = _unnest(hash, signature);
        (bool decoded, IWalletCore.Authorization memory auth) = decodeAuthorization(inner);
        if (!decoded) return bytes4(0xffffffff);
        uint8 quorum = WalletStorage.threshold();
        WalletStorage.Verified memory v = _verify(signed, auth.signatures, quorum, 0);
        bool allowed = v.adminPlatforms >= quorum
            || (_cosigned(v, auth.signatures.length, quorum)
                && app != 0
                && MerkleProof.verify(
                    auth.domainProof, WalletStorage.session(v.keyHash).domainsRoot, WalletStorage.leaf(abi.encode(app))
                ));
        return v.ok && _inWindow(v) && allowed ? this.isValidSignature.selector : bytes4(0xffffffff);
    }

    /// The hash an ERC-7739 nested signature signs, its `Authorization`, and the app separator of a
    /// `TypedDataSign`, zero for `PersonalSign`.
    function _unnest(bytes32 hash, bytes calldata signature) private view returns (bytes32, bytes calldata, bytes32) {
        (bytes calldata inner, bytes32 appSeparator, bytes32 contentsHash, string calldata descr) =
            signature.decodeTypedDataSig();
        bytes memory domain = abi.encode(NAME_HASH, VERSION_HASH, block.chainid, address(this), _salt());
        // Zero for an empty or malformed contents type, which binds nothing.
        bytes32 structHash = descr.typedDataSignStructHash(contentsHash, domain);
        if (structHash != 0 && hash == appSeparator.toTypedDataHash(contentsHash)) {
            return (appSeparator.toTypedDataHash(structHash), inner, appSeparator);
        }
        return (_domainSeparator().toTypedDataHash(hash.personalSignStructHash()), signature, 0);
    }

    /// The domain `eip712Domain()` reports.
    function _domainSeparator() private view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_TYPEHASH, NAME_HASH, VERSION_HASH, block.chainid, address(this), _salt()));
    }

    /// `keccak256(abi.encode(epoch, rootEpoch))`: a `reset` or a move of the root epoch retires every signature made
    /// before it.
    function _salt() private view returns (bytes32) {
        WalletStorage.WalletState storage w = WalletStorage.wallet();
        bytes32 epoch = w.epoch;
        return keccak256(abi.encode(epoch, w.epochs[epoch].rootEpoch));
    }

    /// `_verify` over `hash` at `auth.at`, whether the signers fall short of `quorum`, and whether they sign:
    /// below it, `_cosigned`.
    function _signers(bytes32 hash, IWalletCore.Authorization memory auth, uint8 quorum)
        private
        view
        returns (bool ok, bool below, WalletStorage.Verified memory v)
    {
        v = _verify(hash, auth.signatures, quorum, auth.at);
        below = v.adminPlatforms < quorum;
        ok = v.ok && (!below || _cosigned(v, auth.signatures.length, quorum));
    }

    /// Checks that every signature is by a live session, and counts the distinct platforms of its signers and
    /// of the admin sessions among them. Short of `quorum`, every signature is over
    /// `keccak256(abi.encode(hash, at, keccak256(sigs[0].key)))`: the governing session.
    function _verify(bytes32 hash, IWalletCore.SessionSignature[] memory sigs, uint8 quorum, uint48 at)
        private
        view
        returns (WalletStorage.Verified memory v)
    {
        if (sigs.length == 0) return v;
        WalletStorage.EpochState storage st = WalletStorage.state();
        uint256[] memory platforms = new uint256[](sigs.length);
        uint256[] memory adminPlatforms = new uint256[](sigs.length);
        for (uint256 i; i < sigs.length; ++i) {
            bytes32 keyHash = keccak256(sigs[i].key);
            // One slot of the session and one of its link.
            WalletStorage.SessionRecord storage s = st.sessions[keyHash];
            uint32 index = s.link;
            WalletStorage.Link storage l = st.links[index];
            if (index == 0 || s.generation != l.generation) return v;
            if (s.byProof) v.byProof = true;
            if (i == 0) (v.keyHash, v.signers) = (keyHash, s.signers);
            if (s.activeAt > v.activeAt) v.activeAt = s.activeAt;
            WalletStorage.narrow(v, s.validAfter > s.activeAt ? s.validAfter : s.activeAt, s.validUntil);
            uint256 platform = l.platform;
            if (!_contains(platforms, v.platforms, platform)) platforms[v.platforms++] = platform;
            if (s.admin && !_contains(adminPlatforms, v.adminPlatforms, platform)) {
                adminPlatforms[v.adminPlatforms++] = platform;
            }
        }
        bytes32 signed = v.adminPlatforms < quorum ? keccak256(abi.encode(hash, at, v.keyHash)) : hash;
        for (uint256 i; i < sigs.length; ++i) {
            if (!_signedBy(sigs[i].key, signed, sigs[i].signature)) return v;
        }
        v.ok = true;
    }

    /// Below quorum: `n` signatures, by sessions none by proof unless `quorum` is 1, of as many distinct
    /// platforms as the first session's `signers`.
    function _cosigned(WalletStorage.Verified memory v, uint256 n, uint8 quorum) private pure returns (bool) {
        uint256 need = v.signers == 0 ? 1 : v.signers;
        return (quorum == 1 || !v.byProof) && n == need && v.platforms == need;
    }

    /// A 20-byte key is recovered with ECDSA, never asked through ERC-1271: validation may not read a codeless
    /// address's code size (ERC-7562).
    function _signedBy(bytes memory key, bytes32 hash, bytes memory signature) private view returns (bool) {
        if (key.length != 20) return SignatureChecker.isValidSignatureNow(key, hash, signature);
        (address signer, ECDSA.RecoverError err,) = ECDSA.tryRecover(hash, signature);
        // forge-lint: disable-next-line(unsafe-typecast)
        return err == ECDSA.RecoverError.NoError && signer == address(bytes20(key));
    }

    /// The block's timestamp is inside `v`'s window.
    function _inWindow(WalletStorage.Verified memory v) private view returns (bool) {
        return v.validAfter < block.timestamp && (v.validUntil == 0 || block.timestamp <= v.validUntil);
    }

    /// SessionRules' verdict on `call`, and the signers' window narrowed to the periods it charged.
    function _rules(bytes memory call) private returns (bool, WalletStorage.Verified memory) {
        (bool ok, bytes memory returned) = RULES.delegatecall(call);
        if (!ok) {
            assembly ("memory-safe") {
                revert(add(returned, 0x20), mload(returned))
            }
        }
        return abi.decode(returned, (bool, WalletStorage.Verified));
    }

    function _adminTargets() private view returns (SessionRules.Targets memory) {
        return SessionRules.Targets(REGISTRY, address(entryPoint()));
    }

    function _locked() private view returns (bool) {
        return WalletTransient.get(WalletTransient.LOCK);
    }

    function _contains(uint256[] memory ids, uint256 n, uint256 id) private pure returns (bool) {
        for (uint256 i; i < n; ++i) {
            if (ids[i] == id) return true;
        }
        return false;
    }

    /// The target that runs `selector`: IdentityAdmin's entries, else none.
    function _target(bytes4 selector) private view returns (address) {
        if (
            selector == IIdentityAdmin.linkIdentity.selector || selector == IIdentityAdmin.addSessionByLogin.selector
                || selector == IIdentityAdmin.removeSessionsByLogin.selector
                || selector == IIdentityAdmin.addSession.selector || selector == IIdentityAdmin.revokeSession.selector
                || selector == IIdentityAdmin.setAppList.selector || selector == IIdentityAdmin.sessionOf.selector
                || selector == IIdentityAdmin.isLinked.selector || selector == IIdentityAdmin.appList.selector
                || selector == IIdentityAdmin.genesisIdentity.selector
                || selector == IIdentityAdmin.allowanceOf.selector || selector == IIdentityAdmin.generationOf.selector
                || selector == IIdentityAdmin.linkedPlatforms.selector || selector == IIdentityAdmin.hadSession.selector
                || selector == IIdentityAdmin.rootReadyAt.selector || selector == IIdentityAdmin.queueRoot.selector
                || selector == IIdentityAdmin.cancelRoot.selector || selector == IIdentityAdmin.executeRoot.selector
                || selector == IIdentityAdmin.rootOperation.selector || selector == IIdentityAdmin.threshold.selector
                || selector == IIdentityAdmin.rootDelay.selector || selector == IIdentityAdmin.bump.selector
                || selector == IIdentityAdmin.setThreshold.selector || selector == IIdentityAdmin.setRootDelay.selector
                || selector == IIdentityAdmin.unlink.selector
        ) return ADMIN;
        return address(0);
    }
}

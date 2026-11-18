// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ICeremony} from "../ceremony/ICeremony.sol";
import {IProofVerifier} from "../ceremony/IProofVerifier.sol";
import {OperationList} from "../ceremony/OperationList.sol";
import {IIdentityValidator, identityOf, policyHashOf} from "./IIdentityValidator.sol";
import {IdentityValidator} from "./IdentityValidator.sol";
import {IWalletRegistry} from "./IWalletRegistry.sol";

/// @title WalletRegistry - the Consumer of the `libid.webwallet.*` operations.
/// @notice Turns a proof into a link, a session or a removal by login in the IdentityValidator, and keeps
///         each wallet's app lists for logins. Immutable, no owner.
/// @dev The digest is the nullifier (REQ-COMMON-03A).
contract WalletRegistry is IWalletRegistry {
    bytes32 public constant LINK_IDENTITY_DOMAIN = keccak256("libid.webwallet.link-identity");
    bytes32 public constant ADD_SESSION_DOMAIN = keccak256("libid.webwallet.add-session");
    bytes32 public constant REMOVE_SESSIONS_DOMAIN = keccak256("libid.webwallet.remove-sessions");

    IProofVerifier private immutable PROOF_VERIFIER;
    IIdentityValidator private immutable VALIDATOR;

    /// @custom:storage-location erc7201:libid.storage.WalletRegistry
    struct WalletRegistryStorage {
        mapping(bytes32 digest => bool) spentDigests;
        mapping(address wallet => mapping(bytes32 identity => bytes32[])) appLists;
    }

    // cast index-erc7201 libid.storage.WalletRegistry
    bytes32 private constant WALLET_REGISTRY_STORAGE =
        0x1b521e190b50a237bb32c639281068a3635ba26df4c62304b1a25b9f79aaa000;

    function _s() private pure returns (WalletRegistryStorage storage $) {
        assembly {
            $.slot := WALLET_REGISTRY_STORAGE
        }
    }

    /// @param walletFactory The WalletFactory proxy's address, which may not exist yet.
    constructor(address proofVerifier, address walletFactory) {
        PROOF_VERIFIER = IProofVerifier(proofVerifier);
        VALIDATOR = new IdentityValidator(address(this), walletFactory);
    }

    function identityValidator() external view returns (address) {
        return address(VALIDATOR);
    }

    function proofVerifier() external view returns (address) {
        return address(PROOF_VERIFIER);
    }

    function linkIdentity(
        bytes32 platformId,
        uint16 verifierVersion,
        bytes calldata payload,
        bytes calldata data,
        IIdentityValidator.Policy calldata policy
    ) external payable {
        (ICeremony.VerifiedClaim memory claimed, bytes memory txData) =
            _accept(LINK_IDENTITY_DOMAIN, platformId, verifierVersion, payload, data);
        (address wallet, bytes memory key) = _transactionData(txData, policy);
        if (msg.sender != wallet) revert NotWallet(wallet, msg.sender);
        VALIDATOR.link(wallet, platformId, claimed.idNode);
        if (key.length != 0) {
            VALIDATOR.addSessionByRegistry(wallet, identityOf(platformId, claimed.idNode), key, policy, false);
        }
        emit IdentityLinked(wallet, platformId, claimed.idNode, claimed.sessionId);
    }

    function addSessionByLogin(
        bytes32 platformId,
        uint16 verifierVersion,
        bytes calldata payload,
        bytes calldata data,
        IIdentityValidator.Policy calldata policy
    ) external payable {
        (ICeremony.VerifiedClaim memory claimed, bytes memory txData) =
            _accept(ADD_SESSION_DOMAIN, platformId, verifierVersion, payload, data);
        (address wallet, bytes memory key) = _transactionData(txData, policy);
        bytes32 identity = identityOf(platformId, claimed.idNode);
        _checkApp(wallet, identity, claimed.clientIdentifier);
        VALIDATOR.addSessionByRegistry(wallet, identity, key, policy, true);
    }

    function removeSessionsByLogin(
        bytes32 platformId,
        uint16 verifierVersion,
        bytes calldata payload,
        bytes calldata data,
        IIdentityValidator.Policy calldata policy
    ) external payable {
        (ICeremony.VerifiedClaim memory claimed, bytes memory txData) =
            _accept(REMOVE_SESSIONS_DOMAIN, platformId, verifierVersion, payload, data);
        (address wallet, bytes memory key) = _transactionData(txData, policy);
        bytes32 identity = identityOf(platformId, claimed.idNode);
        _checkApp(wallet, identity, claimed.clientIdentifier);
        VALIDATOR.removeByLogin(wallet, identity, key.length != 0);
        if (key.length != 0) VALIDATOR.addSessionByRegistry(wallet, identity, key, policy, true);
    }

    function setAppList(bytes32 identity, bytes32[] calldata apps) external {
        _s().appLists[msg.sender][identity] = apps;
        emit AppListSet(msg.sender, identity, apps);
    }

    function appList(address wallet, bytes32 identity) external view returns (bytes32[] memory) {
        return _s().appLists[wallet][identity];
    }

    function quote(bytes32 platformId, uint16 verifierVersion) external view returns (uint256) {
        return PROOF_VERIFIER.quote(platformId, verifierVersion);
    }

    function digestSpent(bytes32 digest) external view returns (bool) {
        return _s().spentDigests[digest];
    }

    /// Verifies the proof and spends its digest. Returns the claim and its transaction data, under a list the
    /// entry's `data`, for `domain`.
    function _accept(
        bytes32 domain,
        bytes32 platformId,
        uint16 verifierVersion,
        bytes calldata payload,
        bytes calldata data
    ) private returns (ICeremony.VerifiedClaim memory claimed, bytes memory txData) {
        // The Proof Verifier checks the value.
        claimed = PROOF_VERIFIER.verify{value: msg.value}(platformId, verifierVersion, payload);

        txData = claimed.transactionData;
        if (claimed.operationDomain != domain) {
            if (claimed.operationDomain != OperationList.DOMAIN) {
                revert ForeignOperationDomain(claimed.operationDomain);
            }
            // Every domain commits the chain id, which the transaction data's reader checks (REQ-COMMON-01I).
            bytes32[] memory own = new bytes32[](3);
            own[0] = LINK_IDENTITY_DOMAIN;
            own[1] = ADD_SESSION_DOMAIN;
            own[2] = REMOVE_SESSIONS_DOMAIN;
            bytes32 entryDomain = OperationList.select(txData, data, own, true);
            if (entryDomain != domain) revert ForeignOperationDomain(entryDomain);
            txData = data;
        } else if (data.length != 0) {
            revert DataWithoutList();
        }
        if (claimed.idNode == bytes32(0)) revert NoId();
        if (_s().spentDigests[claimed.sessionId]) revert DigestAlreadySpent(claimed.sessionId);
        _s().spentDigests[claimed.sessionId] = true;
    }

    /// Reverts `AppNotListed` unless the login's app is on the wallet's list for `identity`, or the list is empty.
    function _checkApp(address wallet, bytes32 identity, bytes memory clientIdentifier) private view {
        bytes32[] storage apps = _s().appLists[wallet][identity];
        uint256 n = apps.length;
        if (n == 0) return;
        bytes32 app = keccak256(clientIdentifier);
        uint256 i;
        while (i < n && apps[i] != app) ++i;
        if (i == n) revert AppNotListed(app);
    }

    /// The wallet and session key of canonical transaction data for this chain that commits to `policy`.
    function _transactionData(bytes memory data, IIdentityValidator.Policy calldata policy)
        private
        view
        returns (address wallet, bytes memory key)
    {
        // Canonical: re-encoding gives back the same bytes (REQ-COMMON-01F).
        uint256 chainId;
        bytes32 policyHash;
        (chainId, wallet, key, policyHash) = abi.decode(data, (uint256, address, bytes, bytes32));
        // An empty key adds no session, and commits no policy.
        if (
            keccak256(abi.encode(chainId, wallet, key, policyHash)) != keccak256(data)
                || (key.length == 0 && policyHash != 0)
        ) {
            revert BadTransactionData(data.length);
        }
        if (chainId != block.chainid) revert WrongChain(chainId);
        if (key.length != 0) {
            bytes32 given = policyHashOf(policy);
            if (given != policyHash) revert PolicyMismatch(policyHash, given);
        }
    }
}

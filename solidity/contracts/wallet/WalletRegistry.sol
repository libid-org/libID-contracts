// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ICeremony} from "../ceremony/ICeremony.sol";
import {IProofVerifier} from "../ceremony/IProofVerifier.sol";
import {OperationList} from "../ceremony/OperationList.sol";
import {IIdentityValidator, identityOf, policyHashOf} from "./IIdentityValidator.sol";
import {IdentityValidator} from "./IdentityValidator.sol";
import {IWalletRegistry} from "./IWalletRegistry.sol";

/// @title WalletRegistry - the Consumer of the `libid.webwallet.*` operations.
/// @notice Turns a proof into a link or a session in the IdentityValidator. Immutable, no owner.
/// @dev The digest is the nullifier (REQ-COMMON-03A).
contract WalletRegistry is IWalletRegistry {
    bytes32 public constant LINK_IDENTITY_DOMAIN = keccak256("libid.webwallet.link-identity");
    bytes32 public constant ADD_SESSION_DOMAIN = keccak256("libid.webwallet.add-session");

    IProofVerifier private immutable PROOF_VERIFIER;
    IIdentityValidator private immutable VALIDATOR;

    /// @custom:storage-location erc7201:libid.storage.WalletRegistry
    struct WalletRegistryStorage {
        mapping(bytes32 digest => bool) spentDigests;
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
        IIdentityValidator.Policy calldata policy
    ) external payable {
        (bytes32 idNode, bytes32 digest, address wallet, bytes memory key) =
            _accept(LINK_IDENTITY_DOMAIN, platformId, verifierVersion, payload, policy);
        if (msg.sender != wallet) revert NotWallet(wallet, msg.sender);
        VALIDATOR.link(wallet, platformId, idNode);
        if (key.length != 0) VALIDATOR.addSessionByAccount(wallet, identityOf(platformId, idNode), key, policy);
        emit IdentityLinked(wallet, platformId, idNode, digest);
    }

    function addSessionByProof(
        bytes32 platformId,
        uint16 verifierVersion,
        bytes calldata payload,
        IIdentityValidator.Policy calldata policy
    ) external payable {
        (bytes32 idNode,, address wallet, bytes memory key) =
            _accept(ADD_SESSION_DOMAIN, platformId, verifierVersion, payload, policy);
        VALIDATOR.addSessionByProof(wallet, identityOf(platformId, idNode), key, policy);
    }

    function quote(bytes32 platformId, uint16 verifierVersion) external view returns (uint256) {
        return PROOF_VERIFIER.quote(platformId, verifierVersion);
    }

    function digestSpent(bytes32 digest) external view returns (bool) {
        return _s().spentDigests[digest];
    }

    /// Verifies the proof, spends its digest, and checks its transaction data: the identity, the digest,
    /// and the wallet and session key the data names.
    function _accept(
        bytes32 domain,
        bytes32 platformId,
        uint16 verifierVersion,
        bytes calldata payload,
        IIdentityValidator.Policy calldata policy
    ) private returns (bytes32 idNode, bytes32 digest, address wallet, bytes memory key) {
        uint256 required = PROOF_VERIFIER.quote(platformId, verifierVersion);
        if (msg.value != required) revert WrongValue(required, msg.value);
        ICeremony.VerifiedClaim memory claimed =
            PROOF_VERIFIER.verify{value: required}(platformId, verifierVersion, payload);

        // Both domains are this Consumer's, so a list may carry only one of them (REQ-COMMON-01I).
        (bytes32 entryDomain, bytes memory data) = OperationList.select(
            claimed.operationDomain, claimed.transactionData, LINK_IDENTITY_DOMAIN, ADD_SESSION_DOMAIN
        );
        if (entryDomain != domain) revert ForeignOperationDomain(entryDomain);
        if (claimed.idNode == bytes32(0)) revert NoId();
        if (_s().spentDigests[claimed.sessionId]) revert DigestAlreadySpent(claimed.sessionId);
        _s().spentDigests[claimed.sessionId] = true;

        (wallet, key) = _transactionData(data, policy);
        return (claimed.idNode, claimed.sessionId, wallet, key);
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
        // An empty key links only, and commits no policy.
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

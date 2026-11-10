// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ICeremony} from "../ceremony/ICeremony.sol";
import {IProofVerifier} from "../ceremony/IProofVerifier.sol";
import {IIdentityValidator, identityOf} from "./IIdentityValidator.sol";
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

    /// What a proof authorizes, once accepted.
    struct Accepted {
        bytes32 idNode;
        bytes32 digest;
        address wallet;
        bytes key;
        uint256 dataLength;
    }

    constructor(address proofVerifier, address identityValidator) {
        PROOF_VERIFIER = IProofVerifier(proofVerifier);
        VALIDATOR = IIdentityValidator(identityValidator);
    }

    function linkIdentity(
        bytes32 platformId,
        uint16 verifierVersion,
        bytes calldata payload,
        IIdentityValidator.Policy calldata policy
    ) external payable {
        Accepted memory a = _accept(LINK_IDENTITY_DOMAIN, platformId, verifierVersion, payload, policy);
        bool byWallet = msg.sender == a.wallet;
        if (!byWallet) {
            (bytes32 genesisPlatform, bytes32 genesisId) = VALIDATOR.genesisIdentity(a.wallet);
            if (genesisPlatform != platformId || genesisId != a.idNode) revert NotWallet(a.wallet, msg.sender);
        }
        VALIDATOR.link(a.wallet, platformId, a.idNode);
        if (a.key.length != 0) {
            bytes32 identity = identityOf(platformId, a.idNode);
            if (byWallet) VALIDATOR.addSessionByAccount(a.wallet, identity, a.key, policy);
            else VALIDATOR.addSessionByProof(a.wallet, identity, a.key, policy);
        }
        emit IdentityLinked(a.wallet, platformId, a.idNode, a.digest);
    }

    function addSessionByProof(
        bytes32 platformId,
        uint16 verifierVersion,
        bytes calldata payload,
        IIdentityValidator.Policy calldata policy
    ) external payable {
        Accepted memory a = _accept(ADD_SESSION_DOMAIN, platformId, verifierVersion, payload, policy);
        if (a.key.length == 0) revert BadTransactionData(a.dataLength);
        VALIDATOR.addSessionByProof(a.wallet, identityOf(platformId, a.idNode), a.key, policy);
    }

    function quote(bytes32 platformId, uint16 verifierVersion) external view returns (uint256) {
        return PROOF_VERIFIER.quote(platformId, verifierVersion);
    }

    function digestSpent(bytes32 digest) external view returns (bool) {
        return _s().spentDigests[digest];
    }

    /// Verifies the proof, spends its digest, and checks its transaction data.
    function _accept(
        bytes32 domain,
        bytes32 platformId,
        uint16 verifierVersion,
        bytes calldata payload,
        IIdentityValidator.Policy calldata policy
    ) private returns (Accepted memory a) {
        uint256 required = PROOF_VERIFIER.quote(platformId, verifierVersion);
        if (msg.value != required) revert WrongValue(required, msg.value);
        ICeremony.VerifiedClaim memory claimed =
            PROOF_VERIFIER.verify{value: required}(platformId, verifierVersion, payload);

        if (claimed.operationDomain != domain) revert ForeignOperationDomain(claimed.operationDomain);
        if (claimed.idNode == bytes32(0)) revert NoId();
        if (_s().spentDigests[claimed.sessionId]) revert DigestAlreadySpent(claimed.sessionId);
        _s().spentDigests[claimed.sessionId] = true;

        // Canonical: re-encoding gives back the same bytes (REQ-COMMON-01F).
        bytes memory data = claimed.transactionData;
        (uint256 chainId, address wallet, bytes memory key, bytes32 policyHash) =
            abi.decode(data, (uint256, address, bytes, bytes32));
        bool linkOnly = key.length == 0 && policyHash == bytes32(0);
        if (
            keccak256(abi.encode(chainId, wallet, key, policyHash)) != keccak256(data) || (!linkOnly && key.length < 20)
        ) revert BadTransactionData(data.length);
        if (chainId != block.chainid) revert WrongChain(chainId);
        if (key.length != 0) {
            bytes32 given = keccak256(abi.encode(policy));
            if (given != policyHash) revert PolicyMismatch(policyHash, given);
        }
        return Accepted({
            idNode: claimed.idNode, digest: claimed.sessionId, wallet: wallet, key: key, dataLength: data.length
        });
    }
}

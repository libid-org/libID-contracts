// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";

import {ICeremony} from "../ceremony/ICeremony.sol";
import {IProofVerifier} from "../ceremony/IProofVerifier.sol";
import {OperationList} from "../ceremony/OperationList.sol";
import {ADD_SESSION_DOMAIN, IWalletRegistry, LINK_IDENTITY_DOMAIN, REMOVE_SESSIONS_DOMAIN} from "./IWalletRegistry.sol";
import {identityOf} from "./WalletStorage.sol";

/// @title WalletRegistry - the Consumer of the `libid.webwallet.*` operations.
/// @notice Verifies a proof for the wallet that calls it and spends its digest; the wallet applies the result.
/// @dev Behind a UUPS proxy, owned like WalletFactory. The digest is the nullifier (REQ-COMMON-03A).
contract WalletRegistry is IWalletRegistry, UUPSUpgradeable, Ownable2StepUpgradeable {
    /// @custom:storage-location erc7201:libid.storage.WalletRegistry
    struct WalletRegistryStorage {
        mapping(bytes32 digest => bool) spentDigests;
        IProofVerifier proofVerifier;
    }

    // cast index-erc7201 libid.storage.WalletRegistry
    bytes32 private constant WALLET_REGISTRY_STORAGE =
        0x1b521e190b50a237bb32c639281068a3635ba26df4c62304b1a25b9f79aaa000;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address owner_, IProofVerifier verifier) external initializer {
        __Ownable_init(owner_);
        __Ownable2Step_init();
        _setProofVerifier(verifier);
    }

    function check(
        bytes32 domain,
        bytes32 platformId,
        uint16 verifierVersion,
        bytes calldata payload,
        bytes calldata data,
        address submitter,
        bytes32 policyHash
    ) external payable returns (Checked memory) {
        if (domain != LINK_IDENTITY_DOMAIN && domain != ADD_SESSION_DOMAIN && domain != REMOVE_SESSIONS_DOMAIN) {
            revert UnknownOperationDomain(domain);
        }
        // The Proof Verifier checks the value.
        ICeremony.VerifiedClaim memory claimed =
            _s().proofVerifier.verify{value: msg.value}(platformId, verifierVersion, payload);

        bytes memory txData = claimed.transactionData;
        bytes32 entry = claimed.operationDomain;
        if (entry == OperationList.DOMAIN) {
            // Every domain commits the chain id, which `_key` checks (REQ-COMMON-01I).
            bytes32[] memory own = new bytes32[](3);
            (own[0], own[1], own[2]) = (LINK_IDENTITY_DOMAIN, ADD_SESSION_DOMAIN, REMOVE_SESSIONS_DOMAIN);
            entry = OperationList.select(txData, data, own, true);
            txData = data;
        } else if (data.length != 0) {
            revert DataWithoutList();
        }
        if (entry != domain) revert WrongOperationDomain(domain, entry);
        if (claimed.idNode == bytes32(0)) revert NoId();
        bytes memory key = _key(txData, submitter, policyHash);
        WalletRegistryStorage storage $ = _s();
        if ($.spentDigests[claimed.sessionId]) revert DigestSpent(claimed.sessionId);
        $.spentDigests[claimed.sessionId] = true;
        return Checked({identity: identityOf(platformId, claimed.idNode), key: key, app: claimed.clientIdentifier});
    }

    function quote(bytes32 platformId, uint16 verifierVersion) external view returns (uint256) {
        return _s().proofVerifier.quote(platformId, verifierVersion);
    }

    function proofVerifier() external view returns (IProofVerifier) {
        return _s().proofVerifier;
    }

    function setProofVerifier(IProofVerifier verifier) external onlyOwner {
        _setProofVerifier(verifier);
    }

    function spentDigests(bytes32 digest) external view returns (bool) {
        return _s().spentDigests[digest];
    }

    function owner() public view override(IWalletRegistry, OwnableUpgradeable) returns (address) {
        return super.owner();
    }

    /// @dev The upgrade is the only repair lever, so ownership stays.
    function renounceOwnership() public pure override {
        revert RenounceDisabled();
    }

    /// The session key of canonical transaction data naming this chain, the caller and `submitter`; a key commits
    /// `policyHash`, an empty key none.
    function _key(bytes memory data, address submitter, bytes32 policyHash) private view returns (bytes memory key) {
        uint256 chainId;
        address wallet;
        address named;
        bytes32 committed;
        (chainId, wallet, named, key, committed) = abi.decode(data, (uint256, address, address, bytes, bytes32));
        // Canonical: re-encoding gives back the same bytes (REQ-COMMON-01F).
        if (keccak256(abi.encode(chainId, wallet, named, key, committed)) != keccak256(data)) {
            revert BadTransactionData(data.length);
        }
        if (chainId != block.chainid) revert WrongChain(chainId);
        if (wallet != msg.sender) revert WrongWallet(msg.sender, wallet);
        if (named == address(0)) revert ZeroSubmitter();
        if (named != submitter) revert WrongSubmitter(submitter, named);
        if (key.length == 0) {
            if (committed != 0) revert BadTransactionData(data.length);
        } else if (committed != policyHash) {
            revert WrongPolicy(policyHash, committed);
        }
    }

    function _setProofVerifier(IProofVerifier verifier) private {
        if (address(verifier) == address(0)) revert ZeroAddress();
        _s().proofVerifier = verifier;
        emit ProofVerifierConfigured(address(verifier));
    }

    function _s() private pure returns (WalletRegistryStorage storage $) {
        assembly ("memory-safe") {
            $.slot := WALLET_REGISTRY_STORAGE
        }
    }

    function _authorizeUpgrade(address) internal override onlyOwner {}
}

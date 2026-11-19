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
    IProofVerifier private immutable PROOF_VERIFIER;

    /// @custom:storage-location erc7201:libid.storage.WalletRegistry
    struct WalletRegistryStorage {
        mapping(bytes32 digest => bool) spentDigests;
    }

    // cast index-erc7201 libid.storage.WalletRegistry
    bytes32 private constant WALLET_REGISTRY_STORAGE =
        0x1b521e190b50a237bb32c639281068a3635ba26df4c62304b1a25b9f79aaa000;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor(address proofVerifier) {
        PROOF_VERIFIER = IProofVerifier(proofVerifier);
        _disableInitializers();
    }

    function initialize(address owner_) external initializer {
        __Ownable_init(owner_);
        __Ownable2Step_init();
    }

    function check(
        bytes32 domain,
        bytes32 platformId,
        uint16 verifierVersion,
        bytes calldata payload,
        bytes calldata data,
        bytes32 policyHash
    ) external payable returns (Checked memory) {
        if (domain != LINK_IDENTITY_DOMAIN && domain != ADD_SESSION_DOMAIN && domain != REMOVE_SESSIONS_DOMAIN) {
            revert UnknownOperationDomain(domain);
        }
        // The Proof Verifier checks the value.
        ICeremony.VerifiedClaim memory claimed =
            PROOF_VERIFIER.verify{value: msg.value}(platformId, verifierVersion, payload);

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
        bytes memory key = _key(txData, policyHash);
        WalletRegistryStorage storage $ = _s();
        if ($.spentDigests[claimed.sessionId]) revert DigestSpent(claimed.sessionId);
        $.spentDigests[claimed.sessionId] = true;
        return Checked({identity: identityOf(platformId, claimed.idNode), key: key, app: claimed.clientIdentifier});
    }

    function quote(bytes32 platformId, uint16 verifierVersion) external view returns (uint256) {
        return PROOF_VERIFIER.quote(platformId, verifierVersion);
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

    /// The session key of canonical transaction data naming this chain and the caller; a key commits
    /// `policyHash`, an empty key none.
    function _key(bytes memory data, bytes32 policyHash) private view returns (bytes memory key) {
        uint256 chainId;
        address wallet;
        bytes32 committed;
        (chainId, wallet, key, committed) = abi.decode(data, (uint256, address, bytes, bytes32));
        // Canonical: re-encoding gives back the same bytes (REQ-COMMON-01F).
        if (keccak256(abi.encode(chainId, wallet, key, committed)) != keccak256(data)) {
            revert BadTransactionData(data.length);
        }
        if (chainId != block.chainid) revert WrongChain(chainId);
        if (wallet != msg.sender) revert WrongWallet(msg.sender, wallet);
        if (key.length == 0) {
            if (committed != 0) revert BadTransactionData(data.length);
        } else if (committed != policyHash) {
            revert WrongPolicy(policyHash, committed);
        }
    }

    function _s() private pure returns (WalletRegistryStorage storage $) {
        assembly ("memory-safe") {
            $.slot := WALLET_REGISTRY_STORAGE
        }
    }

    function _authorizeUpgrade(address) internal override onlyOwner {}
}

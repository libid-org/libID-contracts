// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IIdentityValidator} from "./IIdentityValidator.sol";

/// @title IWalletRegistry - links proved identities to wallets.
/// @notice Constructor: `WalletRegistry(address proofVerifier)`, which deploys its IdentityValidator.
///         Immutable, no owner.
/// @dev Both domains carry `abi.encode(uint256 chainId, address wallet, bytes sessionKey, bytes32 policyHash)`,
///      canonically encoded. An empty key with a zero policy hash links only, and `policy` is then ignored.
///      Anyone may submit the link of the wallet's genesis identity (`IIdentityValidator.genesisIdentity`)
///      while the wallet has never had a session; every other link only the wallet.
///      `msg.value` is exactly `quote`. Links are not exclusive.
interface IWalletRegistry {
    event IdentityLinked(
        address indexed wallet, bytes32 indexed platformId, bytes32 indexed idNode, bytes32 authorizationDigest
    );

    error ForeignOperationDomain(bytes32 operationDomain);
    error DigestAlreadySpent(bytes32 digest);
    /// Not the canonical encoding, or an empty key with a policy hash.
    error BadTransactionData(uint256 length);
    /// The chain id the proof commits is not this chain's.
    error WrongChain(uint256 committed);
    /// Only the wallet may submit this link.
    error NotWallet(address wallet, address caller);
    /// The policy given does not hash to the one the proof commits.
    error PolicyMismatch(bytes32 committed, bytes32 given);
    error NoId();
    error WrongValue(uint256 required, uint256 provided);

    /// keccak256("libid.webwallet.link-identity")
    function LINK_IDENTITY_DOMAIN() external view returns (bytes32);
    /// keccak256("libid.webwallet.add-session")
    function ADD_SESSION_DOMAIN() external view returns (bytes32);

    function linkIdentity(
        bytes32 platformId,
        uint16 verifierVersion,
        bytes calldata payload,
        IIdentityValidator.Policy calldata policy
    ) external payable;

    /// Anyone may submit; the identity must already be linked to the wallet.
    function addSessionByProof(
        bytes32 platformId,
        uint16 verifierVersion,
        bytes calldata payload,
        IIdentityValidator.Policy calldata policy
    ) external payable;

    /// The IdentityValidator this registry deployed and alone may call.
    function identityValidator() external view returns (address);

    function quote(bytes32 platformId, uint16 verifierVersion) external view returns (uint256);
    function digestSpent(bytes32 digest) external view returns (bool);
}

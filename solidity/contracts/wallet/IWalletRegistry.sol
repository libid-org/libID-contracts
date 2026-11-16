// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IOperationLists} from "../ceremony/IOperationLists.sol";
import {IIdentityValidator} from "./IIdentityValidator.sol";

/// @title IWalletRegistry - links proved identities to wallets.
/// @notice Constructor: `WalletRegistry(address proofVerifier, address walletFactory)`, which deploys its
///         IdentityValidator for the wallets of `walletFactory`. Immutable, no owner.
/// @dev Both domains carry `abi.encode(uint256 chainId, address wallet, bytes sessionKey, bytes32 policyHash)`,
///      canonically encoded. A proof of one operation carries it as its transaction data, and the call's
///      `data` is empty. A proof of an Operation List (`IOperationLists`) commits its hash in an entry of
///      either domain, and the call carries it as `data`. An empty key with a zero policy hash links
///      only, and `policy` is then ignored.
///      The wallet's genesis identity (`IIdentityValidator.genesisIdentity`) is linked when the wallet
///      is created. Only the wallet links, usually inside its own direct `execute`; the session a link adds
///      is the wallet's own (`IIdentityValidator.addSessionByAccount`), from any OAuth client.
///      `msg.value` is exactly `quote`. Links are not exclusive.
///      Every proof goes through `proofVerifier`, whose owner this registry trusts (README.md).
interface IWalletRegistry is IOperationLists {
    event IdentityLinked(
        address indexed wallet, bytes32 indexed platformId, bytes32 indexed idNode, bytes32 authorizationDigest
    );

    error ForeignOperationDomain(bytes32 operationDomain);
    error DigestAlreadySpent(bytes32 digest);
    /// The transaction data, or under a list the entry's `data`, is not the canonical encoding, or
    /// commits an empty key with a policy hash; `length` is its length.
    error BadTransactionData(uint256 length);
    /// The chain id the proof commits is not this chain's.
    error WrongChain(uint256 committed);
    /// Only the wallet may submit this link.
    error NotWallet(address wallet, address caller);
    /// The policy given does not hash to the one the proof commits.
    error PolicyMismatch(bytes32 committed, bytes32 given);
    error NoId();
    /// `data` is given with a proof that is no Operation List.
    error DataWithoutList();

    /// keccak256("libid.webwallet.link-identity")
    function LINK_IDENTITY_DOMAIN() external view returns (bytes32);
    /// keccak256("libid.webwallet.add-session")
    function ADD_SESSION_DOMAIN() external view returns (bytes32);

    function linkIdentity(
        bytes32 platformId,
        uint16 verifierVersion,
        bytes calldata payload,
        bytes calldata data,
        IIdentityValidator.Policy calldata policy
    ) external payable;

    /// Anyone may submit; the identity must already be linked to the wallet, which must have had a session.
    function addSessionByProof(
        bytes32 platformId,
        uint16 verifierVersion,
        bytes calldata payload,
        bytes calldata data,
        IIdentityValidator.Policy calldata policy
    ) external payable;

    /// The IdentityValidator this registry deployed and alone may call.
    function identityValidator() external view returns (address);
    /// The CeremonyProofVerifier every proof goes through.
    function proofVerifier() external view returns (address);

    function quote(bytes32 platformId, uint16 verifierVersion) external view returns (uint256);
    function digestSpent(bytes32 digest) external view returns (bool);
}

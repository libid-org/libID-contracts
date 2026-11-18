// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IOperationLists} from "../ceremony/IOperationLists.sol";
import {IIdentityValidator} from "./IIdentityValidator.sol";

/// @title IWalletRegistry - links proved identities to wallets.
/// @notice Constructor: `WalletRegistry(address proofVerifier, address walletFactory)`, which deploys its
///         IdentityValidator for the wallets of `walletFactory`. Immutable, no owner.
/// @dev Each domain carries
///      `abi.encode(uint256 chainId, address wallet, bytes sessionKey, bytes32 policyHash)`, canonically
///      encoded. A proof
///      of one operation carries it as its transaction data, and the call's `data` is empty. A proof of an
///      Operation List (`IOperationLists`) commits its hash in an entry of any of the three domains, and the
///      call carries it as `data`. An empty key with a zero policy hash adds no session, and `policy` is
///      then ignored.
///      The wallet's genesis identity (`IIdentityValidator.genesisIdentity`) is linked when the wallet
///      is created. Only the wallet links, usually inside its own direct `execute`; the session a link adds
///      is the wallet's own (`IIdentityValidator.addSessionByRegistry`), from any OAuth client.
///      `msg.value` goes whole to `proofVerifier.verify`, under its value rule (`IProofVerifier.verify`):
///      `quote`, or zero for a payload an earlier call of the caller's own batch verified. Links are not
///      exclusive.
///      Every proof goes through `proofVerifier`, whose owner this registry trusts (README.md).
interface IWalletRegistry is IOperationLists {
    event IdentityLinked(
        address indexed wallet, bytes32 indexed platformId, bytes32 indexed idNode, bytes32 authorizationDigest
    );

    /// `wallet` set the list of apps that may add `identity`'s sessions by login; empty is any app.
    event AppListSet(address indexed wallet, bytes32 indexed identity, bytes32[] apps);

    error ForeignOperationDomain(bytes32 operationDomain);
    /// The login's app, `keccak256(clientIdentifier)`, is not on the list the wallet set for the identity.
    error AppNotListed(bytes32 app);
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
    /// keccak256("libid.webwallet.remove-sessions")
    function REMOVE_SESSIONS_DOMAIN() external view returns (bytes32);

    function linkIdentity(
        bytes32 platformId,
        uint16 verifierVersion,
        bytes calldata payload,
        bytes calldata data,
        IIdentityValidator.Policy calldata policy
    ) external payable;

    /// Anyone may submit; the identity must already be linked to the wallet, which must have had a session, and
    /// the login's app must be on the wallet's list for the identity, if it set one.
    /// Adds a session `byProof` (`IIdentityValidator.addSessionByRegistry`).
    function addSessionByLogin(
        bytes32 platformId,
        uint16 verifierVersion,
        bytes calldata payload,
        bytes calldata data,
        IIdentityValidator.Policy calldata policy
    ) external payable;

    /// Anyone may submit, from any app; the identity must be linked to the wallet. Kills its sessions and voids the
    /// wallet's queued root operations (`IIdentityValidator.removeByLogin`). With an empty key it unlinks the
    /// identity unless it is the genesis. With a key it keeps the link and then adds the key `byProof`, as
    /// `addSessionByLogin` does, so the wallet must have had a session.
    function removeSessionsByLogin(
        bytes32 platformId,
        uint16 verifierVersion,
        bytes calldata payload,
        bytes calldata data,
        IIdentityValidator.Policy calldata policy
    ) external payable;

    /// Sets the caller's list of apps, each `keccak256(clientIdentifier)`, whose logins may add `identity`'s
    /// sessions; empty is any app. A removal by login leaves it. A wallet's validator treats this call as an admin
    /// operation.
    function setAppList(bytes32 identity, bytes32[] calldata apps) external;
    function appList(address wallet, bytes32 identity) external view returns (bytes32[] memory);

    /// The IdentityValidator this registry deployed and alone may call.
    function identityValidator() external view returns (address);
    /// The CeremonyProofVerifier every proof goes through.
    function proofVerifier() external view returns (address);

    function quote(bytes32 platformId, uint16 verifierVersion) external view returns (uint256);
    function digestSpent(bytes32 digest) external view returns (bool);
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IProofVerifier} from "../ceremony/IProofVerifier.sol";

// The wallet operations' domains.
bytes32 constant LINK_IDENTITY_DOMAIN = keccak256("libid.webwallet.link-identity");
bytes32 constant ADD_SESSION_DOMAIN = keccak256("libid.webwallet.add-session");
bytes32 constant REMOVE_SESSIONS_DOMAIN = keccak256("libid.webwallet.remove-sessions");

/// @title IWalletRegistry
/// @notice Verifies a wallet operation proof for its caller and spends its digest.
/// @dev `check`'s selector and return layout are frozen: every WebWallet release calls it.
interface IWalletRegistry {
    /// What a verified operation names: the identity `keccak256(abi.encode(platformId, idNode))`, the session
    /// key (empty for a link only) and the OAuth client the login came from.
    struct Checked {
        bytes32 identity;
        bytes key;
        bytes app;
    }

    /// The registry was pointed at a Proof Verifier.
    event ProofVerifierConfigured(address verifier);

    error WrongOperationDomain(bytes32 expected, bytes32 actual);
    error WrongWallet(address expected, address actual);
    error WrongChain(uint256 chainId);
    error WrongPolicy(bytes32 expected, bytes32 actual);
    error DigestSpent(bytes32 digest);
    /// `domain` is none of the three wallet operations.
    error UnknownOperationDomain(bytes32 domain);
    /// `data` was given for a proof that is not an Operation List.
    error DataWithoutList();
    /// The claim names no identity.
    error NoId();
    /// The transaction data is not the canonical `abi.encode(chainId, wallet, key, policyHash)`, or an empty key
    /// commits a policy.
    error BadTransactionData(uint256 length);
    /// Ownership cannot be renounced.
    error RenounceDisabled();
    /// A zero Proof Verifier.
    error ZeroAddress();

    function initialize(address owner, IProofVerifier verifier) external;
    function owner() external view returns (address);

    /// The Proof Verifier every proof goes through. One-fee onboarding needs IdentityRegistry to name the same one.
    function proofVerifier() external view returns (IProofVerifier);
    /// Owner only.
    function setProofVerifier(IProofVerifier verifier) external;

    /// Verifies `payload` for an operation of `domain` whose transaction data names this chain, `msg.sender`
    /// and `policyHash`, spends its digest, and returns what it names.
    function check(
        bytes32 domain,
        bytes32 platformId,
        uint16 verifierVersion,
        bytes calldata payload,
        bytes calldata data,
        bytes32 policyHash
    ) external payable returns (Checked memory);

    function quote(bytes32 platformId, uint16 verifierVersion) external view returns (uint256);
    function spentDigests(bytes32 digest) external view returns (bool);
}

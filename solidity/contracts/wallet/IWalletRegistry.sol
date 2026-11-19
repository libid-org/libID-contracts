// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

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

    error WrongOperationDomain(bytes32 expected, bytes32 actual);
    error WrongWallet(address expected, address actual);
    error WrongChain(uint256 chainId);
    error WrongPolicy(bytes32 expected, bytes32 actual);
    error DigestSpent(bytes32 digest);

    function initialize(address owner) external;
    function owner() external view returns (address);

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

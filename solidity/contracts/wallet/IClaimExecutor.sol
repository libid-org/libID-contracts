// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC7579Module} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";

/// @title IClaimExecutor - the one ERC-7579 executor of every WebWallet.
/// @notice Constructor: `ClaimExecutor(address identityRegistry, address handleEscrow, address identityValidator)`.
///         Stateless, no owner. Anyone may call either function for any wallet that installed it;
///         the proof or the wallet's own address fixes what each call does.
interface IClaimExecutor is IERC7579Module {
    /// After a bind, an identity the wallet holds in the IdentityRegistry is not linked to it.
    error NotLinked(address wallet, bytes32 platformId, bytes32 idNode);

    /// The wallet calls `IdentityRegistry.bindPrivately(platformId, verifierVersion, payload, 0, address(0))`
    /// with `msg.value`, which must be `quoteBind`. Reverts unless every identity the wallet then holds
    /// in the IdentityRegistry is linked to it in the IdentityValidator.
    function bind(address wallet, bytes32 platformId, uint16 verifierVersion, bytes calldata payload) external payable;

    /// The wallet calls `HandleEscrow.claim(handleNode, tokens, wallet)`.
    function claimToSelf(address wallet, bytes32 handleNode, address[] calldata tokens) external;
}

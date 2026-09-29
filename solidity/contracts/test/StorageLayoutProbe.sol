// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {CeremonyProofVerifier} from "../ceremony/CeremonyProofVerifier.sol";
import {GoogleJwtRoots} from "../ceremony/GoogleJwtRoots.sol";
import {GooglePlatformVerifier} from "../ceremony/GooglePlatformVerifier.sol";
import {NotaryService} from "../ceremony/NotaryService.sol";
import {PlatformVerifierBase} from "../ceremony/PlatformVerifierBase.sol";
import {HandleEscrow} from "../escrow/HandleEscrow.sol";
import {IdentityNames} from "../identity/IdentityNames.sol";

/// @notice Holds each upgradeable contract's namespaced struct as an ordinary
///         state variable, so the compiler's storage layout lists its fields.
///
/// @dev `forge inspect <Contract> storageLayout` is empty for these
///      contracts: every field they keep is under an ERC-7201 root, which the
///      layout output does not describe. Declared here, each struct's fields
///      come out with their slots and offsets relative to that root, and
///      `scripts/check-storage-layout.py` compares them with the snapshots
///      committed beside each contract. Never deployed; nothing calls it.
contract StorageLayoutProbe {
    CeremonyProofVerifier.ProofVerifierStorage internal ceremonyProofVerifier;
    GoogleJwtRoots.GoogleJwtRootsStorage internal googleJwtRoots;
    GooglePlatformVerifier.GoogleStorage internal googlePlatformVerifier;
    NotaryService.NotaryServiceStorage internal notaryService;
    PlatformVerifierBase.PlatformVerifierStorage internal platformVerifier;
    HandleEscrow.HandleEscrowStorage internal handleEscrow;
    IdentityNames.IdentityNamesStorage internal identityNames;
}

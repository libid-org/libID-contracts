// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {CeremonyProfile} from "./CeremonyProfile.sol";
import {INotaryService} from "./INotaryService.sol";
import {IHonkVerifier} from "./PlatformVerifierBase.sol";
import {TlsNotaryVerifierBase} from "./TlsNotaryVerifierBase.sol";

/// @title GitHubPlatformVerifier — the `github/v1` profile.
///
/// @notice The X relation for GitHub, proved under `bearer-link` with GitHub's tags.
///
/// @dev Two authorities: `github.com` for the exchange, `api.github.com` for
///      the identity read. The token body is exactly `GITHUB_TOKEN_FIELDS`
///      (REQ-PLAT-61), revealed whole, so the application credential is public.
///      The identity response reveals the `"id":` and `"login":"` anchors and
///      their terminators; id and handle are committed for the circuit.
contract GitHubPlatformVerifier is TlsNotaryVerifierBase {
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address owner_, INotaryService notary_, IHonkVerifier honkVerifier_) external initializer {
        __PlatformVerifierBase_init(owner_, notary_, honkVerifier_);
    }

    function _platform() internal pure override returns (bytes32) {
        return CeremonyProfile.PLATFORM_GITHUB;
    }
}

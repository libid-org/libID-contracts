// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";

import {IHonkVerifier} from "../PlatformVerifierBase.sol";

/// @notice A platform's real Honk verifier, with its answer set by the test.
/// @dev Deploys the vendored verifier (its code hash is pinned) and mocks `verify`.
library HonkStub {
    Vm private constant VM = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    string internal constant X = "BearerLinkXHonkVerifier.sol:BearerLinkXHonkVerifier";
    string internal constant GITHUB = "BearerLinkGithubHonkVerifier.sol:BearerLinkGithubHonkVerifier";
    string internal constant GOOGLE = "OidcGoogleHonkVerifier.sol:OidcGoogleHonkVerifier";

    /// @notice Deploy `artifact` and have its `verify` answer `true`.
    function deploy(string memory artifact) internal returns (address honk) {
        honk = VM.deployCode(artifact);
        answer(honk, true);
    }

    /// @notice What `verify` at `honk` answers from now on, whatever it is
    ///         asked.
    function answer(address honk, bool value) internal {
        VM.mockCall(honk, abi.encodeWithSelector(IHonkVerifier.verify.selector), abi.encode(value));
    }
}

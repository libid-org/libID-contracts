// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";

import {IHonkVerifier} from "../PlatformVerifierBase.sol";

/// @notice A platform's real Honk verifier, with its answer set by the test.
///
/// @dev A Platform Verifier accepts only its own circuit's verifier, by
///      runtime code hash, so a stand-in contract cannot be wired at all.
///      This deploys the vendored verifier itself -- the code the pin names --
///      and mocks `verify` on that address, so a test that is not about the
///      proof reaches the checks it is about, and one that is can set the
///      answer to `false`. A call still reaches the address, so `expectCall`
///      sees it.
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

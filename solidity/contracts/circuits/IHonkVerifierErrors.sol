// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IHonkVerifierErrors
/// @notice What a vendored Honk verifier reverts with, as an ABI a client can
///         decode against.
///
/// @dev bb's generated verifier declares no errors: it reverts from assembly
///      with selectors held in `*_SELECTOR` constants, so its artifact's ABI
///      is silent about them. A refused proof reaches a `bind` caller
///      unchanged through the Platform Verifier, and these declarations,
///      under bb's own names, are what name it. Nothing implements this
///      interface.
///
///      The names are bb's, `MODEXP_FAILED` included: a selector is the hash
///      of the name, so another spelling would decode nothing. The Rust and
///      TypeScript packages each check that these selectors are exactly the
///      `*_SELECTOR` constants of the vendored verifiers.
interface IHonkVerifierErrors {
    /// A proof coordinate limb is not below the limb bound.
    error ValueGeLimbMax();
    /// A proof scalar is not below the curve's group order.
    error ValueGeGroupOrder();
    /// A proof element is not below the field modulus.
    error ValueGeFieldOrder();
    /// The sumcheck rounds do not verify.
    error SumcheckFailed();
    /// The Shplemini opening does not verify.
    error ShpleminiFailed();
    /// The proof is not the length the circuit's `logN` implies; raised
    /// before anything else.
    error ProofLengthWrongWithLogN(uint256 logN, uint256 actualLength, uint256 expectedLength);
    /// The public inputs are not the circuit's count.
    error PublicInputsLengthWrong();
    /// The MODEXP precompile call failed.
    error MODEXP_FAILED();
    /// A consistency check between the proof's evaluations failed.
    error ConsistencyCheckFailed();
    /// The Gemini challenge falls in the evaluation subgroup.
    error GeminiChallengeInSubgroup();
}

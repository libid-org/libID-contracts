// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IHonkVerifierErrors
/// @notice What a vendored Honk verifier reverts with, as an ABI a client can
///         decode against.
/// @dev bb reverts from assembly and declares no errors. The names are bb's, so the selectors match.
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
    /// The proof is not the length the circuit's `logN` implies.
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

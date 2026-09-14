// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Libraries named like a bb verifier's, compiled from other code.
///
/// @dev The crate deploys a library once per distinct bytecode, whatever
///      file names it. The vendored verifiers exercise the sharing half of
///      that rule and cannot exercise the other: their copies of
///      `RelationsLib` and `ZKTranscriptLib` are identical today. This
///      contract links libraries under the same two names whose bytecode
///      is its own, so `rust/contracts/tests/anvil.rs` — which reads it from
///      `out/` through `Artifacts::from_dir` — can show them deployed apart
///      from the verifiers' rather than shared by name. No forge test reads
///      this file. The functions are `external` so the libraries are linked
///      rather than inlined, which is what puts them in `linkReferences`.
library RelationsLib {
    function accumulate(uint256 value) external pure returns (uint256) {
        return value + 1;
    }
}

library ZKTranscriptLib {
    function challenge(uint256 value) external pure returns (uint256) {
        return value * 2;
    }
}

contract LinkFixture {
    function relate(uint256 value) external pure returns (uint256) {
        return RelationsLib.accumulate(value);
    }

    function transcribe(uint256 value) external pure returns (uint256) {
        return ZKTranscriptLib.challenge(value);
    }
}

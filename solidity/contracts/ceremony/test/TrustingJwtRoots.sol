// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IGoogleJwtRoots} from "../GooglePlatformVerifier.sol";

/// @notice A JWT root list that trusts each modulus hash until the expiry the test sets.
contract TrustingJwtRoots is IGoogleJwtRoots {
    mapping(bytes32 => uint256) public expiry;

    function trust(bytes32 modulusHash, uint256 until) external {
        expiry[modulusHash] = until;
    }

    function trustedHashExpiresAt(bytes32 modulusHash) external view returns (uint256) {
        return expiry[modulusHash];
    }
}

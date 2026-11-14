// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/IERC4337.sol";

import {IIdentityValidator} from "../IIdentityValidator.sol";
import {IdentityValidatorState} from "../IdentityValidatorState.sol";
import {SessionRules} from "../SessionRules.sol";

/// SessionRules runs only through the validator's DELEGATECALL.
contract SessionRulesTest is Test {
    function test_aDirectCallReverts() public {
        address rules = deployCode("SessionRules.sol:SessionRules", abi.encode(address(0)));
        IdentityValidatorState.Verified memory v;
        PackedUserOperation memory op;
        bytes memory call = abi.encodeCall(SessionRules.allowed, (v, op, false));
        (bool ok, bytes memory err) = rules.call(call);
        assertFalse(ok, "accepted");
        assertEq(err, abi.encodeWithSignature("NotDelegated()"), "not NotDelegated");
    }

    function test_aDirectCallOfTheDirectPathsRulesReverts() public {
        address rules = deployCode("SessionRules.sol:SessionRules", abi.encode(address(0)));
        IdentityValidatorState.Verified memory v;
        IIdentityValidator.Authorization memory a;
        bytes memory call = abi.encodeCall(SessionRules.allowedExecution, (v, bytes32(0), "", a, false));
        (bool ok, bytes memory err) = rules.call(call);
        assertFalse(ok, "accepted");
        assertEq(err, abi.encodeWithSignature("NotDelegated()"), "not NotDelegated");
    }
}

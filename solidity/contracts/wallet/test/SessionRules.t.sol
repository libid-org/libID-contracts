// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/IERC4337.sol";

/// SessionRules runs only through the validator's DELEGATECALL.
contract SessionRulesTest is Test {
    function test_aDirectCallReverts() public {
        address rules = deployCode("SessionRules.sol:SessionRules");
        PackedUserOperation memory op;
        // `allowed(account, registry, v, userOp, below)`, its `Verified` the eight zero words.
        bytes memory call = abi.encodePacked(
            bytes4(0x7795e026), abi.encode(address(this), address(0), [uint256(0), 0, 0, 0, 0, 0, 0, 0], op, false)
        );
        (bool ok, bytes memory err) = rules.call(call);
        assertFalse(ok, "accepted");
        assertEq(err, abi.encodeWithSignature("NotDelegated()"), "not NotDelegated");
    }
}

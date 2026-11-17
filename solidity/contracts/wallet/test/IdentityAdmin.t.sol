// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";

import {IIdentityValidator} from "../IIdentityValidator.sol";

/// IdentityAdmin runs only through the validator's DELEGATECALL.
contract IdentityAdminTest is Test {
    function test_aDirectCallReverts() public {
        address admin = deployCode("IdentityAdmin.sol:IdentityAdmin", abi.encode(address(this), address(0)));
        bytes memory call = abi.encodeCall(IIdentityValidator.link, (address(1), bytes32(0), bytes32(0)));
        (bool ok, bytes memory err) = admin.call(call);
        assertFalse(ok, "accepted");
        assertEq(err, abi.encodeWithSignature("NotDelegated()"), "not NotDelegated");
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/IERC4337.sol";
import {IERC7579Execution} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";

import {NATIVE_TOKEN} from "../../NativeToken.sol";
import {IIdentityValidator} from "../IIdentityValidator.sol";
import {IdentityValidatorState} from "../IdentityValidatorState.sol";
import {SessionRules} from "../SessionRules.sol";
import {WalletTestBase} from "./WalletTestBase.sol";

contract HitOrFallback {
    uint256 public hits;
    uint256 public fallbacks;

    function hit() external payable {
        hits++;
    }

    fallback() external payable {
        fallbacks++;
    }
}

/// @notice A UserOperation batch whose element offset is negative. The account, decoding its own calldata, would
///         run an empty call; the rules, decoding the batch inside theirs, would read a `hit()` call from the
///         operation's gas words in front of it.
contract NoncanonicalUserOpBatchTest is WalletTestBase {
    function _wordAt(bytes memory b, uint256 off) private pure returns (bytes32 w) {
        assembly {
            w := mload(add(add(b, 0x20), off))
        }
    }

    function test_aBatchWithANegativeElementOffsetIsRefused() public {
        HitOrFallback t = new HitOrFallback();
        address w = _claim();
        IIdentityValidator.Policy memory p = _app();
        p.rules.scopeRoot = _leaf(address(t), HitOrFallback.hit.selector, 0);
        p.rules.allowances = new IIdentityValidator.Allowance[](1);
        p.rules.allowances[0] = IIdentityValidator.Allowance({token: NATIVE_TOKEN, amount: 1 ether, period: 0});
        vm.prank(w);
        validator.addSession(_identity(X, ALICE), _key(APP_PK), p);
        vm.warp(_now() + 1);

        // In `allowed(v, userOp, below)`: the userOp tuple after the selector, `v` (8 words) and two heads; its
        // callData's content (initCode empty); the rules' element, one byte into preVerificationGas.
        uint256 u = 4 + 8 * 32 + 2 * 32;
        uint256 cd = u + 352;
        uint256 element = u + 160 + 1;
        // The batch starts after execute's selector, two heads, a length, and its own two words.
        int256 rel = int256(element) - int256(cd + 0x64 + 0x60);
        assertLt(0x64 + 0x60 + rel, 0, "the account's element lands below its calldata");
        bytes memory execs = abi.encodePacked(
            uint256(0x20), uint256(1), uint256(0x20), uint256(uint160(address(t))), uint256(0), uint256(rel), uint256(0)
        );
        bytes memory callData = abi.encodeCall(IERC7579Execution.execute, (MODE_BATCH, execs));
        PackedUserOperation memory op = _op(w, 0, callData);
        // The rules' element callData: length `1 << 8`, then `hit()` from maxPriorityFeePerGas.
        op.preVerificationGas = 1;
        op.gasFees = bytes32(((uint256(uint32(HitOrFallback.hit.selector)) << 88) << 128) | 1 gwei);

        IdentityValidatorState.Verified memory v;
        bytes memory rulesCall = abi.encodeCall(SessionRules.allowed, (v, op, true));
        assertEq(uint256(_wordAt(rulesCall, cd - 32)), callData.length, "callData layout");
        assertEq(uint256(_wordAt(rulesCall, element)), 0x100, "element callData length");
        assertEq(bytes4(_wordAt(rulesCall, element + 32)), HitOrFallback.hit.selector, "element selector");

        _refused(_signedWith(op, _pks(APP_PK), _hitProofs(1)), "a batch read differently by the rules");
        assertEq(t.hits() + t.fallbacks(), 0, "a call ran");
    }
}

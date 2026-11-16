// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IIdentityValidator} from "../IIdentityValidator.sol";
import {IdentityValidatorState} from "../IdentityValidatorState.sol";
import {AUTHORIZED_MODE, IWebWallet} from "../IWebWallet.sol";
import {SessionRules} from "../SessionRules.sol";
import {CallTarget} from "./WalletTestBase.sol";
import {ExecuteBase, Gate} from "./DirectExecute.t.sol";

/// @notice A signed batch whose element offset points past its own bytes. The wallet would read that element
///         from the rest of its `data`, and the rules, from the rest of their own calldata: a session scoped to
///         `hit()` would open a gate.
contract NoncanonicalBatchTest is ExecuteBase {
    Gate internal gate;

    function _wordAt(bytes memory b, uint256 off) private pure returns (bytes32 w) {
        assembly {
            w := mload(add(add(b, 0x20), off))
        }
    }

    function _setWord(bytes memory b, uint256 off, bytes32 v) private pure {
        assembly {
            mstore(add(add(b, 0x20), off), v)
        }
    }

    /// The byte offset of the first word after the selector equal to `needle`.
    function _find(bytes memory cd, bytes32 needle) private pure returns (uint256) {
        for (uint256 off = 4; off + 32 <= cd.length; off += 32) {
            if (_wordAt(cd, off) == needle) return off;
        }
        revert("not found");
    }

    function test_aBatchReadingPastItsBytesIsRefused() public {
        address w = _fresh();
        gate = new Gate();
        vm.prank(w);
        validator.addSession(_identity(X, ALICE), _key(APP_PK), _hitOnly());
        vm.warp(_now() + 1);

        uint48 at = uint48(_now());
        uint48 deadline = at + 1 hours;
        // The rules read an in-scope `hit()` Execution from the domain proof: target, value, offset, length, selector.
        bytes32[] memory planted = new bytes32[](5);
        (planted[0], planted[2], planted[3], planted[4]) =
        (
            bytes32(uint256(uint160(address(target)))),
            bytes32(uint256(0x60)),
            bytes32(uint256(4)),
            CallTarget.hit.selector
        );
        IIdentityValidator.Authorization memory auth = IIdentityValidator.Authorization({
            signatures: new IIdentityValidator.SessionSignature[](1),
            at: at,
            calls: new IIdentityValidator.CallProof[](1),
            domainProof: planted,
            paymasterProof: new bytes32[](0)
        });
        auth.signatures[0] = IIdentityValidator.SessionSignature({key: _key(APP_PK), signature: new bytes(65)});

        // The signed batch is its pointer table alone: [0x20][1][rel]. `rel` lands the rules' element on `planted`.
        bytes memory batch = abi.encodePacked(uint256(0x20), uint256(1), uint256(0));
        IdentityValidatorState.Verified memory v;
        bytes memory rulesCall = abi.encodeCall(SessionRules.allowedExecution, (v, AUTHORIZED_MODE, batch, auth, true));
        uint256 batchAt = _find(rulesCall, bytes32(uint256(0x60))) + 0x20;
        uint256 rel = _find(rulesCall, planted[0]) - (batchAt + 0x40);
        _setWord(batch, 0x40, bytes32(rel));

        bytes32 h = _execDigest(w, AUTHORIZED_MODE, batch, at, _nonce(w, address(validator)), deadline);
        (uint8 sv, bytes32 sr, bytes32 ss) = vm.sign(APP_PK, _belowQuorum(h, at, _key(APP_PK)));
        auth.signatures[0].signature = abi.encodePacked(sr, ss, sv);
        bytes memory authBytes = abi.encode(auth);

        // `data`: the head, the batch at 0x80, a `gate.openUp()` Execution where the wallet's element lands, then
        // the authorization.
        uint256 g = 0xe0 + rel;
        uint256 a = g + 0xa0;
        bytes memory data = new bytes(a + 0x20 + authBytes.length);
        _setWord(data, 0x00, bytes32(uint256(0x80)));
        _setWord(data, 0x20, bytes32(uint256(deadline)));
        _setWord(data, 0x40, bytes32(CALL_GAS));
        _setWord(data, 0x60, bytes32(a));
        _setWord(data, 0x80, bytes32(uint256(0x60)));
        for (uint256 i; i < 3; ++i) {
            _setWord(data, 0xa0 + i * 0x20, _wordAt(batch, i * 0x20));
        }
        _setWord(data, g, bytes32(uint256(uint160(address(gate)))));
        _setWord(data, g + 0x40, bytes32(uint256(0x60)));
        _setWord(data, g + 0x60, bytes32(uint256(4)));
        _setWord(data, g + 0x80, Gate.openUp.selector);
        _setWord(data, a, bytes32(authBytes.length));
        for (uint256 i; i < authBytes.length / 0x20; ++i) {
            _setWord(data, a + 0x20 + i * 0x20, _wordAt(authBytes, i * 0x20));
        }

        vm.prank(relayer);
        vm.expectRevert(IWebWallet.NoncanonicalBatch.selector);
        IWebWallet(w).execute(AUTHORIZED_MODE, data);
        assertFalse(gate.open(), "the wallet ran a call no signer signed");
    }
}

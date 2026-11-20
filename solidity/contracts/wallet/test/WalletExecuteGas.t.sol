// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Test.sol";
import {IEntryPoint, PackedUserOperation} from "@openzeppelin/contracts/interfaces/IERC4337.sol";

import {AUTHORIZED_MODE, IWebWallet} from "../IWebWallet.sol";
import {WalletSuite} from "./WalletSuite.sol";

/// @notice What one `hit()` costs on a factory wallet, by path: a whole transaction, gas used less the refund.
contract WalletExecuteGasTest is WalletSuite {
    /// forge-config: gas.isolate = true
    function test_aUserOperationAtQuorum() public {
        address w = _claim();
        vm.warp(_now() + 1);
        _measureOp(_signed(_op(w, _hitCall()), _pks(ALICE_PK)), "UserOperation hit(), quorum");
    }

    /// forge-config: gas.isolate = true
    function test_aUserOperationBelowQuorum() public {
        address w = _belowWallet();
        _measureOp(_signedWith(_op(w, _hitCall()), _pks(BOT_PK), _hitProofs(1)), "UserOperation hit(), below quorum");
    }

    /// forge-config: gas.isolate = true
    function test_anAuthorizedBatchAtQuorum() public {
        address w = _claim();
        vm.warp(_now() + 1);
        _measureBatch(w, ALICE_PK, false, "AUTHORIZED batch hit(), quorum");
    }

    /// forge-config: gas.isolate = true
    function test_anAuthorizedBatchBelowQuorum() public {
        _measureBatch(_belowWallet(), BOT_PK, true, "AUTHORIZED batch hit(), below quorum");
    }

    /// Alice's wallet with Bot's `hit()`-only session, active.
    function _belowWallet() internal returns (address w) {
        w = _claim();
        _addSession(w, _identity(X, ALICE), _key(BOT_PK), _hitGas());
        vm.warp(_now() + 1);
    }

    function _measureOp(PackedUserOperation memory op, string memory name) internal {
        vm.deal(op.sender, 1 ether + _prefund(op));
        vm.prank(bundler, bundler);
        IEntryPoint(EP).handleOps(_ops(op), payable(bundler));
        _record(name);
    }

    function _measureBatch(address w, uint256 pk, bool below, string memory name) internal {
        bytes memory calls = _one(_hitX());
        bytes memory data = _data(calls, _direct(w, _pks(pk), calls, below));
        vm.prank(relayer, relayer);
        IWebWallet(w).execute(AUTHORIZED_MODE, data);
        _record(name);
    }

    function _record(string memory name) internal {
        Vm.Gas memory used = vm.lastFrameGas();
        assertEq(target.calls(), 1, "hit() did not run");
        // forge-lint: disable-next-line(unsafe-typecast)
        vm.snapshotValue("wallet-execute", name, used.gasTotalUsed - uint64(used.gasRefunded));
    }
}

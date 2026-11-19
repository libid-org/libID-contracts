// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/IERC4337.sol";
import {CallType, ERC7579Utils, Execution} from "@openzeppelin/contracts/account/utils/draft-ERC7579Utils.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

import {NATIVE_TOKEN} from "../escrow/HandleEscrow.sol";
import {IWebWallet} from "./IWebWallet.sol";
import {WalletStorage} from "./WalletStorage.sol";

/// @title SessionRules - what an operation may do, and the allowances it charges below quorum.
/// @notice WebWallet runs it through DELEGATECALL on its own storage, never routes to it; called at its own address,
///         it reverts. Each entry takes its arguments ABI-encoded in one `bytes`.
contract SessionRules {
    address private immutable SELF = address(this);

    /// What every execution of an operation is checked against below quorum: the governing session's scope and
    /// rules hash, the signed `at`, the native value and gas charged so far, and the registry.
    struct Spend {
        bytes32 keyHash;
        bytes32 scopeRoot;
        bytes32 rulesHash;
        uint48 at;
        bool below;
        uint256 native;
        address registry;
    }

    /// A UserOperation's `execute(mode, executionCalldata)` with mode selector 0, a batch encoded canonically.
    /// `input` is `abi.encode(Verified v, PackedUserOperation userOp, Authorization auth, bool below,
    /// address registry)`. Returns the verdict and `v` narrowed to the periods charged.
    function allowed(bytes calldata input) external returns (bool, WalletStorage.Verified memory) {
        _delegated();
        (
            WalletStorage.Verified memory v,
            PackedUserOperation memory op,
            IWebWallet.Authorization memory auth,
            bool below,
            address registry
        ) = abi.decode(input, (WalletStorage.Verified, PackedUserOperation, IWebWallet.Authorization, bool, address));
        bytes memory callData = op.callData;
        if (callData.length < 4 || bytes4(_word(callData, 0)) != IWebWallet.execute.selector) return (false, v);
        (bytes32 mode, bytes memory executions) = abi.decode(_from(callData, 4), (bytes32, bytes));
        if (bytes4(mode << 48) != 0) return (false, v);
        CallType callType = CallType.wrap(mode[0]);
        bool batch = callType == ERC7579Utils.CALLTYPE_BATCH;
        if (!batch && !(callType == ERC7579Utils.CALLTYPE_SINGLE)) return (false, v);
        Spend memory sp = Spend(v.keyHash, 0, 0, auth.at, below, 0, registry);
        // At quorum neither the paymaster nor the gas is read.
        if (below) {
            WalletStorage.SessionRecord storage s = WalletStorage.session(v.keyHash);
            (sp.scopeRoot, sp.rulesHash) = (s.scopeRoot, s.rulesHash);
            if (op.paymasterAndData.length != 0) {
                // Shorter than a paymaster's address and gas limits, it names none.
                if (op.paymasterAndData.length < 52) return (false, v);
                address paymaster = address(bytes20(_word(op.paymasterAndData, 0)));
                // `address(0)` stands for no paymaster.
                if (
                    paymaster == address(0)
                        || !MerkleProof.verify(
                            auth.paymasterProof, s.paymastersRoot, WalletStorage.leaf(abi.encode(paymaster))
                        )
                ) return (false, v);
            } else {
                uint256 limits = uint256(op.accountGasLimits);
                sp.native = ((limits >> 128) + uint128(limits) + op.preVerificationGas) * uint128(uint256(op.gasFees));
            }
        }
        return (_calls(v, sp, batch, executions, auth.calls), v);
    }

    /// An `AUTHORIZED_MODE` batch, with no paymaster and no gas charge. `input` is `abi.encode(Verified v,
    /// bytes executionCalldata, Authorization auth, bool below, address registry)`.
    function allowedExecution(bytes calldata input) external returns (bool, WalletStorage.Verified memory) {
        _delegated();
        (
            WalletStorage.Verified memory v,
            bytes memory executions,
            IWebWallet.Authorization memory auth,
            bool below,
            address registry
        ) = abi.decode(input, (WalletStorage.Verified, bytes, IWebWallet.Authorization, bool, address));
        Spend memory sp = Spend(v.keyHash, 0, 0, auth.at, below, 0, registry);
        if (below) {
            WalletStorage.SessionRecord storage s = WalletStorage.session(v.keyHash);
            (sp.scopeRoot, sp.rulesHash) = (s.scopeRoot, s.rulesHash);
        }
        return (_calls(v, sp, true, executions, auth.calls), v);
    }

    function _delegated() private view {
        if (address(this) == SELF) revert IWebWallet.NotDelegated();
    }

    /// Single or batch calls, each passing `_execution`. Below quorum, at least one, and the native value charged
    /// to `NATIVE_TOKEN` with `sp.native`.
    function _calls(
        WalletStorage.Verified memory v,
        Spend memory sp,
        bool batch,
        bytes memory executions,
        IWebWallet.CallProof[] memory proofs
    ) private returns (bool) {
        bool below = sp.below;
        if (batch) {
            Execution[] memory x = abi.decode(executions, (Execution[]));
            // The rules and the wallet read the same calls only from a canonical batch.
            if (keccak256(abi.encode(x)) != keccak256(executions)) return false;
            if (below && (x.length == 0 || proofs.length != x.length)) return false;
            for (uint256 i; i < x.length; ++i) {
                if (!_execution(v, sp, x[i].target, x[i].value, x[i].callData, proofs, i)) return false;
            }
        } else {
            if (below && proofs.length != 1) return false;
            if (executions.length < 52) return false;
            address target = address(bytes20(_word(executions, 0)));
            if (!_execution(v, sp, target, uint256(_word(executions, 20)), _from(executions, 52), proofs, 0)) {
                return false;
            }
        }
        return
            sp.native == 0
                || _charge(v, WalletStorage.counter(sp.keyHash, sp.rulesHash, NATIVE_TOKEN), sp.native, sp.at);
    }

    /// One execution. Below quorum, an outside call proved by `proofs[i]` under the session's scope, its token
    /// spend charged and its value added to `sp.native`.
    /// @dev `scopeRoot == 0` proves no leaf. A value past uint128 fits no allowance; refusing it keeps the sum
    ///      from overflowing.
    function _execution(
        WalletStorage.Verified memory v,
        Spend memory sp,
        address target,
        uint256 value,
        bytes memory data,
        IWebWallet.CallProof[] memory proofs,
        uint256 i
    ) private returns (bool) {
        if (!sp.below) return true;
        // A call to the wallet (or `address(0)`, the wallet) or to the registry is an admin operation.
        if (target == address(this) || target == address(0) || target == sp.registry) return false;
        IWebWallet.CallProof memory proof = proofs[i];
        bytes4 selector = data.length < 4 ? bytes4(0) : bytes4(_word(data, 0));
        if (
            value > proof.maxValue || value > type(uint128).max
                || !MerkleProof.verify(
                    proof.proof, sp.scopeRoot, WalletStorage.leaf(abi.encode(target, selector, proof.maxValue))
                )
        ) return false;
        sp.native += value;
        return _chargeToken(v, WalletStorage.counter(sp.keyHash, sp.rulesHash, target), data, selector, sp.at);
    }

    /// Refuses a token call the allowances forbid, and charges a `transfer` or `approve` amount.
    /// @dev A token with an allowance takes only `transfer` and `approve`, which only such a token takes.
    function _chargeToken(
        WalletStorage.Verified memory v,
        WalletStorage.Counter storage c,
        bytes memory data,
        bytes4 selector,
        uint48 at
    ) private returns (bool) {
        bool spends = selector == IERC20.transfer.selector || selector == IERC20.approve.selector;
        if (selector == IERC20.transferFrom.selector || spends != c.listed) return false;
        return !spends || (data.length >= 68 && _charge(v, c, uint256(_word(data, 36)), at));
    }

    /// Charges `amount` to `c` in the period of `at`, and narrows the window to that period.
    /// @dev `at == 0` is refused: the period 1 starting at 0 would end at 0, an unbounded window.
    function _charge(WalletStorage.Verified memory v, WalletStorage.Counter storage c, uint256 amount, uint48 at)
        private
        returns (bool)
    {
        if (at == 0) return false;
        uint48 period = c.period;
        uint48 start = c.periodStart;
        uint128 spent = c.spent;
        if (period != 0) {
            uint48 current = at - at % period;
            // Past periods are closed; window bounds stay below bit 47, a block-number flag to EntryPoint v0.9.
            if (current < start || uint256(current) + period > 1 << 47) return false;
            WalletStorage.narrow(v, current == 0 ? 0 : current - 1, current + period - 1);
            if (current != start) (start, spent) = (current, 0);
        }
        if (amount > c.amount - spent) return false;
        // forge-lint: disable-next-line(unsafe-typecast)
        (c.periodStart, c.spent) = (start, spent + uint128(amount));
        return true;
    }

    /// The 32 bytes of `b` from `at`, zero-padded past its end.
    function _word(bytes memory b, uint256 at) private pure returns (bytes32 w) {
        assembly ("memory-safe") {
            w := mload(add(add(b, 0x20), at))
        }
        if (b.length < at + 32) w &= ~bytes32(type(uint256).max >> (8 * (b.length > at ? b.length - at : 0)));
    }

    /// `b` from `at` on.
    function _from(bytes memory b, uint256 at) private pure returns (bytes memory r) {
        r = new bytes(b.length - at);
        for (uint256 i; i < r.length; ++i) {
            r[i] = b[at + i];
        }
    }
}

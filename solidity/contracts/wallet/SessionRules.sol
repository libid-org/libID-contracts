// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/IERC4337.sol";
import {IERC7579Execution, IERC7579Module} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {ERC4337Utils} from "@openzeppelin/contracts/account/utils/ERC4337Utils.sol";
import {
    CallType,
    ERC7579Utils,
    Execution,
    Mode,
    ModeSelector
} from "@openzeppelin/contracts/account/utils/draft-ERC7579Utils.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

import {NATIVE_TOKEN} from "../NativeToken.sol";
import {bytesAt} from "./AbiBytes.sol";
import {IIdentityValidator} from "./IIdentityValidator.sol";
import {IdentityValidatorState} from "./IdentityValidatorState.sol";

/// @title SessionRules - what an operation may do, and the allowances it charges below quorum.
/// @notice Deployed by IdentityValidator's constructor, which runs it through DELEGATECALL: it reads
///         and writes the validator's storage. Called directly, it reverts.
contract SessionRules is IdentityValidatorState {
    using ERC4337Utils for PackedUserOperation;
    using ERC7579Utils for bytes;
    using ERC7579Utils for Mode;

    address private immutable SELF = address(this);

    /// Called other than through the validator's DELEGATECALL.
    error NotDelegated();

    /// What one execution asks of the account.
    enum Scope {
        Call,
        Admin,
        Refused
    }

    /// What every execution of an operation is checked against: the account and its registry; below
    /// quorum, the governing session's scope and rules hash, the signed `at`, and the native value and
    /// gas charged so far.
    struct Spend {
        address account;
        address registry;
        bytes32 keyHash;
        bytes32 scopeRoot;
        bytes32 rulesHash;
        uint48 at;
        bool below;
        uint256 native;
    }

    /// `_allowed` for a UserOperation's `execute(mode, executionCalldata)` under the default mode selector, and
    /// `v` with its window narrowed to the periods charged.
    function allowed(
        address account,
        address registry,
        Verified memory v,
        PackedUserOperation calldata userOp,
        bool below
    ) external returns (bool, Verified memory) {
        if (address(this) == SELF) revert NotDelegated();
        bytes calldata callData = userOp.callData;
        if (_selector(callData) != IERC7579Execution.execute.selector) return (false, v);
        IIdentityValidator.Authorization memory auth = abi.decode(userOp.signature, (IIdentityValidator.Authorization));
        (bytes32 mode, bytes calldata executions) = _executions(callData);
        (,, ModeSelector modeSelector,) = Mode.wrap(mode).decodeMode();
        if (ModeSelector.unwrap(modeSelector) != 0) return (false, v);
        address paymaster;
        if (userOp.paymasterAndData.length != 0) {
            paymaster = userOp.paymaster();
            // Refused at every threshold: `address(0)` stands for no paymaster below. EntryPoint v0.8 and
            // later reject it before the account anyway.
            if (paymaster == address(0)) return (false, v);
        }
        return (_allowed(account, registry, v, auth, mode, executions, paymaster, _maxGasCost(userOp), below), v);
    }

    /// `_allowed` for a direct execution, with no paymaster and no gas charge, and `v` with its window narrowed
    /// to the periods charged.
    function allowedExecution(
        address account,
        address registry,
        Verified memory v,
        bytes32 mode,
        bytes calldata executions,
        IIdentityValidator.Authorization memory auth,
        bool below
    ) external returns (bool, Verified memory) {
        if (address(this) == SELF) revert NotDelegated();
        return (_allowed(account, registry, v, auth, mode, executions, address(0), 0, below), v);
    }

    /// Single or batch calls, as `_calls` allows them. Below quorum, a
    /// paymaster must be one the session lists; with none, `maxGasCost` is charged to `NATIVE_TOKEN` with
    /// the value.
    /// @dev `paymastersRoot == 0` proves no leaf.
    function _allowed(
        address account,
        address registry,
        Verified memory v,
        IIdentityValidator.Authorization memory auth,
        bytes32 mode,
        bytes calldata executions,
        address paymaster,
        uint256 maxGasCost,
        bool below
    ) private returns (bool) {
        (CallType callType,,,) = Mode.wrap(mode).decodeMode();
        Spend memory sp = Spend(account, registry, v.keyHash, 0, 0, auth.at, below, 0);
        if (below) {
            IIdentityValidator.Session storage s = _sessions(account, v.keyHash)[account];
            (sp.scopeRoot, sp.rulesHash) = (s.scopeRoot, s.rulesHash);
            if (paymaster == address(0)) {
                sp.native = maxGasCost;
            } else if (!MerkleProof.verify(auth.paymasterProof, s.paymastersRoot, _leaf(abi.encode(paymaster)))) {
                return false;
            }
        }
        return _calls(v, sp, callType, executions, auth.calls);
    }

    /// Single or batch calls, each passing `_execution`. Below quorum, at least one execution, and
    /// the native value charged to `NATIVE_TOKEN` with `sp.native`.
    function _calls(
        Verified memory v,
        Spend memory sp,
        CallType callType,
        bytes calldata executions,
        IIdentityValidator.CallProof[] memory calls
    ) private returns (bool) {
        bool below = sp.below;
        if (callType == ERC7579Utils.CALLTYPE_SINGLE) {
            if (below && calls.length != 1) return false;
            (address target, uint256 value, bytes calldata data) = executions.decodeSingle();
            if (!_execution(v, sp, target, value, data, calls, 0)) return false;
        } else if (callType == ERC7579Utils.CALLTYPE_BATCH) {
            Execution[] calldata batch = executions.decodeBatch();
            if (below && (batch.length == 0 || calls.length != batch.length)) return false;
            for (uint256 i; i < batch.length; ++i) {
                Execution calldata x = batch[i];
                if (!_execution(v, sp, x.target, x.value, x.callData, calls, i)) return false;
            }
        } else {
            return false;
        }
        return
            sp.native == 0 || _charge(v, _counter(sp.account, sp.keyHash, sp.rulesHash, NATIVE_TOKEN), sp.native, sp.at);
    }

    /// One execution, never refused by `_targetScope`. Below quorum, an outside call proved by `calls[i]`
    /// under the session's scope, its token spend charged and its value added to `sp.native`.
    /// @dev `scopeRoot == 0` proves no leaf. A value past uint128 fits no allowance; refusing it keeps
    ///      the operation's sum from overflowing.
    function _execution(
        Verified memory v,
        Spend memory sp,
        address target,
        uint256 value,
        bytes calldata data,
        IIdentityValidator.CallProof[] memory calls,
        uint256 i
    ) private returns (bool) {
        Scope scope = _targetScope(sp, target, data);
        if (scope == Scope.Refused) return false;
        if (!sp.below) return true;
        IIdentityValidator.CallProof memory proof = calls[i];
        bytes4 selector = _selector(data);
        if (
            scope == Scope.Admin || value > proof.maxValue || value > type(uint128).max
                || !MerkleProof.verify(proof.proof, sp.scopeRoot, _leaf(abi.encode(target, selector, proof.maxValue)))
        ) return false;
        sp.native += value;
        return _chargeToken(v, _counter(sp.account, sp.keyHash, sp.rulesHash, target), data, selector, sp.at);
    }

    /// Refuses a token call the allowances forbid, and charges a `transfer` or `approve` amount.
    /// @dev A token with an allowance takes only `transfer` and `approve`, which only such a token takes.
    function _chargeToken(Verified memory v, Counter storage c, bytes calldata data, bytes4 selector, uint48 at)
        private
        returns (bool)
    {
        bool spends = selector == IERC20.transfer.selector || selector == IERC20.approve.selector;
        if (selector == IERC20.transferFrom.selector || spends != c.listed) return false;
        return !spends || (data.length >= 68 && _charge(v, c, uint256(bytes32(data[36:68])), at));
    }

    /// Charges `amount` to `c` in the period of `at`, and narrows the window to that period.
    /// @dev `at == 0` is refused: the period 1 starting at 0 would end at 0, an unbounded window.
    function _charge(Verified memory v, Counter storage c, uint256 amount, uint48 at) private returns (bool) {
        if (at == 0) return false;
        uint48 period = c.period;
        uint48 start = c.periodStart;
        uint128 spent = c.spent;
        if (period != 0) {
            uint48 current = at - at % period;
            // Past periods are closed; window bounds stay below bit 47, a block-number flag to EntryPoint v0.9.
            if (current < start || uint256(current) + period > 1 << 47) return false;
            _narrow(v, current == 0 ? 0 : current - 1, current + period - 1);
            if (current != start) (start, spent) = (current, 0);
        }
        if (amount > c.amount - spent) return false;
        // forge-lint: disable-next-line(unsafe-typecast)
        (c.periodStart, c.spent) = (start, spent + uint128(amount));
        return true;
    }

    /// What the EntryPoint may take from the account for the operation's gas: its limits at its maximum fee.
    function _maxGasCost(PackedUserOperation calldata userOp) private pure returns (uint256) {
        return
            (userOp.verificationGasLimit() + userOp.callGasLimit() + userOp.preVerificationGas) * userOp.maxFeePerGas();
    }

    /// A call to the account, the validator (`address(this)` under DELEGATECALL) or the registry is an
    /// admin operation. Any other target is outside. The validator's `onInstall`/`onUninstall` called
    /// directly is refused.
    function _targetScope(Spend memory sp, address target, bytes calldata data) private view returns (Scope) {
        if (target == address(this)) {
            bytes4 selector = _selector(data);
            bool module =
                selector == IERC7579Module.onInstall.selector || selector == IERC7579Module.onUninstall.selector;
            return module ? Scope.Refused : Scope.Admin;
        }
        // The account executes a call to address(0) on itself.
        if (target == sp.account || target == address(0) || target == sp.registry) return Scope.Admin;
        return Scope.Call;
    }

    /// The mode of `execute(bytes32 mode, bytes executionCalldata)`, and `executionCalldata` as the account's
    /// ABI decoder reads it.
    function _executions(bytes calldata callData) private pure returns (bytes32 mode, bytes calldata) {
        bytes calldata args = callData[4:];
        return (bytes32(args[:32]), bytesAt(args, 32));
    }
}

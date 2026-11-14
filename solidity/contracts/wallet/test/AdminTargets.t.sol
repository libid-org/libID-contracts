// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {
    Execution,
    IERC7579AccountConfig,
    IERC7579Execution
} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/IERC4337.sol";

import {IIdentityValidator} from "../IIdentityValidator.sol";
import {CallTarget, WalletTestBase} from "./WalletTestBase.sol";

/// @notice Below quorum, a call to the account, address(0) or the registry is an admin operation, even
///         with a scope leaf for it; the execution is read where the account's decoder reads it.
contract AdminTargetsTest is WalletTestBase {
    struct Leaf {
        address target;
        bytes4 selector;
    }

    address internal w;
    Leaf[] internal leaves;
    bytes internal toWallet = abi.encodeCall(IERC7579AccountConfig.supportsModule, (2));

    function setUp() public override {
        super.setUp();
        w = _claim();
        leaves.push(Leaf(address(0), IERC7579Execution.execute.selector));
        leaves.push(Leaf(address(registry), bytes4(0)));
        leaves.push(Leaf(w, IERC7579AccountConfig.supportsModule.selector));
        leaves.push(Leaf(address(target), CallTarget.hit.selector));
        leaves.push(Leaf(address(target), bytes4(0)));
        leaves.push(Leaf(address(target), IERC7579Execution.execute.selector));
        bytes32 root;
        (root,) = _tree(_leaves(), 0);
        IIdentityValidator.Policy memory p = _hitOnly();
        p.rules.scopeRoot = root;
        vm.prank(w);
        validator.addSession(_identity(X, ALICE), _key(APP_PK), p);
    }

    function _leaves() internal view returns (bytes32[] memory l) {
        l = new bytes32[](leaves.length);
        for (uint256 i; i < l.length; ++i) {
            l[i] = _leaf(leaves[i].target, leaves[i].selector, 0);
        }
    }

    /// The app session's operation of `x`, each execution with its leaf's proof.
    function _opOf(bytes memory callData, Execution[] memory x) internal view returns (PackedUserOperation memory) {
        IIdentityValidator.CallProof[] memory calls = new IIdentityValidator.CallProof[](x.length);
        for (uint256 i; i < x.length; ++i) {
            // forge-lint: disable-next-line(unsafe-typecast)
            bytes4 selector = x[i].callData.length < 4 ? bytes4(0) : bytes4(x[i].callData);
            for (uint256 j; j < leaves.length; ++j) {
                if (leaves[j].target == x[i].target && leaves[j].selector == selector) {
                    (, calls[i].proof) = _tree(_leaves(), j);
                }
            }
        }
        return _signedWith(_op(w, 0, callData), _pks(APP_PK), calls);
    }

    function _single(address to, bytes memory data) internal view returns (PackedUserOperation memory) {
        Execution[] memory x = new Execution[](1);
        x[0] = Execution({target: to, value: 0, callData: data});
        return _opOf(_exec(to, data), x);
    }

    function _batch(Execution[] memory x) internal view returns (PackedUserOperation memory) {
        return _opOf(abi.encodeCall(IERC7579Execution.execute, (MODE_BATCH, abi.encode(x))), x);
    }

    function test_addressZeroIsAdmin() public {
        _refusedFor(_single(address(0), _hit()), _single(address(target), _hit()), "address(0)");
    }

    function test_theRegistryIsAdmin() public {
        _refusedFor(_single(address(registry), ""), _single(address(target), ""), "the registry");
    }

    /// A batch takes its widest call.
    function test_theAccountIsAdmin() public {
        Execution[] memory x = new Execution[](2);
        x[0] = Execution({target: w, value: 0, callData: toWallet});
        x[1] = Execution({target: address(target), value: 0, callData: ""});
        Execution[] memory control = new Execution[](2);
        control[0] = Execution({target: address(target), value: 0, callData: abi.encodeCall(CallTarget.hit, ())});
        control[1] = x[1];
        _refusedFor(_batch(x), _batch(control), "the account in a batch");
    }

    /// A decoy outside call where a canonical encoding puts the execution; the real one, to the account,
    /// where the offset points.
    function test_theExecutionIsReadAtItsOffset() public {
        bytes memory decoy = abi.encodePacked(address(target), uint256(0), abi.encodeCall(CallTarget.hit, ()));
        bytes memory real = abi.encodePacked(w, uint256(0), toWallet);
        bytes memory callData = abi.encodePacked(
            IERC7579Execution.execute.selector,
            MODE_SINGLE,
            uint256(0xa0),
            decoy.length,
            decoy,
            bytes8(0),
            real.length,
            real
        );
        Execution[] memory x = new Execution[](1);
        x[0] = Execution({target: address(target), value: 0, callData: abi.encodeCall(CallTarget.hit, ())});
        _refusedFor(_opOf(callData, x), _single(address(target), abi.encodeCall(CallTarget.hit, ())), "a decoy");
    }
}

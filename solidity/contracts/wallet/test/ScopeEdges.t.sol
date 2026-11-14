// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/IERC4337.sol";
import {IERC721} from "@openzeppelin/contracts/token/ERC721/IERC721.sol";

import {NATIVE_TOKEN} from "../../NativeToken.sol";
import {IIdentityValidator} from "../IIdentityValidator.sol";
import {CallTarget, IUserOpHash, WalletTestBase} from "./WalletTestBase.sol";

/// @notice What a scope leaf lets one session do below quorum, at the edges the spec states.
contract ScopeEdgesTest is WalletTestBase {
    address internal w;
    address internal nft = makeAddr("nft");
    address internal payee = makeAddr("payee");
    bytes4[6] internal selectors = [
        bytes4(0x42842e0e), // safeTransferFrom(address,address,uint256)
        bytes4(0xb88d4fde), // safeTransferFrom(address,address,uint256,bytes)
        IERC721.setApprovalForAll.selector,
        IERC721.approve.selector,
        IERC721.transferFrom.selector,
        CallTarget.hit.selector
    ];

    function setUp() public override {
        super.setUp();
        w = _claim();
        IIdentityValidator.Policy memory p = _hitOnly();
        p.rules.scopeRoot = _root();
        p.rules.paymastersRoot = _paymasterLeaf(makeAddr("paymaster"));
        vm.prank(w);
        validator.addSession(_identity(X, ALICE), _key(APP_PK), p);
    }

    /// Each selector on `nft`, `hit()` on the target, and selector 0 on `payee`.
    function _leaves() internal view returns (bytes32[] memory l) {
        l = new bytes32[](selectors.length + 1);
        for (uint256 i; i < selectors.length - 1; ++i) {
            l[i] = _leaf(nft, selectors[i], 0);
        }
        l[selectors.length - 1] = _hitScope();
        l[selectors.length] = _leaf(payee, bytes4(0), 0);
    }

    function _root() internal view returns (bytes32 root) {
        (root,) = _tree(_leaves(), 0);
    }

    /// The app session's operation calling `to` with `data`, proved by leaf `index`, signed at `at`.
    function _opAt(address to, bytes memory data, uint256 index, uint48 at)
        internal
        view
        returns (PackedUserOperation memory op)
    {
        IIdentityValidator.CallProof[] memory calls = new IIdentityValidator.CallProof[](1);
        (, calls[0].proof) = _tree(_leaves(), index);
        op = _op(w, 0, _exec(to, data));
        op.signature = _auth(
            _pks(APP_PK), _belowQuorum(IUserOpHash(EP).getUserOpHash(op), at, _key(APP_PK)), at, calls, new bytes32[](0)
        );
    }

    function _opOn(address to, bytes memory data, uint256 index) internal view returns (PackedUserOperation memory) {
        return _opAt(to, data, index, uint48(_now()));
    }

    /// A target with no allowance takes any selector in scope but a spending one: ERC-721 `safeTransferFrom`
    /// and `setApprovalForAll` pass uncharged; its `approve` and `transferFrom` share ERC-20's selectors.
    function test_erc721TransfersPassUncharged() public {
        bytes[5] memory data = [
            abi.encodeWithSelector(selectors[0], w, payee, 1),
            abi.encodeWithSelector(selectors[1], w, payee, 1, ""),
            abi.encodeCall(IERC721.setApprovalForAll, (payee, true)),
            abi.encodeCall(IERC721.approve, (payee, 1)),
            abi.encodeCall(IERC721.transferFrom, (w, payee, 1))
        ];
        for (uint256 i; i < 3; ++i) {
            assertEq(_answer(_opOn(nft, data[i], i)), 0, vm.toString(i));
        }
        assertEq(_answer(_opOn(nft, data[3], 3)), 1, "approve");
        assertEq(_answer(_opOn(nft, data[4], 4)), 1, "transferFrom");
    }

    /// The selector-0 leaf is the fallback and plain-send leaf: it matches empty calldata, calldata of
    /// one to three bytes, and calldata starting with four zero bytes.
    function test_selectorZeroLeafMatches() public {
        uint256 leaf = selectors.length;
        bytes[6] memory data = [bytes(""), hex"ab", hex"abcd", hex"abcdef", hex"00000000", hex"00000000ffff"];
        for (uint256 i; i < data.length; ++i) {
            assertEq(_answer(_opOn(payee, data[i], leaf)), 0, vm.toString(i));
        }
        assertEq(_answer(_opOn(payee, hex"00000001", leaf)), 1, "a nonzero selector");
    }

    /// `at == 0` is refused only when something is charged: here the gas no listed paymaster pays.
    function test_atZeroIsRefusedOnlyWhenCharging() public {
        uint256 hit = selectors.length - 1;
        PackedUserOperation memory op = _opAt(address(target), abi.encodeCall(CallTarget.hit, ()), hit, 0);
        assertEq(_answer(op), 1, "gas charged at 0");
        op.paymasterAndData = abi.encodePacked(makeAddr("paymaster"), uint128(100_000), uint128(0));
        op.signature = _auth(
            _pks(APP_PK),
            _belowQuorum(IUserOpHash(EP).getUserOpHash(op), 0, _key(APP_PK)),
            0,
            abi.decode(op.signature, (IIdentityValidator.Authorization)).calls,
            new bytes32[](0)
        );
        assertEq(_answer(op), 0, "nothing charged at 0");
    }

    /// Under a lifetime allowance, `at` at or past 2^47 still charges: its bound applies only to a nonzero period.
    function test_aLifetimeChargeTakesAnyNonzeroAt() public {
        uint256 hit = selectors.length - 1;
        PackedUserOperation memory op = _opAt(address(target), abi.encodeCall(CallTarget.hit, ()), hit, uint48(1 << 47));
        assertEq(_answer(op), 0, "at 2^47");
        assertGt(validator.allowanceOf(w, _key(APP_PK), NATIVE_TOKEN).spent, 0, "nothing charged");
    }
}

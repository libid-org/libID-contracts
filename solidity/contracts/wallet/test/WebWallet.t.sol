// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IEntryPoint, PackedUserOperation} from "@openzeppelin/contracts/interfaces/IERC4337.sol";
import {
    Execution,
    IERC7579AccountConfig,
    IERC7579Execution,
    IERC7579ModuleConfig
} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {ERC7579Utils} from "@openzeppelin/contracts/account/utils/draft-ERC7579Utils.sol";

import {IIdentityValidator} from "../IIdentityValidator.sol";
import {IWebWallet} from "../IWebWallet.sol";
import {CallTarget, SlotMarker, WalletTestBase} from "./WalletTestBase.sol";

/// @notice The account through a local EntryPoint v0.9 `handleOps`.
contract WebWalletTest is WalletTestBase {
    uint192 internal key;

    function setUp() public override {
        super.setUp();
        key = uint192(uint160(address(validator))) << 32;
    }

    /// R12: the operation is signed for the predicted address before the wallet exists.
    function test_claim_createLinkThenNonceZeroOperation() public {
        address w = factory.walletAddress(X, ALICE);
        PackedUserOperation memory op = _signed(_op(w, 0, _hit()), _pks(ALICE_PK));

        _claim();
        _handle(op);

        assertEq(target.calls(), 1, "the call did not run");
        assertEq(target.last(), w, "not called by the wallet");
        assertEq(uint64(IEntryPoint(EP).getNonce(w, key)), 1, "nonce not used");
    }

    /// R9: a non-admin session may only `execute` single or batch calls to outside targets.
    /// The account, the validator and the registry are not outside; the ClaimExecutor is.
    function test_nonAdminRefusedInValidation() public {
        address w = _claim();
        vm.prank(w);
        validator.addSession(_identity(X, ALICE), _key(APP_PK), _app());
        SlotMarker marker = new SlotMarker();

        Execution[] memory mixed = new Execution[](2);
        mixed[0] = Execution({target: address(target), value: 0, callData: abi.encodeCall(CallTarget.hit, ())});
        mixed[1] = Execution({target: w, value: 0, callData: abi.encodeCall(IERC7579AccountConfig.supportsModule, (2))});

        bytes[6] memory calls = [
            abi.encodeCall(IERC7579ModuleConfig.installModule, (2, address(0xBEEF), "")),
            abi.encodeCall(
                IERC7579Execution.execute,
                (MODE_DELEGATE, abi.encodePacked(address(marker), abi.encodeCall(SlotMarker.mark, ())))
            ),
            _exec(w, abi.encodeCall(IERC7579AccountConfig.supportsModule, (2))),
            _exec(address(validator), abi.encodeCall(IIdentityValidator.setRecoveryDelay, (72 hours))),
            abi.encodeCall(IERC7579Execution.execute, (MODE_BATCH, abi.encode(mixed))),
            abi.encodeCall(IWebWallet.upgradeToAndCall, (address(marker), ""))
        ];
        string[6] memory why = [
            "installModule",
            "delegatecall",
            "call to the wallet",
            "call to the validator",
            "batch to the wallet",
            "upgrade"
        ];
        for (uint256 i; i < calls.length; ++i) {
            _refused(_signed(_op(w, 0, calls[i]), _pks(APP_PK)), why[i]);
        }

        Execution[] memory out = new Execution[](2);
        out[0] = mixed[0];
        out[1] = mixed[0];
        _handle(_signed(_op(w, 0, _hit()), _pks(APP_PK)));
        _handle(
            _signed(_op(w, 1, abi.encodeCall(IERC7579Execution.execute, (MODE_BATCH, abi.encode(out)))), _pks(APP_PK))
        );
        assertEq(target.calls(), 3, "in-scope calls");
    }

    function test_pendingAndExpiredSessionsRefused() public {
        address w = _claim();
        vm.prank(w);
        validator.addSession(
            _identity(X, ALICE),
            _key(APP_PK),
            IIdentityValidator.Policy({validAfter: 0, validUntil: uint48(_now() + 1 hours), admin: false})
        );
        _addByProof(relayer, X, ALICE, w, _key(ALICE2_PK), _admin());
        bytes memory notDue = abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA22 expired or not due");

        PackedUserOperation memory pending = _signed(_op(w, 0, _hit()), _pks(ALICE2_PK));
        vm.deal(w, 1 ether);
        vm.prank(bundler, bundler);
        vm.expectRevert(notDue);
        IEntryPoint(EP).handleOps(_ops(pending), payable(bundler));

        vm.warp(_now() + 2 hours);
        PackedUserOperation memory expired = _signed(_op(w, 0, _hit()), _pks(APP_PK));
        vm.prank(bundler, bundler);
        vm.expectRevert(notDue);
        IEntryPoint(EP).handleOps(_ops(expired), payable(bundler));

        vm.warp(_now() + 48 hours);
        _handle(pending);
        assertEq(target.calls(), 1, "the matured session did not run");
    }

    function test_validUntilZeroNeverExpires() public {
        address w = _claim();
        vm.warp(_now() + 100 * 365 days);
        _handle(_signed(_op(w, 0, _hit()), _pks(ALICE_PK)));
        assertEq(target.calls(), 1);
    }

    /// D16: an admin has no path to code or modules except the root timelock.
    function test_adminCannotBypassTheTimelock() public {
        address w = _claim();
        SlotMarker marker = new SlotMarker();
        address impl2 = _walletImpl();
        address implBefore = address(uint160(uint256(vm.load(w, IMPL_SLOT))));
        bytes[5] memory calls = [
            abi.encodeCall(
                IERC7579Execution.execute,
                (MODE_DELEGATE, abi.encodePacked(address(marker), abi.encodeCall(SlotMarker.mark, ())))
            ),
            abi.encodeCall(IWebWallet.upgradeToAndCall, (impl2, "")),
            _exec(w, abi.encodeCall(IWebWallet.upgradeToAndCall, (impl2, ""))),
            _exec(w, abi.encodeCall(IERC7579ModuleConfig.uninstallModule, (1, address(validator), ""))),
            _exec(w, abi.encodeCall(IERC7579ModuleConfig.uninstallModule, (2, address(executor), "")))
        ];
        for (uint256 i; i < calls.length; ++i) {
            PackedUserOperation memory op =
                _signed(_op(w, uint64(IEntryPoint(EP).getNonce(w, key)), calls[i]), _pks(ALICE_PK));
            vm.deal(w, 1 ether);
            vm.prank(bundler, bundler);
            try IEntryPoint(EP).handleOps(_ops(op), payable(bundler)) {} catch {}
        }
        assertEq(vm.load(w, bytes32(uint256(0x1234))), bytes32(0), "delegatecall ran");
        assertEq(address(uint160(uint256(vm.load(w, IMPL_SLOT)))), implBefore, "upgraded without timelock");
        assertTrue(IWebWallet(w).isModuleInstalled(1, address(validator), ""), "validator removed");
        assertTrue(IWebWallet(w).isModuleInstalled(2, address(executor), ""), "executor removed");
    }

    function test_delegatecallIsUnsupported() public {
        address w = _claim();
        assertTrue(IWebWallet(w).supportsExecutionMode(MODE_SINGLE), "single");
        assertTrue(IWebWallet(w).supportsExecutionMode(MODE_BATCH), "batch");
        assertFalse(IWebWallet(w).supportsExecutionMode(MODE_DELEGATE), "delegatecall");
        vm.prank(EP);
        vm.expectRevert(abi.encodeWithSelector(ERC7579Utils.ERC7579UnsupportedCallType.selector, bytes1(0xff)));
        IERC7579Execution(w).execute(MODE_DELEGATE, abi.encodePacked(address(target)));
    }

    /// Uninstalling the only validator would leave the wallet with no way back, so even a root
    /// operation is refused.
    function test_theValidatorCannotBeUninstalled() public {
        address w = _claim();
        _rootReverts(
            w,
            w,
            abi.encodeCall(IERC7579ModuleConfig.uninstallModule, (1, address(validator), "")),
            abi.encodeWithSelector(IWebWallet.ModuleNotAllowed.selector, address(validator))
        );
        assertTrue(IWebWallet(w).isModuleInstalled(1, address(validator), ""), "uninstalled");
    }
}

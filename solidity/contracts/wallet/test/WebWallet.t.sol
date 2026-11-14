// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";
import {IEntryPoint, PackedUserOperation} from "@openzeppelin/contracts/interfaces/IERC4337.sol";
import {
    Execution,
    IERC7579AccountConfig,
    IERC7579Execution,
    IERC7579ModuleConfig
} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {ERC7579Utils} from "@openzeppelin/contracts/account/utils/draft-ERC7579Utils.sol";
import {IERC721Receiver} from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {IERC1155Receiver} from "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";
import {ERC1155} from "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

import {IIdentityValidator} from "../IIdentityValidator.sol";
import {AUTHORIZED_MODE, IWebWallet} from "../IWebWallet.sol";
import {CallTarget, SlotMarker, WalletTestBase} from "./WalletTestBase.sol";

contract MockERC721 is ERC721("Mock", "M") {
    function mint(address to, uint256 id) external {
        _mint(to, id);
    }
}

contract MockERC1155 is ERC1155("") {
    function mint(address to, uint256 id, uint256 amount) external {
        _mint(to, id, amount, "");
    }
}

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
    /// The account, the validator and the registry are not outside.
    function test_nonAdminRefusedInValidation() public {
        address w = _claim();
        vm.prank(w);
        validator.addSession(_identity(X, ALICE), _key(APP_PK), _hitOnly());
        vm.warp(_now() + 1);
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
        bytes memory batch = abi.encodeCall(IERC7579Execution.execute, (MODE_BATCH, abi.encode(out)));
        _handle(_signedWith(_op(w, 0, _hit()), _pks(APP_PK), _hitProofs(1)));
        _handle(_signedWith(_op(w, 1, batch), _pks(APP_PK), _hitProofs(2)));
        assertEq(target.calls(), 3, "in-scope calls");
    }

    function test_pendingAndExpiredSessionsRefused() public {
        address w = _claim();
        IIdentityValidator.Policy memory hourly = _hitOnly();
        hourly.validUntil = uint48(_now() + 1 hours);
        vm.prank(w);
        validator.addSession(_identity(X, ALICE), _key(APP_PK), hourly);
        _addByProof(relayer, X, ALICE, w, _key(ALICE2_PK), _admin());
        bytes memory notDue = abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA22 expired or not due");

        PackedUserOperation memory pending = _signed(_op(w, 0, _hit()), _pks(ALICE2_PK));
        vm.deal(w, 1 ether);
        vm.prank(bundler, bundler);
        vm.expectRevert(notDue);
        IEntryPoint(EP).handleOps(_ops(pending), payable(bundler));

        vm.warp(_now() + 2 hours);
        PackedUserOperation memory expired = _signedWith(_op(w, 0, _hit()), _pks(APP_PK), _hitProofs(1));
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
        // Refused in validation.
        bytes[2] memory refused = [
            abi.encodeCall(
                IERC7579Execution.execute,
                (MODE_DELEGATE, abi.encodePacked(address(marker), abi.encodeCall(SlotMarker.mark, ())))
            ),
            abi.encodeCall(IWebWallet.upgradeToAndCall, (impl2, ""))
        ];
        for (uint256 i; i < refused.length; ++i) {
            _refused(_signed(_op(w, 0, refused[i]), _pks(ALICE_PK)), vm.toString(i));
        }
        // Admin calls to the wallet itself: validated, then reverted in execution.
        bytes[3] memory reverted = [
            _exec(w, abi.encodeCall(IWebWallet.upgradeToAndCall, (impl2, ""))),
            _exec(w, abi.encodeCall(IERC7579ModuleConfig.uninstallModule, (1, address(validator), ""))),
            _exec(w, abi.encodeCall(IERC7579ModuleConfig.installModule, (1, address(target), "")))
        ];
        for (uint256 i; i < reverted.length; ++i) {
            vm.recordLogs();
            _handle(_signed(_op(w, uint64(i), reverted[i]), _pks(ALICE_PK)));
            assertFalse(_opSucceeded(), vm.toString(i));
        }
        assertEq(vm.load(w, bytes32(uint256(0x1234))), bytes32(0), "delegatecall ran");
        assertEq(address(uint160(uint256(vm.load(w, IMPL_SLOT)))), implBefore, "upgraded without timelock");
        assertTrue(IWebWallet(w).isModuleInstalled(1, address(validator), ""), "validator removed");
        assertFalse(IWebWallet(w).isModuleInstalled(1, address(target), ""), "module installed");
    }

    /// The `success` of the last recorded `UserOperationEvent`.
    function _opSucceeded() internal returns (bool success) {
        Vm.Log[] memory logs = vm.getRecordedLogs();
        bytes32 topic = keccak256("UserOperationEvent(bytes32,address,address,uint256,bool,uint256,uint256)");
        for (uint256 i = logs.length; i > 0; --i) {
            if (logs[i - 1].topics[0] == topic) {
                (, success,,) = abi.decode(logs[i - 1].data, (uint256, bool, uint256, uint256));
                return success;
            }
        }
        fail("no UserOperationEvent");
    }

    function test_delegatecallIsUnsupported() public {
        address w = _claim();
        assertTrue(IWebWallet(w).supportsExecutionMode(MODE_SINGLE), "single");
        assertTrue(IWebWallet(w).supportsExecutionMode(MODE_BATCH), "batch");
        assertFalse(IWebWallet(w).supportsExecutionMode(MODE_DELEGATE), "delegatecall");
        assertFalse(IWebWallet(w).supportsExecutionMode(MODE_BATCH | bytes32(uint256(0xdeadbeef) << 176)), "a selector");
        assertTrue(IWebWallet(w).supportsExecutionMode(AUTHORIZED_MODE), "AUTHORIZED");
        assertFalse(IWebWallet(w).supportsExecutionMode(AUTHORIZED_MODE | bytes32(uint256(1))), "AUTHORIZED, a payload");
        assertFalse(
            IWebWallet(w).supportsExecutionMode(AUTHORIZED_MODE ^ bytes32(uint256(0x01) << 248)), "AUTHORIZED, single"
        );
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

    function test_acceptsSafeTokenTransfers() public {
        address w = _claim();
        MockERC721 nft = new MockERC721();
        nft.mint(mallory, 1);
        vm.prank(mallory);
        nft.safeTransferFrom(mallory, w, 1);
        assertEq(nft.ownerOf(1), w, "ERC-721 refused");

        MockERC1155 multi = new MockERC1155();
        multi.mint(mallory, 1, 5);
        multi.mint(mallory, 2, 7);
        uint256[] memory ids = new uint256[](2);
        uint256[] memory amounts = new uint256[](2);
        (ids[0], ids[1], amounts[0], amounts[1]) = (1, 2, 2, 7);
        vm.startPrank(mallory);
        multi.safeTransferFrom(mallory, w, 1, 3, "");
        multi.safeBatchTransferFrom(mallory, w, ids, amounts, "");
        vm.stopPrank();
        assertEq(multi.balanceOf(w, 1), 5, "ERC-1155 single or batch refused");
        assertEq(multi.balanceOf(w, 2), 7, "ERC-1155 batch refused");

        IERC165 wallet = IERC165(w);
        assertTrue(wallet.supportsInterface(type(IERC721Receiver).interfaceId), "ERC-721 receiver");
        assertTrue(wallet.supportsInterface(type(IERC1155Receiver).interfaceId), "ERC-1155 receiver");
        assertTrue(wallet.supportsInterface(type(IERC165).interfaceId), "ERC-165");
        assertFalse(wallet.supportsInterface(0xffffffff), "ERC-165 invalid id");
    }
}

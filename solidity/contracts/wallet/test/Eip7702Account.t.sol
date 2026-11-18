// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Account as OzAccount} from "@openzeppelin/contracts/account/Account.sol";
import {ERC7579Utils} from "@openzeppelin/contracts/account/utils/draft-ERC7579Utils.sol";
import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/IERC4337.sol";
import {
    Execution,
    IERC7579ModuleConfig,
    MODULE_TYPE_EXECUTOR,
    MODULE_TYPE_FALLBACK,
    MODULE_TYPE_VALIDATOR
} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import {
    AccountERC7579Upgradeable
} from "@openzeppelin/contracts-upgradeable/account/extensions/draft-AccountERC7579Upgradeable.sol";

import {IIdentityValidator} from "../IIdentityValidator.sol";
import {IWalletRegistry} from "../IWalletRegistry.sol";
import {IWebWallet} from "../IWebWallet.sol";
import {ExecuteBase} from "./DirectExecute.t.sol";
import {CallTarget, SlotMarker} from "./WalletTestBase.sol";

/// An earlier OpenZeppelin-based delegate that installs whatever it is given.
contract LeftoverDelegate is AccountERC7579Upgradeable {
    function rig(address module) external {
        _installModule(MODULE_TYPE_VALIDATOR, module, "");
        _installModule(MODULE_TYPE_EXECUTOR, module, "");
        _installModule(MODULE_TYPE_FALLBACK, module, abi.encodePacked(LeftoverModule.hello.selector));
    }
}

/// An executor, fallback handler and validator at once.
contract LeftoverModule {
    function isModuleType(uint256) external pure returns (bool) {
        return true;
    }

    function onInstall(bytes calldata) external {}

    function hello() external pure returns (bool) {
        return true;
    }
}

/// @notice An EOA delegated to WalletForwarder with EIP-7702: its key links an identity and adds the first
///         session in one self-batch; that session then acts as on a factory wallet.
/// forge-config: default.evm_version = "prague"
contract Eip7702AccountTest is ExecuteBase {
    uint256 internal constant KEY_PK = 0x7702;

    address internal a;
    address internal fwd;

    function setUp() public override {
        super.setUp();
        a = vm.addr(KEY_PK);
        fwd = deployCode("WalletForwarder.sol:WalletForwarder", abi.encode(address(factory)));
    }

    /// The key's authorization for this chain, sent by the relayer with an empty call.
    function _delegateTo(address code) internal {
        vm.signAndAttachDelegation(code, KEY_PK);
        vm.prank(relayer);
        (bool ok,) = a.call("");
        ok;
        assertEq(a.code, abi.encodePacked(hex"ef0100", code), "not delegated");
    }

    /// The key's own transaction: link Alice's X identity with a link-only proof, then add her admin session.
    function _setUp() internal {
        _delegateTo(fwd);
        Execution[] memory x = new Execution[](2);
        bytes memory payload = _payload(X, ALICE, LINK, _txData(a, "", 0));
        x[0] = _x(address(registry), 0, abi.encodeCall(IWalletRegistry.linkIdentity, (X, V1, payload, "", _app())));
        x[1] = _x(
            address(validator),
            0,
            abi.encodeCall(IIdentityValidator.addSession, (_identity(X, ALICE), _key(ALICE_PK), _admin()))
        );
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(OzAccount.AccountUnauthorized.selector, relayer));
        IWebWallet(a).execute(MODE_BATCH, abi.encode(x));

        vm.prank(a, a);
        IWebWallet(a).execute(MODE_BATCH, abi.encode(x));
        vm.deal(a, 1 ether);
        vm.warp(_now() + 1);
    }

    function test_theKeysSessionActsByBatchAndByUserOperation() public {
        _setUp();
        assertTrue(validator.isLinked(a, _identity(X, ALICE)), "not linked");
        assertTrue(validator.hadSession(a), "no session");

        bytes memory hit = _one(_hitX());
        _runs(a, hit, _aliceFor(a, hit, _nonce(a, address(validator))));
        _handle(_signed(_op(a, 1, _hit()), _pks(ALICE_PK)));
        assertEq(target.calls(), 2, "the operation did not run");
        assertEq(target.last(), a, "not from the account");
    }

    /// The account has no genesis identity: neither first-session exception opens it to a stranger.
    function test_aStrangerCannotAddASession() public {
        _delegateTo(fwd);
        (bytes32 platformId, bytes32 idNode, uint256 salt) = validator.genesisIdentity(a);
        assertEq(abi.encode(platformId, idNode, salt), abi.encode(bytes32(0), bytes32(0), 0), "a genesis");

        bytes memory refused = abi.encodeWithSelector(IIdentityValidator.FirstSessionRefused.selector, a);
        _addByLoginReverts(
            MALLORY, abi.encodeWithSelector(IIdentityValidator.NotLinked.selector, a, _identity(X, MALLORY))
        );
        bytes memory linkPayload = _payload(X, MALLORY, LINK, _txData(a, _key(MALLORY_PK), _ph(_admin())));
        vm.prank(mallory);
        vm.expectRevert(abi.encodeWithSelector(IWalletRegistry.NotWallet.selector, a, mallory));
        registry.linkIdentity(X, V1, linkPayload, "", _admin());
        // Even the key cannot add a session through a link: only `addSession` adds the first.
        vm.prank(a, a);
        vm.expectRevert(refused);
        registry.linkIdentity(X, V1, linkPayload, "", _admin());

        _link(a, X, ALICE, a, "", _app());
        _addByLoginReverts(ALICE, refused);
        vm.expectRevert(
            abi.encodeWithSelector(IIdentityValidator.NotFactoryWallet.selector, a, factory.walletAddress(X, ALICE, 0))
        );
        IWebWallet(a).initialize(_install(X, ALICE, _key(MALLORY_PK), _admin()));
        assertEq(validator.sessionOf(a, _key(MALLORY_PK)).identity, bytes32(0), "mallory has a session");
    }

    /// A stranger's direct batch that links her identity and adds her session runs as the account, but her
    /// session signs only from the next second: the end check refuses it.
    function test_aStrangersBatchCannotAddTheFirstSession() public {
        _delegateTo(fwd);
        Execution[] memory x = new Execution[](2);
        bytes memory payload = _payload(X, MALLORY, LINK, _txData(a, "", 0));
        x[0] = _x(address(registry), 0, abi.encodeCall(IWalletRegistry.linkIdentity, (X, V1, payload, "", _app())));
        x[1] = _x(
            address(validator),
            0,
            abi.encodeCall(IIdentityValidator.addSession, (_identity(X, MALLORY), _key(MALLORY_PK), _admin()))
        );
        bytes memory calls = abi.encode(x);
        _refuses(a, calls, _direct(a, address(validator), _pks(MALLORY_PK), calls, false), OUTSIDE_WINDOW);
        assertFalse(validator.isLinked(a, _identity(X, MALLORY)), "linked");
        assertFalse(validator.hadSession(a), "a session");
    }

    function test_theKeySignsAsAnEoaAndSessionsAsBefore() public {
        _setUp();
        bytes32 h = keccak256("a message");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(KEY_PK, h);
        assertEq(IWebWallet(a).isValidSignature(h, abi.encodePacked(r, s, v)), bytes4(0x1626ba7e), "the key");
        (v, r, s) = vm.sign(MALLORY_PK, h);
        assertEq(IWebWallet(a).isValidSignature(h, abi.encodePacked(r, s, v)), bytes4(0xffffffff), "a stranger");
        assertTrue(_isValid1271(a, h, ALICE_PK, _wrapped(a, h)), "the session");
    }

    /// An earlier delegate's executor, fallback handler and validator have no effect.
    function test_leftoverModulesAreInert() public {
        LeftoverModule m = new LeftoverModule();
        _delegateTo(address(new LeftoverDelegate()));
        LeftoverDelegate(payable(a)).rig(address(m));
        assertTrue(LeftoverModule(a).hello(), "control: the fallback ran");
        _setUp();

        assertFalse(IWebWallet(a).isModuleInstalled(MODULE_TYPE_VALIDATOR, address(m), ""), "validator");
        assertFalse(IWebWallet(a).isModuleInstalled(MODULE_TYPE_EXECUTOR, address(m), ""), "executor");
        assertFalse(
            IWebWallet(a).isModuleInstalled(MODULE_TYPE_FALLBACK, address(m), abi.encodePacked(m.hello.selector)),
            "fallback"
        );
        assertTrue(IWebWallet(a).isModuleInstalled(MODULE_TYPE_VALIDATOR, address(validator), ""), "ours");

        vm.prank(address(m));
        vm.expectRevert(
            abi.encodeWithSelector(ERC7579Utils.ERC7579UninstalledModule.selector, MODULE_TYPE_EXECUTOR, address(m))
        );
        IWebWallet(a).executeFromExecutor(MODE_BATCH, _one(_hitX()));
        vm.expectRevert(
            abi.encodeWithSelector(AccountERC7579Upgradeable.ERC7579MissingFallbackHandler.selector, m.hello.selector)
        );
        LeftoverModule(a).hello();
        // OpenZeppelin's set still lets it call `migrate`, whose install only a factory wallet passes.
        bytes memory notFactory =
            abi.encodeWithSelector(IIdentityValidator.NotFactoryWallet.selector, a, factory.walletAddress(X, ALICE, 0));
        vm.prank(address(m));
        vm.expectRevert(notFactory);
        IWebWallet(a).migrate(_install(X, ALICE, _key(MALLORY_PK), _admin()));
        _refused(_opVia(address(m)), "a leftover validator");
    }

    /// Pointing away and back resumes the old sessions: no hook runs on either change.
    function test_reDelegatingBackResumesSessions() public {
        _setUp();
        _delegateTo(address(new SlotMarker()));
        SlotMarker(a).mark();
        _delegateTo(fwd);
        _handle(_signed(_op(a, 0, _hit()), _pks(ALICE_PK)));
        assertEq(target.last(), a, "the old session did not act");
    }

    function test_moduleChangesAndDelegatecallAreRefused() public {
        _setUp();
        vm.prank(a, a);
        vm.expectRevert(abi.encodeWithSelector(IWebWallet.NotValidator.selector, a));
        IWebWallet(a).installModule(MODULE_TYPE_EXECUTOR, address(target), "");
        vm.prank(a, a);
        vm.expectRevert(abi.encodeWithSelector(ERC7579Utils.ERC7579UnsupportedCallType.selector, bytes1(0xff)));
        IWebWallet(a).execute(MODE_DELEGATE, abi.encodePacked(address(target), abi.encodeCall(CallTarget.hit, ())));
        // Even a matured root operation cannot install the validator: its install is the factory's.
        bytes memory install = abi.encodeCall(
            IERC7579ModuleConfig.installModule, (MODULE_TYPE_VALIDATOR, address(validator), _install(X, ALICE))
        );
        _rootReverts(
            a,
            a,
            install,
            abi.encodeWithSelector(IIdentityValidator.NotFactoryWallet.selector, a, factory.walletAddress(X, ALICE, 0))
        );
    }

    /// Unsupported: delegated straight to WebWallet, the account has no ERC-1967 slot, so even the validator
    /// cannot upgrade it.
    function test_aDirectDelegationCannotBeUpgraded() public {
        _delegateTo(walletImpl);
        vm.prank(address(validator));
        vm.expectRevert(UUPSUpgradeable.UUPSUnauthorizedCallContext.selector);
        IWebWallet(a).upgradeToAndCall(walletImpl, "");
    }

    /// A login of `idNode` on X, naming Mallory's key for the account, reverts with `err`.
    function _addByLoginReverts(bytes32 idNode, bytes memory err) internal {
        bytes memory payload = _payload(X, idNode, ADD, _txData(a, _key(MALLORY_PK), _ph(_admin())));
        vm.prank(mallory);
        vm.expectRevert(err);
        registry.addSessionByLogin(X, V1, payload, "", _admin());
    }

    /// A UserOperation by Alice's session naming `module` in its nonce key.
    function _opVia(address module) internal view returns (PackedUserOperation memory op) {
        op = _op(a, 0, _hit());
        op.nonce = uint256(uint160(module)) << 96;
        return _signed(op, _pks(ALICE_PK));
    }
}

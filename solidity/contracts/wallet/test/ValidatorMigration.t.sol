// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/IERC4337.sol";
import {ERC7579Utils} from "@openzeppelin/contracts/account/utils/draft-ERC7579Utils.sol";
import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";

import {IIdentityValidator} from "../IIdentityValidator.sol";
import {IWalletRegistry} from "../IWalletRegistry.sol";
import {IWebWallet} from "../IWebWallet.sol";
import {WalletTestBase} from "./WalletTestBase.sol";

/// A root upgrade to a new validator carries the account's admin session in the install data.
contract ValidatorMigrationTest is WalletTestBase {
    IWalletRegistry internal registry2;
    IIdentityValidator internal v2;

    /// A second stack: registry, validator and wallet implementation.
    function _v2Impl() internal returns (address) {
        registry2 = _newRegistry(address(factory));
        v2 = IIdentityValidator(registry2.identityValidator());
        return deployCode("WebWallet.sol:WebWallet", abi.encode(address(v2)));
    }

    function _upgrade(bytes memory installData) internal returns (bytes memory) {
        address impl2 = _v2Impl();
        return abi.encodeCall(IWebWallet.upgradeToAndCall, (impl2, abi.encodeCall(IWebWallet.migrate, (installData))));
    }

    /// Alice's wallet moved to `v2`, carrying her admin session, which signs from the next second.
    function _migrated() internal returns (address w) {
        w = _claim();
        bytes memory upgrade = _upgrade(abi.encode(X, ALICE, _key(ALICE_PK), _admin()));
        _root(w, w, upgrade);
        vm.warp(_now() + 1);
        assertTrue(IWebWallet(w).isModuleInstalled(1, address(v2), ""), "v2 not installed");
    }

    /// The new validator installs only the factory's wallet of the genesis named: a migration cannot rename it.
    function test_aMigrationKeepsTheGenesis() public {
        address w = _claim();
        bytes memory renamed = _upgrade(abi.encode(X, MALLORY, _key(ALICE_PK), _admin()));
        bytes memory err =
            abi.encodeWithSelector(IIdentityValidator.NotFactoryWallet.selector, w, factory.walletAddress(X, MALLORY));
        _rootReverts(w, w, renamed, err);
        assertFalse(IWebWallet(w).isModuleInstalled(1, address(v2), ""), "migrated under another genesis");

        _root(w, w, _upgrade(abi.encode(X, ALICE, _key(ALICE_PK), _admin())));
        assertTrue(IWebWallet(w).isModuleInstalled(1, address(v2), ""), "the same genesis did not migrate");
        (bytes32 platformId, bytes32 idNode) = v2.genesisIdentity(w);
        assertEq(abi.encode(platformId, idNode), abi.encode(X, ALICE), "genesis");
    }

    function test_aValidatorMigrationKeepsStrangersOut() public {
        address w = _migrated();
        assertTrue(v2.hadSession(w), "the genesis rule is open again");

        // Mallory holds any proof of Alice's X identity, from any OAuth client, naming her own key.
        bytes memory payload = _payload(X, ALICE, LINK, _txData(w, _key(MALLORY_PK), _ph(_admin())));
        vm.prank(mallory);
        vm.expectRevert(abi.encodeWithSelector(IWalletRegistry.NotWallet.selector, w, mallory));
        registry2.linkIdentity(X, V1, payload, _admin());
        assertEq(v2.sessionOf(w, _key(MALLORY_PK)).identity, bytes32(0), "mallory has a session");
    }

    /// A UserOperation naming `validator_` in its nonce key, signed by `pk`.
    function _opVia(address w, address validator_, uint256 pk, bytes memory callData)
        internal
        view
        returns (PackedUserOperation memory op)
    {
        op = _op(w, 0, callData);
        op.nonce = uint256(uint160(validator_)) << 96;
        return _signed(op, _pks(pk));
    }

    function _signs(address w, address validator_, uint256 pk) internal view returns (bool) {
        bytes32 h = keccak256("a message");
        bytes memory sig = abi.encodePacked(validator_, _sigs(_pks(pk), _wrapped(w, h)));
        return IWebWallet(w).isValidSignature(h, sig) == bytes4(0x1626ba7e);
    }

    /// The replaced validator stays installed, but neither validates nor signs for the wallet.
    function test_theReplacedValidatorNoLongerValidates() public {
        address w = _claim();
        vm.prank(w);
        validator.addSession(_identity(X, ALICE), _key(APP_PK), _hitOnly());
        assertTrue(_signs(w, address(validator), ALICE_PK), "v1 could not sign before");

        _root(w, w, _upgrade(abi.encode(X, ALICE, _key(ALICE_PK), _admin())));
        vm.warp(_now() + 1);
        assertTrue(IWebWallet(w).isModuleInstalled(1, address(validator), ""), "v1 uninstalled");

        _refused(_opVia(w, address(validator), ALICE_PK, _hit()), "a v1 admin session");
        _refused(_signedWith(_op(w, 0, _hit()), _pks(APP_PK), _hitProofs(1)), "a v1 app session in its scope");
        assertFalse(_signs(w, address(validator), ALICE_PK), "a v1 session signed");

        assertTrue(_signs(w, address(v2), ALICE_PK), "the carried session could not sign");
        _handle(_opVia(w, address(v2), ALICE_PK, _hit()));
        assertEq(target.calls(), 1, "the carried session could not act");
    }

    function test_theCarriedSessionMustBeAdmin() public {
        address w = _claim();
        bytes memory upgrade = _upgrade(abi.encode(X, ALICE, _key(ALICE_PK), _app()));
        _rootReverts(w, w, upgrade, abi.encodeWithSelector(IIdentityValidator.InstallSessionNotAdmin.selector));
    }

    /// Found in review: a v2 app session queued an upgrade on the old validator, which stayed
    /// installed, and anyone executed it after the delay. The session's scope lists that call.
    function test_theOldValidatorCannotUpgradeAfterMigration() public {
        address w = _migrated();
        IIdentityValidator.Policy memory p = _hitOnly();
        p.rules.scopeRoot = _leaf(address(validator), IIdentityValidator.queueRoot.selector, 0);
        vm.prank(w);
        v2.addSession(_identity(X, ALICE), _key(APP_PK), p);
        vm.warp(_now() + 1);
        bytes memory up = abi.encodeCall(IWebWallet.upgradeToAndCall, (_walletImpl(), ""));
        PackedUserOperation memory op =
            _op(w, 0, _exec(address(validator), abi.encodeCall(IIdentityValidator.queueRoot, (w, up))));
        op.nonce = uint256(uint160(address(v2))) << 96;
        _handle(_signedWith(op, _pks(APP_PK), _hitProofs(1)));
        vm.warp(_now() + 48 hours);
        vm.expectRevert(abi.encodeWithSelector(IWebWallet.NotValidator.selector, address(validator)));
        validator.executeRoot(w, w, up);
    }

    function test_rootsQueuedBeforeTheMigrationCannotExecute() public {
        address w = _claim();
        bytes memory up = abi.encodeCall(IWebWallet.upgradeToAndCall, (_walletImpl(), ""));
        vm.prank(w);
        validator.queueRoot(w, up);
        _root(w, w, _upgrade(abi.encode(X, ALICE, _key(ALICE_PK), _admin())));
        vm.expectRevert(abi.encodeWithSelector(IWebWallet.NotValidator.selector, address(validator)));
        validator.executeRoot(w, w, up);
    }

    function test_migrateRunsOnlyInsideTheUpgrade() public {
        address w = _migrated();
        bytes memory data = abi.encode(X, ALICE, _key(MALLORY_PK), _admin());
        vm.prank(mallory);
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        IWebWallet(w).migrate(data);
        vm.prank(address(validator));
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        IWebWallet(w).migrate(data);

        // A wallet that never migrated: only an installed validator may call it.
        address fresh = factory.createWallet(GITHUB, BOB);
        vm.prank(mallory);
        vm.expectRevert(abi.encodeWithSelector(ERC7579Utils.ERC7579UninstalledModule.selector, 1, mallory));
        IWebWallet(fresh).migrate(data);
        assertEq(v2.sessionOf(w, _key(MALLORY_PK)).identity, bytes32(0), "mallory has a session");
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Planned ABI: see the header of WalletLogins.t.sol.

import {Execution} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

import {IIdentityValidator} from "../IIdentityValidator.sol";
import {IWalletFactory, IWalletFactoryOnboarding} from "../IWalletFactory.sol";
import {IWalletRegistry} from "../IWalletRegistry.sol";
import {AUTHORIZED_MODE, IWebWallet} from "../IWebWallet.sol";
import {LoginBase} from "./WalletLogins.t.sol";

/// @notice Wallets at a salt, upgrades only to the factory's implementation, and the root delay.
contract WalletSaltUpgradesTest is LoginBase {
    /// The deployer of the cast vectors below.
    address internal constant D = 0x1111111111111111111111111111111111111111;
    // CREATE3 by cast, for deployer D and genesis (x, alice):
    //   salt 0: identityOf; salt n: keccak256(abi.encode(identityOf, n)).
    address internal constant AT_SALT_0 = 0x74678B208abb48F06B50F6Ec393157C0259AcA14;
    address internal constant AT_SALT_1 = 0x56Ce2e78950E6c22BC5932FB441381555839896F;
    address internal constant AT_SALT_7 = 0xd9438b7E4233fa4954Cb1D6567128788f0790AD8;
    // cast keccak 0x67363d3d37363d34f03d5260086018f3
    bytes32 internal constant PROXY_HASH = 0x21c35dbe1b344a2488cf3321d6ce542f8e9f305544ff09e4993a62319a497c1f;

    /// CREATE3 written out: the CREATE2 proxy, then its nonce-1 CREATE.
    function _c3(bytes32 salt, address deployer) internal pure returns (address) {
        address proxy = address(uint160(uint256(keccak256(abi.encodePacked(hex"ff", deployer, salt, PROXY_HASH)))));
        return address(uint160(uint256(keccak256(abi.encodePacked(hex"d694", proxy, hex"01")))));
    }

    function _create3Salt(uint256 salt) internal pure returns (bytes32) {
        bytes32 id = keccak256(abi.encode(X, ALICE));
        return salt == 0 ? id : keccak256(abi.encode(id, salt));
    }

    /// Moves the factory to a new wallet implementation; with `v2`, one on a second stack.
    function _moveFactory(bool v2) internal returns (address impl, IIdentityValidator v) {
        v = validator;
        if (v2) v = IIdentityValidator(_newRegistry(address(factory)).identityValidator());
        impl = deployCode("WebWallet.sol:WebWallet", abi.encode(address(v)));
        address next = _factoryImpl(impl);
        vm.prank(owner);
        UUPSUpgradeable(address(factory)).upgradeToAndCall(next, "");
    }

    function _migrate(address impl, uint256 salt) internal pure returns (bytes memory) {
        bytes memory install = abi.encode(X, ALICE, salt, _key(ALICE_PK), _admin());
        return abi.encodeCall(IWebWallet.upgradeToAndCall, (impl, abi.encodeCall(IWebWallet.migrate, (install))));
    }

    /// One `createAndExecute` at `salt`: Alice's first session `pk` linked by the wallet, then a `hit()`.
    function _onboard(uint256 salt, uint256 pk) internal returns (address w) {
        w = factory.walletAddress(X, ALICE, salt);
        bytes memory payload = _payload(X, ALICE, LINK, _txData(w, _key(pk), _ph(_admin())));
        Execution[] memory x = new Execution[](2);
        x[0] = _x(address(registry), 0, abi.encodeCall(IWalletRegistry.linkIdentity, (X, V1, payload, "", _admin())));
        x[1] = _hitX();
        bytes memory calls = abi.encode(x);
        uint256 n = uint256(uint160(address(validator))) << 96;
        bytes memory auth = _directAt(w, _pks(pk), calls, n, uint48(_now()), false, _hitProofs(0));
        vm.prank(relayer, relayer);
        IWalletFactoryOnboarding(address(factory)).createAndExecute(X, ALICE, salt, AUTHORIZED_MODE, _data(calls, auth));
        assertEq(target.last(), w, "the onboarding batch did not run");
    }

    // ─── Salt ───────────────────────────────────────────────────────

    function test_saltZeroIsTodaysAddress() public {
        assertEq(_c3(_create3Salt(0), D), AT_SALT_0, "hand CREATE3, salt 0");
        assertEq(_c3(_create3Salt(1), D), AT_SALT_1, "hand CREATE3, salt 1");
        vm.etch(D, _factoryImpl(walletImpl).code);
        IWalletFactory f = IWalletFactory(D);
        assertEq(f.walletAddress(X, ALICE, 0), AT_SALT_0, "salt 0");
        assertEq(f.walletAddress(X, ALICE, 1), AT_SALT_1, "salt 1");
        assertEq(f.walletAddress(X, ALICE, 7), AT_SALT_7, "salt 7");

        assertEq(factory.walletAddress(X, ALICE, 0), _c3(_create3Salt(0), address(factory)), "live, salt 0");
        assertEq(factory.walletAddress(X, ALICE, 1), _c3(_create3Salt(1), address(factory)), "live, salt 1");
    }

    /// One genesis, two wallets; a removal names its wallet.
    function test_twoWalletsForOneGenesis() public {
        address at1 = factory.walletAddress(X, ALICE, 1);
        vm.expectEmit(true, true, true, true, address(factory));
        emit IWalletFactory.WalletCreated(at1, X, ALICE, 1);
        address w1 = factory.createWallet(X, ALICE, 1);
        address w0 = factory.createWallet(X, ALICE, 0);
        assertEq(w1, at1, "salt 1");
        assertNotEq(w0, w1, "one wallet");
        (bytes32 platformId, bytes32 idNode, uint256 salt) = validator.genesisIdentity(w1);
        assertEq(abi.encode(platformId, idNode, salt), abi.encode(X, ALICE, uint256(1)), "genesis of w1");
        (,, salt) = validator.genesisIdentity(w0);
        assertEq(salt, 0, "salt of w0");

        _link(w0, X, ALICE, w0, _key(ALICE_PK), _admin());
        _link(w1, X, ALICE, w1, _key(ALICE2_PK), _admin());
        assertEq(validator.sessionOf(w1, _key(ALICE2_PK)).activeAt, 0, "w1's first session");
        _loginRemove(w0, X, ALICE);
        bytes memory hit = _one(_hitX());
        _refusesBy(w0, hit, _pks(ALICE_PK), NOT_SIGNED);
        _runsBy(w1, hit, _pks(ALICE2_PK));
    }

    function test_squattingAFutureSaltGainsNothing() public {
        vm.prank(mallory);
        address w = factory.createWallet(X, ALICE, 2);
        bytes memory own = _payload(X, MALLORY, LINK, _txData(w, _key(MALLORY_PK), _ph(_admin())));
        vm.prank(mallory);
        vm.expectRevert(abi.encodeWithSelector(IWalletRegistry.NotWallet.selector, w, mallory));
        registry.linkIdentity(X, V1, own, "", _admin());
        // Even a login of Alice's adds no first session.
        bytes memory add = _addPayload(w, X, ALICE, MALLORY_PK, _admin());
        vm.prank(mallory);
        vm.expectRevert(abi.encodeWithSelector(IIdentityValidator.FirstSessionRefused.selector, w));
        registry.addSessionByLogin(X, V1, add, "", _admin());

        assertEq(_onboard(2, ALICE_PK), w, "Alice onboards the squatted wallet");
        assertEq(validator.sessionOf(w, _key(ALICE_PK)).activeAt, 0, "not the first session");
    }

    /// `createAndExecute` at salt 1, then a migration naming the wrong salt.
    function test_aSaltOneWalletOnboardsAndMigratesUnderItsSalt() public {
        address w = _onboard(1, ALICE_PK);
        assertEq(w, _c3(_create3Salt(1), address(factory)), "address");
        assertEq(factory.walletAddress(X, ALICE, 0).code.length, 0, "salt 0 was created");
        (address impl2, IIdentityValidator v2) = _moveFactory(true);
        bytes memory err =
            abi.encodeWithSelector(IIdentityValidator.NotFactoryWallet.selector, w, factory.walletAddress(X, ALICE, 0));
        _rootReverts(w, w, _migrate(impl2, 0), err);
        _root(w, w, _migrate(impl2, 1));
        assertTrue(IWebWallet(w).isModuleInstalled(1, address(v2), ""), "not migrated");
        (,, uint256 salt) = v2.genesisIdentity(w);
        assertEq(salt, 1, "salt");
    }

    // ─── Upgrades ───────────────────────────────────────────────────

    function test_anUpgradeGoesOnlyToTheFactoryImplementation() public {
        address w = _claim();
        address impl2 = _walletImpl();
        bytes memory up = abi.encodeCall(IWebWallet.upgradeToAndCall, (impl2, ""));
        vm.prank(w);
        bytes32 opId = validator.queueRoot(w, up);
        vm.warp(_now() + 1);
        vm.expectPartialRevert(IWebWallet.NotFactoryImplementation.selector);
        validator.executeRoot(w, w, up);
        assertNotEq(validator.rootReadyAt(w, opId), 0, "the refused upgrade left the queue");
        assertEq(address(uint160(uint256(vm.load(w, IMPL_SLOT)))), walletImpl, "upgraded");

        address next = _factoryImpl(impl2);
        vm.prank(owner);
        UUPSUpgradeable(address(factory)).upgradeToAndCall(next, "");
        validator.executeRoot(w, w, up);
        assertEq(address(uint160(uint256(vm.load(w, IMPL_SLOT)))), impl2, "not upgraded");
    }

    function test_aFactoryUpgradeAfterTheQueueBlocksTheUpgrade() public {
        address w = _claim();
        (address impl2,) = _moveFactory(false);
        bytes memory up = abi.encodeCall(IWebWallet.upgradeToAndCall, (impl2, ""));
        vm.prank(w);
        validator.queueRoot(w, up);
        _moveFactory(false);
        vm.warp(_now() + 1);
        vm.expectPartialRevert(IWebWallet.NotFactoryImplementation.selector);
        validator.executeRoot(w, w, up);
        assertEq(address(uint160(uint256(vm.load(w, IMPL_SLOT)))), walletImpl, "upgraded");
    }

    // ─── Root delay ─────────────────────────────────────────────────

    /// At delay 0 and quorum, a batch still cannot queue and execute.
    function test_queueAndExecuteInOneBatchFailAtDelayZero() public {
        address w = _fresh();
        Execution[] memory x = new Execution[](3);
        x[0] = _x(address(validator), 0, abi.encodeCall(IIdentityValidator.queueRoot, (address(validator), _delay(1))));
        bytes memory exec = abi.encodeCall(IIdentityValidator.executeRoot, (w, address(validator), _delay(1)));
        x[1] = _x(address(validator), 0, exec);
        x[2] = _hitX();
        _refusesBy(w, abi.encode(x), _pks(ALICE_PK), IIdentityValidator.RootNotReady.selector);
        assertEq(validator.rootDelay(w), 0, "changed");
    }

    /// Queues `setRootDelay(d)`; it executes after `wait`, not a second earlier.
    function _change(address w, uint48 d, uint48 wait) internal {
        vm.prank(w);
        vm.expectRevert(IIdentityValidator.RootOperationRequired.selector);
        validator.setRootDelay(d);
        vm.prank(w);
        bytes32 opId = validator.queueRoot(address(validator), _delay(d));
        assertEq(validator.rootReadyAt(w, opId), _now() + wait, "not after the current delay");
        vm.warp(_now() + wait - 1);
        vm.expectRevert(abi.encodeWithSelector(IIdentityValidator.RootNotReady.selector, opId));
        validator.executeRoot(w, address(validator), _delay(d));
        vm.warp(_now() + 1);
        validator.executeRoot(w, address(validator), _delay(d));
        assertEq(validator.rootDelay(w), d, "not changed");
    }

    /// A raise too waits the current delay; delay 0 matures the next second.
    function test_everyChangeIsARootOperationAfterTheCurrentDelay() public {
        address w = _claim();
        assertEq(validator.rootDelay(w), 0, "default");
        assertEq(validator.MAX_ROOT_DELAY(), 365 days, "max");
        // Delay 0 matures at now + 1.
        _change(w, 1 days, 1);
        _change(w, 2 days, 1 days);
        _change(w, 0, 2 days);
    }

    function test_theDelayRangeIsZeroTo365Days() public {
        address w = _claim();
        uint48 over = 365 days + 1;
        _rootReverts(
            w,
            address(validator),
            _delay(over),
            abi.encodeWithSelector(IIdentityValidator.RootDelayTooLong.selector, over)
        );
        _root(w, address(validator), _delay(365 days));
        assertEq(validator.rootDelay(w), 365 days, "max");
    }

    function test_aMigrationResetsTheDelay() public {
        address w = _claim();
        _root(w, address(validator), _delay(1 days));
        (address impl2, IIdentityValidator v2) = _moveFactory(true);
        bytes memory up = _migrate(impl2, 0);
        vm.prank(w);
        bytes32 opId = validator.queueRoot(w, up);
        assertEq(validator.rootReadyAt(w, opId), _now() + 1 days, "not after the delay");
        vm.warp(_now() + 1 days);
        validator.executeRoot(w, w, up);
        assertEq(v2.rootDelay(w), 0, "the delay survived the migration");
    }
}

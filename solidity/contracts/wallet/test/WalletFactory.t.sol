// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/IERC4337.sol";
import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

import {IPlatformVerifier} from "../../ceremony/IPlatformVerifier.sol";
import {StubPlatformVerifier} from "../../identity/test/StubPlatformVerifier.sol";
import {IWalletFactory} from "../IWalletFactory.sol";
import {IWalletForwarder} from "../IWalletForwarder.sol";
import {AUTHORIZED_MODE, IWebWallet} from "../IWebWallet.sol";
import {WalletBase} from "./WalletBase.sol";

/// @notice Wallet addresses fixed by `(platformId, idNode, salt)`, the factory's upgrades and ownership, and the
///         stack's wiring by name.
contract WalletFactoryTest is WalletBase {
    /// The deployer of the cast vectors below.
    address internal constant D = 0x1111111111111111111111111111111111111111;
    // CREATE3 by cast, for deployer D and genesis (x, alice):
    //   salt 0: identityOf; salt n: keccak256(abi.encode(x, alice, n)).
    address internal constant AT_SALT_0 = 0x74678B208abb48F06B50F6Ec393157C0259AcA14;
    address internal constant AT_SALT_1 = 0x651FE3166cd83da01eB7Ad678246151bFeEFbe1D;
    address internal constant AT_SALT_7 = 0xEfd86c0C4eF2289D7d4DaC0D0e602Dd7584A0409;
    // cast keccak 0x67363d3d37363d34f03d5260086018f3
    bytes32 internal constant PROXY_HASH = 0x21c35dbe1b344a2488cf3321d6ce542f8e9f305544ff09e4993a62319a497c1f;

    /// CREATE3 written out: the CREATE2 proxy, then its nonce-1 CREATE.
    function _c3(bytes32 salt, address deployer) internal pure returns (address) {
        address proxy = address(uint160(uint256(keccak256(abi.encodePacked(hex"ff", deployer, salt, PROXY_HASH)))));
        return address(uint160(uint256(keccak256(abi.encodePacked(hex"d694", proxy, hex"01")))));
    }

    function _create3Salt(uint256 salt) internal pure returns (bytes32) {
        return salt == 0 ? keccak256(abi.encode(X, ALICE)) : keccak256(abi.encode(X, ALICE, salt));
    }

    // ─── Addresses ──────────────────────────────────────────────────

    /// The cast vectors, and the live factory's addresses on any chain.
    function test_addressesAreCreate3OfTheSalt() public {
        assertEq(_c3(_create3Salt(0), D), AT_SALT_0, "hand CREATE3, salt 0");
        assertEq(_c3(_create3Salt(1), D), AT_SALT_1, "hand CREATE3, salt 1");
        vm.etch(D, _factoryImpl().code);
        IWalletFactory f = IWalletFactory(D);
        assertEq(f.walletAddress(X, ALICE, 0), AT_SALT_0, "salt 0");
        assertEq(f.walletAddress(X, ALICE, 1), AT_SALT_1, "salt 1");
        assertEq(f.walletAddress(X, ALICE, 7), AT_SALT_7, "salt 7");

        address here = factory.walletAddress(X, ALICE, 0);
        assertEq(here, _c3(_create3Salt(0), address(factory)), "live, salt 0");
        assertEq(factory.walletAddress(X, ALICE, 1), _c3(_create3Salt(1), address(factory)), "live, salt 1");
        assertNotEq(factory.walletAddress(GITHUB, ALICE, 0), here, "the platform is not in the address");
        vm.chainId(8453);
        assertEq(factory.walletAddress(X, ALICE, 0), here, "the address depends on the chain");
    }

    /// Anyone creates a wallet once, at its address, on the latest release; a second call returns it unchanged.
    function test_createWalletIsIdempotent() public {
        address at = factory.walletAddress(X, ALICE, 0);
        vm.expectEmit(true, true, true, true, address(factory));
        emit IWalletFactory.WalletCreated(at, X, ALICE, 0);
        vm.prank(mallory);
        address w = factory.createWallet(X, ALICE, 0);
        assertEq(w, at, "not at the predicted address");
        (address impl, uint64 version) = IWebWallet(w).release();
        assertEq(abi.encode(impl, version), abi.encode(impl1, 1), "not the latest release");
        assertEq(address(IWebWallet(w).entryPoint()), EP, "EntryPoint v0.9");
        vm.recordLogs();
        assertEq(factory.createWallet(X, ALICE, 0), w, "a second call moved the wallet");
        assertEq(vm.getRecordedLogs().length, 0, "a second call emitted");
    }

    /// A UserOperation signed for the predicted address before the wallet exists runs once it does, under any
    /// nonce key.
    function test_anOperationSignedBeforeTheWalletExists() public {
        address w = factory.walletAddress(X, ALICE, 0);
        PackedUserOperation memory op = _op(w, _hitCall());
        op.nonce = uint256(1) << 64;
        op = _signOp(op, 1, _pks(ALICE_PK));
        _claim();
        _handle(_ops(op));
        assertEq(target.last(), w, "the operation did not run");
    }

    /// One genesis, two wallets: each its own salt and sessions.
    function test_twoWalletsForOneGenesis() public {
        address w0 = _claim();
        address w1 = _claimAs(X, ALICE, 1, ALICE2_PK);
        assertNotEq(w0, w1, "one wallet");
        (bytes32 platformId, bytes32 idNode, uint256 salt) = IWebWallet(w1).genesisIdentity();
        assertEq(abi.encode(platformId, idNode, salt), abi.encode(X, ALICE, 1), "genesis of w1");
        (,, salt) = IWebWallet(w0).genesisIdentity();
        assertEq(salt, 0, "salt of w0");
        assertEq(IWebWallet(w0).sessionOf(_key(ALICE2_PK)).identity, bytes32(0), "w1's session on w0");
        vm.warp(_now() + 1);
        bytes memory data = _signed(w0, _pks(ALICE2_PK), _one(_hitX()));
        vm.expectRevert(IWebWallet.ExecutionNotSigned.selector);
        IWebWallet(w0).execute(AUTHORIZED_MODE, data);
    }

    /// Creating Alice's wallet at a future salt gives a stranger no link and no session; Alice onboards it.
    function test_squattingAFutureSaltGainsNothing() public {
        vm.prank(mallory);
        address w = factory.createWallet(X, ALICE, 2);
        bytes memory own = _linkPayload(w, X, MALLORY, _key(MALLORY_PK), _admin());
        vm.prank(mallory);
        vm.expectRevert(IWebWallet.OnlySelf.selector);
        IWebWallet(w).linkIdentity(X, V1, own, _admin());
        bytes memory login = _loginPayload(w, mallory, X, ALICE, _key(MALLORY_PK), _admin());
        vm.prank(mallory);
        vm.expectRevert(IWebWallet.FirstSessionRefused.selector);
        IWebWallet(w).addSessionByLogin(X, V1, login, _admin());

        bytes memory data = _signed(w, _pks(ALICE_PK), _one(_linkX(w, X, ALICE, _key(ALICE_PK), _admin())));
        vm.prank(relayer);
        assertEq(factory.createAndExecute(X, ALICE, 2, AUTHORIZED_MODE, data), w, "Alice's wallet moved");
        assertEq(IWebWallet(w).sessionOf(_key(ALICE_PK)).identity, _identity(X, ALICE), "Alice did not onboard");
    }

    /// The genesis `(identityOf(x, alice), 1)` at salt 0 is not Alice's wallet at salt 1.
    function test_aSaltIsNotAnotherGenesis() public {
        bytes32 id = _identity(X, ALICE);
        address at1 = factory.walletAddress(X, ALICE, 1);
        assertNotEq(at1, factory.walletAddress(id, bytes32(uint256(1)), 0), "same address");
        vm.prank(mallory);
        factory.createWallet(id, bytes32(uint256(1)), 0);
        assertEq(at1.code.length, 0, "squatted");
    }

    // ─── Upgrades and ownership ─────────────────────────────────────

    /// The address depends on the factory proxy and the genesis only, not on the factory's code, the chain or the
    /// release it deploys.
    function test_anUpgradeReachesNewWalletsAtTheirPromisedAddress() public {
        address promised = factory.walletAddress(X, ALICE, 0);
        address next = _factoryImpl();
        vm.prank(owner);
        UUPSUpgradeable(address(factory)).upgradeToAndCall(next, "");
        address impl2 = _publish(2);
        vm.chainId(8453);
        assertEq(factory.walletAddress(X, ALICE, 0), promised, "prediction moved");
        address w = factory.createWallet(X, ALICE, 0);
        assertEq(w, promised, "deployed elsewhere");
        (address impl, uint64 version) = IWebWallet(w).release();
        assertEq(abi.encode(impl, version), abi.encode(impl2, 2), "not the latest release");
        (, bytes32 idNode,) = IWebWallet(w).genesisIdentity();
        assertEq(idNode, ALICE, "genesis lost");
    }

    function test_onlyTheOwnerUpgradesAndOwnershipStays() public {
        address next = _factoryImpl();
        vm.prank(mallory);
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, mallory));
        UUPSUpgradeable(address(factory)).upgradeToAndCall(next, "");
        vm.prank(owner);
        vm.expectRevert(IWalletFactory.RenounceDisabled.selector);
        OwnableUpgradeable(address(factory)).renounceOwnership();
        assertEq(factory.owner(), owner, "owner");
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        IWalletFactory(next).initialize(owner);
    }

    // ─── Wiring ─────────────────────────────────────────────────────

    /// The factory and registry sit at their `LibidFactory` names; the release, the forwarder and the registry's
    /// quote name them and the Proof Verifier.
    function test_theStackIsWiredByName() public {
        assertEq(address(factory), names.predict("WalletFactory"), "the factory is not at its name");
        assertEq(address(registry), names.predict("WalletRegistry"), "the registry is not at its name");
        assertEq(IWebWallet(impl1).FACTORY(), address(factory), "the release's factory");
        assertEq(IWebWallet(impl1).REGISTRY(), address(registry), "the release's registry");
        assertEq(factory.REGISTRY(), address(registry), "the factory's registry");
        address fwd = deployCode("WalletForwarder.sol:WalletForwarder", abi.encode(address(factory)));
        assertEq(IWalletForwarder(fwd).FACTORY(), address(factory), "the forwarder's factory");
        IPlatformVerifier paid = IPlatformVerifier(address(new StubPlatformVerifier(GITHUB, 5)));
        vm.prank(owner);
        proofVerifier.setVerifier(GITHUB, 2, paid);
        assertEq(registry.quote(GITHUB, 2), 5, "the registry does not quote its Proof Verifier");
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

import {CeremonyProofVerifier} from "../../ceremony/CeremonyProofVerifier.sol";
import {IPlatformVerifier} from "../../ceremony/IPlatformVerifier.sol";
import {StubPlatformVerifier} from "../../identity/test/StubPlatformVerifier.sol";
import {IWalletRegistry} from "../IWalletRegistry.sol";
import {AUTHORIZED_MODE, IWebWallet} from "../IWebWallet.sol";
import {WalletBase} from "./WalletBase.sol";

interface IRenounce {
    function renounceOwnership() external;
}

/// @notice The registry's one check, the wallet's self-only link and its public login entry.
contract WalletRegistryCheckTest is WalletBase {
    address internal w;

    function setUp() public override {
        super.setUp();
        w = _claim();
        _setApp("client");
        vm.warp(_now() + 1);
    }

    function _setApp(bytes memory app) internal {
        bytes32[] memory a = new bytes32[](1);
        a[0] = keccak256(app);
        _run(w, _one(_x(w, 0, abi.encodeCall(IWebWallet.setAppList, (_identity(X, ALICE), a)))));
    }

    function _login(bytes memory payload) internal {
        vm.prank(relayer);
        IWebWallet(w).addSessionByLogin(X, V1, payload, "", _admin());
    }

    /// Acceptance 5: a login session signs from the next second.
    function test_aLoginSessionSignsFromTheNextSecond() public {
        bytes memory payload = _loginPayload(w, X, ALICE, _key(ALICE2_PK), _admin());
        _login(payload);
        assertTrue(registry.spentDigests(_digestOf(payload)), "digest unspent");
        IWebWallet.Session memory s = IWebWallet(w).sessionOf(_key(ALICE2_PK));
        assertTrue(s.byProof && s.identity == _identity(X, ALICE), "no session by login");

        bytes memory data = _signed(w, _pks(ALICE2_PK), _one(_hitX()));
        vm.expectPartialRevert(IWebWallet.ExecutionNotSigned.selector);
        IWebWallet(w).execute(AUTHORIZED_MODE, data);
        vm.warp(_now() + 1);
        IWebWallet(w).execute(AUTHORIZED_MODE, _signed(w, _pks(ALICE2_PK), _one(_hitX())));
        assertEq(target.calls(), 1, "the login session never signs");
    }

    /// Acceptance 5: an app off the wallet's list is refused, and the proof stays unspent.
    function test_aLoginFromAnUnlistedAppIsRefused() public {
        _setApp("another-app");
        bytes memory payload = _loginPayload(w, X, ALICE, _key(ALICE2_PK), _admin());
        vm.expectRevert(abi.encodeWithSelector(IWebWallet.AppNotListed.selector, keccak256("client")));
        _login(payload);
        assertFalse(registry.spentDigests(_digestOf(payload)), "a refused login spent the digest");
        assertEq(IWebWallet(w).sessionOf(_key(ALICE2_PK)).identity, bytes32(0), "session added");
    }

    /// A proof serves only the operation, wallet, chain and policy it names, once; a refusal spends nothing.
    function test_aProofServesOnlyWhatItNames() public {
        bytes memory k = _key(ALICE2_PK);
        bytes[5] memory payloads = [
            _payload(X, ALICE, LINK, _txData(w, k, _ph(_admin()))),
            _loginPayload(factory.walletAddress(X, ALICE, 1), X, ALICE, k, _admin()),
            _payload(X, ALICE, ADD, abi.encode(vm.getChainId() + 1, w, k, _ph(_admin()))),
            _payload(X, ALICE, ADD, _txData(w, k, keccak256("another policy"))),
            _loginPayload(w, X, ALICE, k, _admin())
        ];
        bytes4[5] memory errs = [
            IWalletRegistry.WrongOperationDomain.selector,
            IWalletRegistry.WrongWallet.selector,
            IWalletRegistry.WrongChain.selector,
            IWalletRegistry.WrongPolicy.selector,
            IWalletRegistry.DigestSpent.selector
        ];
        _login(payloads[4]);
        for (uint256 i; i < errs.length; ++i) {
            vm.prank(relayer);
            vm.expectPartialRevert(errs[i]);
            IWebWallet(w).addSessionByLogin(X, V1, payloads[i], "", _admin());
            assertEq(registry.spentDigests(_digestOf(payloads[i])), i == 4, "a refused proof's digest");
        }
        // A login proof used as a link, in Alice's own batch.
        bytes memory login = _loginPayload(w, X, ALICE, k, _admin());
        bytes memory data = _signed(w, _pks(ALICE_PK), _one(_linkWith(w, X, login, _admin())));
        vm.expectPartialRevert(IWalletRegistry.WrongOperationDomain.selector);
        IWebWallet(w).execute(AUTHORIZED_MODE, data);
        assertFalse(registry.spentDigests(_digestOf(login)), "a refused link spent the digest");
    }

    /// Acceptance 4: a link adds no session after the genesis bootstrap; a later key comes from `addSession`.
    function test_aLinkCarriesAKeyOnlyAtTheGenesisBootstrap() public {
        bytes memory again = _signed(w, _pks(ALICE_PK), _one(_linkX(w, X, ALICE, _key(ALICE2_PK), _admin())));
        vm.expectRevert(IWebWallet.LinkSessionRefused.selector);
        IWebWallet(w).execute(AUTHORIZED_MODE, again);
        bytes memory bob = _signed(w, _pks(ALICE_PK), _one(_linkX(w, GITHUB, BOB, _key(BOB_PK), _admin())));
        vm.expectRevert(IWebWallet.LinkSessionRefused.selector);
        IWebWallet(w).execute(AUTHORIZED_MODE, bob);

        bytes memory add = abi.encodeCall(IWebWallet.addSession, (_identity(GITHUB, BOB), _key(BOB_PK), _admin()));
        _run(w, _two(_linkX(w, GITHUB, BOB, "", _admin()), _x(w, 0, add)));
        assertTrue(IWebWallet(w).isLinked(_identity(GITHUB, BOB)), "control: link only");
        assertEq(IWebWallet(w).sessionOf(_key(BOB_PK)).identity, _identity(GITHUB, BOB), "control: addSession");
    }

    /// Transaction data that is not canonical, a proof naming no id, and a fee off the quote are refused.
    function test_malformedProofsAreRefused() public {
        bytes memory k = _key(ALICE2_PK);
        bytes32 ph = _ph(_admin());
        bytes memory good = _txData(w, k, ph);
        bytes memory gap = abi.encodePacked(block.chainid, uint256(uint160(w)), uint256(0xa0), ph, bytes32(0));
        bytes memory padding = bytes.concat(good);
        padding[191] = 0x01;
        bytes[2] memory bad = [abi.encodePacked(gap, uint256(20), k, bytes12(0)), padding];
        for (uint256 i; i < bad.length; ++i) {
            bytes memory payload = _payload(X, ALICE, ADD, bad[i]);
            vm.expectPartialRevert(IWalletRegistry.BadTransactionData.selector);
            _login(payload);
        }
        bytes memory head = abi.encodePacked(block.chainid, uint256(uint160(w)) | (1 << 200), uint256(0x80), ph);
        bytes memory dirty = _payload(X, ALICE, ADD, abi.encodePacked(head, uint256(20), k, bytes12(0)));
        vm.expectRevert();
        _login(dirty);
        bytes memory noId = _payload(X, bytes32(0), ADD, good);
        vm.expectRevert(IWalletRegistry.NoId.selector);
        _login(noId);

        StubPlatformVerifier paid = new StubPlatformVerifier(X, 5);
        vm.prank(owner);
        proofVerifier.setVerifier(X, 2, IPlatformVerifier(address(paid)));
        assertEq(registry.quote(X, 2), 5, "quote");
        paid.setNodes(ALICE, keccak256("h"));
        bytes memory fee = abi.encode(
            StubPlatformVerifier.StubPayload({
                ceremonyVersion: 1, operationDomain: ADD, authorizationNonce: keccak256("paid"), transactionData: good
            })
        );
        vm.deal(relayer, 10);
        for (uint256 v = 4; v <= 6; v += 2) {
            vm.prank(relayer);
            vm.expectRevert(abi.encodeWithSelector(CeremonyProofVerifier.WrongValue.selector, 5, v));
            IWebWallet(w).addSessionByLogin{value: v}(X, 2, fee, "", _admin());
        }
        vm.prank(relayer);
        IWebWallet(w).addSessionByLogin{value: 5}(X, 2, fee, "", _admin());
        assertEq(address(paid).balance, 5, "the verifier was not paid");
    }

    /// Calling the check directly spends only a proof naming the caller, and no wallet records it.
    function test_aDirectCheckSpendsOnlyTheCallersOwnProof() public {
        bytes memory forW = _loginPayload(w, X, ALICE, _key(MALLORY_PK), _admin());
        vm.prank(mallory);
        vm.expectPartialRevert(IWalletRegistry.WrongWallet.selector);
        registry.check(ADD, X, V1, forW, "", _ph(_admin()));
        assertFalse(registry.spentDigests(_digestOf(forW)), "a stranger burned the wallet's proof");

        bytes memory own = _linkPayload(mallory, X, MALLORY, _key(MALLORY_PK), _admin());
        vm.prank(mallory);
        IWalletRegistry.Checked memory c = registry.check(LINK, X, V1, own, "", _ph(_admin()));
        assertEq(
            abi.encode(c.identity, c.key, c.app),
            abi.encode(_identity(X, MALLORY), _key(MALLORY_PK), bytes("client")),
            "Checked"
        );
        assertTrue(registry.spentDigests(_digestOf(own)), "own proof unspent");
        assertEq(IWebWallet(w).sessionOf(_key(MALLORY_PK)).identity, bytes32(0), "a wallet recorded it");
    }

    /// G7: the factory's owner, renouncing disabled, upgrades by the owner only.
    function test_theRegistryProxyIsOwnedLikeTheFactory() public {
        assertEq(registry.owner(), factory.owner(), "owner");
        vm.prank(owner);
        vm.expectRevert();
        IRenounce(address(registry)).renounceOwnership();
        address next = deployCode("WalletRegistry.sol:WalletRegistry", abi.encode(address(proofVerifier)));
        vm.prank(mallory);
        vm.expectPartialRevert(bytes4(keccak256("OwnableUnauthorizedAccount(address)")));
        UUPSUpgradeable(address(registry)).upgradeToAndCall(next, "");
    }
}

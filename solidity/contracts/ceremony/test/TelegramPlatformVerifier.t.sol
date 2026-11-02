// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {HonkStub} from "./HonkStub.sol";
import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {CeremonyAuthorization} from "../CeremonyAuthorization.sol";
import {CeremonyProofVerifier} from "../CeremonyProofVerifier.sol";
import {ICeremony} from "../ICeremony.sol";
import {IPlatformVerifier} from "../IPlatformVerifier.sol";
import {PlatformVerifierBase} from "../PlatformVerifierBase.sol";
import {OidcPlatformVerifierBase, TelegramPlatformVerifier} from "../TelegramPlatformVerifier.sol";
import {TrustingJwtRoots} from "./TrustingJwtRoots.sol";
import {CeremonyProfile} from "../CeremonyProfile.sol";

/// @notice The `telegram/v1` profile: one oidc-telegram proof, timed by `iat`.
contract TelegramPlatformVerifierTest is Test {
    TelegramPlatformVerifier verifier;
    TrustingJwtRoots roots;
    address honk;

    address constant OWNER = address(0xA11CE);
    uint64 constant IAT = 1_770_000_000;
    bytes constant BOT_ID = "7000000001";
    bytes32 constant DOMAIN = keccak256(bytes("libid.bind-identity"));
    bytes32 constant AUTH_NONCE = bytes32(uint256(0x5555555555555555555555555555555555555555555555555555555555555555));
    // hashlib.sha256(b"libid.telegram.user-id7051836294")
    bytes32 constant ID_NODE = 0x9ff44e615ff14505c3a406e9931e2442ad4f56f3fb5b12e91c143fa6384a3a4c;
    // hashlib.sha256(b"libid.telegram.handlebrynn_qx"): Brynn_QX folded
    bytes32 constant HANDLE_NODE = 0xf6416e7788cea1d8d9d7ada243b2f998a33296b61db647298ce61722c04c925b;
    /// The real proof's signed `iat`.
    uint64 constant REAL_IAT = 1_893_452_400;
    string constant FIXTURE = "contracts/circuits/test/fixtures/oidc-telegram-proof.json";
    bytes32 digest;

    function setUp() public {
        digest = CeremonyAuthorization.digest(DOMAIN, 1, AUTH_NONCE, _txData());
        vm.warp(IAT);
        roots = new TrustingJwtRoots(CeremonyProfile.AUTHORITY_TELEGRAM_OAUTH);
        honk = HonkStub.deploy(HonkStub.TELEGRAM);
        verifier = _deploy(honk, address(roots));
        roots.trust(keccak256(abi.encodePacked(_modulus())), IAT + 30 days);
    }

    function _initData(address notary, address honk_, address roots_) private pure returns (bytes memory) {
        return abi.encodeWithSelector(TelegramPlatformVerifier.initialize.selector, OWNER, notary, honk_, roots_);
    }

    function _deploy(address honk_, address roots_) private returns (TelegramPlatformVerifier) {
        return TelegramPlatformVerifier(
            address(new ERC1967Proxy(address(new TelegramPlatformVerifier()), _initData(address(0), honk_, roots_)))
        );
    }

    function _txData() private pure returns (bytes memory) {
        return abi.encode(address(0xBEEF));
    }

    function _modulus() private pure returns (bytes32[18] memory m) {
        for (uint256 i = 0; i < 18; ++i) {
            m[i] = bytes32(uint256(0x1000 + i));
        }
    }

    function _payload() private pure returns (TelegramPlatformVerifier.TelegramProof memory s) {
        s.ceremonyVersion = 1;
        s.operationDomain = DOMAIN;
        s.authorizationNonce = AUTH_NONCE;
        s.transactionData = _txData();
        s.clientIdentifier = BOT_ID;
        s.idNode = ID_NODE;
        s.handleNode = HANDLE_NODE;
        s.iat = IAT;
        s.modulus = _modulus();
        s.proof = hex"00";
    }

    function run(TelegramPlatformVerifier v, TelegramPlatformVerifier.TelegramProof memory s)
        external
        returns (ICeremony.VerifiedClaim memory)
    {
        return v.verify(abi.encode(s));
    }

    // ─── Identity of the profile ────────────────────────────────────

    function test_isThePlatformTelegramAndTheProofVerifierRoutesIt() public {
        assertEq(verifier.platformId(), keccak256("telegram"));
        assertEq(verifier.quote(), 0);
        CeremonyProofVerifier pv = CeremonyProofVerifier(
            address(
                new ERC1967Proxy(
                    address(new CeremonyProofVerifier()), abi.encodeCall(CeremonyProofVerifier.initialize, (OWNER))
                )
            )
        );
        vm.prank(OWNER);
        pv.setVerifier(keccak256("telegram"), 1, IPlatformVerifier(address(verifier)));
        assertEq(pv.verify(keccak256("telegram"), 1, abi.encode(_payload())).idNode, ID_NODE);
    }

    /// The Google circuit's verifier is not the Telegram circuit's, and a
    /// notary is refused.
    function test_refusesAnotherCircuitAndANotary() public {
        address google = HonkStub.deploy(HonkStub.GOOGLE);
        address impl = address(new TelegramPlatformVerifier());
        vm.expectPartialRevert(PlatformVerifierBase.WrongCircuit.selector);
        new ERC1967Proxy(impl, _initData(address(0), google, address(roots)));
        vm.expectPartialRevert(PlatformVerifierBase.WrongNotaryForProfile.selector);
        new ERC1967Proxy(impl, _initData(address(0xDEAD), honk, address(roots)));
    }

    // ─── Time: iat - 5 min <= now < iat + 1 h ───────────────────────

    function test_theTimeWindowEdges() public {
        int64[4] memory offset = [int64(3599), 3600, -300, -301];
        bool[4] memory ok = [true, false, true, false];
        for (uint256 i = 0; i < 4; ++i) {
            // IAT and every offset are far inside int64 and the sum is positive.
            // forge-lint: disable-next-line(unsafe-typecast)
            vm.warp(uint64(int64(IAT) + offset[i]));
            (bool accepted,) = address(this).call(abi.encodeCall(this.run, (verifier, _payload())));
            assertEq(accepted, ok[i], vm.toString(offset[i]));
        }
    }

    /// `iat` less the five-minute allowance, whenever it is submitted.
    function test_observedAtIsIatOnTheSharedScale() public {
        vm.warp(IAT - 300);
        assertEq(this.run(verifier, _payload()).metadataObservedAt, IAT - 300);
        vm.warp(IAT + 60);
        assertEq(this.run(verifier, _payload()).metadataObservedAt, IAT - 300);
    }

    // ─── The signing key ────────────────────────────────────────────

    function test_rejectsAnUntrustedOrLapsedModulus() public {
        TrustingJwtRoots other = new TrustingJwtRoots(CeremonyProfile.AUTHORITY_TELEGRAM_OAUTH);
        TelegramPlatformVerifier v = _deploy(honk, address(other));
        vm.expectPartialRevert(OidcPlatformVerifierBase.UntrustedModulus.selector);
        this.run(v, _payload());
        bytes32 h = keccak256(abi.encodePacked(_modulus()));
        other.trust(h, IAT);
        vm.expectPartialRevert(OidcPlatformVerifierBase.UntrustedModulus.selector);
        this.run(v, _payload());
        other.trust(h, IAT + 1);
        this.run(v, _payload());
    }

    // ─── The real proof ─────────────────────────────────────────────

    function _realProof()
        private
        returns (TelegramPlatformVerifier real, TelegramPlatformVerifier.TelegramProof memory s)
    {
        string memory json = vm.readFile(FIXTURE);
        real = _deploy(vm.deployCode(HonkStub.TELEGRAM), address(roots));
        bytes32[] memory pi = vm.parseJsonBytes32Array(json, ".public_inputs");
        s = _payload();
        s.iat = uint64(uint256(pi[38]));
        for (uint256 i = 0; i < 18; ++i) {
            s.modulus[i] = pi[39 + i];
        }
        s.proof = vm.parseJsonBytes(json, ".proof");
        assertEq(s.iat, REAL_IAT);
        roots.trust(keccak256(abi.encodePacked(s.modulus)), REAL_IAT + 30 days);
        vm.warp(REAL_IAT + 60);
    }

    function test_verifiesARealProof() public {
        (TelegramPlatformVerifier real, TelegramPlatformVerifier.TelegramProof memory s) = _realProof();
        ICeremony.VerifiedClaim memory c = real.verify(abi.encode(s));
        assertEq(c.idNode, ID_NODE);
        assertEq(c.handleNode, HANDLE_NODE);
        assertEq(c.metadataObservedAt, REAL_IAT - 300);
        assertEq(c.sessionId, digest);
        assertEq(string(c.clientIdentifier), string(BOT_ID));
        assertEq(c.operationDomain, DOMAIN);
        assertEq(c.transactionData, _txData());
        assertEq(c.ceremonyVersion, 1);
    }

    /// No value is accepted, Google's root list is refused, and pointing at
    /// another Telegram one is announced.
    function test_refusesValueAndAnnouncesItsRoots() public {
        vm.expectRevert(abi.encodeWithSelector(PlatformVerifierBase.WrongValue.selector, 0, 1));
        verifier.verify{value: 1}(abi.encode(_payload()));
        bytes32 google = CeremonyProfile.AUTHORITY_GOOGLEAPIS_WWW;
        TrustingJwtRoots googles = new TrustingJwtRoots(google);
        vm.prank(OWNER);
        vm.expectRevert(
            abi.encodeWithSelector(
                PlatformVerifierBase.WrongAuthority.selector, CeremonyProfile.AUTHORITY_TELEGRAM_OAUTH, google
            )
        );
        verifier.setJwtRoots(googles);
        TrustingJwtRoots other = new TrustingJwtRoots(CeremonyProfile.AUTHORITY_TELEGRAM_OAUTH);
        vm.expectEmit(address(verifier));
        emit OidcPlatformVerifierBase.JwtRootsChanged(address(other));
        vm.prank(OWNER);
        verifier.setJwtRoots(other);
    }

    /// Every value the verifier builds an input from is bound: digest parts,
    /// nodes, iat, the bot id.
    function test_refusesTheRealProofUnderAnyOtherValue() public {
        TelegramPlatformVerifier real;
        TelegramPlatformVerifier.TelegramProof memory s;
        for (uint256 i = 0; i < 7; ++i) {
            (real, s) = _realProof();
            if (i == 0) s.authorizationNonce ^= bytes32(uint256(1));
            if (i == 1) s.transactionData = abi.encode(address(0xCAFE));
            if (i == 2) s.operationDomain = keccak256("libid.other");
            if (i == 3) s.idNode ^= bytes32(uint256(1));
            if (i == 4) s.handleNode ^= bytes32(uint256(1));
            if (i == 5) s.iat = REAL_IAT - 1;
            if (i == 6) s.clientIdentifier = "7000000002";
            (bool ok,) = address(real).call{gas: 5_000_000}(abi.encodeCall(real.verify, (abi.encode(s))));
            assertFalse(ok, vm.toString(i));
        }
    }
}

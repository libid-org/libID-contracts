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

    function _payload() private pure returns (OidcPlatformVerifierBase.OidcProof memory s) {
        s.ceremonyVersion = 1;
        s.operationDomain = DOMAIN;
        s.authorizationNonce = AUTH_NONCE;
        s.transactionData = _txData();
        s.clientIdentifier = BOT_ID;
        s.idNode = ID_NODE;
        s.handleNode = HANDLE_NODE;
        s.time = IAT;
        s.modulus = _modulus();
        s.proof = hex"00";
    }

    function run(TelegramPlatformVerifier v, OidcPlatformVerifierBase.OidcProof memory s)
        external
        returns (ICeremony.VerifiedClaim memory)
    {
        return v.verify(abi.encode(s));
    }

    // ─── Identity of the profile ────────────────────────────────────

    function test_isTheTelegramPlatform() public view {
        assertEq(verifier.platformId(), keccak256("telegram"));
    }

    function test_quotesNothing() public view {
        assertEq(verifier.quote(), 0);
    }

    function test_theProofVerifierRoutesIt() public {
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

    /// The Google circuit's verifier is not the Telegram circuit's.
    function test_refusesAnotherCircuit() public {
        address google = HonkStub.deploy(HonkStub.GOOGLE);
        address impl = address(new TelegramPlatformVerifier());
        vm.expectRevert(
            abi.encodeWithSelector(
                PlatformVerifierBase.WrongCircuit.selector, verifier.circuitCodehash(), google.codehash
            )
        );
        new ERC1967Proxy(impl, _initData(address(0), google, address(roots)));
    }

    function test_refusesANotary() public {
        address impl = address(new TelegramPlatformVerifier());
        vm.expectPartialRevert(PlatformVerifierBase.WrongNotaryForProfile.selector);
        new ERC1967Proxy(impl, _initData(address(0xDEAD), honk, address(roots)));
    }

    // ─── The payload ────────────────────────────────────────────────

    function test_refusesAnyValue() public {
        vm.expectRevert(abi.encodeWithSelector(PlatformVerifierBase.WrongValue.selector, 0, 1));
        verifier.verify{value: 1}(abi.encode(_payload()));
    }

    function test_rejectsAPayloadForAnotherCeremonyVersion() public {
        OidcPlatformVerifierBase.OidcProof memory s = _payload();
        s.ceremonyVersion = 2;
        vm.expectRevert(abi.encodeWithSelector(PlatformVerifierBase.WrongCeremonyVersion.selector, 1, 2));
        this.run(verifier, s);
    }

    function test_rejectsAMissingClientIdentifier() public {
        OidcPlatformVerifierBase.OidcProof memory s = _payload();
        s.clientIdentifier = "";
        vm.expectRevert(OidcPlatformVerifierBase.MissingClientIdentifier.selector);
        this.run(verifier, s);
    }

    // ─── Time: iat - 5 min <= now < iat + 1 h ───────────────────────

    function test_acceptsTheWindowsEdges() public {
        vm.warp(IAT + 3599);
        this.run(verifier, _payload());
        vm.warp(IAT - 300);
        this.run(verifier, _payload());
    }

    function test_rejectsATokenAnHourOld() public {
        vm.warp(IAT + 3600);
        vm.expectRevert(abi.encodeWithSelector(PlatformVerifierBase.ProofExpired.selector, IAT + 3600, IAT + 3600));
        this.run(verifier, _payload());
    }

    function test_rejectsATokenFromFurtherAheadThanTheSkew() public {
        vm.warp(IAT - 301);
        vm.expectRevert(abi.encodeWithSelector(PlatformVerifierBase.AttestationAhead.selector, IAT, IAT - 301, 300));
        this.run(verifier, _payload());
    }

    /// `iat` less the five-minute allowance, whenever it is submitted.
    function test_observedAtIsIatOnTheSharedScale() public {
        vm.warp(IAT - 300);
        assertEq(this.run(verifier, _payload()).metadataObservedAt, IAT - 300);
        vm.warp(IAT + 60);
        assertEq(this.run(verifier, _payload()).metadataObservedAt, IAT - 300);
    }

    // ─── The signing key ────────────────────────────────────────────

    function test_rejectsAnUntrustedModulus() public {
        TelegramPlatformVerifier v =
            _deploy(honk, address(new TrustingJwtRoots(CeremonyProfile.AUTHORITY_TELEGRAM_OAUTH)));
        vm.expectRevert(
            abi.encodeWithSelector(
                OidcPlatformVerifierBase.UntrustedModulus.selector, keccak256(abi.encodePacked(_modulus()))
            )
        );
        this.run(v, _payload());
    }

    function test_rejectsAModulusWhoseTrustHasLapsed() public {
        bytes32 h = keccak256(abi.encodePacked(_modulus()));
        roots.trust(h, IAT);
        vm.expectRevert(abi.encodeWithSelector(OidcPlatformVerifierBase.UntrustedModulus.selector, h));
        this.run(verifier, _payload());
    }

    // ─── The roots list ─────────────────────────────────────────────

    function test_refusesGooglesRootsList() public {
        bytes32 google = CeremonyProfile.AUTHORITY_GOOGLEAPIS_WWW;
        TrustingJwtRoots googles = new TrustingJwtRoots(google);
        vm.prank(OWNER);
        vm.expectRevert(
            abi.encodeWithSelector(
                PlatformVerifierBase.WrongAuthority.selector, CeremonyProfile.AUTHORITY_TELEGRAM_OAUTH, google
            )
        );
        verifier.setJwtRoots(googles);
    }

    function test_announcesANewRootsList() public {
        TrustingJwtRoots other = new TrustingJwtRoots(CeremonyProfile.AUTHORITY_TELEGRAM_OAUTH);
        vm.expectEmit(address(verifier));
        emit OidcPlatformVerifierBase.JwtRootsChanged(address(other));
        vm.prank(OWNER);
        verifier.setJwtRoots(other);
    }

    // ─── The real proof ─────────────────────────────────────────────

    function _realProof() private returns (TelegramPlatformVerifier real, OidcPlatformVerifierBase.OidcProof memory s) {
        string memory json = vm.readFile(FIXTURE);
        real = _deploy(vm.deployCode(HonkStub.TELEGRAM), address(roots));
        bytes32[] memory pi = vm.parseJsonBytes32Array(json, ".public_inputs");
        s = _payload();
        s.clientIdentifier = bytes(vm.parseJsonString(json, ".client_identifier"));
        s.time = uint64(uint256(pi[38]));
        for (uint256 i = 0; i < 18; ++i) {
            s.modulus[i] = pi[39 + i];
        }
        s.proof = vm.parseJsonBytes(json, ".proof");
        assertEq(s.time, REAL_IAT);
        roots.trust(keccak256(abi.encodePacked(s.modulus)), REAL_IAT + 30 days);
        vm.warp(REAL_IAT + 60);
    }

    /// The real proof fails once any value the verifier builds an input from changes.
    function _refusedByTheRealProof(TelegramPlatformVerifier real, OidcPlatformVerifierBase.OidcProof memory s)
        private
    {
        (bool ok,) = address(real).call{gas: 5_000_000}(abi.encodeCall(real.verify, (abi.encode(s))));
        assertFalse(ok);
    }

    function test_verifiesARealProof() public {
        (TelegramPlatformVerifier real, OidcPlatformVerifierBase.OidcProof memory s) = _realProof();
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

    /// The signed `nonce` is the digest of the domain, nonce and transaction.
    function test_refusesARealProofForAnotherDigest() public {
        (TelegramPlatformVerifier real, OidcPlatformVerifierBase.OidcProof memory s) = _realProof();
        s.authorizationNonce ^= bytes32(uint256(1));
        _refusedByTheRealProof(real, s);
        (, s) = _realProof();
        s.transactionData = abi.encode(address(0xCAFE));
        _refusedByTheRealProof(real, s);
        (, s) = _realProof();
        s.operationDomain = keccak256("libid.other");
        _refusedByTheRealProof(real, s);
    }

    function test_refusesARealProofUnderAnotherNode() public {
        (TelegramPlatformVerifier real, OidcPlatformVerifierBase.OidcProof memory s) = _realProof();
        s.idNode ^= bytes32(uint256(1));
        _refusedByTheRealProof(real, s);
        (, s) = _realProof();
        s.handleNode ^= bytes32(uint256(1));
        _refusedByTheRealProof(real, s);
    }

    /// The proof binds `sha256(aud)`, so another bot is refused.
    function test_refusesARealProofForAnotherBot() public {
        (TelegramPlatformVerifier real, OidcPlatformVerifierBase.OidcProof memory s) = _realProof();
        s.clientIdentifier = "7000000002";
        _refusedByTheRealProof(real, s);
    }

    /// An earlier `iat` is still inside the window, so only the proof refuses it.
    function test_refusesARealProofForAnotherIat() public {
        (TelegramPlatformVerifier real, OidcPlatformVerifierBase.OidcProof memory s) = _realProof();
        s.time = REAL_IAT - 1;
        _refusedByTheRealProof(real, s);
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {HonkStub} from "./HonkStub.sol";
import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {CeremonyAuthorization} from "../CeremonyAuthorization.sol";
import {CeremonyProfile} from "../CeremonyProfile.sol";
import {GooglePlatformVerifier, IGoogleJwtRoots} from "../GooglePlatformVerifier.sol";
import {ICeremony} from "../ICeremony.sol";
import {INotaryService} from "../INotaryService.sol";
import {IHonkVerifier, PlatformVerifierBase} from "../PlatformVerifierBase.sol";
import {TrustingJwtRoots} from "./TrustingJwtRoots.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {TlsNotaryVerifierBase} from "../TlsNotaryVerifierBase.sol";

/// @notice The `google/v1` profile: no notarized session, Notary Service or fee;
///         the digest is a public proof input.
contract GooglePlatformVerifierTest is Test {
    GooglePlatformVerifier verifier;
    TrustingJwtRoots roots;
    address honk;

    address constant OWNER = address(0xA11CE);
    uint64 constant T0 = 1_770_000_000;
    uint64 constant GOOGLE_ALLOWANCE = CeremonyProfile.FUTURE_OBSERVATION_ALLOWANCE_SECONDS_GOOGLE;
    uint64 constant EXP = T0 + 3600;

    bytes32 constant DOMAIN = keccak256(bytes("libid.claim-identity"));
    bytes32 constant AUTH_NONCE = bytes32(uint256(0x5555555555555555555555555555555555555555555555555555555555555555));
    /// The digest the public inputs carry as the signed `nonce`; set in `setUp`.
    bytes32 digest;
    bytes constant CLIENT_ID = "123456789-abcdef.apps.googleusercontent.com";
    string constant SUB = "123456789012345678901";
    /// The id node the oidc-google circuit outputs for `SUB`:
    ///   hashlib.sha256(b"libid.google.user-id123456789012345678901")
    bytes32 constant USER_ID = 0xa83e66b34468315fb68c3098b3c521b749aafb1db3390cb53ec03a8db139f2c7;
    // The handle node for `A.B+tag@Example.COM`, lowercased only:
    //   hashlib.sha256(b"libid.google.handlea.b+tag@example.com")
    bytes32 constant HANDLE_NODE = 0x40169b5cc6400158aeef2a13b73a14fc36e5e1df8595572b8fe282a269f26dd4;
    /// The signed `exp` of the real proof's token.
    uint64 constant REAL_EXP = 1_893_456_000;

    function setUp() public {
        digest = CeremonyAuthorization.digest(DOMAIN, 1, AUTH_NONCE, _txData());
        vm.warp(T0);
        roots = new TrustingJwtRoots();
        honk = HonkStub.deploy(HonkStub.GOOGLE);
        GooglePlatformVerifier impl = new GooglePlatformVerifier();
        verifier = GooglePlatformVerifier(
            address(
                new ERC1967Proxy(
                    address(impl),
                    abi.encodeCall(
                        GooglePlatformVerifier.initialize,
                        (
                            OWNER,
                            INotaryService(address(0)),
                            IHonkVerifier(address(honk)),
                            IGoogleJwtRoots(address(roots))
                        )
                    )
                )
            )
        );
        roots.trust(_modulusHash(), EXP + 86400);
        vm.deal(address(this), 1 ether);
    }

    // ─── Building the public inputs ─────────────────────────────────

    function _modulusLimb(uint256 i) private pure returns (bytes32) {
        return bytes32(uint256(0x1000 + i));
    }

    function _modulus() private pure returns (bytes32[18] memory m) {
        for (uint256 i = 0; i < 18; ++i) {
            m[i] = _modulusLimb(i);
        }
    }

    function _modulusHash() private pure returns (bytes32) {
        return keccak256(abi.encodePacked(_modulus()));
    }

    /// REQ-PLAT-16B's layout, written independently of the verifier.
    function _inputs(bytes32 digest_, bytes memory clientId, uint64 exp) private pure returns (bytes32[] memory pi) {
        pi = new bytes32[](57);
        for (uint256 i = 0; i < 32; ++i) {
            pi[i] = bytes32(uint256(uint8(digest_[i])));
        }
        bytes32 aud = sha256(clientId);
        pi[32] = bytes32(uint256(aud) >> 128);
        pi[33] = bytes32(uint256(aud) & type(uint128).max);
        pi[34] = bytes32(uint256(USER_ID) >> 128);
        pi[35] = bytes32(uint256(USER_ID) & type(uint128).max);
        pi[36] = bytes32(uint256(HANDLE_NODE) >> 128);
        pi[37] = bytes32(uint256(HANDLE_NODE) & type(uint128).max);
        pi[38] = bytes32(uint256(exp));
        for (uint256 i = 0; i < 18; ++i) {
            pi[39 + i] = _modulusLimb(i);
        }
    }

    function _txData() private pure returns (bytes memory) {
        return abi.encode(address(0xBEEF), uint256(0), address(0));
    }

    /// The `google/v1` payload; the verifier builds the public inputs from it.
    function _payload() private pure returns (GooglePlatformVerifier.GoogleProof memory s) {
        s.ceremonyVersion = 1;
        s.operationDomain = DOMAIN;
        s.authorizationNonce = AUTH_NONCE;
        s.transactionData = _txData();
        s.clientIdentifier = CLIENT_ID;
        s.idNode = USER_ID;
        s.handleNode = HANDLE_NODE;
        s.exp = EXP;
        s.modulus = _modulus();
        s.proof = hex"00";
    }

    function run(GooglePlatformVerifier.GoogleProof memory s)
        external
        payable
        returns (ICeremony.VerifiedClaim memory)
    {
        return verifier.verify{value: msg.value}(abi.encode(s));
    }

    // ─── The happy path ─────────────────────────────────────────────

    /// @dev A far-future `exp` would set a watermark that refuses the holder's re-proof until then.
    function test_rejectsAnExpiryFurtherAheadThanTheAllowance() public {
        uint64 farOut = uint64(block.timestamp) + GOOGLE_ALLOWANCE + 1;
        GooglePlatformVerifier.GoogleProof memory s = _payload();
        s.exp = farOut;
        vm.expectPartialRevert(PlatformVerifierBase.ObservedInTheFuture.selector);
        this.run(s);
    }

    /// @dev A real oidc-google proof whose nonce is the digest for `_payload`.
    ///      The fixture's `source` field says how it was made.
    function _realProof() private returns (GooglePlatformVerifier real, GooglePlatformVerifier.GoogleProof memory s) {
        string memory json = vm.readFile("contracts/ceremony/test/fixtures/google-ceremony-proof.json");
        address honkVerifier = vm.deployCode(HonkStub.GOOGLE);
        real = GooglePlatformVerifier(
            address(
                new ERC1967Proxy(
                    address(new GooglePlatformVerifier()),
                    abi.encodeCall(
                        GooglePlatformVerifier.initialize,
                        (
                            OWNER,
                            INotaryService(address(0)),
                            IHonkVerifier(honkVerifier),
                            IGoogleJwtRoots(address(roots))
                        )
                    )
                )
            )
        );
        bytes32[] memory pi = vm.parseJsonBytes32Array(json, ".public_inputs");
        s = _payload();
        s.clientIdentifier = bytes(vm.parseJsonString(json, ".client_identifier"));
        s.idNode = bytes32((uint256(pi[34]) << 128) | uint256(pi[35]));
        s.handleNode = bytes32((uint256(pi[36]) << 128) | uint256(pi[37]));
        s.exp = uint64(uint256(pi[38]));
        for (uint256 i = 0; i < 18; ++i) {
            s.modulus[i] = pi[39 + i];
        }
        s.proof = vm.parseJsonBytes(json, ".proof");
        assertEq(s.exp, REAL_EXP);
        roots.trust(keccak256(abi.encodePacked(s.modulus)), REAL_EXP + 86400);
        vm.warp(REAL_EXP - 3600);
    }

    /// The real proof fails once any value the verifier builds an input from changes.
    function _refusedByTheRealProof(GooglePlatformVerifier real, GooglePlatformVerifier.GoogleProof memory s) private {
        (bool ok,) = address(real).call{gas: 5_000_000}(abi.encodeCall(real.verify, (abi.encode(s))));
        assertFalse(ok);
    }

    function test_verifiesARealProof() public {
        (GooglePlatformVerifier real, GooglePlatformVerifier.GoogleProof memory s) = _realProof();
        ICeremony.VerifiedClaim memory f = real.verify(abi.encode(s));
        // hashlib.sha256(b"libid.google.user-id100000000000000000001")
        assertEq(f.idNode, 0x5e13b7e56f17994a08b7464e5c5c5758228d6816db0a0af9bbd73f65335fcec8);
        // The token's email, Fixture@Example.com, lowercased:
        //   hashlib.sha256(b"libid.google.handlefixture@example.com")
        assertEq(f.handleNode, 0xfbda24950a7bc55993b7aacc3acbde636931dbb45f04c1ff6f6909027962885f);
    }

    /// @dev One changed bit in either node is another account.
    function test_refusesARealProofUnderAnotherNode() public {
        (GooglePlatformVerifier real, GooglePlatformVerifier.GoogleProof memory s) = _realProof();
        s.idNode ^= bytes32(uint256(1));
        _refusedByTheRealProof(real, s);
        (, s) = _realProof();
        s.handleNode ^= bytes32(uint256(1));
        _refusedByTheRealProof(real, s);
    }

    /// @dev REQ-COMMON-02A: the signed `nonce` is the digest, so another nonce
    ///      or transaction fails the proof.
    function test_refusesARealProofForAnotherDigest() public {
        (GooglePlatformVerifier real, GooglePlatformVerifier.GoogleProof memory s) = _realProof();
        s.authorizationNonce = bytes32(uint256(AUTH_NONCE) ^ 1);
        _refusedByTheRealProof(real, s);
        (, s) = _realProof();
        s.transactionData = abi.encode(address(0xBEEF), uint256(1), address(0));
        _refusedByTheRealProof(real, s);
    }

    /// @dev The digest commits no chain, so the real proof verifies on another
    ///      chain too.
    function test_verifiesARealProofOnAnotherChain() public {
        (GooglePlatformVerifier real, GooglePlatformVerifier.GoogleProof memory s) = _realProof();
        vm.chainId(block.chainid + 1);
        ICeremony.VerifiedClaim memory f = real.verify(abi.encode(s));
        assertEq(f.sessionId, digest);
    }

    /// @dev REQ-PLAT-19A: the proof binds `sha256(aud)`, so another client
    ///      identifier is refused.
    function test_refusesARealProofForAnotherClientIdentifier() public {
        (GooglePlatformVerifier real, GooglePlatformVerifier.GoogleProof memory s) = _realProof();
        s.clientIdentifier = "attacker.apps.googleusercontent.com";
        _refusedByTheRealProof(real, s);
    }

    /// @dev An earlier `exp` is still in the future, so only the proof refuses it.
    function test_refusesARealProofForAnotherExpiry() public {
        (GooglePlatformVerifier real, GooglePlatformVerifier.GoogleProof memory s) = _realProof();
        s.exp = REAL_EXP - 1;
        _refusedByTheRealProof(real, s);
    }

    /// @dev The verifier hands the Honk verifier REQ-PLAT-16B's layout, built
    ///      from the payload, its own digest and `sha256(aud)`.
    function test_buildsThePublicInputsInTheirFixedOrder() public {
        GooglePlatformVerifier.GoogleProof memory s = _payload();
        vm.expectCall(honk, abi.encodeCall(IHonkVerifier.verify, (s.proof, _inputs(digest, CLIENT_ID, EXP))));
        this.run(s);
    }

    function test_verifiesAWholeGoogleCeremony() public {
        ICeremony.VerifiedClaim memory f = this.run(_payload());
        assertEq(f.idNode, USER_ID);
        assertEq(f.handleNode, HANDLE_NODE);
        assertEq(string(f.clientIdentifier), string(CLIENT_ID));
        // Section 2.2: the watermark is the signed `exp` on the shared scale,
        // so it does not outrank X or GitHub claims from the same hour.
        assertEq(f.metadataObservedAt, EXP - GOOGLE_ALLOWANCE);
    }

    // ─── Zero attestations, zero fee ────────────────────────────────

    /// @dev A profile that verifies no attestation refuses a Notary Service at initialization.
    function test_refusesANotaryItWouldNeverCall() public {
        GooglePlatformVerifier impl = new GooglePlatformVerifier();
        vm.expectPartialRevert(PlatformVerifierBase.WrongNotaryForProfile.selector);
        new ERC1967Proxy(
            address(impl),
            abi.encodeCall(
                GooglePlatformVerifier.initialize,
                (OWNER, INotaryService(address(0xDEAD)), IHonkVerifier(address(honk)), IGoogleJwtRoots(address(roots)))
            )
        );
    }

    /// @dev REQ-COMMON-05D: a profile requiring no attestation holds no Notary Service.
    function test_holdsNoNotary() public view {
        assertEq(verifier.notaryService(), address(0));
    }

    function test_quotesNothing() public view {
        assertEq(verifier.quote(), 0);
    }

    /// @dev With no Notary Service, there is nothing to forward value to.
    function test_refusesAnyValue() public {
        GooglePlatformVerifier.GoogleProof memory s = _payload();
        vm.expectRevert(abi.encodeWithSelector(PlatformVerifierBase.WrongValue.selector, 0, 1));
        this.run{value: 1}(s);
    }

    // ─── The payload ────────────────────────────────────────────────

    function test_rejectsAPayloadForAnotherCeremonyVersion() public {
        GooglePlatformVerifier.GoogleProof memory s = _payload();
        s.ceremonyVersion = 2;
        vm.expectRevert(abi.encodeWithSelector(PlatformVerifierBase.WrongCeremonyVersion.selector, 1, 2));
        this.run(s);
    }

    // ─── The audience ───────────────────────────────────────────────

    function test_rejectsAMissingClientIdentifier() public {
        GooglePlatformVerifier.GoogleProof memory s = _payload();
        s.clientIdentifier = "";
        vm.expectRevert(GooglePlatformVerifier.MissingClientIdentifier.selector);
        this.run(s);
    }

    // ─── The trusted modulus ────────────────────────────────────────

    /// @dev REQ-PLAT-23: the verifier, not the circuit, decides which modulus is trusted.
    function test_rejectsAnUntrustedModulus() public {
        TrustingJwtRoots empty = new TrustingJwtRoots();
        vm.prank(OWNER);
        verifier.setJwtRoots(IGoogleJwtRoots(address(empty)));
        GooglePlatformVerifier.GoogleProof memory s = _payload();
        vm.expectPartialRevert(GooglePlatformVerifier.UntrustedModulus.selector);
        this.run(s);
    }

    /// @dev Google rotates its keys, so a lapsed one fails closed.
    function test_rejectsAModulusWhoseTrustHasLapsed() public {
        TrustingJwtRoots lapsed = new TrustingJwtRoots();
        lapsed.trust(_modulusHash(), T0);
        vm.prank(OWNER);
        verifier.setJwtRoots(IGoogleJwtRoots(address(lapsed)));
        GooglePlatformVerifier.GoogleProof memory s = _payload();
        vm.expectPartialRevert(GooglePlatformVerifier.UntrustedModulus.selector);
        this.run(s);
    }

    // ─── Evidence time ──────────────────────────────────────────────

    function test_rejectsAnExpiredToken() public {
        vm.warp(EXP);
        GooglePlatformVerifier.GoogleProof memory s = _payload();
        vm.expectPartialRevert(GooglePlatformVerifier.TokenExpired.selector);
        this.run(s);
    }

    function test_acceptsRightUpToExpiry() public {
        vm.warp(EXP - 1);
        this.run(_payload());
    }

    // ─── The proof ──────────────────────────────────────────────────

    function test_rejectsAProofThatDoesNotVerify() public {
        HonkStub.answer(honk, false);
        GooglePlatformVerifier.GoogleProof memory s = _payload();
        vm.expectRevert(PlatformVerifierBase.BadProof.selector);
        this.run(s);
    }

    function test_onlyTheOwnerPointsAtJwtRoots() public {
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(this)));
        verifier.setJwtRoots(IGoogleJwtRoots(address(roots)));
        vm.prank(OWNER);
        vm.expectRevert(PlatformVerifierBase.ZeroAddress.selector);
        verifier.setJwtRoots(IGoogleJwtRoots(address(0)));
    }

    /// @dev A TLSNotary-shaped payload at the Google verifier is refused.
    function test_aTlsPayloadIsRefused() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory x;
        x.ceremonyVersion = 1;
        (bool ok,) = address(verifier).call(abi.encodeCall(verifier.verify, (abi.encode(x))));
        assertFalse(ok);
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {CeremonyAuthorization} from "../CeremonyAuthorization.sol";
import {GooglePlatformVerifier, IGoogleJwtRoots} from "../GooglePlatformVerifier.sol";
import {ICeremony} from "../ICeremony.sol";
import {INotaryService} from "../INotaryService.sol";
import {IHonkVerifier, PlatformVerifierBase} from "../PlatformVerifierBase.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {TlsNotaryVerifierBase} from "../TlsNotaryVerifierBase.sol";

contract Honk is IHonkVerifier {
    bool public answer = true;

    function setAnswer(bool a) external {
        answer = a;
    }

    function verify(bytes calldata, bytes32[] calldata) external view returns (bool) {
        return answer;
    }
}

contract Roots is IGoogleJwtRoots {
    mapping(bytes32 => uint256) public expiry;

    function trust(bytes32 h, uint256 until) external {
        expiry[h] = until;
    }

    function trustedHashExpiresAt(bytes32 h) external view returns (uint256) {
        return expiry[h];
    }
}

/// @notice The `google/v1` profile: no notarized session, no Notary Service, no
///         fee, and the digest bound as a public proof input rather than
///         through PKCE.
contract GooglePlatformVerifierTest is Test {
    GooglePlatformVerifier verifier;
    Roots roots;
    Honk honk;

    address constant OWNER = address(0xA11CE);
    uint64 constant T0 = 1_770_000_000;
    /// @dev Google id_tokens live an hour; two gives room without letting a
    ///      claim lock a name for longer than the token itself was valid.
    uint64 constant GOOGLE_ALLOWANCE = 7200;
    uint64 constant EXP = T0 + 3600;

    bytes32 constant DOMAIN = keccak256(bytes("libid.claim-identity"));
    bytes32 constant AUTH_NONCE = bytes32(uint256(0x5555555555555555555555555555555555555555555555555555555555555555));
    /// The digest the public inputs carry as the signed `nonce`, derived in
    /// `setUp` from the payload below and this chain.
    bytes32 digest;
    bytes constant CLIENT_ID = "123456789-abcdef.apps.googleusercontent.com";
    string constant SUB = "123456789012345678901";
    /// The `userId` platform-ceremonies section 2.1 publishes for `SUB`:
    /// `SHA256("libid.google-user-id" || sub)`, computed outside Solidity.
    string constant USER_ID = "0x20078023c9d4bf6bffc2580ec36446075d10c8453cecbe4f1cb3d326b2b35560";
    string constant EMAIL = "a.b+tag@example.com";
    /// The signed `exp` of the real proof's token.
    uint64 constant REAL_EXP = 1_893_456_000;

    function setUp() public {
        digest = CeremonyAuthorization.digestFor(DOMAIN, 1, AUTH_NONCE, _txData());
        vm.warp(T0);
        roots = new Roots();
        honk = new Honk();
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
                            address(honk).codehash,
                            GOOGLE_ALLOWANCE,
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

    function _pack31(bytes memory s) private pure returns (bytes32 out) {
        require(s.length <= 31, "too long");
        uint256 v;
        for (uint256 i = 0; i < 31; ++i) {
            v = v << 8;
            if (i < s.length) v |= uint8(s[i]);
        }
        return bytes32(v);
    }

    function _packMulti(bytes memory s, uint256 count) private pure returns (bytes32[] memory out) {
        out = new bytes32[](count);
        for (uint256 f = 0; f < count; ++f) {
            bytes memory chunk = new bytes(31);
            for (uint256 i = 0; i < 31; ++i) {
                uint256 at = f * 31 + i;
                chunk[i] = at < s.length ? s[at] : bytes1(0);
            }
            out[f] = _pack31(chunk);
        }
    }

    function _modulusLimb(uint256 i) private pure returns (bytes32) {
        return bytes32(uint256(0x1000 + i));
    }

    function _modulusHash() private pure returns (bytes32) {
        bytes memory packed = new bytes(18 * 32);
        for (uint256 i = 0; i < 18; ++i) {
            bytes32 limb = _modulusLimb(i);
            assembly {
                mstore(add(add(packed, 32), mul(i, 32)), limb)
            }
        }
        return keccak256(packed);
    }

    function _inputs(bytes32 digest_, bytes memory clientId, uint64 exp) private pure returns (bytes32[] memory pi) {
        pi = new bytes32[](57);
        for (uint256 i = 0; i < 32; ++i) {
            pi[i] = bytes32(uint256(uint8(digest_[i])));
        }
        bytes32 aud = sha256(clientId);
        pi[32] = bytes32(uint256(aud) >> 128);
        pi[33] = bytes32(uint256(aud) & type(uint128).max);
        bytes32 userId = sha256(bytes.concat("libid.google-user-id", bytes(SUB)));
        pi[34] = bytes32(uint256(userId) >> 128);
        pi[35] = bytes32(uint256(userId) & type(uint128).max);
        bytes32[] memory email = _packMulti(bytes(EMAIL), 2);
        pi[36] = email[0];
        pi[37] = email[1];
        pi[38] = bytes32(uint256(exp));
        for (uint256 i = 0; i < 18; ++i) {
            pi[39 + i] = _modulusLimb(i);
        }
    }

    function _txData() private pure returns (bytes memory) {
        return abi.encode(address(0xBEEF));
    }

    /// The `google/v1` payload the public inputs are made for. Nothing
    /// notarized in it: the evidence is the proof over a signed token, and the
    /// contract sees only its public inputs.
    function _payload() private view returns (GooglePlatformVerifier.GoogleProof memory s) {
        s.ceremonyVersion = 1;
        s.operationDomain = DOMAIN;
        s.authorizationNonce = AUTH_NONCE;
        s.transactionData = _txData();
        s.clientIdentifier = CLIENT_ID;
        s.publicInputs = _inputs(digest, CLIENT_ID, EXP);
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

    /// @dev Nothing bounded `exp` from above before. `block.timestamp >= exp`
    ///      is a floor, so a token minted with a distant expiry wrote a
    ///      watermark that far ahead -- and `_requireNewer` then refused the
    ///      account owner's own re-proof for as long. Re-proving is the remedy
    ///      for a lost name, so an unbounded expiry buys a lock on one.
    function test_rejectsAnExpiryFurtherAheadThanTheAllowance() public {
        uint64 farOut = uint64(block.timestamp) + GOOGLE_ALLOWANCE + 1;
        GooglePlatformVerifier.GoogleProof memory s = _payload();
        s.publicInputs = _inputs(digest, CLIENT_ID, farOut);
        vm.expectPartialRevert(PlatformVerifierBase.ObservedInTheFuture.selector);
        this.run(s);
    }

    /// @dev libid-circuits v0.5.0's oidc-google, proved over a token signed by
    ///      a synthetic key whose nonce is this chain's digest for `_payload`,
    ///      and checked by the verifier the pin ships.
    function _realProof() private returns (GooglePlatformVerifier real, GooglePlatformVerifier.GoogleProof memory s) {
        string memory json = vm.readFile("contracts/ceremony/test/fixtures/google-ceremony-proof.json");
        address honkVerifier = vm.deployCode("OidcGoogleHonkVerifier.sol:OidcGoogleHonkVerifier");
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
                            honkVerifier.codehash,
                            GOOGLE_ALLOWANCE,
                            IGoogleJwtRoots(address(roots))
                        )
                    )
                )
            )
        );
        s = _payload();
        s.clientIdentifier = bytes(vm.parseJsonString(json, ".client_identifier"));
        s.publicInputs = vm.parseJsonBytes32Array(json, ".public_inputs");
        s.proof = vm.parseJsonBytes(json, ".proof");

        bytes memory modulus = new bytes(18 * 32);
        for (uint256 i = 0; i < 18; ++i) {
            bytes32 limb = s.publicInputs[39 + i];
            assembly {
                mstore(add(add(modulus, 32), mul(i, 32)), limb)
            }
        }
        roots.trust(keccak256(modulus), REAL_EXP + 86400);
        vm.warp(REAL_EXP - 3600);
    }

    function test_verifiesARealProof() public {
        (GooglePlatformVerifier real, GooglePlatformVerifier.GoogleProof memory s) = _realProof();
        ICeremony.VerifiedClaim memory f = real.verify(abi.encode(s));
        assertEq(f.userId, "0x121c75456ead3d5fa8f601dbd629bddb84dcdb4934b2a6b6d2e46b5661c6d35b");
        assertEq(f.handle, "fixture@example.com");
    }

    /// @dev The proof binds the digest: one changed bit is another account.
    function test_refusesARealProofUnderAnotherUserId() public {
        (GooglePlatformVerifier real, GooglePlatformVerifier.GoogleProof memory s) = _realProof();
        s.publicInputs[35] ^= bytes32(uint256(1));
        vm.expectRevert();
        real.verify{gas: 5_000_000}(abi.encode(s));
    }

    function test_verifiesAWholeGoogleCeremony() public {
        ICeremony.VerifiedClaim memory f = this.run(_payload());
        assertEq(f.userId, USER_ID);
        assertEq(f.handle, EMAIL);
        assertEq(string(f.clientIdentifier), string(CLIENT_ID));
        // Section 2.2: the signed `exp` supplies BOTH the watermark and the
        // validity ceiling.
        // The signed expiry, brought onto the shared scale. Raw, it would
        // beat every X or GitHub claim made in the same hour.
        assertEq(f.metadataObservedAt, EXP - GOOGLE_ALLOWANCE);
    }

    /// @dev The handle is RAW: normalization is the Consumer's derivation on its
    ///      own write path, so the address keeps its dot and its plus tag
    ///      exactly as Google signed them.
    function test_returnsTheRawEmailUnnormalized() public {
        assertEq(this.run(_payload()).handle, "a.b+tag@example.com");
    }

    // ─── Zero attestations, zero fee ────────────────────────────────

    /// @dev A path with nothing to verify carries no value.
    /// @dev A profile that verifies no attestation holds no Notary Service.
    ///      Requiring a live address would make a deployer supply a dependency
    ///      purely to satisfy a check, and `notaryService()` would then report
    ///      a collaborator this contract is forbidden to call.
    function test_refusesANotaryItWouldNeverCall() public {
        GooglePlatformVerifier impl = new GooglePlatformVerifier();
        vm.expectPartialRevert(PlatformVerifierBase.WrongNotaryForProfile.selector);
        new ERC1967Proxy(
            address(impl),
            abi.encodeCall(
                GooglePlatformVerifier.initialize,
                (
                    OWNER,
                    INotaryService(address(0xDEAD)),
                    IHonkVerifier(address(honk)),
                    address(honk).codehash,
                    GOOGLE_ALLOWANCE,
                    IGoogleJwtRoots(address(roots))
                )
            )
        );
    }

    /// @dev REQ-COMMON-05D: a profile requiring no attestation must not reach a
    ///      Notary Service. It holds none at all, so there is nothing to reach
    ///      and nothing for `setTrustRoots` to rotate.
    function test_holdsNoNotary() public view {
        assertEq(verifier.notaryService(), address(0));
    }

    function test_quotesNothing() public view {
        assertEq(verifier.quote(), 0);
    }

    /// @dev Not merely "no fee required" but "no value accepted": there is
    ///      nothing downstream to forward it to.
    function test_refusesAnyValue() public {
        GooglePlatformVerifier.GoogleProof memory s = _payload();
        vm.expectRevert(abi.encodeWithSelector(PlatformVerifierBase.WrongValue.selector, 0, 1));
        this.run{value: 1}(s);
    }

    // ─── The digest, bound the other way round ──────────────────────

    /// @dev REQ-COMMON-02A. X and GitHub recompute a PKCE verifier; Google
    ///      compares a public proof input carried by the signed `nonce`
    ///      against the digest it rebuilds from the payload. A token proved
    ///      for another digest does not match.
    function test_rejectsAProofForAnotherDigest() public {
        GooglePlatformVerifier.GoogleProof memory s = _payload();
        s.publicInputs = _inputs(bytes32(uint256(digest) ^ 1), CLIENT_ID, EXP);
        vm.expectPartialRevert(GooglePlatformVerifier.DigestMismatch.selector);
        this.run(s);
    }

    /// @dev And the other way round: the same token, retargeted by changing a
    ///      digest input in the payload, opens against nothing.
    function test_rejectsAPayloadRetargetedToAnotherDigest() public {
        GooglePlatformVerifier.GoogleProof memory s = _payload();
        s.authorizationNonce = bytes32(uint256(AUTH_NONCE) ^ 1);
        vm.expectPartialRevert(GooglePlatformVerifier.DigestMismatch.selector);
        this.run(s);
    }

    function test_rejectsAPayloadForAnotherCeremonyVersion() public {
        GooglePlatformVerifier.GoogleProof memory s = _payload();
        s.ceremonyVersion = 2;
        vm.expectRevert(abi.encodeWithSelector(PlatformVerifierBase.WrongCeremonyVersion.selector, 1, 2));
        this.run(s);
    }

    // ─── The audience ───────────────────────────────────────────────

    /// @dev REQ-PLAT-19A. The digest authenticates the bytes without the
    ///      circuit packing a variable-length string into public inputs.
    function test_rejectsAForgedClientIdentifier() public {
        GooglePlatformVerifier.GoogleProof memory s = _payload();
        s.clientIdentifier = "attacker.apps.googleusercontent.com";
        vm.expectRevert(GooglePlatformVerifier.AudienceMismatch.selector);
        this.run(s);
    }

    function test_rejectsAMissingClientIdentifier() public {
        GooglePlatformVerifier.GoogleProof memory s = _payload();
        s.clientIdentifier = "";
        vm.expectRevert(GooglePlatformVerifier.MissingClientIdentifier.selector);
        this.run(s);
    }

    /// @dev The audience hash arrives as two halves, and only the high one is
    ///      shifted. So an over-wide LOW half alone reproduces any 256-bit
    ///      value -- here the true hash of a client identifier the prover
    ///      never held -- and the audience check passes for free. The contract
    ///      cannot see the circuit's range constraints, so it states its own.
    function test_rejectsAnOverwideLowAudienceHalf() public {
        GooglePlatformVerifier.GoogleProof memory s = _payload();
        bytes32 aud = sha256(CLIENT_ID);
        s.publicInputs[32] = bytes32(0);
        s.publicInputs[33] = aud;
        vm.expectPartialRevert(GooglePlatformVerifier.PublicInputOverwide.selector);
        this.run(s);
    }

    /// @dev The high half is shifted, so bits above its 128th fall off the top
    ///      and many values agree. Same rule, same reason.
    function test_rejectsAnOverwideHighAudienceHalf() public {
        GooglePlatformVerifier.GoogleProof memory s = _payload();
        s.publicInputs[32] = bytes32(uint256(s.publicInputs[32]) | (uint256(1) << 128));
        vm.expectPartialRevert(GooglePlatformVerifier.PublicInputOverwide.selector);
        this.run(s);
    }

    // ─── The user id ────────────────────────────────────────────────

    /// @dev One spelling per digest: `0x`, then 64 lowercase hex digits with
    ///      the leading zeros kept, so an id never has two encodings.
    function test_writesTheUserIdAsSixtyFourLowercaseHexDigits() public {
        GooglePlatformVerifier.GoogleProof memory s = _payload();
        s.publicInputs[34] = bytes32(0);
        s.publicInputs[35] = bytes32(uint256(0xabcdef));
        assertEq(this.run(s).userId, "0x0000000000000000000000000000000000000000000000000000000000abcdef");
    }

    /// @dev The user id is a digest in two halves, like the audience, and the
    ///      same over-wide low half would name any account at all.
    function test_rejectsAnOverwideLowUserIdHalf() public {
        GooglePlatformVerifier.GoogleProof memory s = _payload();
        s.publicInputs[34] = bytes32(0);
        s.publicInputs[35] = sha256(bytes.concat("libid.google-user-id", bytes(SUB)));
        vm.expectRevert(
            abi.encodeWithSelector(
                GooglePlatformVerifier.PublicInputOverwide.selector, 35, uint256(s.publicInputs[35]), 128
            )
        );
        this.run(s);
    }

    function test_rejectsAnOverwideHighUserIdHalf() public {
        GooglePlatformVerifier.GoogleProof memory s = _payload();
        uint256 widened = uint256(s.publicInputs[34]) | (uint256(1) << 128);
        s.publicInputs[34] = bytes32(widened);
        vm.expectRevert(abi.encodeWithSelector(GooglePlatformVerifier.PublicInputOverwide.selector, 34, widened, 128));
        this.run(s);
    }

    // ─── The packed email ───────────────────────────────────────────

    /// @dev `_unpack` reads 31 bytes of each of the email's two field elements
    ///      and drops whatever sits above them in silence. Dropped, the handle
    ///      this returns is not the one the circuit proved.
    function test_rejectsAnOverwideEmailField() public {
        GooglePlatformVerifier.GoogleProof memory s = _payload();
        s.publicInputs[37] = bytes32(uint256(s.publicInputs[37]) | (uint256(1) << 248));
        vm.expectPartialRevert(GooglePlatformVerifier.PublicInputOverwide.selector);
        this.run(s);
    }

    // ─── The trusted modulus ────────────────────────────────────────

    /// @dev REQ-PLAT-23. The circuit exposes the modulus that verified the JWS
    ///      but decides no trust; that decision lives here alone.
    function test_rejectsAnUntrustedModulus() public {
        Roots empty = new Roots();
        vm.prank(OWNER);
        verifier.setJwtRoots(IGoogleJwtRoots(address(empty)));
        GooglePlatformVerifier.GoogleProof memory s = _payload();
        vm.expectPartialRevert(GooglePlatformVerifier.UntrustedModulus.selector);
        this.run(s);
    }

    /// @dev Google rotates weekly, so a lapsed key must fail closed rather than
    ///      keep answering.
    function test_rejectsAModulusWhoseTrustHasLapsed() public {
        Roots lapsed = new Roots();
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
        honk.setAnswer(false);
        GooglePlatformVerifier.GoogleProof memory s = _payload();
        vm.expectRevert(PlatformVerifierBase.BadProof.selector);
        this.run(s);
    }

    /// @dev 56 is the count of the circuit that published the `sub`, so this
    ///      is also its proofs being refused.
    function test_rejectsTheWrongPublicInputCount() public {
        GooglePlatformVerifier.GoogleProof memory s = _payload();
        s.publicInputs = new bytes32[](56);
        vm.expectRevert(abi.encodeWithSelector(GooglePlatformVerifier.WrongPublicInputCount.selector, 57, 56));
        this.run(s);
    }

    function test_rejectsTheSameSubmissionOnAnotherChain() public {
        GooglePlatformVerifier.GoogleProof memory s = _payload();
        vm.chainId(block.chainid + 1);
        vm.expectPartialRevert(GooglePlatformVerifier.DigestMismatch.selector);
        this.run(s);
    }

    function test_rejectsAnExpiryWiderThanUint64() public {
        GooglePlatformVerifier.GoogleProof memory s = _payload();
        s.publicInputs[38] = bytes32(uint256(type(uint64).max) + 1);
        vm.expectPartialRevert(GooglePlatformVerifier.ExpiryNotAUint64.selector);
        this.run(s);
    }

    function test_rejectsADigestInputThatIsNotAByte() public {
        GooglePlatformVerifier.GoogleProof memory s = _payload();
        s.publicInputs[0] = bytes32(uint256(0x100) | uint256(s.publicInputs[0]));
        vm.expectPartialRevert(GooglePlatformVerifier.PublicInputNotAByte.selector);
        this.run(s);
    }

    function test_rejectsFiftyEightPublicInputs() public {
        GooglePlatformVerifier.GoogleProof memory s = _payload();
        s.publicInputs = new bytes32[](58);
        vm.expectRevert(abi.encodeWithSelector(GooglePlatformVerifier.WrongPublicInputCount.selector, 57, 58));
        this.run(s);
    }

    function test_onlyTheOwnerPointsAtJwtRoots() public {
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(this)));
        verifier.setJwtRoots(IGoogleJwtRoots(address(roots)));
        vm.prank(OWNER);
        vm.expectRevert(PlatformVerifierBase.ZeroAddress.selector);
        verifier.setJwtRoots(IGoogleJwtRoots(address(0)));
    }

    /// @dev A TLSNotary-shaped payload at the Google verifier. The first four
    ///      words are common to both layouts; after them the readings diverge,
    ///      and word five points Google's `publicInputs` at the identity
    ///      session, whose leading word reads as a length of 64 elements the
    ///      payload does not carry. The decoder walks out of bounds and
    ///      reverts with no data, so no later check ever runs.
    function test_aTlsPayloadRevertsWithNoData() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory x;
        x.ceremonyVersion = 1;
        (bool ok, bytes memory ret) = address(verifier).call(abi.encodeCall(verifier.verify, (abi.encode(x))));
        assertFalse(ok);
        assertEq(ret.length, 0);
    }
}

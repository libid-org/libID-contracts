// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";

import {CeremonyAttestation} from "./CeremonyAttestation.sol";
import {CeremonyProfile} from "./CeremonyProfile.sol";
import {ICeremony} from "./ICeremony.sol";
import {INotaryService} from "./INotaryService.sol";

/// @dev The bb-generated proof verifier for this platform's circuit.
interface IHonkVerifier {
    function verify(bytes calldata proof, bytes32[] calldata publicInputs) external view returns (bool);
}

/// @title PlatformVerifierBase
/// @notice What every Platform Verifier owes, whichever platform it serves.
///
/// @dev Authenticates attestations and checks their pinned authority, holds
///      the trust roots, and turns a signed creation time into the profile's
///      validity window. Field checks and payload decoding stay in each
///      verifier; REQ-COMMON-19E names one authoritative reader per field.
abstract contract PlatformVerifierBase is ICeremony, Initializable, UUPSUpgradeable, Ownable2StepUpgradeable {
    /// @custom:storage-location erc7201:libid.storage.PlatformVerifier
    struct PlatformVerifierStorage {
        /// Authenticates an attestation and charges for it: the one Notary
        /// Service the profile accepts (REQ-COMMON-18), zero if it notarizes nothing.
        INotaryService notary;
        /// The circuit verifier for this platform, set by the owner, never
        /// by a caller (REQ-COMMON-45).
        IHonkVerifier honkVerifier;
    }

    // keccak256(abi.encode(uint256(keccak256("libid.storage.PlatformVerifier")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant PLATFORM_VERIFIER_STORAGE =
        0xfd6bfa775d4a790b2a39afc6490b76805795bc7d3963618ec6b2ee0a55986900;

    function _base() internal pure returns (PlatformVerifierStorage storage $) {
        assembly {
            $.slot := PLATFORM_VERIFIER_STORAGE
        }
    }

    event TrustRootsChanged(address notary, address honkVerifier);

    /// @dev A profile that verifies no attestation holds a Notary Service, or
    ///      one that verifies some holds none.
    error WrongNotaryForProfile(bytes32 platformId, address notary);
    error WrongValue(uint256 required, uint256 provided);
    /// @dev The payload claims a ceremony version this verifier does not
    ///      implement. Checked before any fee moves.
    error WrongCeremonyVersion(uint16 expected, uint16 found);
    error WrongAuthority(bytes32 expected, bytes32 found);
    error AttestationAhead(uint64 createdAt, uint64 blockTime, uint64 allowance);
    error ProofExpired(uint64 validUntil, uint64 blockTime);
    error ObservedInTheFuture(uint64 observedAt, uint64 limit);
    error BadProof();
    error ZeroAddress();
    /// @dev The verifier at that address is not this platform's circuit's.
    error WrongCircuit(bytes32 expected, bytes32 found);

    // OpenZeppelin's `__Contract_init` initializer convention.
    // forge-lint: disable-next-line(mixed-case-function)
    function __PlatformVerifierBase_init(address owner_, INotaryService notary_, IHonkVerifier honkVerifier_)
        internal
        onlyInitializing
    {
        __Ownable_init(owner_);
        __Ownable2Step_init();
        _setTrustRoots(notary_, honkVerifier_);
    }

    // ─── Trust roots and validity ───────────────────────────────────

    function notaryService() external view returns (address) {
        return address(_base().notary);
    }

    function honkVerifier() external view returns (address) {
        return address(_base().honkVerifier);
    }

    /// @notice The runtime code hash of this platform's vendored circuit verifier:
    ///         the only Honk verifier `setTrustRoots` and `verify` accept.
    function circuitCodehash() external pure returns (bytes32) {
        return _circuitCodehash();
    }

    /// @notice The validity window this verifier enforces, in seconds: the
    ///         values its profile fixes (REQ-PARAM-01).
    function protocolParameters()
        external
        pure
        returns (uint64 proofLifetime, uint64 maxFutureAttestationSkew, uint64 futureObservationAllowance)
    {
        return (_proofLifetime(), _maxFutureAttestationSkew(), _futureObservationAllowance());
    }

    /// @dev The Honk verifier must be this platform's circuit's, `circuitCodehash()`
    ///      (REQ-COMMON-45; `WrongCircuit`).
    function setTrustRoots(INotaryService notary_, IHonkVerifier honkVerifier_) external onlyOwner {
        _setTrustRoots(notary_, honkVerifier_);
    }

    /// @dev The platform this verifier answers for. Asked during
    ///      initialization, so it must not read storage.
    function _platform() internal pure virtual returns (bytes32);

    /// @dev This platform's `CircuitCodehashes` constant.
    function _circuitCodehash() internal pure virtual returns (bytes32);

    /// @dev The protocol revision the Authorization Digest binds, fixed by the
    ///      code. Unrelated to the verifier version the Proof Verifier routes
    ///      on, which is this chain's slot number.
    function _ceremonyVersion() internal pure virtual returns (uint16) {
        return CeremonyProfile.ceremonyVersion(_platform());
    }

    /// @dev The validity window, from `CeremonyProfile`: fixed per ceremony
    ///      version, since a browser derives a proof's expiry from the version
    ///      it ran; a different window is a new ceremony version
    ///      (REQ-PARAM-01). No caller substitute exists (REQ-PARAM-02).
    ///
    ///      The maximum age of the token attestation; `_maxFutureAttestationSkew`
    ///      is its maximum lead over Block Time. Both are zero for a profile
    ///      that notarizes nothing.
    function _proofLifetime() internal pure virtual returns (uint64) {
        return CeremonyProfile.proofLifetime(_platform());
    }

    function _maxFutureAttestationSkew() internal pure virtual returns (uint64) {
        return CeremonyProfile.maxFutureAttestationSkew(_platform());
    }

    /// @dev How far ahead of Block Time this profile's evidence time may run.
    ///      Google's is a signed `exp` about an hour ahead, a TLSNotary
    ///      profile's an attestation creation time. Each verifier subtracts its
    ///      allowance so evidence times compare on one scale, and refuses
    ///      evidence dated further ahead.
    function _futureObservationAllowance() internal pure virtual returns (uint64) {
        return CeremonyProfile.futureObservationAllowance(_platform());
    }

    /// @dev Refuse a payload made for another ceremony version, by name;
    ///      returns this verifier's version.
    function _requireCeremonyVersion(uint16 claimed) internal pure returns (uint16 expected) {
        expected = _ceremonyVersion();
        if (claimed != expected) revert WrongCeremonyVersion(expected, claimed);
    }

    function _setTrustRoots(INotaryService notary_, IHonkVerifier honkVerifier_) private {
        if (address(honkVerifier_) == address(0)) revert ZeroAddress();

        // A Notary Service is set exactly when the profile notarizes; a
        // profile whose Attestation Count is zero must not reach one
        // (REQ-COMMON-05D).
        bytes32 platform = _platform();
        bool wantsNotary = CeremonyProfile.attestationCount(platform) != 0;
        if (wantsNotary != (address(notary_) != address(0))) {
            revert WrongNotaryForProfile(platform, address(notary_));
        }
        // bb's verifiers embed their key as code, so the code hash names the
        // circuit (REQ-COMMON-45).
        bytes32 found = address(honkVerifier_).codehash;
        bytes32 circuit = _circuitCodehash();
        if (found != circuit) revert WrongCircuit(circuit, found);

        _base().notary = notary_;
        _base().honkVerifier = honkVerifier_;
        emit TrustRootsChanged(address(notary_), address(honkVerifier_));
    }

    // ─── Shared duties ──────────────────────────────────────────────

    /// @dev Authenticate and decode one attestation, then check the authority
    ///      its profile pins. The Notary Service's decision is final
    ///      (REQ-COMMON-05D).
    function _authenticate(Attestation memory attestation, bytes32 expectedAuthority, uint256 fee)
        internal
        returns (CeremonyAttestation.AttestedData memory data)
    {
        // One call authenticates and decodes, so only authenticated bytes are read.
        data = _base().notary.verify{value: fee}(attestation.attestedData, attestation.proof);

        // The TLS server name from the handshake, the one field the notary
        // observed. The transcript names the host only in a prover-composed
        // `Host` header. The format is fixed by the pinned notary key
        // (REQ-COMMON-18); the caller checks the request line for the session.
        if (data.authorityId != expectedAuthority) {
            revert WrongAuthority(expectedAuthority, data.authorityId);
        }
    }

    /// @dev Turn the token attestation's signed creation time into the window
    ///      section 2.2 fixes. The token attestation carries the one-time PKCE
    ///      and digest binding, so it alone supplies evidence time.
    function _requireFresh(uint64 createdAt) internal view returns (uint64 metadataObservedAt) {
        uint64 blockTime = uint64(block.timestamp);
        uint64 skew = _maxFutureAttestationSkew();

        // Checked arithmetic throughout (REQ-COMMON-28).
        if (createdAt > blockTime + skew) {
            revert AttestationAhead(createdAt, blockTime, skew);
        }
        uint64 validUntil = createdAt + _proofLifetime();
        if (blockTime >= validUntil) revert ProofExpired(validUntil, blockTime);

        // The skew bounds the notary's clock; this bounds the watermark. A
        // watermark in the future would make later honest proofs read stale.
        _requireNotAhead(createdAt);

        // Onto the shared scale, comparable across profiles.
        return _onSharedScale(createdAt, _futureObservationAllowance());
    }

    /// @dev `observedAt - allowance`, saturating at zero.
    function _onSharedScale(uint64 observedAt, uint64 allowance) internal pure returns (uint64) {
        return observedAt > allowance ? observedAt - allowance : 0;
    }

    /// @dev Refuses evidence dated further ahead than the profile allows, so a
    ///      longer-lived token cannot hold a name longer.
    function _requireNotAhead(uint64 observedAt) internal view {
        uint64 limit = uint64(block.timestamp) + _futureObservationAllowance();
        if (observedAt > limit) revert ObservedInTheFuture(observedAt, limit);
    }

    /// @dev A 32-byte value as two big-endian 16-byte field elements.
    function _halves(bytes32[] memory inputs, uint256 at, bytes32 value) internal pure {
        inputs[at] = value >> 128;
        inputs[at + 1] = bytes32(uint256(uint128(uint256(value))));
    }

    /// @dev Verify the proof under the stored verifier, which must still be this
    ///      implementation's circuit's (REQ-COMMON-45).
    function _requireProof(bytes memory proof, bytes32[] memory publicInputs) internal view {
        IHonkVerifier verifier = _base().honkVerifier;
        bytes32 circuit = _circuitCodehash();
        if (address(verifier).codehash != circuit) revert WrongCircuit(circuit, address(verifier).codehash);
        if (!verifier.verify(proof, publicInputs)) revert BadProof();
    }

    /// @dev Only the owner can upgrade.
    function _authorizeUpgrade(address) internal override onlyOwner {}

    /// @dev Renouncing would leave no way to rotate a trust root.
    function renounceOwnership() public pure override {
        revert("renounce disabled");
    }
}

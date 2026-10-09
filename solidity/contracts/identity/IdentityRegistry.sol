// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

import {ICeremony} from "../ceremony/ICeremony.sol";
import {IProofVerifier} from "../ceremony/IProofVerifier.sol";
import {HandleNormalizer} from "../handles/HandleNormalizer.sol";
import {HandlePlatforms} from "../handles/HandlePlatforms.sol";
import {IIdentityRegistry} from "./IIdentityRegistry.sol";
import {IdentityList} from "./IdentityList.sol";

/// @title IdentityRegistry - proof-derived identities for any address.
/// @notice Binds an identity's id node and handle node to the holder its proof names.
/// @dev A proof binds only the caller it names; the owner can neither write nor move a
///      binding, but chooses the Proof Verifier and can upgrade (UUPS). The digest is the
///      nullifier (REQ-COMMON-03A); `observedAt` orders proofs of one node.
contract IdentityRegistry is
    IIdentityRegistry,
    Initializable,
    UUPSUpgradeable,
    Ownable2StepUpgradeable,
    ReentrancyGuardUpgradeable
{
    using IdentityList for IdentityList.Data;

    /// @notice A node's holder, and the moment the platform stated it.
    /// @dev `observedAt` is the provider's time, less the profile's future allowance.
    struct Binding {
        address holder;
        uint64 observedAt;
    }

    /// @notice One identity a holder proved, as its list reports it.
    /// @dev `handleCurrent` is false once another identity proved `handleNode`.
    struct Identity {
        bytes32 platformId;
        bytes32 idNode;
        bytes32 handleNode;
        bool handleCurrent;
    }

    // ─── State ──────────────────────────────────────────────────────

    /// @custom:storage-location erc7201:libid.storage.IdentityRegistry
    struct IdentityRegistryStorage {
        /// idNode -> the holder that proved that id. Ids are hashed verbatim, never folded.
        mapping(bytes32 => Binding) idBindings;
        /// handleNode -> the holder that last proved that handle.
        mapping(bytes32 => Binding) handleBindings;
        /// holder -> platformId -> the handle it disclosed as its name there.
        mapping(address => mapping(bytes32 => string)) published;
        /// idNode -> the handle node that identity last proved, and back.
        /// The reverse map lets a rename retire only a handle still pointing here.
        mapping(bytes32 => bytes32) handleNodeById;
        mapping(bytes32 => bytes32) idNodeByHandle;
        /// The Proof Verifier, which owns the Supported Version Set.
        IProofVerifier proofVerifier;
        /// platformId -> has any identity ever been bound on it. Never cleared.
        mapping(bytes32 => bool) everBound;
        /// Every Authorization Digest this Consumer has accepted (REQ-COMMON-03A).
        mapping(bytes32 => bool) spentDigests;
        /// holder -> its id nodes, on every platform.
        IdentityList.Data holderIdentities;
        /// idNode -> the platform it was proved on.
        mapping(bytes32 => bytes32) platformOfId;
    }

    // keccak256(abi.encode(uint256(keccak256("libid.storage.IdentityRegistry")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant IDENTITY_REGISTRY_STORAGE =
        0x3e5d6a26bfa3232a8c483e2003eb4b3008d01c0d1cf6c69b6ad133fd72694000;

    /// @dev ERC-7201 storage root. Fields may only be appended on upgrade.
    function _s() private pure returns (IdentityRegistryStorage storage $) {
        assembly {
            $.slot := IDENTITY_REGISTRY_STORAGE
        }
    }

    // ─── Storage reads ──────────────────────────────────────────────

    /// @notice The holder that proved this id node, and when it proved it.
    function idBinding(bytes32 idNode) external view returns (address holder, uint64 observedAt) {
        Binding storage b = _s().idBindings[idNode];
        return (b.holder, b.observedAt);
    }

    /// @notice The holder that last proved this handle node, and when.
    function handleBinding(bytes32 handleNode) external view returns (address holder, uint64 observedAt) {
        Binding storage b = _s().handleBindings[handleNode];
        return (b.holder, b.observedAt);
    }

    function nodeKeyed() external pure returns (bool) {
        return true;
    }

    // ─── Events ─────────────────────────────────────────────────────

    /// @notice An identity was bound. A disclosed handle is in `HandlePublished`.
    event IdentityBound(
        address indexed holder,
        bytes32 indexed idNode,
        bytes32 indexed handleNode,
        bytes32 platformId,
        uint64 observedAt,
        uint16 ceremonyVersion
    );

    /// @notice What a ceremony carried that a binding does not keep.
    /// @dev `clientIdentifier` is logged so an operator can trace bindings to a client.
    event CeremonyBound(
        bytes32 indexed authorizationDigest, address indexed holder, bytes32 indexed platformId, bytes clientIdentifier
    );

    /// @notice The service fee named by a binding's own Authorized Transaction
    ///         Data was delivered.
    event BindFeePaid(bytes32 indexed authorizationDigest, address indexed receiver, uint256 amount);

    /// @notice A handle stopped resolving because the identity that had it
    ///         proved a different one.
    /// @dev Nobody else's entry can be retired this way. See `bind`.
    event HandleRetired(bytes32 indexed platformId, bytes32 indexed handleNode, address indexed holder);

    /// @notice This Consumer was pointed at a Proof Verifier.
    event ProofVerifierConfigured(address verifier);

    /// @notice A holder disclosed its normalized handle as its name on a platform.
    event HandlePublished(
        address indexed holder, bytes32 indexed platformId, bytes32 indexed handleNode, string handle
    );

    /// @notice A holder withdrew its published handle.
    event HandleUnpublished(address indexed holder, bytes32 indexed platformId);

    // ─── Errors ─────────────────────────────────────────────────────

    /// The platform is not in `handles.json`, or a resolver's platform cannot be used.
    error UnknownPlatform(bytes32 platformId);

    /// @notice The one operation this Consumer owns (REQ-COMMON-01A).
    bytes32 public constant OPERATION_DOMAIN = keccak256(bytes("libid.claim-identity"));

    error ZeroAddress();
    /// @dev The submission names an operation this Consumer does not own
    ///      (REQ-COMMON-06A).
    error ForeignOperationDomain(bytes32 operationDomain);
    /// @dev A digest is spendable once here (REQ-COMMON-03A).
    error DigestAlreadySpent(bytes32 digest);
    /// @dev Transaction data is not exactly `(target, feeAmount, feeReceiver)` (REQ-COMMON-01F).
    error BadTransactionData(uint256 length);
    /// @dev Less was delivered than the verification path alone costs.
    error WrongBindValue(uint256 required, uint256 provided);
    /// @dev The value above the verification path is not the authorized fee.
    error WrongFeeValue(uint256 required, uint256 provided);
    /// @dev A free binding is `(0, address(0))` and nothing else.
    error NoncanonicalFee(uint256 amount, address receiver);
    /// @dev The fee receiver refused the value; the binding reverts.
    error FeeTransferFailed(address receiver, uint256 amount);
    /// The proof names a different address than the caller.
    error NotProofTarget(address proved, address caller);
    /// The proof carries no observation time, so it cannot be ordered.
    error NoObservationTime();
    /// The proof names no id node. A binding is anchored on the id.
    error NoId();
    /// The proof names no handle node.
    error NoHandle();
    /// A newer proof already wrote one of these nodes.
    error StaleProof(uint64 observedAt, uint64 known);
    /// The disclosed handle hashes to a node the caller does not hold.
    error NotYourHandle(bytes32 handleNode);

    // ─── Setup ──────────────────────────────────────────────────────

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address owner_) external initializer {
        __Ownable_init(owner_);
        __Ownable2Step_init();
        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();
    }

    // ─── Binding ────────────────────────────────────────────────────

    /// @notice Bind an identity from a ceremony, publishing its handle if the payload discloses it.
    /// @dev `msg.value` is `quoteBind` plus the fee the transaction data names.
    function bind(bytes32 platformId, uint16 verifierVersion, bytes calldata payload) external payable nonReentrant {
        _requireKnown(platformId);

        IProofVerifier pv = _s().proofVerifier;
        uint256 required = pv.quote(platformId, verifierVersion);
        if (msg.value < required) revert WrongBindValue(required, msg.value);

        ICeremony.VerifiedClaim memory claimed = pv.verify{value: required}(platformId, verifierVersion, payload);

        if (claimed.operationDomain != OPERATION_DOMAIN) {
            revert ForeignOperationDomain(claimed.operationDomain);
        }

        if (_s().spentDigests[claimed.sessionId]) {
            revert DigestAlreadySpent(claimed.sessionId);
        }
        _s().spentDigests[claimed.sessionId] = true;

        if (claimed.transactionData.length != 96) {
            revert BadTransactionData(claimed.transactionData.length);
        }
        (address target, uint256 feeAmount, address feeReceiver) =
            abi.decode(claimed.transactionData, (address, uint256, address));
        if (target != msg.sender) revert NotProofTarget(target, msg.sender);

        if ((feeAmount == 0) != (feeReceiver == address(0))) {
            revert NoncanonicalFee(feeAmount, feeReceiver);
        }

        uint256 offered = msg.value - required;
        if (offered != feeAmount) revert WrongFeeValue(feeAmount, offered);

        if (claimed.idNode == bytes32(0)) revert NoId();
        if (claimed.handleNode == bytes32(0)) revert NoHandle();
        if (claimed.metadataObservedAt == 0) revert NoObservationTime();

        _write(platformId, claimed.idNode, claimed.handleNode, claimed.metadataObservedAt, claimed.ceremonyVersion);
        if (bytes(claimed.handle).length != 0) _name(platformId, claimed.handleNode, claimed.handle);

        emit CeremonyBound(claimed.sessionId, msg.sender, platformId, claimed.clientIdentifier);

        if (feeAmount != 0) {
            (bool paid,) = feeReceiver.call{value: feeAmount}("");
            if (!paid) revert FeeTransferFailed(feeReceiver, feeAmount);
            emit BindFeePaid(claimed.sessionId, feeReceiver, feeAmount);
        }
    }

    /// @notice What `bind` costs for this platform and verifier version, before
    ///         any service fee the submission names.
    function quoteBind(bytes32 platformId, uint16 verifierVersion) external view returns (uint256) {
        return _s().proofVerifier.quote(platformId, verifierVersion);
    }

    /// @notice Whether this Consumer has already accepted a digest.
    function digestSpent(bytes32 digest) external view returns (bool) {
        return _s().spentDigests[digest];
    }

    /// @notice The Proof Verifier this Consumer routes every proof through.
    function proofVerifier() external view returns (IProofVerifier) {
        return _s().proofVerifier;
    }

    /// @notice Point this Consumer at a Proof Verifier.
    function setProofVerifier(IProofVerifier verifier) external onlyOwner {
        if (address(verifier) == address(0)) revert ZeroAddress();
        _s().proofVerifier = verifier;
        emit ProofVerifierConfigured(address(verifier));
    }

    function _write(bytes32 platformId, bytes32 idNode, bytes32 handleNode, uint64 observedAt, uint16 ceremonyVersion)
        private
    {
        IdentityRegistryStorage storage $ = _s();
        $.everBound[platformId] = true;

        Binding memory bound = $.idBindings[idNode];
        _requireNewer(observedAt, bound.observedAt);
        _requireNewer(observedAt, $.handleBindings[handleNode].observedAt);

        $.idBindings[idNode] = Binding({holder: msg.sender, observedAt: observedAt});
        $.handleBindings[handleNode] = Binding({holder: msg.sender, observedAt: observedAt});

        _retirePreviousHandle(platformId, idNode, handleNode);
        $.handleNodeById[idNode] = handleNode;
        $.idNodeByHandle[handleNode] = idNode;

        if (bound.holder == address(0)) {
            $.holderIdentities.add(msg.sender, idNode);
            $.platformOfId[idNode] = platformId;
        } else if (bound.holder != msg.sender) {
            $.holderIdentities.remove(bound.holder, idNode);
            $.holderIdentities.add(msg.sender, idNode);
        }

        emit IdentityBound(msg.sender, idNode, handleNode, platformId, observedAt, ceremonyVersion);
    }

    /// @dev Retire the handle node this identity wrote before, if it still
    ///      points back here. A node another identity has since proved is that
    ///      identity's, and is left alone.
    function _retirePreviousHandle(bytes32 platformId, bytes32 idNode, bytes32 handleNode) private {
        bytes32 previous = _s().handleNodeById[idNode];
        if (previous == bytes32(0) || previous == handleNode) return;
        if (_s().idNodeByHandle[previous] != idNode) return;

        _s().handleBindings[previous].holder = address(0);
        emit HandleRetired(platformId, previous, msg.sender);
    }

    // ─── Names ──────────────────────────────────────────────────────

    /// @notice Disclose the caller's handle on a platform as its name there.
    /// @dev The normalized handle must hash to a node the caller holds.
    function publish(bytes32 platformId, string calldata handle) external {
        _requireKnown(platformId);
        (string memory normalized, bytes32 handleNode) = HandlePlatforms.handleNodeOf(platformId, handle);
        if (_s().handleBindings[handleNode].holder != msg.sender) revert NotYourHandle(handleNode);
        _name(platformId, handleNode, normalized);
    }

    /// @notice Withdraw the caller's name on a platform.
    function unpublish(bytes32 platformId) external {
        _requireKnown(platformId);
        delete _s().published[msg.sender][platformId];
        emit HandleUnpublished(msg.sender, platformId);
    }

    /// @dev Store and log a checked, normalized handle as the caller's name.
    function _name(bytes32 platformId, bytes32 handleNode, string memory handle) private {
        _s().published[msg.sender][platformId] = handle;
        emit HandlePublished(msg.sender, platformId, handleNode, handle);
    }

    // ─── Guards ─────────────────────────────────────────────────────

    /// @dev A platform is known when `handles.json` names it.
    function _requireKnown(bytes32 platformId) private pure {
        if (!HandlePlatforms.knows(platformId)) revert UnknownPlatform(platformId);
    }

    /// @dev A resolver answers for a platform that is known and either has
    ///      bound something or can verify now.
    function _requireUsable(bytes32 platformId) private view {
        _requireKnown(platformId);
        if (_s().everBound[platformId]) return;

        IProofVerifier pv = _s().proofVerifier;
        if (address(pv) == address(0) || !pv.verifiesPlatform(platformId)) {
            revert UnknownPlatform(platformId);
        }
    }

    function _requireNewer(uint64 observedAt, uint64 known) private pure {
        if (observedAt <= known) revert StaleProof(observedAt, known);
    }

    // ─── Views ──────────────────────────────────────────────────────

    /// @notice The rules a handle on this platform normalizes with.
    function rulesOf(bytes32 platformId) external pure returns (HandleNormalizer.Rules memory) {
        _requireKnown(platformId);
        return HandlePlatforms.rulesFor(platformId);
    }

    /// @notice The tag this platform's handle nodes are hashed under.
    function handleTagOf(bytes32 platformId) external pure returns (bytes memory) {
        _requireKnown(platformId);
        return HandlePlatforms.handleTagFor(platformId);
    }

    /// @notice The node a handle is bound under, from the handle as typed.
    function handleNodeOf(bytes32 platformId, string calldata handle) external pure returns (bytes32) {
        _requireKnown(platformId);
        (HandleNormalizer.Problem problem, bytes32 handleNode) = HandlePlatforms.tryHandleNodeOf(platformId, handle);
        if (problem != HandleNormalizer.Problem.None) revert HandleNormalizer.UnusableHandle(problem);
        return handleNode;
    }

    /// @notice Whether a platform can be bound right now.
    function acceptsBindings(bytes32 platformId) external view returns (bool) {
        if (!HandlePlatforms.knows(platformId)) return false;
        IProofVerifier pv = _s().proofVerifier;
        return address(pv) != address(0) && pv.verifiesPlatform(platformId);
    }

    /// @notice The holder of an id node. An id node is
    ///         `SHA256(user-id tag || id)`; the id is never stored.
    function resolveId(bytes32 idNode) external view returns (address) {
        return _s().idBindings[idNode].holder;
    }

    /// @notice The holder of a handle as typed, or zero for text no binding
    ///         can have.
    function resolveHandle(bytes32 platformId, string calldata handle) external view returns (address) {
        _requireUsable(platformId);
        (HandleNormalizer.Problem problem, bytes32 handleNode) = HandlePlatforms.tryHandleNodeOf(platformId, handle);
        if (problem != HandleNormalizer.Problem.None) return address(0);
        return _s().handleBindings[handleNode].holder;
    }

    /// @notice The name a holder disclosed on a platform, while it still holds that handle.
    function publishedHandleOf(address holder, bytes32 platformId) external view returns (string memory) {
        _requireKnown(platformId);
        string memory published = _s().published[holder][platformId];
        if (bytes(published).length == 0) return "";
        bytes32 handleNode = HandleNormalizer.node(HandlePlatforms.handleTagFor(platformId), published);
        if (_s().handleBindings[handleNode].holder != holder) return "";
        return published;
    }

    /// @notice How many identities a holder has proved.
    function identityCount(address holder) external view returns (uint256) {
        return _s().holderIdentities.count(holder);
    }

    /// @notice A page of a holder's identities, on every platform.
    function identitiesOf(address holder, uint256 from, uint256 limit) external view returns (Identity[] memory out) {
        IdentityRegistryStorage storage $ = _s();
        bytes32[] memory nodes = $.holderIdentities.page(holder, from, limit);
        out = new Identity[](nodes.length);
        for (uint256 i = 0; i < nodes.length; i++) {
            bytes32 idNode = nodes[i];
            bytes32 handleNode = $.handleNodeById[idNode];
            out[i] = Identity({
                platformId: $.platformOfId[idNode],
                idNode: idNode,
                handleNode: handleNode,
                handleCurrent: $.idNodeByHandle[handleNode] == idNode
            });
        }
    }

    /// @notice The holder of a handle, and whether it also holds `idNode` on that platform.
    function resolveHandleAndId(bytes32 platformId, string calldata handle, bytes32 idNode)
        external
        view
        returns (address holder, bool idAgrees)
    {
        _requireUsable(platformId);
        (HandleNormalizer.Problem problem, bytes32 handleNode) = HandlePlatforms.tryHandleNodeOf(platformId, handle);
        if (problem != HandleNormalizer.Problem.None) return (address(0), false);
        return _resolveNodeAndId(platformId, handleNode, idNode);
    }

    /// @notice `resolveHandleAndId` for a handle node computed off chain, so
    ///         the handle itself never reaches the RPC.
    function resolveHandleNodeAndId(bytes32 platformId, bytes32 handleNode, bytes32 idNode)
        external
        view
        returns (address holder, bool idAgrees)
    {
        _requireUsable(platformId);
        return _resolveNodeAndId(platformId, handleNode, idNode);
    }

    function _resolveNodeAndId(bytes32 platformId, bytes32 handleNode, bytes32 idNode)
        private
        view
        returns (address holder, bool idAgrees)
    {
        holder = _s().handleBindings[handleNode].holder;
        idAgrees =
            holder != address(0) && _s().idBindings[idNode].holder == holder && _s().platformOfId[idNode] == platformId;
    }

    // ─── Upgrades ───────────────────────────────────────────────────

    function _authorizeUpgrade(address) internal override onlyOwner {}

    function renounceOwnership() public pure override {
        revert("renounce disabled");
    }
}

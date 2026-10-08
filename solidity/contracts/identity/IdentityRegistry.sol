// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

import {ICeremony} from "../ceremony/ICeremony.sol";
import {IProofVerifier} from "../ceremony/IProofVerifier.sol";
import {HandleNormalizer} from "../handles/HandleNormalizer.sol";
import {HandleVectors} from "../handles/HandleVectors.sol";
import {IIdentityRegistry} from "./IIdentityRegistry.sol";
import {IdentityList} from "./IdentityList.sol";

/// @title IdentityRegistry - proof-derived identities for any address.
///
/// @notice Binds two keys to a holder address: the node of an identity's
///         immutable id on a platform, and the node of its mutable handle.
///         Anyone may resolve either, and nothing here stores what a node
///         hashes unless its holder discloses it.
///
/// @dev The contract never calls the address it binds, so a target may be an
///      EOA, a Safe, an ERC-4337 smart wallet or a managed wallet. It knows
///      nothing about any of them, which is what makes it usable by a product
///      that is not ours.
///
///      Authorization is one rule: a proof states the address it was made out
///      to, and that address has to be the caller. Nothing else grants a
///      binding: there is no owner function that writes, moves or deletes an
///      entry in either mapping. An identity's own fresh proof retires the
///      handle that identity had before, and nobody else's — see `bind`.
///
///      **Binding can cost more than the verification path, and whoever
///      consented set the price.** A proof also states a service fee and the
///      address to pay it to, both inside the digest it opens against.
///      Composing a ceremony by hand names no fee, so a binding made that way
///      costs only the Notary Fees; a ceremony composed by a hosted
///      application names what that application charges, and whoever consented
///      saw that number, because changing it after the fact changes the
///      digest. This contract knows no application, holds no price list, and
///      takes no cut: it moves exactly what one submission authorized to
///      exactly the address that submission named.
///
///      **What the owner can still do, stated plainly.** It points this
///      contract at a Proof Verifier, whose owner registers the verifiers a
///      platform uses: registering one enables binding on a platform, retiring
///      its last version withdraws it. A verifier is trusted to report what a
///      proof says — so an owner that installs a dishonest verifier can mint
///      any binding. And the contract is UUPS, so the owner can replace all of
///      this. Read the guarantee above as "under honest configuration"; the
///      trust boundary is the owner key, and it is the same one every
///      upgradeable contract here has. Which platforms exist, and their rules
///      and tags, are NOT among the owner's levers: they are `HandleVectors`'
///      constants, generated from the same `handles.json` the circuits that
///      key bindings are built from, so this contract cannot disclose or
///      resolve under rules no circuit used.
///
///      **The keys come from the circuits.** A Platform Verifier returns
///      `idNode = SHA256(user-id tag || id)` and `handleNode = SHA256(handle tag
///      || fold(handle))`, which its proof binds to the values the platform
///      sent; this contract stores what it is given and computes neither from
///      plaintext on the binding path. The id and the handle are hidden by
///      default. "Hidden" means not disclosed, not unguessable: the tags are
///      public, so anyone holding a candidate handle or id can hash it and
///      look it up, which is how every resolver here works.
///
///      **A holder may disclose its handle, and only its own.** A
///      submission's payload may carry the handle, which its Platform
///      Verifier checks against the handle node its proof bound and returns
///      normalized; `publish` takes one later and runs the same check here,
///      against a handle node the caller holds. Both normalize with the
///      platform's rules and hash under its tag. A match proves the
///      bytes are the handle the circuit folded, so the name stored and
///      emitted is that handle. A disclosure is permanent in the transaction
///      that carried it: `unpublish` clears the stored name, not history.
///
///      **A platform has verifier versions, and handle rules it keeps across
///      all of them.** A platform's proof can change shape without the identity
///      behind it changing, so verifiers are keyed by version and several are
///      live at once during a migration. What does NOT vary by version is the
///      node a handle hashes to: two versions keying differently would put one
///      handle on two nodes.
///
///      Retiring a version stops new bindings in that format and touches no
///      binding already made — a binding belongs to the identity that proved
///      it, not to the format the proof was written in. Which ceremony version
///      proved a binding is logged, not stored: the proof has happened and the
///      effect has been applied by the time anybody asks, so the answer is for
///      an operator reading `IdentityBound`, and nothing on chain reads it.
///
///      **This contract does not know what a proof looks like.** `bind` takes
///      a platform, a verifier version and opaque bytes, and hands all three to
///      the Proof Verifier, which routes them to the one contract that does
///      know. What comes back is trusted the way that contract is trusted: it
///      extracted every field from evidence it authenticated, and the owner
///      installed it.
///
///      **The two mappings are separate on purpose.** One proof writes both, so
///      a consumer that holds an id and a handle can compare them later and
///      learn whether its copy is stale. Merging them into one map would remove
///      the only freshness signal the chain can give.
///
///      **The Authorization Digest is the nullifier.** `bind` records every
///      digest it accepts in `spentDigests` and refuses one already recorded
///      with `DigestAlreadySpent` (REQ-COMMON-03, REQ-COMMON-03A). An older
///      proof carries a digest of its own, so the `observedAt` watermark is
///      what stops it undoing a newer binding. Equal is not newer, so the
///      watermark also refuses a second proof of the same observation.
///
///      **There is no pause.** A pause is a lever over other people's bindings,
///      and nothing here needs one: no funds are held, and no address is
///      predicted ahead of its deployment.
///
///      **A holder's identities can be walked, and the walk is paid for by the
///      walker.** Every identity a holder proved sits in that holder's list,
///      whatever the platform, with the platform and the two nodes it has, so
///      a contract can enumerate what a holder is without an indexer and
///      without knowing which platforms exist. The list is kept by the id
///      rather than by the handle: a rename moves one pointer, a handle
///      passing to somebody else changes nothing in it, and only an identity
///      proved by a new holder moves between two lists. Each of those costs
///      the same whether the list holds four identities or four thousand. What
///      grows with the list is reading it, which is why it is read by page and
///      why a contract should never walk a list it did not choose the size of.
contract IdentityRegistry is
    IIdentityRegistry,
    Initializable,
    UUPSUpgradeable,
    Ownable2StepUpgradeable,
    ReentrancyGuardUpgradeable
{
    using IdentityList for IdentityList.Data;

    /// @notice A node's holder, and the moment the platform stated it.
    ///
    /// @dev `observedAt` is a provider timestamp, never a chain timestamp. Two
    ///      proofs of one handle are ordered by when the platform said it, not
    ///      by when somebody got around to submitting.
    ///
    ///      It is that moment on the scale every platform shares: the Platform
    ///      Verifier subtracts its own profile's future allowance before it
    ///      returns, because profiles disagree about what "now" is. Raw values
    ///      would compare two clocks and the looser one would always win.
    struct Binding {
        address holder;
        uint64 observedAt;
    }

    /// @notice One identity a holder proved, as its list reports it.
    ///
    /// @dev `handleNode` is the one the identity proved most recently, and
    ///      `handleCurrent` says whether that node still points back at this
    ///      identity, which is what `bind` writes and what any other identity
    ///      proving the same handle overwrites. Once it is false the node stays
    ///      as the last thing this identity was known as, and the flag says
    ///      not to route by it. The handle itself is the holder's to disclose:
    ///      `publishedHandleOf`.
    struct Identity {
        bytes32 platformId;
        bytes32 idNode;
        bytes32 handleNode;
        bool handleCurrent;
    }

    // ─── State ──────────────────────────────────────────────────────

    /// @custom:storage-location erc7201:libid.storage.IdentityRegistry
    struct IdentityRegistryStorage {
        /// idNode -> the holder that proved that id.
        ///
        /// The id reaches the node verbatim. A handle is folded on the way
        /// in; an id is not, and must not be -- any normalization risks
        /// folding two identities into one. A verifier built on another API
        /// of the same platform (GitHub's GraphQL `node_id` beside its REST
        /// `id`) would key the same person on another node; that is settled
        /// where a verifier is reviewed, not here.
        mapping(bytes32 => Binding) idBindings;
        /// handleNode -> the holder that last proved that handle.
        mapping(bytes32 => Binding) handleBindings;
        /// holder -> platformId -> the handle it disclosed as its name there.
        ///
        /// A node cannot be turned back into a string, so a name needs the
        /// string itself, and only its holder can supply it. One per wallet
        /// per platform, written only by a disclosure and cleared only by
        /// `unpublish`.
        mapping(address => mapping(bytes32 => string)) published;
        /// idNode -> the handle node that identity last proved, and back.
        ///
        /// An identity has one handle at a time. When it proves a new one the
        /// old one has to stop resolving, or a payment meant for whoever has
        /// that handle now would keep going to the holder that renamed away
        /// from it. The reverse map answers "is this node still the one this
        /// identity wrote", so a second identity that took the handle in the
        /// meantime keeps it.
        mapping(bytes32 => bytes32) handleNodeById;
        mapping(bytes32 => bytes32) idNodeByHandle;
        /// The one component this Consumer calls to verify a proof.
        ///
        /// One address, not a version set. The Supported Version Set lives at
        /// the Proof Verifier, because a Consumer holding its own copy would
        /// be a second version-governance surface free to drift from it.
        IProofVerifier proofVerifier;
        /// platformId -> has any identity ever been bound on it.
        ///
        /// Set once and never cleared: it answers "was this platform ever able
        /// to verify", which a retirement cannot make false in retrospect.
        mapping(bytes32 => bool) everBound;
        /// Every Authorization Digest this Consumer has accepted.
        ///
        /// The digest is its own replay nullifier, and recording belongs to the
        /// party the operation authorizes (REQ-COMMON-03A). Recording it at the
        /// Proof Verifier instead would let anyone observing a submission call
        /// first, consume the digest, and leave this contract nothing to apply
        /// -- a denial of service costing the attacker only a fee.
        mapping(bytes32 => bool) spentDigests;
        /// holder -> its id nodes, on every platform.
        IdentityList.Data holderIdentities;
        /// idNode -> the platform it was proved on. A node names no platform
        /// by itself, and a list of nodes tells a reader nothing without one.
        mapping(bytes32 => bytes32) platformOfId;
    }

    // keccak256(abi.encode(uint256(keccak256("libid.storage.IdentityRegistry")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant IDENTITY_REGISTRY_STORAGE =
        0x3e5d6a26bfa3232a8c483e2003eb4b3008d01c0d1cf6c69b6ad133fd72694000;

    /// @dev All state of this contract sits under one namespaced root, like
    ///      every upgradeable contract in this repo. It cannot collide with the
    ///      ERC-7201 namespaces of the OpenZeppelin upgradeable bases, and a
    ///      field may be APPENDED on upgrade without slot arithmetic. Do not
    ///      reorder or remove one: both would make an upgraded proxy read every
    ///      stored value out of the wrong bytes, and a struct read from the
    ///      wrong bytes does not revert — it answers.
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

    // ─── Events ─────────────────────────────────────────────────────

    /// @notice An identity was bound. It carries the two nodes and nothing
    ///         they hash: a disclosed handle is `HandlePublished`, beside it.
    event IdentityBound(
        address indexed holder,
        bytes32 indexed idNode,
        bytes32 indexed handleNode,
        bytes32 platformId,
        uint64 observedAt,
        uint16 ceremonyVersion
    );

    /// @notice What a ceremony carried that a binding does not keep.
    ///
    /// @dev `clientIdentifier` is the exact bytes the platform authenticated.
    ///      The contract has no use for them: the digest already binds the
    ///      transaction. But an operator answering "which application produced
    ///      these bindings", after a client is found compromised, has no other
    ///      source -- the value exists only inside the call that writes the
    ///      binding.
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

    /// @notice A holder disclosed its handle on a platform, which is now its
    ///         name there. `handle` is normalized, and hashes to `handleNode`.
    event HandlePublished(
        address indexed holder, bytes32 indexed platformId, bytes32 indexed handleNode, string handle
    );

    /// @notice A holder withdrew its published handle. The transaction that
    ///         disclosed it stays public.
    event HandleUnpublished(address indexed holder, bytes32 indexed platformId);

    // ─── Errors ─────────────────────────────────────────────────────

    /// `handles.json` names no such platform, or a resolver was asked about
    /// one that has never bound and cannot verify now.
    error UnknownPlatform(bytes32 platformId);
    /// Text the platform's rules refuse, with the normalizer's reason.
    error UnusableHandle(HandleNormalizer.Problem problem);

    /// @notice The one operation this Consumer owns.
    ///
    /// @dev A new operation, or a change to what its transaction data means,
    ///      takes a NEW domain string rather than another digest field
    ///      (REQ-COMMON-01A). A digest is spendable once at EACH Consumer
    ///      accepting this domain, so two deployments choosing the same string
    ///      share a digest space.
    bytes32 public constant OPERATION_DOMAIN = keccak256(bytes("libid.claim-identity"));

    error ZeroAddress();
    /// @dev The submission names an operation this Consumer does not own
    ///      (REQ-COMMON-06A).
    error ForeignOperationDomain(bytes32 operationDomain);
    /// @dev A digest is spendable once here (REQ-COMMON-03A).
    error DigestAlreadySpent(bytes32 digest);
    /// @dev The Authorized Transaction Data of this operation is exactly the
    ///      triple `(address target, uint256 feeAmount, address feeReceiver)`;
    ///      trailing bytes and other shapes are refused (REQ-COMMON-01F).
    error BadTransactionData(uint256 length);
    /// @dev Less was delivered than the verification path alone costs.
    error WrongBindValue(uint256 required, uint256 provided);
    /// @dev What was delivered above the verification path is not the fee the
    ///      digest authorized. Over and under are both refused.
    error WrongFeeValue(uint256 required, uint256 provided);
    /// @dev A free binding is `(0, address(0))` and nothing else.
    error NoncanonicalFee(uint256 amount, address receiver);
    /// @dev The receiver the ceremony named refused the value. Nothing is
    ///      written: a binding that cannot pay its fee did not happen.
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
    /// The disclosed handle hashes to a node the caller does not hold: it is
    /// not the handle the caller proved, or the caller's binding of it has
    /// since passed to someone else. Disclose the handle the platform shows
    /// for your account, as it shows it.
    error NotYourHandle(bytes32 handleNode);
    /// The Platform Verifier returned a disclosed handle that does not hash,
    /// under the platform's tag, to the handle node it returned with it. A
    /// verifier that checked its disclosure never returns this pair; the name
    /// slot is written only with a handle that names the node it is stored
    /// against.
    error DisclosureMismatch(bytes32 disclosed, bytes32 bound);

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

    /// @notice Bind an identity from a ceremony, optionally disclosing its
    ///         handle as the caller's name on the platform.
    ///
    /// @dev The CONSUMER of ceremony-common section 5.1, and only that. It
    ///      owns the operation domain, records the digest, enforces the
    ///      authorization predicate and applies the effect. Dispatch and the
    ///      Notary Fee path belong to the Proof Verifier; decoding and
    ///      verifying the payload belong to the Platform Verifier the route
    ///      ends at. This function does not know what `payload` is.
    ///
    ///      The value attached is `quoteBind` for the same pair plus the
    ///      service fee the submission's own Authorized Transaction Data
    ///      names, which is zero for a ceremony composed by hand.
    ///
    ///      **The two nodes are the verifier's.** It returns them as its proof
    ///      bound them; nothing here hashes an id or a handle to bind it.
    ///
    ///      **An identity can only retire its own handle.** When it proves a
    ///      new handle, the one it had before stops resolving -- but only if
    ///      that node still points back at this identity.
    ///
    ///      **A disclosed handle comes with the claim.** The payload may carry
    ///      the handle; the Platform Verifier checked it against the handle
    ///      node its proof bound and returns it normalized, and it becomes the
    ///      caller's name on the platform, as `publish` would make it. The name
    ///      slot is this contract's, so it hashes the returned handle under the
    ///      platform's tag once more and refuses one that does not name the
    ///      returned node (`DisclosureMismatch`).
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
        if (bytes(claimed.handle).length != 0) {
            bytes32 disclosed = HandleNormalizer.node(HandleVectors.handleTagFor(platformId), claimed.handle);
            if (disclosed != claimed.handleNode) revert DisclosureMismatch(disclosed, claimed.handleNode);
            _name(platformId, claimed.handleNode, claimed.handle);
        }

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
    ///
    /// @dev The handle is normalized with the platform's rules -- `Alice` and
    ///      `alice` are one handle -- hashed under the platform's tag, and must
    ///      be the handle node the caller holds. A match proves the bytes are
    ///      the handle the circuit folded and the platform sent; the name
    ///      stored and emitted is the normalized form.
    ///
    ///      One name per wallet per platform: a second disclosure replaces the
    ///      first. The calldata is public whatever happens, so a refused call
    ///      still shows the handle it carried.
    function publish(bytes32 platformId, string calldata handle) external {
        _requireKnown(platformId);
        (string memory normalized, bytes32 handleNode) =
            HandleNormalizer.nodeOf(handle, HandleVectors.rulesFor(platformId), HandleVectors.handleTagFor(platformId));
        if (_s().handleBindings[handleNode].holder != msg.sender) revert NotYourHandle(handleNode);
        _name(platformId, handleNode, normalized);
    }

    /// @notice Withdraw the caller's name on a platform. The transaction that
    ///         disclosed it stays public. Reverts `UnknownPlatform` for a
    ///         platform `handles.json` does not name.
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

    /// @dev The node typed text names on a platform, or why it names none.
    function _tryNodeOf(bytes32 platformId, string calldata handle)
        private
        pure
        returns (HandleNormalizer.Problem problem, bytes32 handleNode)
    {
        string memory normalized;
        (problem, normalized) = HandleNormalizer.tryNormalize(handle, HandleVectors.rulesFor(platformId));
        if (problem == HandleNormalizer.Problem.None) {
            handleNode = HandleNormalizer.node(HandleVectors.handleTagFor(platformId), normalized);
        }
    }

    // ─── Guards ─────────────────────────────────────────────────────

    /// @dev A platform is one `handles.json` names: its rules and tags are the
    ///      generated constants, and there is nothing to configure.
    function _requireKnown(bytes32 platformId) private pure {
        if (!HandleVectors.knows(platformId)) revert UnknownPlatform(platformId);
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
        return HandleVectors.rulesFor(platformId);
    }

    /// @notice The tag this platform's handle nodes are hashed under.
    function handleTagOf(bytes32 platformId) external pure returns (bytes memory) {
        _requireKnown(platformId);
        return HandleVectors.handleTagFor(platformId);
    }

    /// @notice The node a handle is bound under, from the handle as typed.
    ///
    /// @dev Reverts `UnusableHandle` for text no binding can have, and
    ///      `UnknownPlatform` for a platform `handles.json` does not name. A caller
    ///      paying a handle should compute this once and keep the node: an
    ///      escrow deposit is keyed by it.
    function handleNodeOf(bytes32 platformId, string calldata handle) external pure returns (bytes32) {
        _requireKnown(platformId);
        (HandleNormalizer.Problem problem, bytes32 handleNode) = _tryNodeOf(platformId, handle);
        if (problem != HandleNormalizer.Problem.None) revert UnusableHandle(problem);
        return handleNode;
    }

    /// @notice Whether a platform can be bound right now.
    function acceptsBindings(bytes32 platformId) external view returns (bool) {
        if (!HandleVectors.knows(platformId)) return false;
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
        (HandleNormalizer.Problem problem, bytes32 handleNode) = _tryNodeOf(platformId, handle);
        if (problem != HandleNormalizer.Problem.None) return address(0);
        return _s().handleBindings[handleNode].holder;
    }

    /// @notice The name a holder disclosed on a platform, while it still
    ///         holds that handle; empty otherwise. Reverts `UnknownPlatform`
    ///         for a platform `handles.json` does not name.
    function publishedHandleOf(address holder, bytes32 platformId) external view returns (string memory) {
        _requireKnown(platformId);
        string memory published = _s().published[holder][platformId];
        if (bytes(published).length == 0) return "";
        bytes32 handleNode = HandleNormalizer.node(HandleVectors.handleTagFor(platformId), published);
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

    /// @notice The holder of a handle, and whether the same holder proved
    ///         this id node on the same platform -- whether a consumer's
    ///         (handle, id) pair is still one identity.
    function resolveHandleAndId(bytes32 platformId, string calldata handle, bytes32 idNode)
        external
        view
        returns (address holder, bool idAgrees)
    {
        _requireUsable(platformId);
        (HandleNormalizer.Problem problem, bytes32 handleNode) = _tryNodeOf(platformId, handle);
        holder = problem == HandleNormalizer.Problem.None ? _s().handleBindings[handleNode].holder : address(0);
        idAgrees =
            holder != address(0) && _s().idBindings[idNode].holder == holder && _s().platformOfId[idNode] == platformId;
    }

    // ─── Upgrades ───────────────────────────────────────────────────

    function _authorizeUpgrade(address) internal override onlyOwner {}

    function renounceOwnership() public pure override {
        revert("renounce disabled");
    }
}

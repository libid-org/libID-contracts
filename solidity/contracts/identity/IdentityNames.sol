// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

import {ICeremony} from "../ceremony/ICeremony.sol";
import {IProofVerifier} from "../ceremony/IProofVerifier.sol";
import {HandleNormalizer} from "./HandleNormalizer.sol";
import {IIdentityNames} from "./IIdentityNames.sol";
import {IdentityList} from "./IdentityList.sol";
import {IdentityNodes} from "./IdentityNodes.sol";

/// @title IdentityNames - proof-derived identities for any wallet.
///
/// @notice Binds two things to a holder address: an identity's immutable id
///         on a platform, and its mutable handle. Anyone may resolve either.
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
///      **What the owner can still do, stated plainly.** It configures which
///      verifiers a platform uses, and a verifier is trusted to report what a
///      proof says — so an owner that installs a dishonest verifier can mint
///      any binding. It can also change a platform's normalization rules, which
///      moves every handle already written to another node: the old entries
///      survive but no longer answer the public resolvers. And the contract is
///      UUPS, so the owner can replace all of this. Read the guarantee above as
///      "under honest configuration"; the trust boundary is the owner key, and
///      it is the same one every upgradeable contract here has.
///
///      **A platform has verifier versions, and a keyspace it keeps across all
///      of them.** A platform's proof can change shape without the identity
///      behind it changing — X gaining OIDC, say — so verifiers are keyed by
///      version and several are live at once during a migration. What does
///      NOT vary by version is `rules`: it decides the node a handle hashes to,
///      and two versions normalizing differently would put one handle on two
///      nodes and make `resolveHandle` answer differently depending on which
///      version last wrote.
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
///      **There is no nullifier.** A binding is idempotent, so replaying a
///      proof would rewrite the same value; the danger is an older proof
///      undoing a newer one, and the `observedAt` watermark refuses that. A
///      replay carries the same timestamp, so the same rule refuses it too.
///
///      **There is no pause.** A pause is a lever over other people's bindings,
///      and nothing here needs one: no funds are held, and no address is
///      predicted ahead of its deployment.
///
///      **A holder's identities can be walked, and the walk is paid for by the
///      walker.** Every identity a holder proved sits in that holder's list,
///      whatever the platform, with the platform, the id and the handle it
///      has, so a contract can enumerate what a holder is without an indexer
///      and without knowing which platforms exist. The list is kept by the id
///      rather than by the handle: a rename moves one pointer, a handle
///      passing to somebody else changes nothing in it, and only an identity
///      proved by a new holder moves between two lists. Each of those costs
///      the same whether the list holds four identities or four thousand. What
///      grows with the list is reading it, which is why it is read by page and
///      why a contract should never walk a list it did not choose the size of.
contract IdentityNames is
    IIdentityNames,
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
    /// @dev `handle` is the one the identity proved most recently, and
    ///      `handleCurrent` says whether the handle node still points back at
    ///      this identity, which is what `bind` writes and what any other
    ///      identity proving the same handle overwrites. Once it is false the
    ///      string stays as the last thing this identity was known as, and the
    ///      flag says not to route by it. The flag reads the nodes, so a
    ///      change to the platform's rules, which moves handles to other
    ///      nodes, is seen by `resolveHandle` before it is seen here.
    struct Identity {
        bytes32 platformId;
        string id;
        string handle;
        bool handleCurrent;
    }

    /// @notice What an id node hashes: its platform and its id.
    struct IdentityPreimage {
        bytes32 platformId;
        string id;
    }

    /// @notice A platform this contract accepts proofs for: its keyspace.
    ///
    /// @dev What lives here is what every version of a platform's proof must
    ///      agree on. `rules` decides the node a handle hashes to, so it CANNOT
    ///      vary by version — two versions normalizing differently would put
    ///      one handle on two nodes, and `resolveHandle` would answer
    ///      differently depending on which version last wrote. That is a split
    ///      namespace wearing the costume of a config option.
    ///
    ///      **The id follows from what a version is.** A version is another
    ///      way to prove the SAME identity — a notarized session, an OIDC token
    ///      — not another id space. The identity did not change, so its id did
    ///      not change, and `bind` puts every version on the same
    ///      `idNode(platformId, attested.userId)`.
    ///
    ///      Read that as a test, not as a rule to remember: a proof format that
    ///      reports a different id is not proving the same identity, so it is
    ///      not a version of this platform. It is a second platform, and it
    ///      wants its own `platformId` and its own keyspace.
    ///
    ///      **The id reaches the node verbatim.** A handle passes through
    ///      `rules` on the way in; an id does not, and must not — any
    ///      normalization risks folding two identities into one, which is worse
    ///      than the drift it would fix. So a verifier has to report the id
    ///      exactly as the provider issues it, down to the byte: a stray quote,
    ///      a prefix or a space writes a different node.
    ///
    ///      The trap is not exotic. A provider often has two immutable ids for
    ///      one identity — GitHub's REST `id` (`20213174`) and its GraphQL
    ///      `node_id` (`MDQ6VXNlcjIwMjEzMTc0`) — and a verifier built on the
    ///      other API picks up the other one without anybody making a mistake.
    ///
    ///      The usual cost is not a stolen handle; those two never collide. It
    ///      is that one person now has two id nodes: neither binding supersedes
    ///      the other, a rename through one leaves the handle bound under the
    ///      other resolving, and `resolveId` answers differently depending on
    ///      which id the caller happens to have.
    ///
    ///      A string carries no provenance, so nothing on chain can catch this.
    ///      It is settled where a verifier is reviewed, next to "does it lie
    ///      about the identity" — not in configuration, which sees an address
    ///      and nothing else.
    ///
    /// @param rules      How this platform's handles normalize.
    /// @param configured Whether the platform exists at all. A platform whose
    ///                   every version has been retired still has its
    ///                   keyspace, so "is it wired" cannot be read off the
    ///                   Supported Version Set.
    struct Platform {
        HandleNormalizer.Rules rules;
        bool configured;
    }

    // ─── State ──────────────────────────────────────────────────────

    /// @custom:storage-location erc7201:libid.storage.IdentityNames
    struct IdentityNamesStorage {
        /// idNode -> the holder that proved that id.
        mapping(bytes32 => Binding) idBindings;
        /// handleNode -> the holder that last proved that handle.
        mapping(bytes32 => Binding) handleBindings;
        /// holder -> platformId -> the handle it published, if it chose to.
        ///
        /// A node cannot be turned back into a string, so the reverse direction
        /// needs the string itself. Publishing is optional: the event carries
        /// the plaintext either way, so an indexer never needs this, and only a
        /// contract that must display a handle does.
        mapping(address => mapping(bytes32 => string)) published;
        /// platformId -> its keyspace: handle rules, and whether it is configured.
        mapping(bytes32 => Platform) platforms;
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
        // ── The ceremony path. `proofVerifier` takes the index the retired
        //    `verifiers` mapping held, which is safe only because a mapping's
        //    base slot is never written; `everBound` and `spentDigests` are
        //    appended after everything above.
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
        // ── The identity lists, appended after everything above.
        /// holder -> its id nodes, on every platform.
        IdentityList.Data holderIdentities;
        /// idNode -> its platform, and the id byte for byte as the platform
        /// issued it.
        ///
        /// A node cannot be turned back into what it hashes, and a list of
        /// nodes tells a reader nothing. This is the plaintext behind one.
        mapping(bytes32 => IdentityPreimage) idPreimages;
        /// handleNode -> the handle, as normalized on the way in.
        mapping(bytes32 => string) handlePreimages;
    }

    // keccak256(abi.encode(uint256(keccak256("libid.storage.IdentityNames")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant IDENTITY_NAMES_STORAGE =
        0x064503501234cc9c6e116cf4a84c07475158dabb6a3dcee437a89227e23bf200;

    /// @dev All state of this contract sits under one namespaced root, like
    ///      every upgradeable contract in this repo. Three things follow.
    ///
    ///      It cannot collide with the ERC-7201 namespaces of the OpenZeppelin
    ///      upgradeable bases, so this contract owns its slots outright and
    ///      needs no reserved gap.
    ///
    ///      A field may be APPENDED on upgrade without slot arithmetic. Do not
    ///      reorder or remove one: both would make an upgraded proxy read every
    ///      stored value out of the wrong bytes, and a struct read from the
    ///      wrong bytes does not revert — it answers.
    ///
    ///      And moving here from sequential slots abandons the old ones, so a
    ///      proxy upgraded onto this without re-running `setPlatform` reads a
    ///      root that has never been written: every platform comes back
    ///      unconfigured and every resolver reverts `UnknownPlatform`. Loud and
    ///      uniform, rather than one platform silently answering with rules
    ///      parsed out of an address.
    function _s() private pure returns (IdentityNamesStorage storage $) {
        assembly {
            $.slot := IDENTITY_NAMES_STORAGE
        }
    }

    // ─── Storage reads (the ABI the public variables gave) ─────────

    /// @notice The holder that proved this id, and when it proved it.
    function idBinding(bytes32 idNode) external view returns (address holder, uint64 observedAt) {
        Binding storage b = _s().idBindings[idNode];
        return (b.holder, b.observedAt);
    }

    /// @notice The same for a handle node.
    function handleBinding(bytes32 handleNode) external view returns (address holder, uint64 observedAt) {
        Binding storage b = _s().handleBindings[handleNode];
        return (b.holder, b.observedAt);
    }

    // ─── Events ─────────────────────────────────────────────────────

    /// @notice A holder proved an identity.
    ///
    /// @dev The plaintext rides along so an indexer or a browser can build
    ///      reverse resolution without the on-chain string.
    ///
    ///      `published` says whether the handle is the holder's published
    ///      handle after this bind. Without it the log cannot reconstruct
    ///      `published` at all: only `unpublish` would be observable, so an
    ///      indexer would have to guess which bindings a holder chose to show.
    ///      `ceremonyVersion` names the protocol revision that proved the
    ///      binding, as the verifier reported it. It lives in the log and not
    ///      in storage: nothing on chain acts on it, and what an operator needs
    ///      it for -- which bindings a ceremony version later found unsound
    ///      touched, whether anybody still depends on one before retiring it --
    ///      is answered by reading the log.
    event IdentityBound(
        address indexed holder,
        bytes32 indexed idNode,
        bytes32 indexed handleNode,
        bytes32 platformId,
        string id,
        string handle,
        uint64 observedAt,
        bool published,
        uint16 ceremonyVersion
    );

    /// @notice What a ceremony carried that a binding does not keep.
    ///
    /// @dev Beside `IdentityBound`, not inside it: the binding keeps no
    ///      client identifier, so carrying one on `IdentityBound` would give
    ///      every indexer a field to test for emptiness.
    ///
    ///      `clientIdentifier` is the exact bytes the platform authenticated.
    ///      The contract has no use for them: the digest already binds the
    ///      transaction. But an operator answering "which application produced
    ///      these bindings", after a client is found compromised, has no other
    ///      source -- the value exists only inside the call that writes the
    ///      binding. The digest keys it, because the digest is what identifies
    ///      one ceremony.
    event CeremonyBound(
        bytes32 indexed authorizationDigest, address indexed holder, bytes32 indexed platformId, bytes clientIdentifier
    );

    /// @notice The service fee named by a binding's own Authorized Transaction
    ///         Data was delivered.
    ///
    /// @dev Emitted only when there is one. A ceremony composed by hand names
    ///      no fee and pays only the verification path; one composed by a
    ///      hosted application names what that application charges, and that
    ///      number was approved at consent time, because it is inside the
    ///      digest the proof opens against.
    event BindFeePaid(bytes32 indexed authorizationDigest, address indexed receiver, uint256 amount);

    /// @notice A handle stopped resolving because the identity that had it
    ///         proved a different one.
    /// @dev Nobody else's entry can be retired this way. See `bind`.
    event HandleRetired(bytes32 indexed platformId, bytes32 indexed handleNode, address indexed holder);

    /// @notice A platform's keyspace was configured or reconfigured.
    /// @dev Reconfiguring `rules` moves every handle already written to
    ///      another node.
    event PlatformConfigured(bytes32 indexed platformId);

    /// @notice This Consumer was pointed at a Proof Verifier.
    event ProofVerifierConfigured(address verifier);

    /// @notice A holder withdrew its published handle.
    /// @dev An indexer that mirrors the published handles needs this to stop
    ///      showing one.
    event HandleUnpublished(address indexed holder, bytes32 indexed platformId);

    // ─── Errors ─────────────────────────────────────────────────────

    // `UnknownPlatform` and `UnusableHandle` are declared in `IIdentityNames`.
    /// @notice The one operation this Consumer owns.
    ///
    /// @dev A new operation, or a change to what its transaction data means,
    ///      takes a NEW domain string rather than another digest field
    ///      (REQ-COMMON-01A). The string survives this repository's move from
    ///      one address to the triple below because nothing had built a
    ///      submission against it yet: there is no earlier reading anywhere to
    ///      separate a new one from, and a string spent for that is a string
    ///      spent for nothing. The rule binds from here -- the next change to
    ///      what this data means takes a new string.
    ///
    ///      Note the consequence the specification is candid about: a digest
    ///      is spendable once at EACH Consumer accepting this domain, so two
    ///      deployments choosing the same string share a digest space.
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
    ///      digest authorized. Over and under are both refused: there is no
    ///      refund path, and a caller who could overpay would be funding an
    ///      address the ceremony named, beyond what it consented to.
    error WrongFeeValue(uint256 required, uint256 provided);
    /// @dev A free binding is `(0, address(0))` and nothing else. A receiver
    ///      beside a zero amount is a second encoding of one intent, and an
    ///      amount beside no receiver would burn it.
    error NoncanonicalFee(uint256 amount, address receiver);
    /// @dev The receiver the ceremony named refused the value or ran out of
    ///      gas taking it. Nothing is written: the fee was authorized as part
    ///      of this binding, so a binding that cannot pay it did not happen.
    error FeeTransferFailed(address receiver, uint256 amount);
    /// The proof names a different address than the caller.
    error NotProofTarget(address proved, address caller);
    /// The proof carries no observation time, so it cannot be ordered.
    error NoObservationTime();
    /// The proof names no id. A binding is anchored on the id.
    error NoId();
    /// A newer proof already wrote one of these nodes.
    error StaleProof(uint64 observedAt, uint64 known);

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

    /// @notice Add a platform or change how its handles normalize.
    ///
    /// @dev Owner-managed, and this is the keyspace half: it says what a handle
    ///      on this platform means, not how a proof of one is read. See the
    ///      contract comment for the whole of what the owner's power is — in
    ///      particular, changing `rules` moves handles already written to
    ///      other nodes.
    ///
    ///      A platform is never removed. The bindings would stay in storage
    ///      while every resolver began reverting `UnknownPlatform`, which is
    ///      worse than a platform whose versions have all been retired: that
    ///      one still resolves what it holds and merely accepts nothing new.
    function setPlatform(bytes32 platformId, HandleNormalizer.Rules calldata rules) external onlyOwner {
        Platform storage platform = _s().platforms[platformId];
        platform.rules = rules;
        platform.configured = true;
        emit PlatformConfigured(platformId);
    }

    // ─── Binding ────────────────────────────────────────────────────

    /// @notice Bind an identity from a ceremony.
    ///
    /// @dev The CONSUMER of ceremony-common section 5.1, and only that. It
    ///      owns the operation domain, records the digest, enforces the
    ///      authorization predicate and applies the effect. Dispatch and the
    ///      Notary Fee path belong to the Proof Verifier, which is a contract
    ///      of its own so a second Consumer does not become a second
    ///      version-governance surface; decoding and verifying the payload
    ///      belong to the Platform Verifier the route ends at.
    ///
    ///      This function does not know what `payload` is. It names the
    ///      platform and the verifier version -- this chain's slot for that
    ///      platform, not the ceremony version inside the proof -- and passes
    ///      the bytes through.
    ///
    ///      The value attached is `quoteBind` for the same pair plus the
    ///      service fee the submission's own Authorized Transaction Data
    ///      names, which is zero for a ceremony composed by hand. Exact value
    ///      at every hop needs no refund path, so no partial-failure rule is
    ///      required and nothing can be captured in transit.
    function bind(bytes32 platformId, uint16 verifierVersion, bytes calldata payload, bool publish)
        external
        payable
        nonReentrant
    {
        Platform memory platform = _requireConfigured(platformId);

        IProofVerifier pv = _s().proofVerifier;
        uint256 required = pv.quote(platformId, verifierVersion);
        // Only the floor is knowable here: the fee rides in the payload, which
        // is the Platform Verifier's to decode. A shortfall would otherwise
        // surface as an out-of-funds revert from the call below, with nothing
        // for an operator to read.
        if (msg.value < required) revert WrongBindValue(required, msg.value);

        ICeremony.VerifiedClaim memory claimed = pv.verify{value: required}(platformId, verifierVersion, payload);

        // ── Is this operation ours at all? (REQ-COMMON-06A) ───────────
        //
        // What AUTHENTICATES the domain is the Platform Verifier: it rebuilt
        // the Authorization Digest from this value and the proof opened
        // against that digest -- through the revealed `code_verifier` for X
        // and GitHub, through a public input for Google. Name another domain
        // and the digest changes, so no proof opens against it. This
        // comparison is the Consumer's own duty on top of that: a verifier
        // reports what it read, and this contract applies an effect only for
        // the operation it owns.
        if (claimed.operationDomain != OPERATION_DOMAIN) {
            revert ForeignOperationDomain(claimed.operationDomain);
        }

        // ── Spend the digest before any effect ────────────────────────
        //
        // Recording belongs here rather than one hop up: at the Proof Verifier
        // anyone watching a submission could call first, consume the digest,
        // and leave this contract nothing to apply -- denial of service for the
        // price of a fee (REQ-COMMON-03A).
        //
        // "Before any effect" is true of the WRITE below, but the digest only
        // becomes known from the call above it, so the nullifier cannot be set
        // before that call returns. `nonReentrant` is what closes the window
        // rather than callee goodwill: without it a Platform Verifier could
        // reenter here, find the digest unspent, and be relying on the outer
        // frame reverting.
        if (_s().spentDigests[claimed.sessionId]) {
            revert DigestAlreadySpent(claimed.sessionId);
        }
        _s().spentDigests[claimed.sessionId] = true;

        // ── The authorization predicate ───────────────────────────────
        //
        // The Authorized Transaction Data of this operation is a triple: the
        // holder the identity binds to, and the service fee that holder
        // approved. Requiring the target to be the authenticated caller is what
        // keeps consent-phishing out of identity theft -- binding to a
        // submitter-supplied address instead would let anyone spend a genuine
        // proof at an address of their choosing.
        if (claimed.transactionData.length != 96) {
            revert BadTransactionData(claimed.transactionData.length);
        }
        (address target, uint256 feeAmount, address feeReceiver) =
            abi.decode(claimed.transactionData, (address, uint256, address));
        if (target != msg.sender) revert NotProofTarget(target, msg.sender);

        // One encoding per intent (REQ-COMMON-01F): a free binding is
        // `(0, address(0))`. The two halves stand or fall together, so a
        // receiver beside a zero amount and an amount beside no receiver are
        // both refused rather than silently normalized.
        if ((feeAmount == 0) != (feeReceiver == address(0))) {
            revert NoncanonicalFee(feeAmount, feeReceiver);
        }

        // Whatever was delivered above the verification path is the fee, and it
        // has to be the number inside the digest -- not less, and not more.
        // Nobody consented to more, and there is nowhere to return it to.
        // `required` was already forwarded, so this cannot underflow.
        uint256 offered = msg.value - required;
        if (offered != feeAmount) revert WrongFeeValue(feeAmount, offered);

        if (bytes(claimed.userId).length == 0) revert NoId();
        if (claimed.metadataObservedAt == 0) revert NoObservationTime();

        _write(
            platformId,
            claimed.userId,
            claimed.handle,
            // Already on the shared scale, and already below the profile's own
            // ceiling: the Platform Verifier owns both, because only it knows
            // what "now" means for the evidence it read.
            claimed.metadataObservedAt,
            publish,
            platform,
            claimed.ceremonyVersion
        );

        emit CeremonyBound(claimed.sessionId, msg.sender, platformId, claimed.clientIdentifier);

        // ── The one call out, after every effect ──────────────────────
        //
        // The receiver is an address the ceremony named, not one this contract
        // knows, so it gets what an unknown callee gets: every write already
        // done behind it, and `nonReentrant` in front of it on the way back.
        // `call` rather than `transfer`, because a receiver that hosts an
        // application is more likely to be a contract than an EOA.
        if (feeAmount != 0) {
            (bool paid,) = feeReceiver.call{value: feeAmount}("");
            if (!paid) revert FeeTransferFailed(feeReceiver, feeAmount);
            emit BindFeePaid(claimed.sessionId, feeReceiver, feeAmount);
        }
    }

    /// @notice What `bind` requires to be delivered for this pair.
    ///
    /// @dev Asked of the Proof Verifier rather than worked out here: quoting
    ///      covers the whole path -- two Notary Fees on X and GitHub, zero on
    ///      Google -- and a Consumer that computed it would need to know the
    ///      path's topology (REQ-COMMON-06E).
    ///
    ///      This is the verification path only. A caller adds the service fee
    ///      named by its own submission, which no quotation could know: it is
    ///      chosen per ceremony by whoever composed it, and authorized by the
    ///      digest rather than by anything on this chain.
    function quoteBind(bytes32 platformId, uint16 verifierVersion) external view returns (uint256) {
        return _s().proofVerifier.quote(platformId, verifierVersion);
    }

    /// @notice Whether this digest has already been spent here.
    function digestSpent(bytes32 digest) external view returns (bool) {
        return _s().spentDigests[digest];
    }

    /// @notice The Proof Verifier this Consumer calls.
    function proofVerifier() external view returns (IProofVerifier) {
        return _s().proofVerifier;
    }

    /// @notice Point this Consumer at a Proof Verifier.
    ///
    /// @dev The Supported Version Set is not this contract's to hold. Which
    ///      proof statements the chain accepts is governance's decision over
    ///      there, and a Consumer keeping its own copy would be a second such
    ///      decision, free to drift.
    function setProofVerifier(IProofVerifier verifier) external onlyOwner {
        if (address(verifier) == address(0)) revert ZeroAddress();
        _s().proofVerifier = verifier;
        emit ProofVerifierConfigured(address(verifier));
    }

    /// @dev Everything after authentication. Which proof established a
    ///      binding is `bind`'s business; the keyspace, the ordering and the
    ///      display are decided here.
    function _write(
        bytes32 platformId,
        string memory id,
        string memory rawHandle,
        uint64 observedAt,
        bool publish,
        Platform memory platform,
        uint16 ceremonyVersion
    ) private {
        // This platform has now verified something, and no later retirement of
        // its versions makes that untrue. The resolvers read it so a binding
        // outlives the format that established it.
        _s().everBound[platformId] = true;

        // `observedAt` arrives already on the shared scale. Profiles disagree
        // about what "now" is -- a notary states wall-clock time, an OIDC claim
        // carries the token's `exp` and runs about an hour ahead -- and the
        // nodes are shared, so raw values would compare two clocks and the
        // looser one would win every time. The Platform Verifier subtracts its
        // own allowance before returning, because only it knows the evidence it
        // read. Subtracting again here would push one platform below every
        // other.

        // Normalize here rather than trusting the verifier or the caller. The
        // node has to come from the same transform every reader uses.
        string memory handle = HandleNormalizer.normalize(rawHandle, platform.rules);

        bytes32 idNode = IdentityNodes.idNode(platformId, id);
        bytes32 handleNode = IdentityNodes.handleNode(platformId, handle);

        // Strictly newer than BOTH, which is what stops a proof held back from
        // undoing a newer one. It also stops a plain replay, because equal is
        // not newer.
        //
        // Checking the handle node too is the load-bearing half: after somebody
        // else proves this handle, an older proof of it must not take it back.
        Binding memory bound = _s().idBindings[idNode];
        _requireNewer(observedAt, bound.observedAt);
        _requireNewer(observedAt, _s().handleBindings[handleNode].observedAt);

        _s().idBindings[idNode] = Binding({holder: msg.sender, observedAt: observedAt});
        _s().handleBindings[handleNode] = Binding({holder: msg.sender, observedAt: observedAt});

        _retirePreviousHandle(platformId, idNode, handleNode);
        _s().handleNodeById[idNode] = handleNode;
        _s().idNodeByHandle[handleNode] = idNode;

        _list(platformId, idNode, handleNode, id, handle, bound.holder);

        // Publishing follows the holder's own handle, rather than the flag's
        // default. A caller that re-proves after a rename must not keep
        // displaying the handle it no longer has, and `publish: false` must
        // not silently withdraw the display either — so an existing
        // publication is refreshed, and only `unpublish` removes one.
        bool published = publish || bytes(_s().published[msg.sender][platformId]).length != 0;
        if (published) {
            _s().published[msg.sender][platformId] = handle;
        }

        emit IdentityBound(
            msg.sender, idNode, handleNode, platformId, id, handle, observedAt, published, ceremonyVersion
        );
    }

    /// @dev Put the identity just bound in the caller's list, and keep the
    ///      plaintext behind its nodes.
    ///
    ///      An identity enters a list on its first proof and leaves it only
    ///      for another list, so `idBindings` says which case this is: no
    ///      holder yet, a first proof; another holder, a move. Each node's
    ///      preimage is written once, and a handle's may already be there from
    ///      an earlier holder.
    function _list(
        bytes32 platformId,
        bytes32 idNode,
        bytes32 handleNode,
        string memory id,
        string memory handle,
        address previousHolder
    ) private {
        IdentityNamesStorage storage $ = _s();
        if (previousHolder == address(0)) {
            $.holderIdentities.add(msg.sender, idNode);
            $.idPreimages[idNode] = IdentityPreimage({platformId: platformId, id: id});
        } else if (previousHolder != msg.sender) {
            $.holderIdentities.remove(previousHolder, idNode);
            $.holderIdentities.add(msg.sender, idNode);
        }
        if (bytes($.handlePreimages[handleNode]).length == 0) $.handlePreimages[handleNode] = handle;
    }

    /// @dev Stop resolving the handle this identity had before.
    ///
    ///      A rename is invisible to the chain until somebody proves the new
    ///      state, and this bind is that proof: the identity states it has a
    ///      different handle now, so the old one must stop routing to this
    ///      holder. Leaving it would send a payment meant for whoever has that
    ///      handle today to the holder that renamed away from it.
    ///
    ///      Only the entry this identity itself wrote is retired. If somebody
    ///      else has since proved that handle, `idNodeByHandle` names their
    ///      identity and the entry is left alone — which also covers one
    ///      holder with two identities on a platform, where the second may
    ///      have taken the handle the first released.
    ///
    ///      The holder is cleared, the watermark is kept. Deleting the whole
    ///      record would drop the node back to `observedAt == 0` and let a
    ///      proof older than the one just retired take it — the exact ordering
    ///      `_requireNewer` exists to enforce.
    function _retirePreviousHandle(bytes32 platformId, bytes32 idNode, bytes32 handleNode) private {
        bytes32 previous = _s().handleNodeById[idNode];
        if (previous == bytes32(0) || previous == handleNode) return;
        if (_s().idNodeByHandle[previous] != idNode) return;

        _s().handleBindings[previous].holder = address(0);
        emit HandleRetired(platformId, previous, msg.sender);
    }

    /// @notice Withdraw a published handle. Affects the caller's record only.
    ///
    /// @dev Publishing is the one thing here a holder can undo, and it needs
    ///      its own door. Passing `publish: false` to `bind` does NOT clear an
    ///      earlier publish — a caller that binds again after a rename should
    ///      not silently withdraw a handle because a flag defaulted; it
    ///      refreshes the published string to the handle just proved.
    ///      Withdrawing what you chose to display must not depend on being able
    ///      to log in again.
    ///
    ///      The binding itself stays. This clears the on-chain string, not the
    ///      proof that binds the identity to its holder, and the
    ///      `IdentityBound` event that carried the plaintext is already public
    ///      and always will be. Read this as "stop displaying it here", not as
    ///      erasure.
    function unpublish(bytes32 platformId) external {
        delete _s().published[msg.sender][platformId];
        emit HandleUnpublished(msg.sender, platformId);
    }

    /// @dev The write path's gate: the keyspace exists, and nothing more. What
    ///      may be claimed against it is the Proof Verifier's question, and it
    ///      is asked there.
    function _requireConfigured(bytes32 platformId) private view returns (Platform memory platform) {
        platform = _s().platforms[platformId];
        if (!platform.configured) revert UnknownPlatform(platformId);
    }

    /// @dev A resolver answers once the platform has both halves: a keyspace,
    ///      and a way to verify. `configured` alone is not enough — between
    ///      `setPlatform` and the first registered version a platform has a
    ///      keyspace and can verify nothing, and answering `address(0)` there
    ///      would tell a caller "nobody proved this" about a platform that is
    ///      not wired yet.
    function _requireUsable(bytes32 platformId) private view returns (Platform memory platform) {
        platform = _requireConfigured(platformId);
        // `everBound` first: it is a storage read the resolvers already make,
        // and it settles every identity already bound. "Can verify" moves, and
        // governance retiring the last version of a platform must not stop
        // those bindings resolving -- a binding does not belong to the proof
        // that established it.
        //
        // The Proof Verifier holds the Supported Version Set, so it is asked
        // rather than mirrored. It is an external call, so it is asked only
        // when the local answer says nothing.
        if (_s().everBound[platformId]) return platform;

        IProofVerifier pv = _s().proofVerifier;
        if (address(pv) == address(0) || !pv.verifiesPlatform(platformId)) {
            revert UnknownPlatform(platformId);
        }
    }

    function _requireNewer(uint64 observedAt, uint64 known) private pure {
        if (observedAt <= known) revert StaleProof(observedAt, known);
    }

    // ─── Reading ────────────────────────────────────────────────────

    // `rulesOf`, `handleHashOf` and `handleNodeOf` answer keyspace questions,
    // so they need a keyspace and nothing more: they agree with each other,
    // and keep answering before a platform's first verifier and after its
    // last.

    /// @notice The platform's normalization rules as configured now, for a
    ///         client that normalizes locally. Reverts `UnknownPlatform`.
    function rulesOf(bytes32 platformId) external view returns (HandleNormalizer.Rules memory) {
        return _requireConfigured(platformId).rules;
    }

    /// @notice `keccak256` of a handle normalized under the platform's current
    ///         rules: the `handleHash` `HandleEscrow.deposit` takes.
    /// @dev Reverts `UnusableHandle` for text the rules refuse (where
    ///      `resolveHandle` answers zero).
    function handleHashOf(bytes32 platformId, string calldata handle) public view returns (bytes32 handleHash) {
        (HandleNormalizer.Problem problem, string memory normalized) =
            HandleNormalizer.tryNormalize(handle, _requireConfigured(platformId).rules);
        if (problem != HandleNormalizer.Problem.None) revert UnusableHandle(problem);
        return keccak256(bytes(normalized));
    }

    /// @notice The node a handle hashes to under the platform's current rules,
    ///         with `handleHashOf`'s reverts.
    function handleNodeOf(bytes32 platformId, string calldata handle) external view returns (bytes32) {
        return handleNodeOfHash(platformId, handleHashOf(platformId, handle));
    }

    /// @notice The node of a handle given as its hash: what `bind` binds and
    ///         `handleBinding` reads. Unchecked; any hash has a node.
    function handleNodeOfHash(bytes32 platformId, bytes32 handleHash) public pure returns (bytes32) {
        return IdentityNodes.handleNodeOfHash(platformId, handleHash);
    }

    /// @notice Whether `bind` can bind a holder on this platform now: a
    ///         keyspace, and a Proof Verifier that verifies it. Unlike the
    ///         resolvers, false after every version is retired.
    function acceptsBindings(bytes32 platformId) external view returns (bool) {
        if (!_s().platforms[platformId].configured) return false;
        IProofVerifier pv = _s().proofVerifier;
        return address(pv) != address(0) && pv.verifiesPlatform(platformId);
    }

    /// @notice The holder that proved this id, or the zero address.
    ///
    /// @dev Reverts for a platform with no verifier, like the other two
    ///      resolvers. Returning the zero address there would answer "nobody
    ///      proved this" to a question that was never asked — the platform is
    ///      not wired — and a caller cannot tell the two apart from a zero.
    function resolveId(bytes32 platformId, string calldata id) external view returns (address) {
        _requireUsable(platformId);
        return _s().idBindings[IdentityNodes.idNode(platformId, id)].holder;
    }

    /// @notice The holder that last proved this handle, or the zero address.
    ///
    /// @dev Takes the handle as written. Normalization happens here, so a
    ///      caller cannot reach a node by hashing the handle its own way.
    ///
    ///      Total in the handle: text the platform's rules refuse answers the
    ///      zero address, not a revert. A contract resolving whatever was typed
    ///      into a recipient field would otherwise fail the whole transaction
    ///      on a stray space, with a library error it cannot tell apart from
    ///      `UnknownPlatform`. An unwired platform still reverts, because that
    ///      question was never asked.
    function resolveHandle(bytes32 platformId, string calldata handle) external view returns (address) {
        Platform memory platform = _requireUsable(platformId);
        (HandleNormalizer.Problem problem, bytes32 handleNode) = _handleNode(platformId, handle, platform.rules);
        return problem == HandleNormalizer.Problem.None ? _s().handleBindings[handleNode].holder : address(0);
    }

    /// @dev The node a handle hashes to under the given rules, or the problem
    ///      that stops the text normalizing under them (and a zero node).
    function _handleNode(bytes32 platformId, string memory handle, HandleNormalizer.Rules memory rules)
        private
        pure
        returns (HandleNormalizer.Problem problem, bytes32 handleNode)
    {
        string memory normalized;
        (problem, normalized) = HandleNormalizer.tryNormalize(handle, rules);
        if (problem == HandleNormalizer.Problem.None) handleNode = IdentityNodes.handleNode(platformId, normalized);
    }

    /// @notice The handle a holder published, but only while it still resolves
    ///         back to that holder. Empty otherwise.
    ///
    /// @dev This is the forward check ENS requires of its integrators, done
    ///      here so an integrator cannot skip it. Their reverse records can lie,
    ///      because anyone may set their own; ours cannot, because a proof
    ///      wrote it. Ours can still go stale, which needs the same check: after
    ///      a rename, a holder's published handle may belong to somebody else.
    ///      The stored string is re-normalized rather than hashed as it stands.
    ///      It was normalized when it was written, but under the rules of that
    ///      moment: after the owner narrows a platform's rules, hashing it
    ///      as-is would reach a node the forward resolver can no longer name,
    ///      and this would keep handing out a handle `resolveHandle` refuses.
    function publishedHandleOf(address holder, bytes32 platformId) external view returns (string memory) {
        string memory published = _s().published[holder][platformId];
        if (bytes(published).length == 0) return "";
        (HandleNormalizer.Problem problem, bytes32 handleNode) =
            _handleNode(platformId, published, _s().platforms[platformId].rules);
        if (problem != HandleNormalizer.Problem.None) return "";
        if (_s().handleBindings[handleNode].holder != holder) return "";
        return published;
    }

    /// @notice How many identities a holder has, on every platform together.
    function identityCount(address holder) external view returns (uint256) {
        return _s().holderIdentities.count(holder);
    }

    /// @notice A page of a holder's identities, on every platform together.
    ///
    /// @dev The page is the indices `[from, from + limit)`, counted from
    ///      zero and clipped to the list. A `from` past the end answers an
    ///      empty page. Reading costs about six storage loads per identity
    ///      returned, so the whole of a list is only for a caller that chose
    ///      the list, and a contract reading a holder it did not choose keeps
    ///      `limit` small. A reader that wants one platform filters a page by
    ///      `platformId`, which keeps a read bounded by the page and never by
    ///      the list.
    ///
    ///      Order is arbitrary and changes when an identity leaves the list,
    ///      so two pages read across a removal may overlap or skip. A reader
    ///      that needs every identity reads `identityCount` and the pages in
    ///      one block.
    ///
    ///      `handleCurrent` is decided by the handle node pointing back at
    ///      this identity, which is what `bind` writes and what a takeover by
    ///      any other identity overwrites -- including a second identity of the
    ///      same holder, where the holder still holds the handle node and a
    ///      holder check alone would report both identities as holding it.
    function identitiesOf(address holder, uint256 from, uint256 limit) external view returns (Identity[] memory out) {
        IdentityNamesStorage storage $ = _s();
        bytes32[] memory nodes = $.holderIdentities.page(holder, from, limit);
        out = new Identity[](nodes.length);
        for (uint256 i = 0; i < nodes.length; i++) {
            bytes32 idNode = nodes[i];
            bytes32 handleNode = $.handleNodeById[idNode];
            IdentityPreimage storage preimage = $.idPreimages[idNode];
            out[i] = Identity({
                platformId: preimage.platformId,
                id: preimage.id,
                handle: $.handlePreimages[handleNode],
                handleCurrent: $.idNodeByHandle[handleNode] == idNode
            });
        }
    }

    /// @notice Resolve a handle, and say whether the caller's id agrees.
    ///
    /// @dev The whole point of the two mappings. A consumer has a
    ///      `(handle, id)` pair it learned at some moment; this reports
    ///      whether the chain still puts them together.
    ///
    ///      Disagreement is not corruption. It means somebody proved the handle
    ///      after the caller learned who held it. It is also NOT a reason to
    ///      refuse a transfer: a handle that will not route is not a handle.
    ///      The caller reads this before it signs and decides what to tell
    ///      whoever is paying.
    ///
    /// @return holder    The handle's holder, or the zero address.
    /// @return idAgrees  True only when the id resolves to that same holder.
    function resolveHandleAndId(bytes32 platformId, string calldata handle, string calldata id)
        external
        view
        returns (address holder, bool idAgrees)
    {
        Platform memory platform = _requireUsable(platformId);

        (HandleNormalizer.Problem problem, bytes32 handleNode) = _handleNode(platformId, handle, platform.rules);
        holder = problem == HandleNormalizer.Problem.None ? _s().handleBindings[handleNode].holder : address(0);

        address idHolder = _s().idBindings[IdentityNodes.idNode(platformId, id)].holder;
        // An unknown id does not agree either. A caller with an id the chain
        // has never seen is exactly as uninformed as one with a stale id.
        idAgrees = holder != address(0) && idHolder == holder;
    }

    // ─── Upgrade ────────────────────────────────────────────────────

    function _authorizeUpgrade(address) internal override onlyOwner {}

    /// @dev Renouncing would freeze platform configuration forever, which
    ///      leaves no way to replace a verifier whose provider changed.
    function renounceOwnership() public pure override {
        revert("renounce disabled");
    }
}

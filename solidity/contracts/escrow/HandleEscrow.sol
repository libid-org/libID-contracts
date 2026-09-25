// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

import {HandleNormalizer} from "../identity/HandleNormalizer.sol";
import {IdentityNodes} from "../identity/IdentityNodes.sol";
import {IIdentityNames} from "./IIdentityNames.sol";

/// @title HandleEscrow - send to a platform handle before anybody claims it.
///
/// @notice Holds tokens against a platform handle. Whoever the naming system
///         names as that handle's holder takes what is held for it; until
///         the holder takes it, each depositor can take its own deposit back.
///
/// @dev The point is a sender who knows `@alice` and nothing else. The Bank's
///      escrow is keyed by an account's immutable id, which such a sender does
///      not have, so this keys by the handle.
///
///      **The key is the naming system's handle node.** A slot is
///      `IdentityNodes.handleNode(platformId, normalized)`, the node
///      `IdentityNames` stores the binding under and emits as
///      `IdentityBound.handleNode`. A claim is authorized by
///      `names.byHandle(node).owner` and nothing else, so the escrow and the
///      naming system agree on who holds a slot by construction, and an
///      indexer joins `Deposited.handleNode` to `IdentityBound.handleNode`.
///      No event here carries the handle's text.
///
///      **A payment to a holder is routed; a payment to nobody is escrowed,
///      and an escrow can be refunded.** A deposit for a node somebody holds
///      goes straight to that holder and nothing here can bring it back. A
///      deposit for a node nobody holds is booked to its depositor, and the
///      depositor may take its own contribution back with `refund` until the
///      holder collects it: refundable until collected. Whether the node has
///      a holder yet plays no part. There is no deadline: the refund is open
///      from the deposit onwards, and it closes only when the node's holder
///      `claim`s. A claim takes everything held for the node in that token,
///      so what it took is nobody's to refund afterwards.
///
///      The refund is the sender's protection against a holder it did not
///      mean: a recycled handle, or a stale binding (below), can make the
///      holder somebody else, and the sender can take the value back until
///      that holder claims it.
///
///      **There is no refund delay, and the race with the payee is
///      accepted.** A depositor can take a deposit back at any time after
///      making it, the same block included, and after the payee holds the
///      handle, so held value promises the payee nothing until the payee
///      claims it. A refund and
///      the payee's `claim` here can land in the same block. Whichever lands
///      first wins: the refund returns the contribution and the claim takes
///      the rest, or the claim takes everything and the refund is refused
///      with `NothingToRefund`. Both are outcomes of an escrow.
///
///      **The handle is the whole key.** Whoever holds the node takes what
///      was not refunded. A PLATFORM THAT RECYCLES A HANDLE HANDS THE NEW
///      HOLDER WHATEVER ITS DEPOSITORS LEFT HELD FOR THE PREVIOUS ONE AND
///      HAVE NOT TAKEN BACK. A rename retires the handle: its node has no
///      holder again, the account that renamed away can no longer claim, and
///      what nobody claimed waits for whoever proves the freed handle next,
///      or goes back to its depositors on `refund`.
///
///      **A stale binding is paid, and that is accepted.** `byHandle` names
///      whoever last proved the handle, however long ago. A rename is
///      invisible to the chain until the renamed account proves its new
///      handle: an account that proved `alice`, renamed to `alice2` on the
///      platform and never proved again is still `alice`'s holder here. A
///      deposit to `alice` pays straight through to it, and it can claim
///      anything held for `alice`, until somebody proves `alice` with a
///      newer observation — even if the platform has long since given the
///      handle to someone else. Value held for the node stays refundable to
///      its depositors until that holder claims it; a pay-through is not.
///      A wallet should show the binding's age, `byHandle(node).observedAt`,
///      before it sends.
///
///      **The escrow is for the window before a handle is claimed, and only
///      that.** A deposit for a node somebody holds is paid straight to that
///      holder; once an account has claimed its identity, holding the value
///      would add a claim transaction and reach the same wallet. So an escrow
///      slot is written only while nobody holds the node, and only on a
///      platform where a new claim can bind a holder (`acceptsClaims`):
///      anywhere else nothing could ever take what it would hold.
///
///      **Two ways in.** `depositToHandle` takes the handle as text,
///      normalizes it under the platform's current rules and refuses text no
///      rules accept. `depositToNode` takes the node itself and can validate
///      nothing; it exists so a payee whose handle must not appear in
///      calldata — a private, digest-profile binding — can still be paid.
///
///      **The platform's rules decide where text goes, not who holds a
///      node.** Normalization runs once, on the way in, under the rules of
///      the moment, exactly as the naming system's own resolvers run it. A
///      later `setPlatform` changes which node the same text reaches for both
///      contracts alike; value already held stays on its node and remains
///      claimable by whoever `byHandle` names there.
///
///      **The naming contract is set once and never moved.** Repointing it
///      would redirect every entitlement held, so changing it is an upgrade,
///      which leaves a record.
///
///      **There is no pause function; there are freeze levers.** A pause on
///      `claim` would freeze other people's money behind an owner key, so
///      there is none, and the emergency lever here is the upgrade, which is
///      visible. The naming side can still freeze value without touching this
///      contract. The `IdentityNames` owner's `setPlatform` can narrow a
///      platform's rules so that the handle a node was derived from now
///      normalizes to another node or is refused; retiring every version of
///      a platform's verifiers in `CeremonyProofVerifier` stops new claims on
///      it. Either leaves value held for a node nobody holds with no possible
///      claimer. A node that already has a holder is unaffected, since `claim`
///      goes by node and not by text. The depositor's `refund` is the way
///      out: it depends on neither the rules nor `acceptsClaims`.
///
///      **Rebasing tokens are not supported.** The books record what arrived
///      when it arrived. A token whose balances later shrink on their own — a
///      negative rebase — leaves this contract holding less than the books
///      promise, and the last claim or refund for that token reverts for want
///      of balance. There is no function that reconciles the books against a
///      balance.
///
///      **Surplus stays, and nothing sweeps it.** Value that reaches this
///      contract other than through a deposit sits on no slot, and no
///      function moves it; only an upgrade could. That is a token transferred
///      here directly, native value forced in without a call (there is no
///      `receive`, so only a self-destruct or a block reward can), and a
///      positive rebase. A fee-on-transfer token leaves no remainder: a
///      deposit is booked at what arrived.
///
///      **A token's blocklist reaches the escrow.** A recipient a token
///      refuses fails only its own payout: the `claim` or `refund` reverts,
///      the books stay as they were, and the caller can name another
///      recipient. A holder the token refuses fails a pay-through deposit.
///      But a token that blocklists this contract's address — USDC and USDT
///      can — freezes every slot in that token, deposits, claims and refunds
///      alike, until the token lifts it or an upgrade adds a way out.
///
///      **Trust base.** Authorization here is `byHandle` and nothing else, so
///      every key that can decide what `byHandle` answers, or replace the code
///      that asks it, can take what is held. Read every guarantee in this
///      contract as holding under honest holders of these keys:
///
///      * the `IdentityNames` owner — `setProofVerifier` to a verifier it
///        controls, or `upgradeToAndCall`;
///      * the `CeremonyProofVerifier` owner — `setVerifier` to register a
///        Platform Verifier it controls, or `upgradeToAndCall`;
///      * the `NotaryService` owner — `setNotary` to trust a notary key it
///        holds, whose attestations the X and GitHub Platform Verifiers and
///        `GoogleJwtRoots` rotations accept, or `upgradeToAndCall`;
///      * each Platform Verifier's owner (`XPlatformVerifier`,
///        `GitHubPlatformVerifier`, `GooglePlatformVerifier`) —
///        `setTrustRoots` to a Notary Service or Honk verifier it controls, or
///        `upgradeToAndCall`; for Google also `setJwtRoots`;
///      * the `GoogleJwtRoots` owner — `setNotaryService` to a Notary Service
///        it controls, whose attested key rotations the Google verifier then
///        trusts, or `upgradeToAndCall`;
///      * this contract's own owner — `upgradeToAndCall` to code that moves
///        any balance;
///      * every notary signing key the `NotaryService` trusts — it can sign
///        an attestation of an X or GitHub session that never happened, and a
///        `GoogleJwtRoots` rotation that installs a signing key of its choice
///        for Google tokens;
///      * the platforms themselves — Google as the OIDC issuer whose signing
///        keys sign the ID tokens the Google verifier accepts, and X and
///        GitHub as the TLS-authenticated APIs whose answers the notary
///        attests. Each decides which account a handle belongs to.
///
///      Anyone who can make themselves the holder of a funded handle can take
///      what is held for it. Each of the keys above does that through an
///      ordinary identity `claim`, which `claim` here then pays, except this
///      contract's owner, who replaces the code instead. They are the keys
///      that already decide which proofs bind names at all; the escrow adds a
///      new thing they can reach, not a new party.
///
///      Not on the list: the `HandleResolver` owner and its gateway signers
///      decide what an ENS lookup of a name answers, which this contract never
///      reads; the `LibidFactory` owner deploys contracts and has no call into
///      them afterwards. Neither can move a balance here.
contract HandleEscrow is Initializable, UUPSUpgradeable, Ownable2StepUpgradeable, ReentrancyGuardUpgradeable {
    using SafeERC20 for IERC20;

    /// @notice The native token of the chain, as a token address.
    address public constant NATIVE = address(0);

    /// @custom:storage-location erc7201:libid.storage.HandleEscrow
    struct HandleEscrowStorage {
        /// handle node -> token -> amount held.
        mapping(bytes32 => mapping(address => uint256)) held;
        /// The naming system this escrow resolves through. Set in `initialize`.
        IIdentityNames names;
        /// handle node -> token -> how many claims have emptied the slot.
        /// Contributions are booked under the current round, and a claim
        /// moves the slot to the next one, so what a claim took stops being
        /// anybody's to refund.
        mapping(bytes32 => mapping(address => uint256)) round;
        /// handle node -> token -> round -> depositor -> what that depositor
        /// put into the slot during that round and has not taken back. In the
        /// current round these sum to `held`.
        mapping(bytes32 => mapping(address => mapping(uint256 => mapping(address => uint256)))) contributions;
    }

    // keccak256(abi.encode(uint256(keccak256("libid.storage.HandleEscrow")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant HANDLE_ESCROW_STORAGE = 0xfcca8d7d2c66f78c2760f3fcd99e0bf938b0aeb0d0b471f481dd50b8aff6b400;

    /// @dev One namespaced root, as `IdentityNames` has. Fields may be
    ///      APPENDED on upgrade; reordering or removing one would make every
    ///      stored balance read out of the wrong bytes, and a balance read from
    ///      the wrong bytes does not revert — it answers.
    function _s() private pure returns (HandleEscrowStorage storage $) {
        assembly {
            $.slot := HANDLE_ESCROW_STORAGE
        }
    }

    // ─── Events ─────────────────────────────────────────────────────

    /// @notice Value was placed against a handle node nobody holds yet.
    /// @dev `platformId` is the one the depositor named. On `depositToNode`
    ///      nothing checks that the node belongs to it.
    event Deposited(
        bytes32 indexed handleNode, address indexed token, address indexed depositor, bytes32 platformId, uint256 amount
    );

    /// @notice A deposit for a handle node somebody already held was paid
    ///         straight to that holder, and never entered the books.
    /// @dev Distinct from `Deposited` on purpose: an indexer must be able to tell
    ///      "this is waiting" from "this was delivered", and no balance changed
    ///      here for it to read.
    event Forwarded(
        bytes32 indexed handleNode,
        address indexed token,
        address indexed depositor,
        address holder,
        bytes32 platformId,
        uint256 amount
    );

    /// @notice The holder of a handle node took what was held for it.
    event Claimed(
        bytes32 indexed handleNode, address indexed token, address indexed claimer, address recipient, uint256 amount
    );

    /// @notice A depositor took its own contribution back before the node's
    ///         holder claimed it.
    event Refunded(
        bytes32 indexed handleNode, address indexed token, address indexed depositor, address recipient, uint256 amount
    );

    // ─── Errors ─────────────────────────────────────────────────────

    /// A deposit of nothing writes nothing. Also what a token deposit that
    /// DELIVERED nothing reverts with: a token that moved no balance.
    error ZeroAmount();
    /// The handle node's holder is the caller: a deposit would pay the caller
    /// back to itself.
    error PayingYourself(address holder);
    /// Native value must equal the amount, and a token deposit carries none.
    error ValueMismatch(uint256 expected, uint256 provided);
    /// Nothing is held for this handle node in this token.
    error NothingHeld(bytes32 handleNode, address token);
    /// The caller does not hold this handle node.
    error NotTheHolder(address holder, address caller);
    /// This depositor has nothing refundable held for this handle node in
    /// this token: it never deposited there, took it back already, or a claim
    /// took it.
    error NothingToRefund(bytes32 handleNode, address token, address depositor);
    /// A payout to the zero address burns it; one to this contract strands it.
    error BadRecipient(address recipient);
    /// Text this platform could never accept as a handle.
    error UnusableHandle(HandleNormalizer.Problem problem);
    /// Nobody holds the node and no new claim can bind a holder on this
    /// platform, so nothing could ever take what the escrow would hold.
    error PlatformAcceptsNoClaims(bytes32 platformId);
    /// The recipient refused the transfer.
    error NativeTransferFailed(address recipient, uint256 amount);
    /// The escrow needs a naming system to resolve through.
    error NoNames();
    /// Ownership cannot be renounced; see `renounceOwnership`.
    error RenounceDisabled();

    // ─── Setup ──────────────────────────────────────────────────────

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address owner_, IIdentityNames names_) external initializer {
        if (address(names_) == address(0)) revert NoNames();
        __Ownable_init(owner_);
        __Ownable2Step_init();
        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();
        _s().names = names_;
    }

    /// @notice The naming system this escrow resolves through.
    function names() external view returns (IIdentityNames) {
        return _s().names;
    }

    // ─── Depositing ─────────────────────────────────────────────────

    /// @notice Put `amount` of `token` against a handle, given as text.
    ///
    /// @dev The text is normalized under the platform's current rules, once,
    ///      and the result is the node. A typo — a space, a character the
    ///      platform forbids, a handle past its length — is refused here
    ///      rather than accepted into a slot no proof could ever claim. A
    ///      platform that is not usable reverts `UnknownPlatform` from the
    ///      naming system before anything moves.
    ///
    ///      The text is in this call's calldata for anybody to read. A payee
    ///      whose handle must stay out of it is paid with `depositToNode`.
    ///
    ///      Otherwise the same as `depositToNode`: see it for pay-through, the
    ///      accepted race, and how a fee-on-transfer token is booked.
    ///
    /// @param platformId Which platform the handle belongs to.
    /// @param handle     The handle, as written. Whatever the platform's
    ///                   normalization folds — case, surrounding spaces, a
    ///                   leading at-sign where the platform strips one — does
    ///                   not matter.
    /// @param token      The ERC-20, or `NATIVE` for the chain's own token.
    /// @param amount     How much. For `NATIVE` it must equal `msg.value`.
    function depositToHandle(bytes32 platformId, string calldata handle, address token, uint256 amount)
        external
        payable
        nonReentrant
    {
        _deposit(platformId, _nodeOf(platformId, handle), token, amount);
    }

    /// @notice Put `amount` of `token` against a handle node.
    ///
    /// @dev **Nothing about the node is checked, and nothing can be.** A node
    ///      is a hash; this contract cannot tell the node of a real handle
    ///      from 32 arbitrary bytes, nor tell which platform it was derived
    ///      for. A wrong node funds a slot nothing can ever claim; since nobody
    ///      ever holds it, the depositor can take the value back with
    ///      `refund`, and nobody else can. Derive it the way `nodeOf` does:
    ///      `IdentityNodes.handleNode(platformId, normalized)`, where
    ///      `normalized` is the handle after the platform's normalization, and
    ///      never the raw text.
    ///
    ///      It exists so a payee whose handle must not reach calldata — a
    ///      private binding under a digest profile, whose handle the chain only
    ///      ever sees as its node — can still be paid.
    ///
    ///      `platformId` is taken on trust: it decides whether a new claim can
    ///      bind a holder (for the escrow branch) and is logged, but it does
    ///      not enter the key.
    ///
    ///      **A node somebody holds is paid straight through.** The escrow
    ///      exists for the window before a handle is claimed. Once it is
    ///      claimed the escrow has no purpose: holding the value would only add
    ///      a claim transaction to reach the same wallet. So a deposit for a
    ///      held node is a payment, and only an unheld node escrows — and only
    ///      on a platform where a new claim can bind a holder.
    ///
    ///      A holder depositing to its own node is refused with
    ///      `PayingYourself`: the pay-through would move value from the
    ///      caller back to the caller.
    ///
    ///      This is what makes a deposit depend on the recipient: a holder that
    ///      cannot receive value fails the whole call. That is the honest
    ///      outcome — the sender learns instead of the value waiting in a slot
    ///      only that same wallet could ever claim.
    ///
    ///      **The race is accepted.** One calldata has two outcomes depending on
    ///      whether it lands before or after an identity claim in the same
    ///      block: it pays through, or it escrows and waits for a claim. Both
    ///      deliver to the holder of the handle, so the difference is one
    ///      transaction, not one of destination. The escrowed outcome stays
    ///      refundable until that holder claims it; the paid-through one is
    ///      not refundable at all.
    ///
    ///      An escrowed deposit is booked to `msg.sender` as its depositor:
    ///      that address, and no other, can `refund` it.
    ///
    ///      Both branches measure what arrived rather than trusting the amount
    ///      asked for: an escrow credits the balance this contract gained, and
    ///      `Forwarded` reports the balance the holder gained. A token that
    ///      takes a fee on transfer therefore books and reports what it
    ///      delivered, not what was asked for. A rebasing token is not
    ///      supported; see the contract comment.
    ///
    /// @param platformId Which platform the node was derived for.
    /// @param handleNode `IdentityNodes.handleNode(platformId, normalized)`.
    /// @param token      The ERC-20, or `NATIVE` for the chain's own token.
    /// @param amount     How much. For `NATIVE` it must equal `msg.value`.
    function depositToNode(bytes32 platformId, bytes32 handleNode, address token, uint256 amount)
        external
        payable
        nonReentrant
    {
        _deposit(platformId, handleNode, token, amount);
    }

    function _deposit(bytes32 platformId, bytes32 node, address token, uint256 amount) private {
        if (amount == 0) revert ZeroAmount();

        if (token == NATIVE) {
            if (msg.value != amount) revert ValueMismatch(amount, msg.value);
        } else if (msg.value != 0) {
            // Ether riding on a token deposit has nowhere to land.
            revert ValueMismatch(0, msg.value);
        }

        (address holder,) = _s().names.byHandle(node);
        if (holder != address(0)) {
            if (holder == msg.sender) revert PayingYourself(holder);
            uint256 delivered = amount;
            if (token == NATIVE) {
                _sendNative(holder, amount);
            } else {
                // What the holder GAINED, not what was asked for. A token that
                // takes a fee on transfer delivers less, and an event carrying
                // the requested figure would be the only record of a payment
                // that never happened at that size.
                //
                // A token that moved nothing, or whose transfer left the
                // holder with no more than before, delivered nothing, and it
                // is refused like any other deposit of nothing rather than
                // underflowing.
                uint256 before = IERC20(token).balanceOf(holder);
                IERC20(token).safeTransferFrom(msg.sender, holder, amount);
                uint256 afterwards = IERC20(token).balanceOf(holder);
                delivered = afterwards > before ? afterwards - before : 0;
                if (delivered == 0) revert ZeroAmount();
            }
            emit Forwarded(node, token, msg.sender, holder, platformId, delivered);
            return;
        }

        if (!_s().names.acceptsClaims(platformId)) revert PlatformAcceptsNoClaims(platformId);

        uint256 credited;
        if (token == NATIVE) {
            credited = amount;
        } else {
            uint256 before = IERC20(token).balanceOf(address(this));
            IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
            credited = IERC20(token).balanceOf(address(this)) - before;
            if (credited == 0) revert ZeroAmount();
        }

        HandleEscrowStorage storage $ = _s();
        $.held[node][token] += credited;
        $.contributions[node][token][$.round[node][token]][msg.sender] += credited;
        emit Deposited(node, token, msg.sender, platformId, credited);
    }

    // ─── Claiming ───────────────────────────────────────────────────

    /// @notice Take everything held for a handle node in one token.
    ///
    /// @dev Authorized by the naming system and nothing else: the caller has to
    ///      be `byHandle(handleNode).owner`. No text is passed and nothing is
    ///      normalized, so the platform's current rules play no part — the
    ///      holder of a node claims it whatever those rules are now. Copying
    ///      this calldata out of the mempool gains nothing, because the check
    ///      is against the caller.
    ///
    ///      A retired handle — one whose account renamed away — has no owner,
    ///      so nobody can claim its slot until somebody proves that handle
    ///      again. Whoever proves it next may be a different account, and then
    ///      what is left is theirs. Until a claim, whoever holds the node,
    ///      depositors can `refund` what they put in. See the contract comment.
    ///
    ///      A claim takes everything held for the node in this token and
    ///      closes the round: every contribution it took stops being
    ///      refundable, whatever becomes of the holder afterwards.
    ///
    ///      **The destination is checked, not only the caller.** The zero
    ///      address accepts a native transfer without reverting, so an unset
    ///      recipient would burn the slot and log a success; this contract's
    ///      own address would empty the books while the value stayed put as
    ///      surplus nothing points at. No function here recovers either, so both
    ///      are refused.
    ///
    /// @param recipient Where the value goes. The claimer's choice, so a wallet
    ///                  that holds the name can pay out somewhere else.
    function claim(bytes32 handleNode, address token, address recipient) external nonReentrant {
        if (recipient == address(0) || recipient == address(this)) revert BadRecipient(recipient);

        (address holder,) = _s().names.byHandle(handleNode);
        if (holder != msg.sender) revert NotTheHolder(holder, msg.sender);

        HandleEscrowStorage storage $ = _s();
        uint256 amount = $.held[handleNode][token];
        if (amount == 0) revert NothingHeld(handleNode, token);
        $.held[handleNode][token] = 0;
        ++$.round[handleNode][token];

        _pay(token, recipient, amount);
        emit Claimed(handleNode, token, msg.sender, recipient, amount);
    }

    // ─── Refunding ──────────────────────────────────────────────────

    /// @notice Take back what the caller deposited for a handle node and the
    ///         node's holder has not claimed, in one token.
    ///
    /// @dev Refundable until collected. The naming system is not asked: a
    ///      node nobody has proved, a node no handle reaches, a retired
    ///      handle and a handle somebody holds all refund alike, up to the
    ///      moment the holder `claim`s. That is the sender's way back from a
    ///      holder it did not mean — a recycled handle or a stale binding —
    ///      and the reason held value promises the payee nothing until it is
    ///      claimed. A refund and a claim racing in one block: whichever lands
    ///      first wins.
    ///
    ///      The platform plays no part either: a platform that no longer
    ///      accepts claims still refunds, because nothing there could ever
    ///      take the value otherwise.
    ///
    ///      The caller gets its own contribution in the current round and
    ///      nothing more — what it deposited since the last claim of this
    ///      slot, as the escrow received it, less what it took back already.
    ///      Other depositors' contributions stay held.
    ///
    ///      The books are settled before the payout, and the destination is
    ///      checked as `claim` checks it.
    ///
    /// @param recipient Where the value goes. The depositor's choice.
    function refund(bytes32 handleNode, address token, address recipient) external nonReentrant {
        if (recipient == address(0) || recipient == address(this)) revert BadRecipient(recipient);

        HandleEscrowStorage storage $ = _s();
        mapping(address => uint256) storage current = $.contributions[handleNode][token][$.round[handleNode][token]];
        uint256 amount = current[msg.sender];
        if (amount == 0) revert NothingToRefund(handleNode, token, msg.sender);
        current[msg.sender] = 0;
        $.held[handleNode][token] -= amount;

        _pay(token, recipient, amount);
        emit Refunded(handleNode, token, msg.sender, recipient, amount);
    }

    // ─── Reading ────────────────────────────────────────────────────

    /// @notice How much is held for a handle node in one token.
    ///
    /// @dev Takes the node as given and checks nothing about it. A node that
    ///      was never funded and a node that could never exist both answer
    ///      zero. `nodeOf` turns a handle into its node.
    function escrowed(bytes32 handleNode, address token) external view returns (uint256) {
        return _s().held[handleNode][token];
    }

    /// @notice What `refund` would pay `depositor` for a handle node in one
    ///         token now.
    ///
    /// @dev The depositor's contribution in the current round: what it
    ///      deposited since the last claim of this slot, less what it took
    ///      back. Whether the node has a holder does not change it.
    function refundable(bytes32 handleNode, address token, address depositor) external view returns (uint256) {
        HandleEscrowStorage storage $ = _s();
        return $.contributions[handleNode][token][$.round[handleNode][token]][depositor];
    }

    /// @notice The node a handle keys to under the platform's current rules.
    ///
    /// @dev The same node `depositToHandle` would fund and `IdentityNames`
    ///      would bind, so a client can read a balance or check two spellings
    ///      land together before it sends anything. Reverts `UnusableHandle`
    ///      for text the platform's rules refuse, and `UnknownPlatform` for a
    ///      platform that is not usable.
    function nodeOf(bytes32 platformId, string calldata handle) external view returns (bytes32) {
        return _nodeOf(platformId, handle);
    }

    function _pay(address token, address to, uint256 amount) private {
        if (token == NATIVE) {
            _sendNative(to, amount);
        } else {
            IERC20(token).safeTransfer(to, amount);
        }
    }

    function _sendNative(address to, uint256 amount) private {
        (bool ok,) = to.call{value: amount}("");
        if (!ok) revert NativeTransferFailed(to, amount);
    }

    /// @dev Normalize once under the platform's current rules and key the
    ///      result. `rulesOf` reverts for a platform that is not usable, which
    ///      catches a mistyped `platformId` before it takes anybody's money.
    ///      `tryNormalize` then decides whether this text could ever be a
    ///      handle there, and its output is the string the node is built from.
    function _nodeOf(bytes32 platformId, string calldata handle) private view returns (bytes32) {
        HandleNormalizer.Rules memory rules = _s().names.rulesOf(platformId);
        (HandleNormalizer.Problem problem, string memory normalized) = HandleNormalizer.tryNormalize(handle, rules);
        if (problem != HandleNormalizer.Problem.None) revert UnusableHandle(problem);
        return IdentityNodes.handleNode(platformId, normalized);
    }

    // ─── Upgrade ────────────────────────────────────────────────────

    function _authorizeUpgrade(address) internal override onlyOwner {}

    /// @dev Renouncing would leave no way to repair a broken deployment, and
    ///      the upgrade is the only lever there is.
    function renounceOwnership() public pure override {
        revert RenounceDisabled();
    }
}

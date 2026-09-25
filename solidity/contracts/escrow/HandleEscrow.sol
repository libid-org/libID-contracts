// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {
    ReentrancyGuardTransientUpgradeable
} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardTransientUpgradeable.sol";

import {HandleNormalizer} from "../identity/HandleNormalizer.sol";
import {IdentityNodes} from "../identity/IdentityNodes.sol";
import {IIdentityNames} from "./IIdentityNames.sol";

/// @title HandleEscrow - send to a platform handle before anybody claims it.
///
/// @notice Holds tokens against a platform handle. Whoever the naming system
///         names as that handle's holder takes what is held for it.
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
///      **The handle is the whole key. There is no deadline and no refund.**
///      That was decided deliberately, and the consequence is stated here
///      rather than left to be discovered: A PLATFORM THAT RECYCLES A HANDLE
///      HANDS THE NEW HOLDER WHATEVER ACCUMULATED FOR THE PREVIOUS ONE. So does
///      a rename — the account that renames away stops being able to claim, and
///      whoever proves the freed handle next receives it. A depositor cannot
///      take a deposit back, and neither can the owner. Send to a handle the
///      way you send to an address: because you mean that name to have it.
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
///      **There is no pause.** A pause on `claim` freezes other people's money
///      behind an owner key, and the emergency lever is the upgrade, which is
///      already visible.
///
///      **The naming system's owners are part of this contract's trust base,
///      and that is not a pause substitute — it is larger.** Authorization
///      here is `byHandle` and nothing else, so whoever can decide what that
///      answers can take what is held. Two keys can: the naming owner, through
///      `setProofVerifier`, and the Proof Verifier's owner, through
///      `setVerifier` — either installs a verifier it controls, an identity
///      `claim` through it makes it the holder of any handle, and `claim` here
///      then pays it. Ordinary transactions, no upgrade and no proxy event.
///      Read every guarantee here as "under honest naming and Proof Verifier
///      owners"; they are the keys that already decide which proofs bind
///      names at all, so this adds no new party — only a new thing those keys
///      can reach.
contract HandleEscrow is Initializable, UUPSUpgradeable, Ownable2StepUpgradeable, ReentrancyGuardTransientUpgradeable {
    using SafeERC20 for IERC20;

    /// @notice The native token of the chain, as a token address.
    address public constant NATIVE = address(0);

    /// @custom:storage-location erc7201:libid.storage.HandleEscrow
    struct HandleEscrowStorage {
        /// handle node -> token -> amount held.
        mapping(bytes32 => mapping(address => uint256)) held;
        /// The naming system this escrow resolves through. Set in `initialize`.
        IIdentityNames names;
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

    // ─── Errors ─────────────────────────────────────────────────────

    /// A deposit of nothing writes nothing.
    error ZeroAmount();
    /// Native value must equal the amount, and a token deposit carries none.
    error ValueMismatch(uint256 expected, uint256 provided);
    /// Nothing is held for this handle node in this token.
    error NothingHeld(bytes32 handleNode, address token);
    /// The caller does not hold this handle node.
    error NotTheHolder(address holder, address caller);
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
        __ReentrancyGuardTransient_init();
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
    ///      for. A wrong node funds a slot nothing can ever claim, and there is
    ///      no refund. Derive it the way `nodeOf` does:
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
    ///      This is what makes a deposit depend on the recipient: a holder that
    ///      cannot receive value fails the whole call. That is the honest
    ///      outcome — the sender learns instead of the value waiting in a slot
    ///      only that same wallet could ever claim.
    ///
    ///      **The race is accepted.** One calldata has two outcomes depending on
    ///      whether it lands before or after an identity claim in the same
    ///      block: it pays through, or it escrows and waits for a claim. Both
    ///      deliver to the holder of the handle, so the difference is one
    ///      transaction, not one of destination.
    ///
    ///      Both branches measure what arrived rather than trusting the amount
    ///      asked for: an escrow credits the balance this contract gained, and
    ///      `Forwarded` reports the balance the holder gained. A token that
    ///      takes a fee on transfer therefore cannot make the books promise
    ///      more than the contract holds, nor the log report more than was
    ///      delivered.
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
            uint256 delivered = amount;
            if (token == NATIVE) {
                _sendNative(holder, amount);
            } else {
                // What the holder GAINED, not what was asked for. A token that
                // takes a fee on transfer delivers less, and an event carrying
                // the requested figure would be the only record of a payment
                // that never happened at that size.
                uint256 before = IERC20(token).balanceOf(holder);
                IERC20(token).safeTransferFrom(msg.sender, holder, amount);
                delivered = IERC20(token).balanceOf(holder) - before;
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

        _s().held[node][token] += credited;
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
    ///      so its slot waits until somebody proves that handle again. That may
    ///      be a different account, and then the balance is theirs. See the
    ///      contract comment.
    ///
    ///      **The destination is checked, not only the caller.** The zero
    ///      address accepts a native transfer without reverting, so an unset
    ///      recipient would burn the slot and log a success; this contract's
    ///      own address would empty the books while the value stayed put as
    ///      surplus nothing points at. Neither is recoverable — there is no
    ///      refund and no owner lever — so both are refused here.
    ///
    /// @param recipient Where the value goes. The claimer's choice, so a wallet
    ///                  that holds the name can pay out somewhere else.
    function claim(bytes32 handleNode, address token, address recipient) external nonReentrant {
        if (recipient == address(0) || recipient == address(this)) revert BadRecipient(recipient);

        (address holder,) = _s().names.byHandle(handleNode);
        if (holder != msg.sender) revert NotTheHolder(holder, msg.sender);

        uint256 amount = _s().held[handleNode][token];
        if (amount == 0) revert NothingHeld(handleNode, token);
        _s().held[handleNode][token] = 0;

        if (token == NATIVE) {
            _sendNative(recipient, amount);
        } else {
            IERC20(token).safeTransfer(recipient, amount);
        }
        emit Claimed(handleNode, token, msg.sender, recipient, amount);
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
        revert("renounce disabled");
    }
}

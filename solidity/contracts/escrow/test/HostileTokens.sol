// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// @notice What an ERC-777-style token calls on the two sides of a transfer.
interface ITransferHooks {
    /// Called on the sender before its balance moves.
    function tokensToSend(address from, address to, uint256 amount) external;
    /// Called on the recipient after its balance moved.
    function tokensReceived(address from, address to, uint256 amount) external;
}

/// @notice A token that calls into the sender before a transfer and into the
///         recipient after it, the way ERC-777 hooks do, for every address
///         that registered itself.
///
/// @dev Test-only. The hooks run inside the escrow's `safeTransfer` and
///      `safeTransferFrom`, so a registered depositor, holder or recipient
///      gets control in the middle of a deposit, claim or refund.
contract HookToken is ERC20 {
    mapping(address => bool) public hooked;

    constructor() ERC20("Hook", "HOOK") {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    /// Opt the caller in to both hooks.
    function register() external {
        hooked[msg.sender] = true;
    }

    function _update(address from, address to, uint256 value) internal override {
        if (from != address(0) && hooked[from]) ITransferHooks(from).tokensToSend(from, to, value);
        super._update(from, to, value);
        if (to != address(0) && hooked[to]) ITransferHooks(to).tokensReceived(from, to, value);
    }
}

/// @notice A token that answers `false` instead of reverting while `failing`
///         is set, and moves nothing then.
contract FalseToken is ERC20 {
    bool public failing;

    constructor() ERC20("False", "FALSE") {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function setFailing(bool failing_) external {
        failing = failing_;
    }

    function transfer(address to, uint256 amount) public override returns (bool) {
        if (failing) return false;
        return super.transfer(to, amount);
    }

    function transferFrom(address from, address to, uint256 amount) public override returns (bool) {
        if (failing) return false;
        return super.transferFrom(from, to, amount);
    }
}

/// @notice A token whose `transfer`, `transferFrom` and `approve` return
///         nothing, the way USDT's do on mainnet.
///
/// @dev Deliberately not an OpenZeppelin `ERC20`: overriding its functions
///      cannot drop the `bool` return. A caller that decodes a `bool` from
///      these reverts, which is what `SafeERC20` exists to avoid.
contract NoReturnToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    uint256 public totalSupply;

    error Insufficient();

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
    }

    function approve(address spender, uint256 amount) external {
        allowance[msg.sender][spender] = amount;
    }

    function transfer(address to, uint256 amount) external {
        _move(msg.sender, to, amount);
    }

    function transferFrom(address from, address to, uint256 amount) external {
        uint256 allowed = allowance[from][msg.sender];
        if (allowed < amount) revert Insufficient();
        allowance[from][msg.sender] = allowed - amount;
        _move(from, to, amount);
    }

    function _move(address from, address to, uint256 amount) private {
        if (balanceOf[from] < amount) revert Insufficient();
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
    }
}

/// @notice A token that refuses every transfer from or to an address on its
///         blocklist, the way USDC and USDT do.
contract BlocklistToken is ERC20 {
    mapping(address => bool) public blocked;

    error Blocked(address account);

    constructor() ERC20("Block", "BLOCK") {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function setBlocked(address account, bool blocked_) external {
        blocked[account] = blocked_;
    }

    function _update(address from, address to, uint256 value) internal override {
        if (blocked[from]) revert Blocked(from);
        if (blocked[to]) revert Blocked(to);
        super._update(from, to, value);
    }
}

/// @notice A token whose `transferFrom`, while `shrinking` is set, burns
///         twice the amount from the recipient after crediting it: the
///         recipient ends with less than it had before the transfer.
contract ShrinkingToken is ERC20 {
    bool public shrinking;

    constructor() ERC20("Shrink", "SHRINK") {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function setShrinking(bool shrinking_) external {
        shrinking = shrinking_;
    }

    function transferFrom(address from, address to, uint256 amount) public override returns (bool) {
        bool ok = super.transferFrom(from, to, amount);
        if (shrinking) _burn(to, 2 * amount);
        return ok;
    }
}

/// @notice A token that takes 1% of every `transfer` — the call a payout
///         makes — and none of a `transferFrom`, so a deposit arrives whole
///         and a claim or refund delivers less than the books release.
contract PayoutFeeToken is ERC20 {
    uint256 public constant FEE_BPS = 100;

    constructor() ERC20("PayoutFee", "PFEE") {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function transfer(address to, uint256 amount) public override returns (bool) {
        uint256 fee = (amount * FEE_BPS) / 10_000;
        _transfer(msg.sender, address(0xdead), fee);
        _transfer(msg.sender, to, amount - fee);
        return true;
    }
}

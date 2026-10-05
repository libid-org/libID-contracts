// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

import {IdentityNodes} from "../../identity/IdentityNodes.sol";
import {IIdentityRegistry} from "../../identity/IIdentityRegistry.sol";

/// @notice A one-token list for `HandleEscrow.claim`.
function one(address token) pure returns (address[] memory tokens) {
    tokens = new address[](1);
    tokens[0] = token;
}

/// @notice A registry whose holders are set directly; deposits go by hash.
contract SettableRegistry is IIdentityRegistry {
    mapping(bytes32 => address) public holderOf;

    function setHolder(bytes32 handleNode, address holder) external {
        holderOf[handleNode] = holder;
    }

    function handleBinding(bytes32 handleNode) external view returns (address holder, uint64 observedAt) {
        return (holderOf[handleNode], 0);
    }

    function handleNodeOf(bytes32 platformId, string calldata handle) external pure returns (bytes32) {
        return IdentityNodes.handleNode(platformId, handle);
    }

    function handleHashOf(bytes32, string calldata handle) external pure returns (bytes32) {
        return keccak256(bytes(handle));
    }

    function handleNodeOfHash(bytes32 platformId, bytes32 handleHash) external pure returns (bytes32) {
        return IdentityNodes.handleNodeOfHash(platformId, handleHash);
    }

    function acceptsBindings(bytes32 platformId) external pure returns (bool) {
        return platformId != bytes32(0);
    }

    // The registry's one-call reads are not modelled: escrow reads holders
    // through `handleBinding` alone. Each reverts, so a test that starts
    // depending on one fails here instead of reading a made-up answer.

    function normalizeHandle(bytes32, string calldata) external pure returns (string memory) {
        revert("SettableRegistry: normalizeHandle not modelled");
    }

    function handleBindingOf(bytes32, string calldata) external pure returns (address, uint64) {
        revert("SettableRegistry: handleBindingOf not modelled");
    }

    function idBindingOf(bytes32, string calldata) external pure returns (address, uint64) {
        revert("SettableRegistry: idBindingOf not modelled");
    }

    function handleOfId(bytes32, string calldata) external pure returns (string memory, bool) {
        revert("SettableRegistry: handleOfId not modelled");
    }

    function idOfHandle(bytes32, string calldata) external pure returns (string memory) {
        revert("SettableRegistry: idOfHandle not modelled");
    }
}

/// @notice A plain ERC-20 anybody can mint.
contract TestERC20 is ERC20 {
    constructor() ERC20("Token", "TKN") {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

/// @notice Takes 1% of every `transferFrom`: a deposit arrives short.
contract FeeToken is TestERC20 {
    uint256 public constant FEE_BPS = 100;

    function transferFrom(address from, address to, uint256 amount) public override returns (bool) {
        uint256 fee = (amount * FEE_BPS) / 10_000;
        _transfer(from, address(0xdead), fee);
        _transfer(from, to, amount - fee);
        _spendAllowance(from, msg.sender, amount);
        return true;
    }
}

/// @notice Takes 1% of every `transfer`: a payout delivers less than the books release.
contract PayoutFeeToken is TestERC20 {
    function transfer(address to, uint256 amount) public override returns (bool) {
        _transfer(msg.sender, address(0xdead), amount / 100);
        _transfer(msg.sender, to, amount - amount / 100);
        return true;
    }
}

/// @notice Charges the sender 1% on top of every `transfer`: a payout over-debits the pool.
contract SenderFeeToken is TestERC20 {
    function transfer(address to, uint256 amount) public override returns (bool) {
        _transfer(msg.sender, address(0xdead), amount / 100);
        _transfer(msg.sender, to, amount);
        return true;
    }
}

/// @notice Reports success on `transferFrom` and moves nothing.
contract InertToken is TestERC20 {
    function transferFrom(address, address, uint256) public pure override returns (bool) {
        return true;
    }
}

/// @notice Balances shrink without a transfer, as in a negative rebase.
contract RebasingToken is TestERC20 {
    function slash(address account, uint256 amount) external {
        _burn(account, amount);
    }
}

/// @notice Answers `false`, moving nothing, while `failing` is set.
contract FalseToken is TestERC20 {
    bool public failing;

    function setFailing(bool failing_) external {
        failing = failing_;
    }

    function transfer(address to, uint256 amount) public override returns (bool) {
        return failing ? false : super.transfer(to, amount);
    }

    function transferFrom(address from, address to, uint256 amount) public override returns (bool) {
        return failing ? false : super.transferFrom(from, to, amount);
    }
}

/// @notice Refuses transfers from or to a blocked address, as USDC does.
contract BlocklistToken is TestERC20 {
    mapping(address => bool) public blocked;

    error Blocked(address account);

    function setBlocked(address account, bool blocked_) external {
        blocked[account] = blocked_;
    }

    function _update(address from, address to, uint256 value) internal override {
        if (blocked[from]) revert Blocked(from);
        if (blocked[to]) revert Blocked(to);
        super._update(from, to, value);
    }
}

/// @notice ERC-777-style hooks on both sides of a transfer.
interface ITransferHooks {
    function tokensToSend(address from, address to, uint256 amount) external;
    function tokensReceived(address from, address to, uint256 amount) external;
}

/// @notice Calls the hooks of every registered sender and recipient.
contract HookToken is TestERC20 {
    mapping(address => bool) public hooked;

    function register() external {
        hooked[msg.sender] = true;
    }

    function _update(address from, address to, uint256 value) internal override {
        if (from != address(0) && hooked[from]) ITransferHooks(from).tokensToSend(from, to, value);
        super._update(from, to, value);
        if (to != address(0) && hooked[to]) ITransferHooks(to).tokensReceived(from, to, value);
    }
}

/// @notice `transfer`, `transferFrom` and `approve` return nothing, as USDT's do.
contract NoReturnToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external {
        allowance[msg.sender][spender] = amount;
    }

    function transfer(address to, uint256 amount) external {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
    }

    function transferFrom(address from, address to, uint256 amount) external {
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
    }
}

/// @notice Refuses every native transfer.
contract RejectEther {}

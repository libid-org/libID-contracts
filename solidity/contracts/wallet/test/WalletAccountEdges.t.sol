// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {IERC721Receiver} from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import {ERC1155} from "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";
import {IERC1155Receiver} from "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";
import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/IERC4337.sol";

import {IWebWallet} from "../IWebWallet.sol";
import {IUserOpHash, WalletBase} from "./WalletBase.sol";

contract Nft is ERC721("n", "N") {
    function mint(address to, uint256 id) external {
        _safeMint(to, id);
    }
}

contract Multi is ERC1155("") {
    function mint(address to, uint256 id) external {
        _mint(to, id, 1, "");
    }

    function mintBatch(address to, uint256[] calldata ids, uint256[] calldata values) external {
        _mintBatch(to, ids, values, "");
    }
}

/// @notice Token receipts, and malformed signatures failing instead of reverting.
contract WalletAccountEdgesTest is WalletBase {
    address internal w;

    function setUp() public override {
        super.setUp();
        w = _claim();
        vm.warp(_now() + 1);
    }

    function test_theWalletReceivesErc721AndErc1155() public {
        Nft nft = new Nft();
        nft.mint(w, 1);
        assertEq(nft.ownerOf(1), w, "ERC-721");
        Multi multi = new Multi();
        multi.mint(w, 1);
        uint256[] memory ids = new uint256[](2);
        (ids[0], ids[1]) = (2, 3);
        multi.mintBatch(w, ids, ids);
        assertEq(multi.balanceOf(w, 1) + multi.balanceOf(w, 3), 4, "ERC-1155");
        bytes4[3] memory ifaces =
            [type(IERC721Receiver).interfaceId, type(IERC1155Receiver).interfaceId, type(IERC165).interfaceId];
        for (uint256 i; i < ifaces.length; ++i) {
            assertTrue(IWebWallet(w).supportsInterface(ifaces[i]), "interface");
        }
        assertFalse(IWebWallet(w).supportsInterface(0xffffffff), "0xffffffff");
    }

    /// Writes `word` at byte `at` of `b`.
    function _put(bytes memory b, uint256 at, uint256 word) internal pure returns (bytes memory) {
        assembly {
            mstore(add(add(b, 0x20), at), word)
        }
        return b;
    }

    /// A UserOperation signed by `signature`, and its EntryPoint hash.
    function _opWith(bytes memory signature) internal view returns (PackedUserOperation memory op, bytes32 h) {
        op = _op(w, _hitCall());
        h = IUserOpHash(EP).getUserOpHash(op);
        op.signature = signature;
    }

    /// Both entries answer failure for `signature`, never revert.
    function _failsSoftly(bytes memory signature, string memory why) internal {
        assertEq(IWebWallet(w).isValidSignature(keccak256("h"), signature), bytes4(0xffffffff), why);
        (PackedUserOperation memory op, bytes32 h) = _opWith(signature);
        vm.prank(EP);
        assertEq(IWebWallet(w).validateUserOp(op, h, 0), 1, why);
    }

    /// Head layout of `_auth`: the tuple at 0x20, `at` at 0x40, the signature array's length at 0xc0.
    function test_aMalformedAuthorizationFailsSoftly() public {
        bytes memory valid = _auth(_pks(ALICE_PK), keccak256("h"), uint48(_now()), false, 0);
        // Control: the well-formed one is signed by Alice.
        (PackedUserOperation memory op, bytes32 h) = _opWith("");
        op = _signOp(op, 1, _pks(ALICE_PK));
        vm.prank(EP);
        assertEq(IWebWallet(w).validateUserOp(op, h, 0), 0, "control");

        bytes memory truncated = new bytes(valid.length - 1);
        for (uint256 i; i < truncated.length; ++i) {
            truncated[i] = valid[i];
        }
        bytes memory ecdsa = new bytes(65);
        ecdsa[64] = 0x1b;
        _failsSoftly("", "empty");
        _failsSoftly(ecdsa, "a 65-byte signature");
        _failsSoftly(truncated, "truncated");
        _failsSoftly(_put(bytes.concat(valid), 0, 1 << 255), "offset out of range");
        _failsSoftly(_put(bytes.concat(valid), 0xc0, type(uint64).max), "oversized length");
        _failsSoftly(_put(bytes.concat(valid), 0x40, 1 << 48), "dirty at");
    }

    function testFuzz_anyBytesFailSoftly(bytes calldata signature) public {
        _failsSoftly(signature, "fuzzed");
    }
}

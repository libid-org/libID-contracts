// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {HandleVectors} from "../HandleVectors.sol";
import {IdentityNames} from "../IdentityNames.sol";
import {CeremonyProofVerifier} from "../../ceremony/CeremonyProofVerifier.sol";
import {IPlatformVerifier} from "../../ceremony/IPlatformVerifier.sol";
import {IProofVerifier} from "../../ceremony/IProofVerifier.sol";
import {StubPlatformVerifier} from "./StubPlatformVerifier.sol";

/// @notice What a wallet pays, and what reading it costs, does not depend on
///         how many accounts the wallet holds.
///
/// @dev Two wallets on one contract, one holding four accounts and one
///      holding a thousand. Each operation runs for both from cold storage,
///      and the gas the contract used is compared exactly rather than within
///      a tolerance: one storage read more would show as thousands.
///
///      Account ids and handles have one width each, so a claim's hashing
///      and normalization cost the same whichever account it names. The
///      measured call is the last one a helper makes, which is what
///      `vm.lastCallGas` reports on.
contract IdentityNamesGasTest is Test {
    IdentityNames internal names;
    CeremonyProofVerifier internal proofVerifier;
    StubPlatformVerifier internal xVerifier;

    bytes32 internal constant X = HandleVectors.PLATFORM_X;
    uint16 internal constant V1 = 1;
    uint256 internal constant FEW = 4;
    uint256 internal constant MANY = 1000;

    address internal owner = makeAddr("owner");
    address internal few = makeAddr("few");
    address internal many = makeAddr("many");

    uint256 private nonce;
    uint64 private clock = 1;

    function setUp() public {
        IdentityNames impl = new IdentityNames();
        names =
            IdentityNames(address(new ERC1967Proxy(address(impl), abi.encodeCall(IdentityNames.initialize, (owner)))));
        CeremonyProofVerifier pvImpl = new CeremonyProofVerifier();
        proofVerifier = CeremonyProofVerifier(
            address(new ERC1967Proxy(address(pvImpl), abi.encodeCall(CeremonyProofVerifier.initialize, (owner))))
        );
        xVerifier = new StubPlatformVerifier(X, 0);
        vm.startPrank(owner);
        names.setProofVerifier(IProofVerifier(address(proofVerifier)));
        names.setPlatform(X, HandleVectors.rulesFor(X));
        proofVerifier.setVerifier(X, V1, IPlatformVerifier(address(xVerifier)));
        vm.stopPrank();
        vm.warp(1_000_000);

        for (uint256 k = 0; k < FEW; k++) {
            _prove(few, _id(few, k), _handle(few, k));
        }
        for (uint256 k = 0; k < MANY; k++) {
            _prove(many, _id(many, k), _handle(many, k));
        }
    }

    // ─── Fixed-width names ──────────────────────────────────────────

    function _tag(address wallet) internal view returns (uint256) {
        return wallet == few ? 1 : 2;
    }

    /// Ten digits, the width of an X account id in the fixtures.
    function _id(address wallet, uint256 k) internal view returns (string memory) {
        return string(abi.encodePacked("17", _digits(_tag(wallet), 2), _digits(k, 6)));
    }

    /// Fifteen characters, the most X allows.
    function _handle(address wallet, uint256 k) internal view returns (string memory) {
        return string(abi.encodePacked("u", _digits(_tag(wallet), 2), "_", _digits(k, 6), "_abcd"));
    }

    function _digits(uint256 value, uint256 width) internal pure returns (string memory) {
        bytes memory digits = "0123456789";
        bytes memory out = new bytes(width);
        for (uint256 i = width; i > 0; i--) {
            out[i - 1] = digits[value % 10];
            value /= 10;
        }
        return string(out);
    }

    // ─── Operations, each ending in the call to measure ─────────────

    /// Every measurement starts from the same footing: the contracts are
    /// warm, because a test begins with them cold and the first call would
    /// otherwise pay the account accesses the second does not, and their
    /// storage is cold, so what a call reads is paid for in full both times.
    modifier measured() {
        names.owner();
        proofVerifier.owner();
        xVerifier.fee();
        _;
    }

    function _cool() internal {
        vm.cool(address(names));
        vm.cool(address(proofVerifier));
        vm.cool(address(xVerifier));
    }

    function _used() internal view returns (uint64) {
        return vm.lastCallGas().gasTotalUsed;
    }

    /// A claim made out to `who`, from cold storage.
    function _prove(address who, string memory userId, string memory handle) internal {
        xVerifier.set(userId, handle);
        xVerifier.setObservedAt(++clock);
        bytes memory payload = abi.encode(
            StubPlatformVerifier.StubPayload({
                ceremonyVersion: V1,
                operationDomain: keccak256(bytes("libid.claim-identity")),
                authorizationNonce: bytes32(++nonce),
                transactionData: abi.encode(who, uint256(0), address(0))
            })
        );
        _cool();
        vm.prank(who);
        names.claim(X, V1, payload, true);
    }

    /// How many accounts a wallet was given. Half of that is an account in
    /// the middle of its list: never the last one, so a removal has to move
    /// the last one into its place.
    function _size(address wallet) internal view returns (uint256) {
        return wallet == few ? FEW : MANY;
    }

    // ─── Writes ─────────────────────────────────────────────────────

    function test_aNewAccountCostsTheSame() public measured {
        _prove(few, _id(few, 900_000), _handle(few, 900_000));
        uint64 atFew = _used();
        _prove(many, _id(many, 900_000), _handle(many, 900_000));
        assertEq(atFew, _used(), "a new account");
    }

    function test_aRenameCostsTheSame() public measured {
        _prove(few, _id(few, _size(few) / 2), _handle(few, 900_001));
        uint64 atFew = _used();
        _prove(many, _id(many, _size(many) / 2), _handle(many, 900_001));
        assertEq(atFew, _used(), "a rename");
    }

    function test_provingTheSameHandleAgainCostsTheSame() public measured {
        _prove(few, _id(few, 1), _handle(few, 1));
        uint64 atFew = _used();
        _prove(many, _id(many, 1), _handle(many, 1));
        assertEq(atFew, _used(), "a re-proof");
    }

    /// Another wallet's new account takes a handle from the middle of the
    /// list. The list is not touched, and the taker pays for its own.
    function test_aHandleTakenFromTheWalletCostsTheSame() public measured {
        _prove(makeAddr("taker of few"), _id(few, 900_002), _handle(few, _size(few) / 2));
        uint64 atFew = _used();
        _prove(makeAddr("taker of many"), _id(many, 900_002), _handle(many, _size(many) / 2));
        assertEq(atFew, _used(), "a takeover");
    }

    /// An account from the middle of the list is proved from a new wallet:
    /// the one write that removes from a list.
    function test_anAccountLeavingTheMiddleCostsTheSame() public measured {
        _prove(makeAddr("new home of few"), _id(few, _size(few) / 2), _handle(few, _size(few) / 2));
        uint64 atFew = _used();
        _prove(makeAddr("new home of many"), _id(many, _size(many) / 2), _handle(many, _size(many) / 2));
        assertEq(atFew, _used(), "a move");
    }

    function test_unpublishingCostsTheSame() public measured {
        _cool();
        vm.prank(few);
        names.unpublish(X);
        uint64 atFew = _used();
        _cool();
        vm.prank(many);
        names.unpublish(X);
        assertEq(atFew, _used(), "unpublish");
    }

    // ─── Reads ──────────────────────────────────────────────────────

    /// A page shorter than either list, so neither read is clipped and both
    /// take the same path through the paging.
    function test_aPageCostsTheSame() public measured {
        _cool();
        names.accountsOf(few, X, 0, FEW - 1);
        uint64 atFew = _used();
        _cool();
        names.accountsOf(many, X, 0, FEW - 1);
        assertEq(atFew, _used(), "a page of three");
    }

    function test_countingCostsTheSame() public measured {
        _cool();
        names.accountCount(few, X);
        uint64 atFew = _used();
        _cool();
        names.accountCount(many, X);
        assertEq(atFew, _used(), "the count");
    }

    function test_theResolversCostTheSame() public measured {
        _cool();
        names.resolveHandle(X, _handle(few, 0));
        uint64 atFew = _used();
        _cool();
        names.resolveHandle(X, _handle(many, 0));
        assertEq(atFew, _used(), "resolveHandle");

        _cool();
        names.resolveId(X, _id(few, 0));
        atFew = _used();
        _cool();
        names.resolveId(X, _id(many, 0));
        assertEq(atFew, _used(), "resolveId");

        _cool();
        names.resolvePair(X, _handle(few, 0), _id(few, 0));
        atFew = _used();
        _cool();
        names.resolvePair(X, _handle(many, 0), _id(many, 0));
        assertEq(atFew, _used(), "resolvePair");

        _cool();
        names.primaryOf(few, X);
        atFew = _used();
        _cool();
        names.primaryOf(many, X);
        assertEq(atFew, _used(), "primaryOf");

        _cool();
        names.reverseOf(few, X);
        atFew = _used();
        _cool();
        names.reverseOf(many, X);
        assertEq(atFew, _used(), "reverseOf");
    }
}

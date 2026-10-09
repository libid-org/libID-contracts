// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {HandlePlatforms} from "../../handles/HandlePlatforms.sol";
import {IdentityRegistry} from "../IdentityRegistry.sol";
import {TestNodes} from "./TestNodes.sol";
import {CeremonyProofVerifier} from "../../ceremony/CeremonyProofVerifier.sol";
import {IPlatformVerifier} from "../../ceremony/IPlatformVerifier.sol";
import {IProofVerifier} from "../../ceremony/IProofVerifier.sol";
import {StubPlatformVerifier} from "./StubPlatformVerifier.sol";

/// @notice What a holder pays, and what reading it costs, does not depend on
///         how many identities the holder has.
///
/// @dev Two holders on one contract, one with four identities and one with a
///      thousand. Each operation runs for both from cold storage, and the gas
///      the contract used is compared exactly rather than within a tolerance:
///      one storage read more would show as thousands. The measured call is
///      the last one a helper makes, which is what `vm.lastCallGas` reports
///      on.
contract IdentityRegistryGasTest is Test {
    IdentityRegistry internal registry;
    CeremonyProofVerifier internal proofVerifier;
    StubPlatformVerifier internal xVerifier;

    bytes32 internal constant X = HandlePlatforms.PLATFORM_X;
    uint16 internal constant V1 = 1;
    uint256 internal constant FEW = 4;
    uint256 internal constant MANY = 1000;

    address internal owner = makeAddr("owner");
    address internal few = makeAddr("few");
    address internal many = makeAddr("many");

    uint256 private nonce;
    uint64 private clock = 1;

    function setUp() public {
        IdentityRegistry impl = new IdentityRegistry();
        registry = IdentityRegistry(
            address(new ERC1967Proxy(address(impl), abi.encodeCall(IdentityRegistry.initialize, (owner))))
        );
        CeremonyProofVerifier pvImpl = new CeremonyProofVerifier();
        proofVerifier = CeremonyProofVerifier(
            address(new ERC1967Proxy(address(pvImpl), abi.encodeCall(CeremonyProofVerifier.initialize, (owner))))
        );
        xVerifier = new StubPlatformVerifier(X, 0);
        vm.startPrank(owner);
        registry.setProofVerifier(IProofVerifier(address(proofVerifier)));
        proofVerifier.setVerifier(X, V1, IPlatformVerifier(address(xVerifier)));
        vm.stopPrank();
        vm.warp(1_000_000);

        for (uint256 k = 0; k < FEW; k++) {
            _prove(few, _id(_tag(few), k), _handle(_tag(few), k));
        }
        for (uint256 k = 0; k < MANY; k++) {
            _prove(many, _id(_tag(many), k), _handle(_tag(many), k));
        }
    }

    // ─── Fixed-width ids and handles ────────────────────────────────

    /// Ids and handles of one width each, so a bind's hashing and
    /// normalization cost the same whichever identity it names. A tag tells
    /// one holder's identities from another's. Ten digits is the width of an
    /// X id in the fixtures, fifteen characters the most X allows.
    function _id(uint256 tag, uint256 k) internal pure returns (string memory) {
        return string(abi.encodePacked("17", _digits(tag, 2), _digits(k, 6)));
    }

    function _handle(uint256 tag, uint256 k) internal pure returns (string memory) {
        return string(abi.encodePacked("u", _digits(tag, 2), "_", _digits(k, 6), "_abcd"));
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

    function _tag(address holder) internal view returns (uint256) {
        return holder == few ? 1 : 2;
    }

    /// How many identities a holder was given. Half of that is an identity
    /// in the middle of its list: never the last one, so a removal has to move
    /// the last one into its place.
    function _size(address holder) internal view returns (uint256) {
        return holder == few ? FEW : MANY;
    }

    // ─── Operations, each ending in the call to measure ─────────────

    /// Every measurement starts from the same footing: the contracts are
    /// warm, because a test begins with them cold and the first call would
    /// otherwise pay the address accesses the second does not, and their
    /// storage is cold, so what a call reads is paid for in full both times.
    modifier measured() {
        registry.owner();
        proofVerifier.owner();
        xVerifier.fee();
        _;
    }

    function _cool() internal {
        vm.cool(address(registry));
        vm.cool(address(proofVerifier));
        vm.cool(address(xVerifier));
    }

    function _used() internal view returns (uint64) {
        return vm.lastCallGas().gasTotalUsed;
    }

    /// A cold bind made out to `who` that discloses the handle.
    function _prove(address who, string memory id, string memory handle) internal {
        xVerifier.set(id, handle);
        xVerifier.setObservedAt(++clock);
        bytes memory payload = abi.encode(
            StubPlatformVerifier.StubPayload({
                ceremonyVersion: V1,
                operationDomain: keccak256(bytes("libid.claim-identity")),
                authorizationNonce: bytes32(++nonce),
                transactionData: abi.encode(who, uint256(0), address(0)),
                handle: handle
            })
        );
        _cool();
        vm.prank(who);
        registry.bind(X, V1, payload);
    }

    // ─── Writes ─────────────────────────────────────────────────────

    function test_aNewIdentityCostsTheSame() public measured {
        _prove(few, _id(1, 900_000), _handle(1, 900_000));
        uint64 atFew = _used();
        _prove(many, _id(2, 900_000), _handle(2, 900_000));
        assertEq(atFew, _used(), "a new identity");
    }

    function test_aRenameCostsTheSame() public measured {
        _prove(few, _id(1, _size(few) / 2), _handle(1, 900_001));
        uint64 atFew = _used();
        _prove(many, _id(2, _size(many) / 2), _handle(2, 900_001));
        assertEq(atFew, _used(), "a rename");
    }

    function test_provingTheSameHandleAgainCostsTheSame() public measured {
        _prove(few, _id(1, 1), _handle(1, 1));
        uint64 atFew = _used();
        _prove(many, _id(2, 1), _handle(2, 1));
        assertEq(atFew, _used(), "a re-proof");
    }

    /// Another holder's new identity takes a handle from the middle of the
    /// list. The list is not touched, and the taker pays for its own.
    function test_aHandleTakenFromTheHolderCostsTheSame() public measured {
        _prove(makeAddr("taker of few"), _id(1, 900_002), _handle(1, _size(few) / 2));
        uint64 atFew = _used();
        _prove(makeAddr("taker of many"), _id(2, 900_002), _handle(2, _size(many) / 2));
        assertEq(atFew, _used(), "a takeover");
    }

    /// An identity from the middle of the list is proved by a new holder:
    /// the one write that removes from a list.
    function test_anIdentityLeavingTheMiddleCostsTheSame() public measured {
        _prove(makeAddr("new home of few"), _id(1, _size(few) / 2), _handle(1, _size(few) / 2));
        uint64 atFew = _used();
        _prove(makeAddr("new home of many"), _id(2, _size(many) / 2), _handle(2, _size(many) / 2));
        assertEq(atFew, _used(), "a move");
    }

    function test_unpublishingCostsTheSame() public measured {
        _cool();
        vm.prank(few);
        registry.unpublish(X);
        uint64 atFew = _used();
        _cool();
        vm.prank(many);
        registry.unpublish(X);
        assertEq(atFew, _used(), "unpublish");
    }

    // ─── Reads ──────────────────────────────────────────────────────

    /// A page shorter than either list, so neither read is clipped and both
    /// take the same path through the paging.
    function test_aPageCostsTheSame() public measured {
        _cool();
        registry.identitiesOf(few, 0, FEW - 1);
        uint64 atFew = _used();
        _cool();
        registry.identitiesOf(many, 0, FEW - 1);
        assertEq(atFew, _used(), "a page of three");
    }

    function test_countingCostsTheSame() public measured {
        _cool();
        registry.identityCount(few);
        uint64 atFew = _used();
        _cool();
        registry.identityCount(many);
        assertEq(atFew, _used(), "the count");
    }

    /// The reads under the resolvers: a binding by its node, and a digest.
    function test_theRawReadsCostTheSame() public measured {
        _cool();
        registry.idBinding(TestNodes.idNode(X, _id(1, 0)));
        uint64 atFew = _used();
        _cool();
        registry.idBinding(TestNodes.idNode(X, _id(2, 0)));
        assertEq(atFew, _used(), "idBinding");

        _cool();
        registry.handleBinding(TestNodes.handleNode(X, _handle(1, 0)));
        atFew = _used();
        _cool();
        registry.handleBinding(TestNodes.handleNode(X, _handle(2, 0)));
        assertEq(atFew, _used(), "handleBinding");

        _prove(few, _id(1, 900_003), _handle(1, 900_003));
        bytes32 spentByFew = xVerifier.lastDigest();
        _prove(many, _id(2, 900_003), _handle(2, 900_003));
        bytes32 spentByMany = xVerifier.lastDigest();
        _cool();
        registry.digestSpent(spentByFew);
        atFew = _used();
        _cool();
        registry.digestSpent(spentByMany);
        assertEq(atFew, _used(), "digestSpent");
    }

    function test_theResolversCostTheSame() public measured {
        _cool();
        registry.resolveHandle(X, _handle(1, 0));
        uint64 atFew = _used();
        _cool();
        registry.resolveHandle(X, _handle(2, 0));
        assertEq(atFew, _used(), "resolveHandle");

        _cool();
        registry.resolveId(TestNodes.idNode(X, _id(1, 0)));
        atFew = _used();
        _cool();
        registry.resolveId(TestNodes.idNode(X, _id(2, 0)));
        assertEq(atFew, _used(), "resolveId");

        _cool();
        registry.resolveHandleAndId(X, _handle(1, 0), TestNodes.idNode(X, _id(1, 0)));
        atFew = _used();
        _cool();
        registry.resolveHandleAndId(X, _handle(2, 0), TestNodes.idNode(X, _id(2, 0)));
        assertEq(atFew, _used(), "resolveHandleAndId");

        _cool();
        registry.publishedHandleOf(few, X);
        atFew = _used();
        _cool();
        registry.publishedHandleOf(many, X);
        assertEq(atFew, _used(), "publishedHandleOf");
    }
}

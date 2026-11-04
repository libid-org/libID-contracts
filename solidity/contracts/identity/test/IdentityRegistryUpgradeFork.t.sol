// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC1967Utils} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";

import {CeremonyProfile} from "../../ceremony/CeremonyProfile.sol";
import {ICeremony} from "../../ceremony/ICeremony.sol";
import {IProofVerifier} from "../../ceremony/IProofVerifier.sol";
import {IdentityRegistry} from "../IdentityRegistry.sol";
import {RecordingReceiver} from "./BindFeeCall.t.sol";
import {TestNodes} from "./TestNodes.sol";

/// @notice Upgrades a deployed registry proxy on a fork to this source, then
///         binds through `bind` and `bindWithFeeCall`. A binding written by the
///         deployed code reads back unchanged through the new code.
/// @dev Runs only with `FORK_RPC_URL` and `FORK_IDENTITY_REGISTRY` set, e.g. a
///      testnet's RPC and its `identity_registry`. The deployed Proof Verifier
///      stays in place, its `quote` and `verify` mocked, so no proof is needed.
contract IdentityRegistryUpgradeForkTest is Test {
    IdentityRegistry registry;
    IProofVerifier proofVerifier;
    address owner;

    bytes32 constant X = CeremonyProfile.PLATFORM_X;
    uint16 constant V1 = 1;
    uint256 constant QUOTE = 0.002 ether;
    uint256 constant SERVICE_FEE = 0.01 ether;

    address holder = makeAddr("fork holder");
    address host = makeAddr("fork host");

    function setUp() public {
        string memory rpc = vm.envOr("FORK_RPC_URL", string(""));
        if (bytes(rpc).length == 0) {
            vm.skip(true);
            return;
        }
        vm.createSelectFork(rpc);
        registry = IdentityRegistry(vm.envAddress("FORK_IDENTITY_REGISTRY"));
        proofVerifier = registry.proofVerifier();
        owner = registry.owner();
        vm.mockCall(address(proofVerifier), abi.encodeCall(IProofVerifier.quote, (X, V1)), abi.encode(QUOTE));
        vm.deal(holder, 1 ether);
    }

    /// The claim the mocked Proof Verifier returns for the payload `n`: the
    /// holder's id `n` with handle `forkholder<n>`, observed now.
    function _claim(uint256 n) private returns (bytes memory payload, ICeremony.VerifiedClaim memory claimed) {
        payload = abi.encode("fork payload", n);
        claimed = ICeremony.VerifiedClaim({
            sessionId: keccak256(abi.encode("fork session", n, block.number)),
            operationDomain: registry.OPERATION_DOMAIN(),
            transactionData: abi.encode(holder),
            ceremonyVersion: 1,
            clientIdentifier: "fork",
            idNode: TestNodes.idNode(X, vm.toString(9_000_000_000 + n)),
            handleNode: TestNodes.handleNode(X, _handle(n)),
            metadataObservedAt: uint64(block.timestamp)
        });
        vm.mockCall(
            address(proofVerifier), abi.encodeCall(IProofVerifier.verify, (X, V1, payload)), abi.encode(claimed)
        );
    }

    function _handle(uint256 n) private pure returns (string memory) {
        return string.concat("forkholder", vm.toString(n));
    }

    /// Everything the registry stores about the holder's first binding, read through its views.
    function _state(ICeremony.VerifiedClaim memory claimed) private view returns (bytes memory) {
        (address idHolder, uint64 idAt) = registry.idBinding(claimed.idNode);
        (address handleHolder, uint64 handleAt) = registry.handleBinding(claimed.handleNode);
        (bytes32 namedOn, string memory name) = registry.primaryHandleOf(holder);
        return abi.encode(
            registry.owner(),
            registry.pendingOwner(),
            registry.proofVerifier(),
            idHolder,
            idAt,
            handleHolder,
            handleAt,
            namedOn,
            name,
            registry.identitiesOf(holder, 0, 10),
            registry.digestSpent(claimed.sessionId)
        );
    }

    function test_anUpgradeKeepsBindingsAndBindsThroughBothPaths() public {
        (bytes memory first, ICeremony.VerifiedClaim memory firstClaim) = _claim(1);
        vm.prank(holder);
        registry.bind{value: QUOTE}(X, V1, first, _handle(1), true, 0, address(0));
        bytes memory before = _state(firstClaim);

        IdentityRegistry impl = new IdentityRegistry();
        vm.prank(owner);
        registry.upgradeToAndCall(address(impl), "");
        assertEq(address(uint160(uint256(vm.load(address(registry), ERC1967Utils.IMPLEMENTATION_SLOT)))), address(impl));
        assertEq(_state(firstClaim), before, "the upgrade changed what the registry reads");

        (bytes memory second, ICeremony.VerifiedClaim memory secondClaim) = _claim(2);
        vm.expectEmit(true, true, false, true, address(registry));
        emit IdentityRegistry.BindFeePaid(secondClaim.sessionId, host, SERVICE_FEE);
        vm.prank(holder);
        registry.bind{value: QUOTE + SERVICE_FEE}(X, V1, second, "", false, SERVICE_FEE, host);
        assertEq(host.balance, SERVICE_FEE);

        RecordingReceiver receiver = new RecordingReceiver(registry);
        (bytes memory third, ICeremony.VerifiedClaim memory thirdClaim) = _claim(3);
        vm.prank(holder);
        registry.bindWithFeeCall{value: QUOTE + SERVICE_FEE}(
            X, V1, third, _handle(3), false, SERVICE_FEE, address(receiver), "referral"
        );
        assertEq(receiver.binder(), holder);
        assertEq(receiver.handleNode(), thirdClaim.handleNode);
        assertEq(receiver.sessionId(), thirdClaim.sessionId);
        assertEq(receiver.value(), SERVICE_FEE);
        assertEq(receiver.holderSeen(), holder);

        assertEq(registry.identityCount(holder), 3);
        (bytes32 namedOn, string memory name) = registry.primaryHandleOf(holder);
        assertEq(namedOn, X);
        assertEq(name, _handle(1));
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {CeremonyAuthorization} from "../../ceremony/CeremonyAuthorization.sol";
import {IPlatformVerifier} from "../../ceremony/IPlatformVerifier.sol";
import {HandleDisclosure} from "../../ceremony/PlatformVerifierBase.sol";
import {HandlePlatforms} from "../../handles/HandlePlatforms.sol";
import {TestNodes} from "./TestNodes.sol";

/// @notice Stands in for a Platform Verifier: decodes its own payload, rebuilds
///         the digest, and returns the nodes a circuit would (X's tags for an unknown platform).
/// @dev Takes the ceremony version from the payload, so one stub serves several.
contract StubPlatformVerifier is IPlatformVerifier {
    /// @dev The digest inputs and the handle to disclose (empty when private).
    struct StubPayload {
        uint16 ceremonyVersion;
        bytes32 operationDomain;
        bytes32 authorizationNonce;
        bytes transactionData;
        string handle;
    }

    bytes32 private immutable PLATFORM;
    uint256 public fee;
    string public userId = "2244994945";
    string public handle = "alice";
    uint64 public observedAt = 1_770_000_000;
    bytes32 public lastDigest;
    uint256 public lastValue;
    bytes public lastPayload;
    /// While set, report the nodes from `setNodes` as given and return the payload's handle unchecked.
    bool public rawNodes;
    bytes32 public rawIdNode;
    bytes32 public rawHandleNode;

    constructor(bytes32 platform, uint256 fee_) {
        PLATFORM = platform;
        fee = fee_;
    }

    function set(string memory u, string memory h) external {
        userId = u;
        handle = h;
    }

    /// Report these nodes as they are.
    function setNodes(bytes32 idNode, bytes32 handleNode) external {
        rawNodes = true;
        rawIdNode = idNode;
        rawHandleNode = handleNode;
    }

    function setObservedAt(uint64 t) external {
        observedAt = t;
    }

    function platformId() external view returns (bytes32) {
        return PLATFORM;
    }

    function quote() external view returns (uint256) {
        return fee;
    }

    function verify(bytes calldata payload) external payable returns (VerifiedClaim memory c) {
        StubPayload memory p = abi.decode(payload, (StubPayload));
        lastPayload = payload;
        lastValue = msg.value;
        lastDigest = CeremonyAuthorization.digestFor(
            p.operationDomain, p.ceremonyVersion, p.authorizationNonce, p.transactionData
        );

        c.sessionId = lastDigest;
        c.operationDomain = p.operationDomain;
        c.transactionData = p.transactionData;
        c.ceremonyVersion = p.ceremonyVersion;
        c.clientIdentifier = "client";
        if (rawNodes) {
            c.idNode = rawIdNode;
            c.handleNode = rawHandleNode;
            c.handle = p.handle;
        } else {
            bytes32 known = HandlePlatforms.knows(PLATFORM) ? PLATFORM : HandlePlatforms.PLATFORM_X;
            c.idNode = TestNodes.idNode(known, userId);
            (, c.handleNode) = HandlePlatforms.handleNodeOf(known, handle);
            c.handle = HandleDisclosure.check(known, p.handle, c.handleNode);
        }
        c.metadataObservedAt = observedAt;
    }
}

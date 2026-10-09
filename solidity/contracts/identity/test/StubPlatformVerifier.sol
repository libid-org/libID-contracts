// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {CeremonyAuthorization} from "../../ceremony/CeremonyAuthorization.sol";
import {IPlatformVerifier} from "../../ceremony/IPlatformVerifier.sol";
import {HandlePlatforms} from "../../handles/HandlePlatforms.sol";
import {TestNodes} from "./TestNodes.sol";

/// @notice Stands in for a Platform Verifier.
///
/// @dev Everything a real one checks has its own suite. Here it only has to
///      charge, decode, answer, and let the Consumer's and the Proof Verifier's
///      own duties be exercised.
///
///      It decodes a payload of its own shape and rebuilds the digest the way
///      a real verifier does -- from the decoded fields and the chain it runs
///      on -- so a test above it can watch the domain, the transaction data
///      and the digest travel, rather than have the stub invent them. Unlike a
///      real verifier it takes the ceremony version from the payload instead
///      of a constant, so one stub can stand in for several.
///
///      It returns the nodes a circuit would: the id hashed as given, the
///      handle folded with the platform's rules and hashed, under the
///      platform's tags -- X's for a platform the table does not know.
contract StubPlatformVerifier is IPlatformVerifier {
    /// @dev The stub's payload: what the digest needs, and the handle to
    ///      disclose (empty for a private submission).
    struct StubPayload {
        uint16 ceremonyVersion;
        bytes32 operationDomain;
        bytes32 authorizationNonce;
        bytes transactionData;
        string handle;
    }

    /// @dev `PlatformVerifierBase.HandleNotProved`, so a test reads one
    ///      selector whichever verifier refused.
    error HandleNotProved(bytes32 disclosed, bytes32 proved);

    bytes32 private immutable PLATFORM;
    uint256 public fee;
    string public userId = "2244994945";
    string public handle = "alice";
    uint64 public observedAt = 1_770_000_000;
    bytes32 public lastDigest;
    uint256 public lastValue;
    bytes public lastPayload;
    /// Nodes reported as given instead of hashed from `userId` and `handle`,
    /// while `rawNodes` is set: a node no circuit would output, zero among them.
    /// The payload's handle is then returned as it came, unchecked, as a
    /// verifier that skipped its disclosure check would return it.
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

    /// Report these nodes as they are, for a test of what the registry does
    /// with a node it did not expect.
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
            // The real verifiers' disclosure check: the disclosed handle,
            // normalized, must hash to the handle node.
            if (bytes(p.handle).length != 0) {
                (string memory normalized, bytes32 node) = HandlePlatforms.handleNodeOf(known, p.handle);
                if (node != c.handleNode) revert HandleNotProved(node, c.handleNode);
                c.handle = normalized;
            }
        }
        c.metadataObservedAt = observedAt;
    }
}

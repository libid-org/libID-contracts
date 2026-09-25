/// The key the identity system stores a handle under.
///
/// This mirrors `IdentityNodes.handleNode` in
/// `solidity/contracts/identity/IdentityNodes.sol`. `IdentityNames` binds a
/// handle under this node and emits it as `IdentityBound.handleNode`, and
/// `HandleEscrow` holds value against the same node, so a client that pays
/// with `depositToNode` computes it here rather than putting the handle in
/// calldata.

import { encodeAbiParameters, type Hex, keccak256, toHex } from 'viem'

/// The version tag that leads every handle-node preimage.
export const HANDLE_NODE_V1: Hex = keccak256(toHex('libid.identity.handle-node.v1'))

/// The node a handle is stored under.
///
/// `normalizedHandle` must be the handle AFTER `normalize` under the platform's
/// rules. A raw handle gives a node nothing on chain was ever keyed by, and a
/// deposit to it can never be claimed.
export function handleNode(platformId: Hex, normalizedHandle: string): Hex {
  return keccak256(
    encodeAbiParameters(
      [{ type: 'bytes32' }, { type: 'bytes32' }, { type: 'bytes32' }],
      [HANDLE_NODE_V1, platformId, keccak256(toHex(normalizedHandle))],
    ),
  )
}

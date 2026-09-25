/// The key the identity system stores a handle under.
///
/// This mirrors `IdentityNodes.handleNode` in
/// `solidity/contracts/identity/IdentityNodes.sol`. `IdentityNames` binds a
/// handle under this node and emits it as `IdentityBound.handleNode`, and
/// `HandleEscrow` holds value against the same node, so a client that pays
/// with `depositToNode` computes it here rather than putting the handle in
/// calldata.

import { encodeAbiParameters, type Hex, keccak256, toHex } from 'viem'

import { type NormalizedHandle, normalize, rulesFor } from './handle.js'
import { platformId } from './resolve.js'

/// The version tag that leads every handle-node preimage.
export const HANDLE_NODE_V1: Hex = keccak256(toHex('libid.identity.handle-node.v1'))

/// The node a handle is stored under.
///
/// Takes the handle AFTER `normalize` under the platform's rules, and the type
/// says so: a raw handle gives a node nothing on chain was ever keyed by, and
/// a deposit to it can never be claimed. From what a user typed, use
/// `handleNodeOf`, or `normalize` first with the rules the platform has on
/// chain now (`IdentityNames.rulesOf`).
export function handleNode(platformId: Hex, normalizedHandle: NormalizedHandle): Hex {
  return keccak256(
    encodeAbiParameters(
      [{ type: 'bytes32' }, { type: 'bytes32' }, { type: 'bytes32' }],
      [HANDLE_NODE_V1, platformId, keccak256(toHex(normalizedHandle))],
    ),
  )
}

/// The node of a handle as a user typed it, on one of the platforms in the
/// generated table (`'x'`, `'github'`, `'google'`).
///
/// Normalizes under that platform's rules from the table, then keys the result,
/// so the platform id and the rules cannot come from two different platforms.
/// Throws `HandleError` for text the rules refuse, and an `Error` for a platform
/// the table does not have.
///
/// The table holds the rules the platforms launched with. `IdentityNames`
/// normalizes under the rules its owner configured, which `setPlatform` can
/// change; a client that must follow a change reads `rulesOf` and calls
/// `handleNode(platformId(domain), normalize(raw, rules))` itself.
export function handleNodeOf(platform: string, rawHandle: string): Hex {
  const rules = rulesFor(platform)
  if (rules === null) throw new Error(`no handle rules for platform ${JSON.stringify(platform)}`)
  return handleNode(platformId(platform), normalize(rawHandle, rules))
}

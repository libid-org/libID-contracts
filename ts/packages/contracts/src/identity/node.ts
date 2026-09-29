/// Handle nodes and hashes, mirroring `IdentityNodes.handleNode` and
/// `handleNodeOfHash`. `HandleEscrow.deposit` takes `handleHash`; `byHandle`
/// and the escrow's reads take `handleNode`.

import { encodeAbiParameters, type Hex, keccak256, toHex } from 'viem'

import { type NormalizedHandle, normalize, rulesFor } from './handle.js'
import { platformId } from './resolve.js'

/// The version tag that leads every handle-node preimage.
export const HANDLE_NODE_V1: Hex = keccak256(toHex('libid.identity.handle-node.v1'))

/// The node a normalized handle is stored under.
export function handleNode(platform: Hex, normalizedHandle: NormalizedHandle): Hex {
  return handleNodeOfHash(platform, handleHash(normalizedHandle))
}

/// `keccak256` of a normalized handle: the inner hash of `handleNode`.
export function handleHash(normalizedHandle: NormalizedHandle): Hex {
  return keccak256(toHex(normalizedHandle))
}

/// The node of a handle given as `handleHash`, under a platform id.
export function handleNodeOfHash(platform: Hex, hash: Hex): Hex {
  return keccak256(
    encodeAbiParameters(
      [{ type: 'bytes32' }, { type: 'bytes32' }, { type: 'bytes32' }],
      [HANDLE_NODE_V1, platform, hash],
    ),
  )
}

/// The node of raw text on a platform in the generated table. Throws
/// `HandleError` for text the rules refuse. Valid text is not always a real
/// account (e.g. `a.lice@gmail.com`); a deposit to it is only refundable.
export function handleNodeOf(platform: string, rawHandle: string): Hex {
  return handleNode(platformId(platform), normalizeFor(platform, rawHandle))
}

/// The `handleHash` of raw text: the off-chain `IdentityNames.handleHashOf`.
export function handleHashOf(platform: string, rawHandle: string): Hex {
  return handleHash(normalizeFor(platform, rawHandle))
}

function normalizeFor(platform: string, rawHandle: string): NormalizedHandle {
  const rules = rulesFor(platform)
  if (rules === null) throw new Error(`no handle rules for platform ${JSON.stringify(platform)}`)
  return normalize(rawHandle, rules)
}

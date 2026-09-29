/// Handle nodes and hashes, mirroring `IdentityNodes.handleNode` and
/// `IdentityNames.nodeOfHash`. `HandleEscrow.deposit` takes `handleHash`;
/// `byHandle` and the escrow's reads take `handleNode`.
///
/// Raw text is normalized under rules the caller passes. `rulesOnChain` reads
/// the rules a platform has now; `rulesFor` is the generated table, which the
/// chain's owner can narrow after release.

import { encodeAbiParameters, type Hex, keccak256, toHex } from 'viem'

import { type NormalizedHandle, normalize, type Rules } from './handle.js'
import { type NamesReader, platformId, rulesOnChain } from './resolve.js'

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

/// The `handleHash` of raw text under `rules`. Throws `HandleError` for text
/// the rules refuse. Valid text is not always a real account (e.g.
/// `a.lice@gmail.com`); a deposit to it is only refundable.
export function handleHashOf(rawHandle: string, rules: Rules): Hex {
  return handleHash(normalize(rawHandle, rules))
}

/// The node of raw text on a platform (its domain, e.g. `'x'`) under `rules`.
export function handleNodeOf(platform: string, rawHandle: string, rules: Rules): Hex {
  return handleNodeOfHash(platformId(platform), handleHashOf(rawHandle, rules))
}

/// The `handleHash` of raw text under the platform's rules on chain now,
/// computed locally: only the platform id reaches the RPC, never the text.
export async function handleHashOnChainRules(
  reader: NamesReader,
  platform: string,
  rawHandle: string,
): Promise<Hex> {
  return handleHashOf(rawHandle, await rulesOnChain(reader, platformId(platform)))
}

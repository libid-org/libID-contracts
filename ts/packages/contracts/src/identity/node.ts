/// Handle hashes and nodes, mirroring `IdentityNames.handleHashOf` and
/// `nodeOfHash`, computed locally so the handle text never reaches an RPC.
/// `HandleEscrow.deposit` takes the hash; `byHandle` and the escrow's reads
/// take the node.

import { encodeAbiParameters, type Hex, keccak256, toHex } from 'viem'

import { normalize, type Rules } from './handle.js'
import { type PlatformDomain, platformId } from './resolve.js'

const HANDLE_NODE_V1: Hex = keccak256(toHex('libid.identity.handle-node.v1'))

/// `keccak256` of `raw` normalized under `rules` (from `rulesOnChain`, or
/// `rulesFor` offline). Throws `HandleError` for text the rules refuse.
export function handleHash(raw: string, rules: Rules): Hex {
  return keccak256(toHex(normalize(raw, rules)))
}

/// The node a handle hash keys to on a platform, named by its domain (`'x'`).
export function handleNode<D extends string>(domain: PlatformDomain<D>, hash: Hex): Hex {
  return keccak256(
    encodeAbiParameters(
      [{ type: 'bytes32' }, { type: 'bytes32' }, { type: 'bytes32' }],
      [HANDLE_NODE_V1, platformId(domain), hash],
    ),
  )
}

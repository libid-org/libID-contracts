/// Handle hashes and nodes, mirroring `IdentityNames.handleHashOf` and
/// `handleNodeOfHash`, computed locally so the handle text never reaches an
/// RPC. `HandleEscrow.deposit` takes the hash; `handleBinding` and the
/// escrow's reads take the node.

import { encodeAbiParameters, type Hex, keccak256, toHex } from 'viem'

import { normalize, type Rules } from './handle.js'
import { type PlatformKey, platformId } from './resolve.js'

const HANDLE_NODE_V1: Hex = keccak256(toHex('libid.identity.handle-node.v1'))

/// `keccak256` of `raw` normalized under `rules` (from `rulesOf`, or
/// `rulesFor` offline). Throws `HandleError` for text the rules refuse.
export function handleHash(raw: string, rules: Rules): Hex {
  return keccak256(toHex(normalize(raw, rules)))
}

/// The node a handle hash sits on, on a platform named by its key (`'x'`).
export function handleNode<K extends string>(platformKey: PlatformKey<K>, hash: Hex): Hex {
  return keccak256(
    encodeAbiParameters(
      [{ type: 'bytes32' }, { type: 'bytes32' }, { type: 'bytes32' }],
      [HANDLE_NODE_V1, platformId(platformKey), hash],
    ),
  )
}

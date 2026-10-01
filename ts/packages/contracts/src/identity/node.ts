/// Handle hashes and nodes, mirroring `IdentityRegistry.handleHashOf` and
/// `handleNodeOfHash`, computed locally so the handle text never reaches an
/// RPC. `HandleEscrow.deposit` takes the hash; `handleBinding` and the
/// escrow's reads take the node.

import { encodeAbiParameters, type Hex, keccak256, toHex } from 'viem'

import { normalize, type Rules } from './handle.js'

const HANDLE_NODE_V1: Hex = keccak256(toHex('libid.identity.handle-node.v1'))

/// `keccak256` of `raw` normalized under `rules` (from `rulesOf`, or
/// `rulesFor` offline). Throws `HandleError` for text the rules refuse.
export function handleHash(raw: string, rules: Rules): Hex {
  return keccak256(toHex(normalize(raw, rules)))
}

/// The node a handle hash sits on, on the platform `platformId` names
/// (`platformId(PLATFORM_X_KEY)`), as `IdentityRegistry.handleNodeOfHash` derives
/// it.
export function handleNode(platformId: Hex, hash: Hex): Hex {
  return keccak256(
    encodeAbiParameters(
      [{ type: 'bytes32' }, { type: 'bytes32' }, { type: 'bytes32' }],
      [HANDLE_NODE_V1, platformId, hash],
    ),
  )
}

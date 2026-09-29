/// The key the identity system stores a handle under.
///
/// This mirrors `IdentityNodes.handleNode` and `handleNodeOfHash` in
/// `solidity/contracts/identity/IdentityNodes.sol`. `IdentityNames` binds a
/// handle under this node and emits it as `IdentityBound.handleNode`, and
/// `HandleEscrow` holds value against the same node. A client pays with
/// `HandleEscrow.deposit`, which takes `handleHash`, and reads balances by
/// `handleNode`.

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
export function handleNode(platform: Hex, normalizedHandle: NormalizedHandle): Hex {
  return handleNodeOfHash(platform, handleHash(normalizedHandle))
}

/// `keccak256` of a normalized handle: what `HandleEscrow.deposit` takes, and
/// the inner hash of `handleNode`. Takes only a `NormalizedHandle`,
/// for the reason `handleNode` does.
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

/// The node of a handle as a user typed it, on one of the platforms in the
/// generated table (`'x'`, `'github'`, `'google'`).
///
/// Normalizes under that platform's rules from the table, then keys the result,
/// so the platform id and the rules cannot come from two different platforms.
/// Throws `HandleError` for text the rules refuse, and an `Error` for a platform
/// the table does not have.
///
/// Text the rules accept is not thereby a handle a proof will bind. Google signs
/// the exact address an account has, so `a.lice@gmail.com` and
/// `alice+tag@gmail.com` are valid text that key to nodes of their own, not to
/// `alice@gmail.com`'s, and no proof binds them. Pass the address as the payee
/// uses it; a deposit to such a node is only recoverable by its `refundTo`.
///
/// The table holds the rules the platforms launched with. `IdentityNames`
/// normalizes under the rules its owner configured, which `setPlatform` can
/// change; a client that must follow a change reads `rulesOf` and calls
/// `handleNode(platformId(domain), normalize(raw, rules))` itself.
export function handleNodeOf(platform: string, rawHandle: string): Hex {
  return handleNode(platformId(platform), normalizeFor(platform, rawHandle))
}

/// The `handleHash` of a handle as a user typed it, for `HandleEscrow.deposit`:
/// the off-chain equivalent of `IdentityNames.handleHashOf`, under the rules
/// in the generated table. Throws as `handleNodeOf` does.
export function handleHashOf(platform: string, rawHandle: string): Hex {
  return handleHash(normalizeFor(platform, rawHandle))
}

function normalizeFor(platform: string, rawHandle: string): NormalizedHandle {
  const rules = rulesFor(platform)
  if (rules === null) throw new Error(`no handle rules for platform ${JSON.stringify(platform)}`)
  return normalize(rawHandle, rules)
}

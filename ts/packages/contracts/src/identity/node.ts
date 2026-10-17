/// The keys a binding is stored under, `SHA256(tag || value)`, computed
/// locally so the handle or id never reaches an RPC.

import { concat, type Hex, sha256, toHex } from 'viem'

import { checkId, normalize, type Platform, platform } from '../platforms/index.js'

function keysOf(platformKey: string): Platform {
  const keys = platform(platformKey)
  if (keys === undefined) throw new Error(`unknown platform ${JSON.stringify(platformKey)}`)
  return keys
}

/// The node a typed handle is bound under: normalized, then hashed under
/// its handle tag. Throws `HandleError` for text no binding can have.
export function handleNode(platformKey: string, raw: string): Hex {
  const keys = keysOf(platformKey)
  return sha256(concat([toHex(keys.handleTag), toHex(normalize(raw, keys.rules))]))
}

/// The node `depositToHandle` and the registry's `handleNodeOf` derive from
/// `text`: A-Z folded, nothing checked, so text no circuit hashes has one too.
export function foldedHandleNode(platformKey: string, text: string): Hex {
  const bytes = new TextEncoder().encode(text).map((b) => (b >= 0x41 && b <= 0x5a ? b + 0x20 : b))
  return sha256(concat([toHex(keysOf(platformKey).handleTag), toHex(bytes)]))
}

/// The node an id is bound under: the id as given, under its user-id tag.
export function idNode(platformKey: string, id: string): Hex {
  checkId(platformKey, id)
  return sha256(concat([toHex(keysOf(platformKey).userIdTag), toHex(id)]))
}

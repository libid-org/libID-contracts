/// The keys a binding is stored under, `SHA256(tag || value)`, computed
/// locally so the handle or id never reaches an RPC.

import { sha256 } from '@noble/hashes/sha2.js'
import { bytesToHex, concatBytes, utf8ToBytes } from '@noble/hashes/utils.js'

import { normalize } from './handle.js'
import { checkId } from './id.js'
import { type Platform, platform } from './platforms.js'

function keysOf(platformKey: string): Platform {
  const keys = platform(platformKey)
  if (keys === undefined) throw new Error(`unknown platform ${JSON.stringify(platformKey)}`)
  return keys
}

/// `SHA256(tag || value)` as lowercase `0x` hex.
function nodeOf(tag: string, value: Uint8Array): `0x${string}` {
  return `0x${bytesToHex(sha256(concatBytes(utf8ToBytes(tag), value)))}`
}

/// The node a typed handle is bound under: normalized, then hashed under
/// its handle tag. Throws `HandleError` for text no binding can have.
export function handleNode(platformKey: string, raw: string): `0x${string}` {
  const keys = keysOf(platformKey)
  return nodeOf(keys.handleTag, utf8ToBytes(normalize(raw, keys.rules)))
}

/// The node `depositToHandle` and the registry's `handleNodeOf` derive from
/// `text`: A-Z folded, nothing checked, so text no circuit hashes has one too.
export function foldedHandleNode(platformKey: string, text: string): `0x${string}` {
  const bytes = utf8ToBytes(text).map((b) => (b >= 0x41 && b <= 0x5a ? b + 0x20 : b))
  return nodeOf(keysOf(platformKey).handleTag, bytes)
}

/// The node an id is bound under: the id as given, under its user-id tag.
/// Throws `IdError` for an id no circuit hashes.
export function idNode(platformKey: string, id: string): `0x${string}` {
  checkId(platformKey, id)
  return nodeOf(keysOf(platformKey).userIdTag, utf8ToBytes(id))
}

/// The keys a binding is stored under, `SHA256(tag || value)`, computed
/// locally so the handle or id never reaches an RPC. Unsalted: anyone can
/// test a guess.

import { concat, type Hex, sha256, toHex } from 'viem'

import { isStringByte, normalize } from './handle.js'
import { IdError, type Platform, platform } from './platforms.js'

/// What a platform allows in an id, as the generated table states it.
export interface IdRules {
  /** Bytes the circuit's buffer holds. */
  maxLength: number
  /** ASCII digits; otherwise printable ASCII without a quote or backslash. */
  decimal: boolean
}

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

/// The node `depositToHandle` and the registry's `handleNodeOf` key `text`
/// by: A-Z folded, nothing checked. Text no circuit hashes still has one.
export function foldedHandleNode(platformKey: string, text: string): Hex {
  const bytes = new TextEncoder().encode(text).map((b) => (b >= 0x41 && b <= 0x5a ? b + 0x20 : b))
  return sha256(concat([toHex(keysOf(platformKey).handleTag), toHex(bytes)]))
}

/// Accept an id exactly as given, or throw an `IdError` saying why no circuit would hash it.
export function checkId(platformKey: string, id: string): void {
  const rules = keysOf(platformKey).idRules
  const bytes = new TextEncoder().encode(id)
  if (bytes.length === 0) throw new IdError('Empty')
  if (bytes.length > rules.maxLength) throw new IdError('TooLong')
  for (const b of bytes) {
    const ok = rules.decimal ? b >= 0x30 && b <= 0x39 : isStringByte(b)
    if (!ok) throw new IdError('BadCharacter')
  }
}

/// The node an id is bound under: the id as given, under its user-id tag.
export function idNode(platformKey: string, id: string): Hex {
  checkId(platformKey, id)
  return sha256(concat([toHex(keysOf(platformKey).userIdTag), toHex(id)]))
}

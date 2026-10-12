/// The keys a binding is stored under, `SHA256(tag || value)`, computed
/// locally so the handle or id never reaches an RPC. Unsalted: anyone can
/// test a guess.

import { concat, type Hex, sha256, toHex } from 'viem'

import { HandleError, normalize } from './handle.js'
import {
  ERROR_BADCHARACTER,
  ERROR_BADSHAPE,
  ERROR_EMPTY,
  ERROR_TOOLONG,
  type Platform,
  platform,
} from './handleVectors.js'

/// What a platform allows in an id, as the generated table states it.
export interface IdRules {
  /** Bytes allowed. */
  maxLength: number
  /** ASCII digits; otherwise printable ASCII without a quote or backslash. */
  decimal: boolean
  /** The id may start with `0` when longer than one byte. */
  leadingZero: boolean
  /** The id may not be `0`. */
  nonzero: boolean
  /** The largest id, as decimal as long as `maxLength`. */
  max: string | null
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

/// Accept an id exactly as given, or throw why no circuit would hash it.
export function checkId(platformKey: string, id: string): void {
  const rules = keysOf(platformKey).idRules
  const bytes = new TextEncoder().encode(id)
  if (bytes.length === 0) throw new HandleError(ERROR_EMPTY, 'the id is empty')
  if (bytes.length > rules.maxLength) {
    throw new HandleError(ERROR_TOOLONG, 'the id is too long for this platform')
  }
  for (const b of bytes) {
    const ok = rules.decimal
      ? b >= 0x30 && b <= 0x39
      : b >= 0x20 && b <= 0x7e && b !== 0x22 && b !== 0x5c
    if (!ok)
      throw new HandleError(ERROR_BADCHARACTER, 'the id has a byte this platform does not allow')
  }
  const notIssued = () =>
    new HandleError(ERROR_BADSHAPE, 'the id is not a number this platform issues')
  if (!rules.leadingZero && bytes.length > 1 && bytes[0] === 0x30) throw notIssued()
  if (rules.nonzero && id === '0') throw notIssued()
  // Equal-length digit strings order as their numbers do.
  if (rules.max !== null && id.length === rules.max.length && id > rules.max) throw notIssued()
}

/// The node an id is bound under: the id as given, under its user-id tag.
export function idNode(platformKey: string, id: string): Hex {
  checkId(platformKey, id)
  return sha256(concat([toHex(keysOf(platformKey).userIdTag), toHex(id)]))
}

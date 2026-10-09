/// The keys a binding is stored under, computed locally so the handle or id
/// never reaches an RPC: `SHA256(tag || value)`, the node the platform's
/// circuit outputs. `IdentityRegistry.handleBinding`, `idBinding`,
/// `resolveId` and `HandleEscrow.deposit` all take a node.

import { concat, type Hex, sha256, toHex } from 'viem'

import { HandleError, normalize, rulesFor } from './handle.js'
import {
  ERROR_BADCHARACTER,
  ERROR_BADSHAPE,
  ERROR_EMPTY,
  ERROR_TOOLONG,
  HANDLE_TAG_GITHUB,
  HANDLE_TAG_GOOGLE,
  HANDLE_TAG_X,
  ID_DECIMAL_GITHUB,
  ID_DECIMAL_GOOGLE,
  ID_DECIMAL_X,
  ID_LEADING_ZERO_GITHUB,
  ID_LEADING_ZERO_GOOGLE,
  ID_LEADING_ZERO_X,
  MAX_ID_LENGTH_GITHUB,
  MAX_ID_LENGTH_GOOGLE,
  MAX_ID_LENGTH_X,
  PLATFORM_GITHUB_KEY,
  PLATFORM_GOOGLE_KEY,
  PLATFORM_X_KEY,
  USER_ID_TAG_GITHUB,
  USER_ID_TAG_GOOGLE,
  USER_ID_TAG_X,
} from './handleVectors.js'

/// A platform's node tags and id rules, from the generated table.
interface PlatformKeys {
  userIdTag: string
  handleTag: string
  idMaxLength: number
  idDecimal: boolean
  idLeadingZero: boolean
}

const PLATFORMS: Record<string, PlatformKeys> = {
  [PLATFORM_X_KEY]: {
    userIdTag: USER_ID_TAG_X,
    handleTag: HANDLE_TAG_X,
    idMaxLength: MAX_ID_LENGTH_X,
    idDecimal: ID_DECIMAL_X,
    idLeadingZero: ID_LEADING_ZERO_X,
  },
  [PLATFORM_GITHUB_KEY]: {
    userIdTag: USER_ID_TAG_GITHUB,
    handleTag: HANDLE_TAG_GITHUB,
    idMaxLength: MAX_ID_LENGTH_GITHUB,
    idDecimal: ID_DECIMAL_GITHUB,
    idLeadingZero: ID_LEADING_ZERO_GITHUB,
  },
  [PLATFORM_GOOGLE_KEY]: {
    userIdTag: USER_ID_TAG_GOOGLE,
    handleTag: HANDLE_TAG_GOOGLE,
    idMaxLength: MAX_ID_LENGTH_GOOGLE,
    idDecimal: ID_DECIMAL_GOOGLE,
    idLeadingZero: ID_LEADING_ZERO_GOOGLE,
  },
}

/// Own keys only: a name `Object.prototype` carries, such as `toString` or
/// `__proto__`, is an unknown platform like any other.
function keysOf(platformKey: string): PlatformKeys {
  if (!Object.hasOwn(PLATFORMS, platformKey)) {
    throw new Error(`unknown platform ${JSON.stringify(platformKey)}`)
  }
  return PLATFORMS[platformKey] as PlatformKeys
}

/// The node a handle is bound under, from the handle as a user typed it:
/// normalized with the platform's rules, then hashed under its handle tag.
/// Throws `HandleError` for text no binding can have.
export function handleNode(platformKey: string, raw: string): Hex {
  const keys = keysOf(platformKey)
  const rules = rulesFor(platformKey)
  if (rules === null) throw new Error(`unknown platform ${JSON.stringify(platformKey)}`)
  return sha256(concat([toHex(keys.handleTag), toHex(normalize(raw, rules))]))
}

/// Accept an id exactly as the platform sent it, or throw the `HandleError`
/// kind no circuit would hash it under. Ids are never normalized.
export function checkId(platformKey: string, id: string): void {
  const keys = keysOf(platformKey)
  const bytes = new TextEncoder().encode(id)
  if (bytes.length === 0) throw new HandleError(ERROR_EMPTY, 'the id is empty')
  if (bytes.length > keys.idMaxLength) {
    throw new HandleError(ERROR_TOOLONG, 'the id is too long for this platform')
  }
  for (const b of bytes) {
    const ok = keys.idDecimal
      ? b >= 0x30 && b <= 0x39
      : b >= 0x20 && b <= 0x7e && b !== 0x22 && b !== 0x5c
    if (!ok)
      throw new HandleError(ERROR_BADCHARACTER, 'the id has a byte this platform does not allow')
  }
  if (!keys.idLeadingZero && bytes.length > 1 && bytes[0] === 0x30) {
    throw new HandleError(ERROR_BADSHAPE, 'the id has a leading zero')
  }
}

/// The node an id is bound under: the id exactly as given, hashed under the
/// platform's user-id tag.
export function idNode(platformKey: string, id: string): Hex {
  checkId(platformKey, id)
  return sha256(concat([toHex(keysOf(platformKey).userIdTag), toHex(id)]))
}

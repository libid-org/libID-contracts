/// Turns a typed handle into the form the identity circuits hash into a node.
///
/// A-Z fold to a-z and anything else invalid is refused, never repaired. It
/// mirrors the circuits, Solidity and Rust; all run the `handles.json` vectors.

import {
  ERROR_BADCHARACTER,
  ERROR_BADSHAPE,
  ERROR_EMPTY,
  ERROR_TOOLONG,
  PLATFORM_GITHUB,
  PLATFORM_GOOGLE,
  PLATFORM_X,
  platform,
} from './handleVectors.js'

/// Why a handle was refused. The kinds match the Solidity errors and the Rust
/// ones, because the vector table names which refusal it expects.
export class HandleError extends Error {
  constructor(
    readonly kind: number,
    message: string,
  ) {
    super(message)
    this.name = 'HandleError'
  }
}

const EMPTY = () => new HandleError(ERROR_EMPTY, 'the handle is empty')
const TOO_LONG = () => new HandleError(ERROR_TOOLONG, 'the handle is too long for this platform')
const BAD_CHARACTER = () =>
  new HandleError(ERROR_BADCHARACTER, 'the handle has a character this platform does not allow')
const BAD_SHAPE = () =>
  new HandleError(ERROR_BADSHAPE, 'the handle has an arrangement this platform does not allow')

/// What one platform accepts, generated from `handles.json`.
export interface Rules {
  /** Bytes allowed. */
  maxLength: number
  /** Validate as an address instead of a bare handle. */
  isEmail: boolean
  /** Allowed by X, not by GitHub. */
  allowUnderscore: boolean
  /** A hyphen may not start or end the handle, and two may not touch. */
  allowHyphen: boolean
}

export const RULES_X: Rules = PLATFORM_X.rules
export const RULES_GITHUB: Rules = PLATFORM_GITHUB.rules
export const RULES_GOOGLE: Rules = PLATFORM_GOOGLE.rules

/// The rules for a platform key from the generated table.
export function rulesFor(platformKey: string): Rules | null {
  return platform(platformKey)?.rules ?? null
}

/// The normalized handle, or a `HandleError` naming what was wrong.
export function normalize(raw: string, rules: Rules): string {
  // Work on bytes, not code units. A character above 0x7f is several bytes and
  // must be refused as bytes, the way Solidity sees it.
  const input = new TextEncoder().encode(raw)

  const length = input.length
  if (length === 0) throw EMPTY()
  if (length > rules.maxLength) throw TOO_LONG()

  const out = new Uint8Array(length)
  for (let i = 0; i < length; i++) {
    let c = input[i]
    // Fold A-Z down. Nothing else changes, so two addresses that differ in more
    // than case stay two identities.
    if (c >= 0x41 && c <= 0x5a) c += 0x20
    if (!allowed(c, rules)) throw BAD_CHARACTER()
    out[i] = c
  }

  if (rules.isEmail) requireEmailShape(out)
  else if (rules.allowHyphen) requireHyphenShape(out)

  return new TextDecoder().decode(out)
}

/// One byte, after folding. Anything outside the platform's set is refused,
/// including every byte above 0x7f, so a multi-byte character never reaches a
/// node.
function allowed(c: number, rules: Rules): boolean {
  if (c >= 0x61 && c <= 0x7a) return true // a-z
  if (c >= 0x30 && c <= 0x39) return true // 0-9
  if (rules.isEmail) {
    // The set a Google address uses. The dot, the plus and the tag stay exactly
    // as proved: this transform must never map two addresses onto one identity.
    return c === 0x2e || c === 0x2b || c === 0x2d || c === 0x5f || c === 0x40
  }
  if (rules.allowUnderscore && c === 0x5f) return true
  if (rules.allowHyphen && c === 0x2d) return true
  return false
}

/// Exactly one `@`, and not at either edge.
function requireEmailShape(value: Uint8Array): void {
  let at = -1
  for (let i = 0; i < value.length; i++) {
    if (value[i] === 0x40) {
      if (at !== -1) throw BAD_SHAPE() // a second one
      at = i
    }
  }
  if (at === -1) throw BAD_SHAPE() // none
  if (at === 0 || at === value.length - 1) throw BAD_SHAPE() // an empty side
}

/// A hyphen may not start or end the handle, and two may not touch.
function requireHyphenShape(value: Uint8Array): void {
  if (value[0] === 0x2d || value[value.length - 1] === 0x2d) throw BAD_SHAPE()
  for (let i = 1; i < value.length; i++) {
    if (value[i] === 0x2d && value[i - 1] === 0x2d) throw BAD_SHAPE()
  }
}

/// Turns a typed handle into the form the identity circuits hash into a node.
///
/// A-Z fold to a-z. The handle must be one JSON string as a platform sends it:
/// printable ASCII without `"` or `\`, no longer than the circuit's buffer. Its
/// format is the platform's. It mirrors the circuits and Rust; all run the
/// `handles.json` vectors.

import {
  ERROR_BADCHARACTER,
  ERROR_EMPTY,
  ERROR_TOOLONG,
  PLATFORM_GITHUB,
  PLATFORM_GOOGLE,
  PLATFORM_X,
  platform,
} from './handleVectors.js'

/// Why a handle was refused. The kinds match the circuits' messages and the Rust
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
  new HandleError(
    ERROR_BADCHARACTER,
    'the handle has a byte outside printable ASCII, or a quote or backslash',
  )

/// What one platform's circuit takes, generated from its profile's `keys`.
export interface Rules {
  /** Bytes the circuit's buffer holds. */
  maxLength: number
}

export const RULES_X: Rules = PLATFORM_X.rules
export const RULES_GITHUB: Rules = PLATFORM_GITHUB.rules
export const RULES_GOOGLE: Rules = PLATFORM_GOOGLE.rules

/// The rules for a platform key from the generated table.
export function rulesFor(platformKey: string): Rules | null {
  return platform(platformKey)?.rules ?? null
}

/// A byte of a JSON string as sent: printable ASCII, not `"` or `\`.
export function isStringByte(b: number): boolean {
  return b >= 0x20 && b <= 0x7e && b !== 0x22 && b !== 0x5c
}

/// The handle folded, or a `HandleError` naming what was wrong.
export function normalize(raw: string, rules: Rules): string {
  // Work on bytes, not code units. A character above 0x7f is several bytes and
  // must be refused as bytes, the way the circuits see it.
  const input = new TextEncoder().encode(raw)
  if (input.length === 0) throw EMPTY()
  if (input.length > rules.maxLength) throw TOO_LONG()
  if (!input.every(isStringByte)) throw BAD_CHARACTER()
  // ASCII alone, so this folds A-Z and nothing else.
  return raw.toLowerCase()
}

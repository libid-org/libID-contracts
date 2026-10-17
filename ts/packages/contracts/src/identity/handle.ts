/// Turns a typed handle into the form the identity circuits hash into a node.
///
/// A-Z fold to a-z. The handle must be one JSON string as a platform sends it:
/// printable ASCII without `"` or `\`, no longer than the circuit's buffer. Its
/// format is the platform's. It mirrors the circuits and Rust; all run the
/// `handles.json` vectors.

import { HandleError, PLATFORM_GITHUB, PLATFORM_GOOGLE, PLATFORM_X, platform } from './platforms.js'

/// What one platform's circuit takes, generated from the circuits' `platforms.json`.
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
  if (input.length === 0) throw new HandleError('Empty')
  if (input.length > rules.maxLength) throw new HandleError('TooLong')
  if (!input.every(isStringByte)) throw new HandleError('BadCharacter')
  // ASCII alone, so this folds A-Z and nothing else.
  return raw.toLowerCase()
}

/// The id check the identity circuits apply: an id is hashed exactly as the
/// platform sent it, so it is checked and never normalized.

import { isStringByte } from './handle.js'
import { IdError, platform } from './platforms.js'

/// What a platform allows in an id, as the generated table states it.
export interface IdRules {
  /** Bytes the circuit's buffer holds. */
  maxLength: number
  /** True: ASCII digits. False: printable ASCII without a quote or backslash. */
  decimal: boolean
}

/// Accept an id exactly as given, or throw an `IdError` saying why no circuit would hash it.
export function checkId(platformKey: string, id: string): void {
  const rules = platform(platformKey)?.idRules
  if (rules === undefined) throw new Error(`unknown platform ${JSON.stringify(platformKey)}`)
  const bytes = new TextEncoder().encode(id)
  if (bytes.length === 0) throw new IdError('Empty')
  if (bytes.length > rules.maxLength) throw new IdError('TooLong')
  for (const b of bytes) {
    const ok = rules.decimal ? b >= 0x30 && b <= 0x39 : isStringByte(b)
    if (!ok) throw new IdError('BadCharacter')
  }
}

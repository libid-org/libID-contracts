import { describe, expect, it } from 'vitest'
import { checkId } from './id.js'
import { IdError, type RefusalKind } from './platforms.js'
import { ID_VECTORS } from './vectors.js'

/// What `checkId` answers, or the refusal it threw, in the vector table's shape.
function checked(
  platformKey: string,
  id: string,
): { ok: true } | { ok: false; refusal: RefusalKind } {
  try {
    checkId(platformKey, id)
    return { ok: true }
  } catch (e) {
    if (!(e instanceof IdError)) throw e
    return { ok: false, refusal: e.kind }
  }
}

describe('checkId', () => {
  it('accepts or refuses every id vector as the table states', () => {
    for (const [i, v] of ID_VECTORS.entries()) {
      const want = v.expected.ok ? { ok: true } : v.expected
      expect(checked(v.platform, v.input), `id vector ${i}`).toEqual(want)
    }
  })

  it('throws for a platform the table does not name', () => {
    expect(() => checkId('mastodon', '1')).toThrow(/unknown platform/)
    expect(() => checkId('toString', '1')).toThrow(/unknown platform/)
  })
})

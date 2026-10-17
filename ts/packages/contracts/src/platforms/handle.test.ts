import { describe, expect, it } from 'vitest'
import { normalize, RULES_GITHUB, RULES_GOOGLE, RULES_X, type Rules, rulesFor } from './handle.js'
import { HandleError, type RefusalKind } from './platforms.js'
import { HANDLE_VECTORS } from './vectors.js'

/// What `normalize` answers, or the refusal it threw, in the vector table's shape.
function normalized(
  input: string,
  rules: Rules,
): { ok: true; handle: string } | { ok: false; refusal: RefusalKind } {
  try {
    return { ok: true, handle: normalize(input, rules) }
  } catch (e) {
    if (!(e instanceof HandleError)) throw e
    return { ok: false, refusal: e.kind }
  }
}

/// The shared handle vector table, run against the TypeScript normalizer.
/// Solidity and Rust run the same JSON, so a language that disagrees fails.
describe('handle normalization', () => {
  it('matches the shared table on every vector', () => {
    for (const [i, v] of HANDLE_VECTORS.entries()) {
      const rules = rulesFor(v.platform)
      expect(rules, `vector ${i}: unknown platform ${v.platform}`).not.toBeNull()

      // The table names which refusal; every language must agree on it.
      const expected = v.expected.ok ? { ok: true, handle: v.expected.handle } : v.expected
      expect(normalized(v.input, rules!), `vector ${i}`).toEqual(expected)
    }
  })

  /// A regeneration that dropped every refusal would leave the vector test green.
  it('keeps covering both outcomes', () => {
    const accepted = HANDLE_VECTORS.filter((v) => v.expected.ok).length
    expect(accepted).toBeGreaterThan(0)
    expect(HANDLE_VECTORS.length - accepted).toBeGreaterThan(0)
  })

  /// Case folding is the only change to an accepted handle. Anything else could
  /// map the handles of two identities onto one node.
  it('folds case and changes nothing else', () => {
    expect(normalize('A.B+tag@Example.COM', RULES_GOOGLE)).toBe('a.b+tag@example.com')
    expect(normalize('Alice_1', RULES_X)).toBe('alice_1')
    expect(normalize('Octo-Cat', RULES_GITHUB)).toBe('octo-cat')
  })
})

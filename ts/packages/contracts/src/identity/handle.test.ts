import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { normalize, RULES_GITHUB, RULES_GOOGLE, RULES_X, type Rules, rulesFor } from './handle.js'
import { HandleError, type RefusalKind } from './platforms.js'
import { HANDLE_VECTORS, TABLE_SHA256 } from './vectors.js'

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
///
/// Solidity and Rust run the same table from the same JSON. That is the whole
/// guard: three hand-written normalizers, one set of cases, so a language that
/// disagrees fails here instead of looking up a node the chain never wrote.
describe('handle normalization', () => {
  it('matches the shared table on every vector', () => {
    for (const [i, v] of HANDLE_VECTORS.entries()) {
      const rules = rulesFor(v.platform)
      expect(rules, `vector ${i}: unknown platform ${v.platform}`).not.toBeNull()

      // The table names WHICH refusal, not merely that one happened: the
      // reason is what the three languages must agree on.
      const expected = v.expected.ok ? { ok: true, handle: v.expected.handle } : v.expected
      expect(normalized(v.input, rules!), `vector ${i}`).toEqual(expected)
    }
  })

  /// The table must keep covering both outcomes. A regeneration that dropped
  /// every refusal would leave the test green and prove nothing.
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

describe('the generated table', () => {
  /// The constants carry the SHA-256 of the vendored `handles.json`.
  it('comes from the vendored handles.json', () => {
    const table = readFileSync(
      new URL('../../../../../solidity/contracts/circuits/handles.json', import.meta.url),
    )
    expect(createHash('sha256').update(table).digest('hex')).toBe(TABLE_SHA256)
  })
})

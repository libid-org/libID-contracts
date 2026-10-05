import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'

/// `@libid/contracts/handle` exists so a consumer without `viem` can normalize
/// a handle. Every module it loads, followed through its relative imports,
/// imports nothing but other relative modules: not `viem`, and not a sibling
/// layer that does. Type-only imports count too, because they survive into the
/// published declarations.
describe('the handle subpath', () => {
  it('loads no package, viem included', () => {
    const seen = new Set<string>()
    const queue = [new URL('./index.ts', import.meta.url)]
    while (queue.length > 0) {
      const file = queue.pop()!
      if (seen.has(file.href)) continue
      seen.add(file.href)
      const text = readFileSync(file, 'utf8')
      for (const [, specifier] of text.matchAll(/\b(?:from|import)\s*\(?\s*['"]([^'"]+)['"]/g)) {
        expect(specifier, file.pathname).toMatch(/^\.\.?\//)
        queue.push(new URL(specifier.replace(/\.js$/, '.ts'), file))
      }
    }
    const loaded = [...seen].map((href) => href.slice(href.indexOf('/src/') + 5)).sort()
    expect(loaded).toEqual([
      'handle/index.ts',
      'identity/ens.ts',
      'identity/handle.ts',
      'identity/handleVectors.ts',
    ])
  })
})

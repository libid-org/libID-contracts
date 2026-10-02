import { readdirSync, readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'

/// `viem` is an optional peer, and a browser ceremony that reads only these
/// profiles does not install it. So this layer imports nothing outside its own
/// directory: not `viem`, and not a sibling layer that does. Type-only imports
/// count too, because they survive into the published declarations.
describe('the ceremony layer', () => {
  it('imports nothing outside its own directory', () => {
    const dir = new URL('./', import.meta.url)
    const sources = readdirSync(dir).filter((f) => f.endsWith('.ts') && !f.endsWith('.test.ts'))
    expect(sources).toContain('index.ts')
    for (const file of sources) {
      const text = readFileSync(new URL(file, dir), 'utf8')
      for (const [, specifier] of text.matchAll(/\b(?:from|import)\s*\(?\s*['"]([^'"]+)['"]/g)) {
        expect(specifier, file).toMatch(/^\.\/[^/]+$/)
      }
    }
  })
})

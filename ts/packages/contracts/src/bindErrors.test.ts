import { readdirSync, readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { concatHex, decodeErrorResult, keccak256, pad, slice, toBytes } from 'viem'
import { describe, expect, it } from 'vitest'

import { bindErrorsAbi, honkVerifierErrorsAbi } from './index.js'

// The selector from the Solidity signature itself, not from the ABI under
// test, so the two cannot agree by sharing a mistake.
const selector = (signature: string) => slice(keccak256(toBytes(signature)), 0, 4)
const selectorOf = (e: { name: string; inputs: readonly { type: string }[] }) =>
  selector(`${e.name}(${e.inputs.map((i) => i.type).join(',')})`)

const DISCLOSED = `0x${'d1'.repeat(32)}` as const
const PROVED = `0x${'e2'.repeat(32)}` as const

describe('bindErrorsAbi', () => {
  it('names a Platform Verifier refusal that comes back out of bind', () => {
    // What `bind` reverts with when the disclosed handle is not the one the
    // proof bound: the Platform Verifier's revert data, passed through.
    const data = concatHex([selector('HandleNotProved(bytes32,bytes32)'), DISCLOSED, PROVED])

    expect(decodeErrorResult({ abi: bindErrorsAbi, data })).toEqual({
      abiItem: expect.objectContaining({ name: 'HandleNotProved' }),
      errorName: 'HandleNotProved',
      args: [DISCLOSED, PROVED],
    })
  })

  it('names the errors of every contract on the route', () => {
    const cases: [string, `0x${string}`][] = [
      ['UnknownPlatform', concatHex([selector('UnknownPlatform(bytes32)'), PROVED])],
      ['NotYourHandle', concatHex([selector('NotYourHandle(bytes32)'), PROVED])],
      ['NoFramedCommitment', selector('NoFramedCommitment()')],
      ['AmbiguousFraming', selector('AmbiguousFraming()')],
      ['UnusableHandle', concatHex([selector('UnusableHandle(uint8)'), pad('0x03')])],
      ['UntrustedModulus', concatHex([selector('UntrustedModulus(bytes32)'), PROVED])],
      [
        'UnknownVersion',
        concatHex([selector('UnknownVersion(bytes32,uint16)'), PROVED, pad('0x01')]),
      ],
    ]
    for (const [name, data] of cases) {
      expect(decodeErrorResult({ abi: bindErrorsAbi, data }).errorName).toBe(name)
    }
  })

  it('carries each signature once', () => {
    const signatures = bindErrorsAbi.map(
      (e) => `${e.name}(${e.inputs.map((i: { type: string }) => i.type).join(',')})`,
    )
    expect(new Set(signatures).size).toBe(signatures.length)
  })

  // bb's verifiers revert from assembly with the selectors their `*_SELECTOR`
  // constants hold. `IHonkVerifierErrors` declares exactly those, across every
  // vendored verifier, and the bind route carries each.
  it('names every error the vendored Honk verifiers raise, and no other', () => {
    const circuits = join(
      dirname(fileURLToPath(import.meta.url)),
      '..',
      '..',
      '..',
      '..',
      'solidity',
      'contracts',
      'circuits',
    )
    const files = readdirSync(circuits).filter((f) => f.endsWith('HonkVerifier.sol'))
    expect(files.length).toBeGreaterThan(0)
    const vendored = new Set<string>()
    for (const file of files) {
      const source = readFileSync(join(circuits, file), 'utf8')
      for (const m of source.matchAll(/\b[A-Z0-9_]+_SELECTOR = (0x[0-9a-f]{8});/g)) {
        vendored.add(m[1] as string)
      }
    }
    const declared = honkVerifierErrorsAbi.map(selectorOf)
    expect([...declared].sort()).toEqual([...vendored].sort())
    const route = new Set(bindErrorsAbi.map(selectorOf))
    for (const selector of declared) expect(route.has(selector), selector).toBe(true)
  })
})

import { concatHex, decodeErrorResult, keccak256, pad, slice, toBytes } from 'viem'
import { describe, expect, it } from 'vitest'

import { bindErrorsAbi } from './index.js'

// The selector from the Solidity signature itself, not from the ABI under
// test, so the two cannot agree by sharing a mistake.
const selector = (signature: string) => slice(keccak256(toBytes(signature)), 0, 4)

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
      [
        'DisclosureMismatch',
        concatHex([selector('DisclosureMismatch(bytes32,bytes32)'), DISCLOSED, PROVED]),
      ],
      ['NoFramedCommitment', selector('NoFramedCommitment()')],
      ['AmbiguousFraming', selector('AmbiguousFraming()')],
      ['BadCharacter', selector('BadCharacter()')],
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
})

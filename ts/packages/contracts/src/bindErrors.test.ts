import { concatHex, decodeErrorResult, keccak256, pad, slice, toBytes } from 'viem'
import { describe, expect, it } from 'vitest'

import { bindErrorsAbi, walletRegistryErrorsAbi } from './index.js'

// The selector from the signature itself, independent of the ABI under test.
const selector = (signature: string) => slice(keccak256(toBytes(signature)), 0, 4)

const DISCLOSED = `0x${'d1'.repeat(32)}` as const
const PROVED = `0x${'e2'.repeat(32)}` as const

describe('bindErrorsAbi', () => {
  it('names a Platform Verifier refusal that comes back out of bind', () => {
    // The registry's revert for a disclosed handle the proof did not bind.
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
      ['NoncanonicalOperationList', selector('NoncanonicalOperationList()')],
      ['NestedOperationList', selector('NestedOperationList()')],
      ['NoOwnOperation', selector('NoOwnOperation()')],
      ['SeveralOwnOperations', selector('SeveralOwnOperations()')],
      ['NoFramedCommitment', selector('NoFramedCommitment()')],
      ['AmbiguousFraming', selector('AmbiguousFraming()')],
      ['SumcheckFailed', selector('SumcheckFailed()')],
      ['MODEXP_FAILED', selector('MODEXP_FAILED()')],
      ['UntrustedModulus', concatHex([selector('UntrustedModulus(bytes32)'), PROVED])],
      [
        'UnknownVersion',
        concatHex([selector('UnknownVersion(bytes32,uint16)'), PROVED, pad('0x01')]),
      ],
      [
        'NotVerifiedInTransaction',
        concatHex([selector('NotVerifiedInTransaction(uint256)'), pad('0x05')]),
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

describe('walletRegistryErrorsAbi', () => {
  it('names the errors of every contract on the route, the wallet last', () => {
    const cases: [string, `0x${string}`][] = [
      ['DataWithoutList', selector('DataWithoutList()')],
      [
        'NotVerifiedInTransaction',
        concatHex([selector('NotVerifiedInTransaction(uint256)'), pad('0x05')]),
      ],
      ['UntrustedModulus', concatHex([selector('UntrustedModulus(bytes32)'), PROVED])],
      ['SumcheckFailed', selector('SumcheckFailed()')],
      ['FirstSessionRefused', selector('FirstSessionRefused()')],
      ['LinkSessionRefused', selector('LinkSessionRefused()')],
      ['AppNotListed', concatHex([selector('AppNotListed(bytes32)'), PROVED])],
      ['NotLinked', concatHex([selector('NotLinked(bytes32)'), PROVED])],
    ]
    for (const [name, data] of cases) {
      expect(decodeErrorResult({ abi: walletRegistryErrorsAbi, data }).errorName).toBe(name)
    }
  })
})

import { type Address, keccak256, type PublicClient, toHex } from 'viem'
import { describe, expect, it, vi } from 'vitest'

import { HandleError, RULES_GITHUB, RULES_GOOGLE, RULES_X, rulesFor } from './handle.js'
import { HANDLE_VECTORS, PLATFORM_GITHUB_KEY, PLATFORM_X_KEY } from './handleVectors.js'
import { handleHash, handleNode } from './node.js'
import { platformId, rulesOf } from './resolve.js'

/// Computed with `cast`; the Solidity suite and the anvil test pin the same nodes.
const ALICE_1_ON_X = '0x1c43d5d3cf3d99e9d5b6e8c74c23d14bcbb6a743712cf7fa7c15750c4fc2150d'
const ALICE_1_ON_GITHUB = '0x2e2bee956f308d03271ce24b26e5aa20103b41841ddee3c96a94d2449902f710'

describe('handleHash and handleNode', () => {
  it('reach the nodes the contracts store under', () => {
    const x = platformId(PLATFORM_X_KEY)
    const github = platformId(PLATFORM_GITHUB_KEY)
    expect(handleNode(x, handleHash(' @Alice_1 ', RULES_X))).toBe(ALICE_1_ON_X)
    expect(handleNode(github, handleHash(' Alice-1 ', RULES_GITHUB))).toBe(ALICE_1_ON_GITHUB)
  })

  /// The Solidity suite pins `IdentityRegistry.handleHashOf` to the same values.
  it('hash every accepted vector to keccak256 of its normalized output', () => {
    const accepted = HANDLE_VECTORS.filter((v) => v.accepted)
    expect(accepted.length).toBeGreaterThan(0)
    for (const [i, v] of accepted.entries()) {
      const rules = rulesFor(v.platform)
      if (rules === null) throw new Error(`no rules for ${v.platform}`)
      expect(handleHash(v.input, rules), `vector ${i}`).toBe(keccak256(toHex(v.output)))
    }
  })

  it('give two spellings of one address one hash', () => {
    expect(handleHash('Alice@Gmail.com', RULES_GOOGLE)).toBe(
      handleHash('alice@gmail.com', RULES_GOOGLE),
    )
    expect(handleHash('Alice@Gmail.com', RULES_GOOGLE)).not.toBe(
      handleHash('alice2@gmail.com', RULES_GOOGLE),
    )
  })

  it('throw for text the rules refuse, under the rules given', () => {
    expect(() => handleHash('alice', RULES_GOOGLE)).toThrow(HandleError)
    expect(() => handleHash('ali ce', RULES_X)).toThrow(HandleError)
    expect(() => handleHash('with_score', { ...RULES_X, allowUnderscore: false })).toThrow(
      HandleError,
    )
    expect(handleHash('with_score', RULES_X)).toBe(keccak256(toHex('with_score')))
  })

  /// An id is hex, and hashing it again as a key names a platform nothing
  /// binds; a key where an id belongs is not a `bytes32` at all.
  it('take a platform id, which only a key derives', () => {
    const hash = handleHash('alice_1', RULES_X)
    // @ts-expect-error a platform key is not a platform id
    expect(() => handleNode('x', hash)).toThrow()
    // @ts-expect-error a platform id is not a platform key
    expect(platformId(platformId('x'))).not.toBe(platformId('x'))
  })
})

describe('rulesOf', () => {
  /// Only the platform id reaches the RPC, and a narrowed platform refuses what the table accepts.
  it('reads the rules the chain has now', async () => {
    const readContract = vi
      .fn()
      .mockResolvedValue({ ...RULES_X, maxLength: 15n, allowUnderscore: false })
    const reader = {
      client: { readContract } as unknown as PublicClient,
      address: '0x1111111111111111111111111111111111111111' as Address,
    }

    const rules = await rulesOf(reader, platformId(PLATFORM_X_KEY))
    expect(readContract.mock.calls[0][0]).toMatchObject({
      functionName: 'rulesOf',
      args: [platformId('x')],
    })
    expect(rules.maxLength).toBe(15)
    expect(handleHash(' @Alice ', rules)).toBe(keccak256(toHex('alice')))
    expect(() => handleHash('with_score', rules)).toThrow(HandleError)
  })
})

import { type Address, keccak256, type PublicClient, toHex } from 'viem'
import { describe, expect, it, vi } from 'vitest'

import {
  HandleError,
  type NormalizedHandle,
  normalize,
  RULES_GITHUB,
  RULES_GOOGLE,
  RULES_X,
  rulesFor,
} from './handle.js'
import {
  handleHash,
  handleHashOf,
  handleHashOnChainRules,
  handleNode,
  handleNodeOf,
  handleNodeOfHash,
} from './node.js'
import { HANDLE_VECTORS } from './handleVectors.js'
import { platformId } from './resolve.js'

/// X's `alice_1`, computed with `cast`; the Solidity suite pins the same value.
const ALICE_1_ON_X = '0x1c43d5d3cf3d99e9d5b6e8c74c23d14bcbb6a743712cf7fa7c15750c4fc2150d'

/// Literals shared with the Solidity suite (X) and the Rust anvil test (GitHub).
describe('handle node', () => {
  it('matches the node the contracts key on', () => {
    expect(handleNode(platformId('x'), normalize(' Alice_1 ', RULES_X))).toBe(ALICE_1_ON_X)
    expect(handleNode(platformId('github'), normalize(' Alice-1 ', RULES_GITHUB))).toBe(
      '0x2e2bee956f308d03271ce24b26e5aa20103b41841ddee3c96a94d2449902f710',
    )
  })

  /// Raw text keys elsewhere, so the type refuses it without a cast.
  it('is not the node of the raw text', () => {
    expect(handleNode(platformId('x'), ' Alice_1 ' as NormalizedHandle)).not.toBe(
      handleNode(platformId('x'), 'alice_1' as NormalizedHandle),
    )
  })
  it('does not take a raw string', () => {
    // @ts-expect-error a raw string is not a NormalizedHandle
    expect(handleNode(platformId('x'), 'alice_1')).toBe(ALICE_1_ON_X)
  })
})

describe('handleNodeOf', () => {
  it('normalizes before it keys, to the pinned node', () => {
    expect(handleNodeOf('x', ' @Alice_1 ', RULES_X)).toBe(ALICE_1_ON_X)
  })

  it('gives two spellings of one address the same node', () => {
    expect(handleNodeOf('google', 'Alice@Gmail.com', RULES_GOOGLE)).toBe(
      handleNodeOf('google', 'alice@gmail.com', RULES_GOOGLE),
    )
    expect(handleNodeOf('google', 'Alice@Gmail.com', RULES_GOOGLE)).not.toBe(
      handleNodeOf('google', 'alice2@gmail.com', RULES_GOOGLE),
    )
  })

  it('throws for text the rules refuse', () => {
    expect(() => handleNodeOf('google', 'alice', RULES_GOOGLE)).toThrow(HandleError)
    expect(() => handleNodeOf('x', 'ali ce', RULES_X)).toThrow(HandleError)
  })

  /// The rules passed decide, not the platform's generated ones: after the
  /// chain narrows X, text X was released accepting is refused.
  it('normalizes under the rules it is given', () => {
    const narrowed = { ...RULES_X, allowUnderscore: false }
    expect(() => handleNodeOf('x', 'new_user', narrowed)).toThrow(HandleError)
    expect(handleNodeOf('x', 'new_user', RULES_X)).toBe(
      handleNode(platformId('x'), 'new_user' as NormalizedHandle),
    )
  })
})

describe('handle hash', () => {
  it('keys to the node of the same handle', () => {
    expect(handleHash(normalize(' Alice_1 ', RULES_X))).toBe(keccak256(toHex('alice_1')))
    expect(handleNodeOfHash(platformId('x'), handleHashOf(' @Alice_1 ', RULES_X))).toBe(
      ALICE_1_ON_X,
    )
  })

  it('throws as handleNodeOf does', () => {
    expect(() => handleHashOf('alice', RULES_GOOGLE)).toThrow(HandleError)
  })

  /// The Solidity suite pins `IdentityNames.handleHashOf` to the same values.
  it('is keccak256 of the normalized output on every accepted vector', () => {
    const accepted = HANDLE_VECTORS.filter((v) => v.accepted)
    expect(accepted.length).toBeGreaterThan(0)
    for (const [i, v] of accepted.entries()) {
      const rules = rulesFor(v.platform)
      if (rules === null) throw new Error(`no rules for ${v.platform}`)
      expect(handleHashOf(v.input, rules), `vector ${i}`).toBe(keccak256(toHex(v.output)))
    }
  })
})

describe('handleHashOnChainRules', () => {
  /// It reads the rules the chain has now and hashes locally: the text never
  /// reaches the RPC, and a narrowed platform refuses what the table accepts.
  it('hashes under the chain rules, sending only the platform id', async () => {
    const narrowed = { ...RULES_X, maxLength: 15n, allowUnderscore: false }
    const readContract = vi.fn().mockResolvedValue(narrowed)
    const reader = {
      client: { readContract } as unknown as PublicClient,
      address: '0x1111111111111111111111111111111111111111' as Address,
    }

    expect(await handleHashOnChainRules(reader, 'x', ' @Alice ')).toBe(keccak256(toHex('alice')))
    expect(readContract.mock.calls[0][0]).toMatchObject({
      functionName: 'rulesOf',
      args: [platformId('x')],
    })
    await expect(handleHashOnChainRules(reader, 'x', 'new_user')).rejects.toThrow(HandleError)
  })
})

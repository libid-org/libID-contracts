import { keccak256, toHex } from 'viem'
import { describe, expect, it } from 'vitest'

import { HandleError, type NormalizedHandle, normalize, RULES_GITHUB, RULES_X } from './handle.js'
import { handleHash, handleHashOf, handleNode, handleNodeOf, handleNodeOfHash } from './node.js'
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
    expect(handleNodeOf('x', ' @Alice_1 ')).toBe(ALICE_1_ON_X)
  })

  it('gives two spellings of one address the same node', () => {
    expect(handleNodeOf('google', 'Alice@Gmail.com')).toBe(
      handleNodeOf('google', 'alice@gmail.com'),
    )
    expect(handleNodeOf('google', 'Alice@Gmail.com')).not.toBe(
      handleNodeOf('google', 'alice2@gmail.com'),
    )
  })

  it('throws for text the rules refuse', () => {
    expect(() => handleNodeOf('google', 'alice')).toThrow(HandleError)
    expect(() => handleNodeOf('x', 'ali ce')).toThrow(HandleError)
  })

  it('throws for a platform the table does not have', () => {
    expect(() => handleNodeOf('mastodon', 'alice')).toThrow(/no handle rules/)
  })
})

describe('handle hash', () => {
  it('keys to the node of the same handle', () => {
    expect(handleHash(normalize(' Alice_1 ', RULES_X))).toBe(keccak256(toHex('alice_1')))
    expect(handleNodeOfHash(platformId('x'), handleHashOf('x', ' @Alice_1 '))).toBe(ALICE_1_ON_X)
  })

  it('throws as handleNodeOf does', () => {
    expect(() => handleHashOf('google', 'alice')).toThrow(HandleError)
    expect(() => handleHashOf('mastodon', 'alice')).toThrow(/no handle rules/)
  })

  /// The Solidity suite pins `IdentityNames.handleHashOf` to the same values.
  it('is keccak256 of the normalized output on every accepted vector', () => {
    const accepted = HANDLE_VECTORS.filter((v) => v.accepted)
    expect(accepted.length).toBeGreaterThan(0)
    for (const [i, v] of accepted.entries()) {
      expect(handleHashOf(v.platform, v.input), `vector ${i}`).toBe(keccak256(toHex(v.output)))
    }
  })
})

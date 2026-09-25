import { describe, expect, it } from 'vitest'

import { HandleError, type NormalizedHandle, normalize, RULES_GITHUB, RULES_X } from './handle.js'
import { handleNode, handleNodeOf } from './node.js'
import { platformId } from './resolve.js'

/// `test_theNodeDerivationIsPinned` in HandleEscrow.t.sol pins this literal
/// for X's `alice_1`, computed with `cast`.
const ALICE_1_ON_X = '0x1c43d5d3cf3d99e9d5b6e8c74c23d14bcbb6a743712cf7fa7c15750c4fc2150d'

/// The node a handle keys to, against literals computed with `cast`. The
/// Solidity suite pins the X literal against `HandleEscrow.nodeOf` and
/// `IdentityNodes.handleNode`, and the Rust anvil test pins the GitHub one
/// against a deployed escrow, so a TypeScript client that derived another node
/// for `depositToNode` would fail here.
describe('handle node', () => {
  it('matches the node the contracts key on', () => {
    expect(handleNode(platformId('x'), normalize(' Alice_1 ', RULES_X))).toBe(ALICE_1_ON_X)
    expect(handleNode(platformId('github'), normalize(' Alice-1 ', RULES_GITHUB))).toBe(
      '0x2e2bee956f308d03271ce24b26e5aa20103b41841ddee3c96a94d2449902f710',
    )
  })

  /// The node is of the normalized handle. Skipping normalization gives a
  /// different key, which is why the type refuses a raw string: the casts
  /// below are the only way past it.
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

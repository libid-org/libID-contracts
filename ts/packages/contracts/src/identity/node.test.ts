import { describe, expect, it } from 'vitest'

import { normalize, RULES_GITHUB, RULES_X } from './handle.js'
import { handleNode } from './node.js'
import { platformId } from './resolve.js'

/// The node a handle keys to, against literals computed with `cast`. The
/// Solidity suite pins the X literal against `HandleEscrow.nodeOf` and
/// `IdentityNodes.handleNode`, and the Rust anvil test pins the GitHub one
/// against a deployed escrow, so a TypeScript client that derived another node
/// for `depositToNode` would fail here.
describe('handle node', () => {
  it('matches the node the contracts key on', () => {
    expect(handleNode(platformId('x'), normalize(' Alice_1 ', RULES_X))).toBe(
      '0x1c43d5d3cf3d99e9d5b6e8c74c23d14bcbb6a743712cf7fa7c15750c4fc2150d',
    )
    expect(handleNode(platformId('github'), normalize(' Alice-1 ', RULES_GITHUB))).toBe(
      '0x2e2bee956f308d03271ce24b26e5aa20103b41841ddee3c96a94d2449902f710',
    )
  })

  /// The node is of the normalized handle. Skipping normalization gives a
  /// different key, which is why the helper's contract says so.
  it('is not the node of the raw text', () => {
    expect(handleNode(platformId('x'), ' Alice_1 ')).not.toBe(
      handleNode(platformId('x'), 'alice_1'),
    )
  })
})

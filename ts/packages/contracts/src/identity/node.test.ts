import { type Address, concat, type PublicClient, sha256, toHex } from 'viem'
import { describe, expect, it, vi } from 'vitest'

import { HandleError, RULES_X } from './handle.js'
import {
  HANDLE_VECTORS,
  ID_VECTORS,
  PLATFORM_GITHUB_KEY,
  PLATFORM_X,
  PLATFORM_X_KEY,
} from './handleVectors.js'
import { checkId, handleNode, idNode } from './node.js'
import { platformId, rulesOf } from './resolve.js'

/// Python's hashlib, as the circuits, Solidity and Rust pin them:
///   hashlib.sha256(b"libid.x.handlealice_1")
///   hashlib.sha256(b"libid.x.user-id2244994945")
const ALICE_1_ON_X = '0xe09c4f5bfbbc723bc35701ea9d718a1c5edb29b1ed5bb0cb0fabb3c43d8136af'
const ID_2244994945_ON_X = '0x68291869976ffad2abf3e933ec9ab2623395ff8b3b9242e655e1da3ef43d4f94'

describe('handleNode and idNode', () => {
  it('reach the nodes the circuits output', () => {
    expect(handleNode(PLATFORM_X_KEY, 'Alice_1')).toBe(ALICE_1_ON_X)
    expect(idNode(PLATFORM_X_KEY, '2244994945')).toBe(ID_2244994945_ON_X)
  })

  /// Every node in the table was computed independently with hashlib.
  it('hash every accepted handle vector to the node the table states', () => {
    const accepted = HANDLE_VECTORS.filter((v) => v.accepted)
    expect(accepted.length).toBeGreaterThan(0)
    for (const [i, v] of accepted.entries()) {
      expect(handleNode(v.platform, v.input), `vector ${i}`).toBe(v.handleNode)
    }
  })

  it('hash every accepted id vector, and refuse the rest for the stated reason', () => {
    for (const [i, v] of ID_VECTORS.entries()) {
      if (v.accepted) {
        expect(idNode(v.platform, v.input), `id vector ${i}`).toBe(v.idNode)
        continue
      }
      let thrown: unknown
      try {
        checkId(v.platform, v.input)
      } catch (e) {
        thrown = e
      }
      expect(thrown, `id vector ${i}: expected a refusal`).toBeInstanceOf(HandleError)
      expect((thrown as HandleError).kind, `id vector ${i}: wrong reason`).toBe(v.errorKind)
    }
  })

  it('give two spellings of one handle one node, and keep platforms apart', () => {
    expect(handleNode('google', 'Alice@Gmail.com')).toBe(handleNode('google', 'alice@gmail.com'))
    expect(handleNode(PLATFORM_X_KEY, 'alice')).not.toBe(handleNode(PLATFORM_GITHUB_KEY, 'alice'))
    expect(idNode(PLATFORM_X_KEY, '7')).not.toBe(handleNode(PLATFORM_X_KEY, '7'))
  })

  /// Text no circuit would have hashed has no node.
  it('throw for text the rules refuse', () => {
    expect(() => handleNode(PLATFORM_X_KEY, ' alice')).toThrow(HandleError)
    expect(() => handleNode(PLATFORM_X_KEY, '@alice')).toThrow(HandleError)
    expect(() => handleNode('google', 'alice')).toThrow(HandleError)
    expect(() => idNode(PLATFORM_GITHUB_KEY, '0583231')).toThrow(HandleError)
    expect(() => handleNode('mastodon', 'alice')).toThrow(/unknown platform/)
    for (const inherited of ['toString', 'constructor', '__proto__', 'hasOwnProperty']) {
      expect(() => handleNode(inherited, 'alice')).toThrow(/unknown platform/)
      expect(() => idNode(inherited, '1')).toThrow(/unknown platform/)
    }
  })

  it('is SHA-256 of the tag, then the normalized handle', () => {
    expect(handleNode(PLATFORM_X_KEY, 'Bob')).toBe(
      sha256(concat([toHex(PLATFORM_X.handleTag), toHex('bob')])),
    )
  })
})

describe('rulesOf', () => {
  /// Only the platform id reaches the RPC.
  it('reads the rules the registry answers', async () => {
    const readContract = vi.fn().mockResolvedValue({ ...RULES_X, maxLength: 15n })
    const reader = {
      client: { readContract } as unknown as PublicClient,
      address: '0x1111111111111111111111111111111111111111' as Address,
    }

    const rules = await rulesOf(reader, platformId(PLATFORM_X_KEY))
    expect(readContract.mock.calls[0][0]).toMatchObject({
      functionName: 'rulesOf',
      args: [platformId('x')],
    })
    expect(rules).toEqual(RULES_X)
  })
})

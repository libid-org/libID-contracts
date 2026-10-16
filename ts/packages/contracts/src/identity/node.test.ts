import { concat, sha256, toHex } from 'viem'
import { describe, expect, it } from 'vitest'

import { HandleError } from './handle.js'
import {
  HANDLE_VECTORS,
  ID_VECTORS,
  PLATFORM_GITHUB_KEY,
  PLATFORM_X,
  PLATFORM_X_KEY,
} from './handleVectors.js'
import { checkId, foldedHandleNode, handleNode, IdError, idNode } from './node.js'

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
      expect(thrown, `id vector ${i}: expected a refusal`).toBeInstanceOf(IdError)
      expect(thrown, `id vector ${i}: a handle refusal`).not.toBeInstanceOf(HandleError)
      expect((thrown as IdError).name).toBe('IdError')
      expect((thrown as IdError).kind, `id vector ${i}: wrong reason`).toBe(v.errorKind)
    }
  })

  /// REQ-PLAT-06: `^[1-9][0-9]{0,19}$` with a value at most 2^64-1, as Rust's
  /// `check_id` and the circuit refuse it.
  it('hold a decimal id to its grammar, and leave a string id as sent', () => {
    for (const id of ['1', '2244994945', '9999999999999999999', '18446744073709551615']) {
      expect(() => checkId(PLATFORM_X_KEY, id), id).not.toThrow()
      expect(() => checkId(PLATFORM_GITHUB_KEY, id), id).not.toThrow()
    }
    for (const id of ['0', '007', '0123', '18446744073709551616', '99999999999999999999']) {
      expect(() => checkId(PLATFORM_X_KEY, id), id).toThrow(
        'the id is not a number this platform issues',
      )
      expect(() => checkId(PLATFORM_GITHUB_KEY, id), id).toThrow(
        'the id is not a number this platform issues',
      )
    }
    expect(() => checkId(PLATFORM_X_KEY, '123456789012345678901')).toThrow(
      'the id is too long for this platform',
    )
    expect(() => checkId(PLATFORM_X_KEY, '')).toThrow('the id is empty')
    expect(() => checkId(PLATFORM_X_KEY, '12a4')).toThrow(
      'the id has a byte this platform does not allow',
    )
    expect(() => checkId('google', '0123')).not.toThrow()
    expect(() => checkId('google', '0')).not.toThrow()
  })

  it('give two spellings of one handle one node, and keep platforms apart', () => {
    expect(handleNode('google', 'Alice@Gmail.com')).toBe(handleNode('google', 'alice@gmail.com'))
    expect(handleNode(PLATFORM_X_KEY, 'alice')).not.toBe(handleNode(PLATFORM_GITHUB_KEY, 'alice'))
    expect(idNode(PLATFORM_X_KEY, '7')).not.toBe(handleNode(PLATFORM_X_KEY, '7'))
  })

  /// Text no circuit would have hashed has no node.
  it('throw for text no circuit hashes', () => {
    expect(() => handleNode(PLATFORM_X_KEY, 'ali"ce')).toThrow(HandleError)
    expect(() => handleNode('google', 'alice\t@example.com')).toThrow(HandleError)
    expect(() => idNode(PLATFORM_GITHUB_KEY, ' 583231')).toThrow(IdError)
    // Rust's `check_id` words this refusal the same way.
    expect(() => idNode(PLATFORM_GITHUB_KEY, '583231,')).toThrow(
      'the id has a byte this platform does not allow',
    )
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

describe('foldedHandleNode', () => {
  /// `printf 'libid.x.handlebo"b' | sha256sum`: the registry's `handleNodeOf`,
  /// for text the circuits refuse.
  it('folds and hashes, checking nothing', () => {
    expect(foldedHandleNode(PLATFORM_X_KEY, 'Bo"b')).toBe(
      '0x650dc467b55054ff038aed82e055439b80903460291078585ad72e334bf0050a',
    )
    expect(foldedHandleNode(PLATFORM_X_KEY, 'Alice_1')).toBe(handleNode(PLATFORM_X_KEY, 'alice_1'))
    // Only A-Z fold: a byte above 0x7f is hashed as is.
    expect(foldedHandleNode(PLATFORM_X_KEY, 'É')).not.toBe(foldedHandleNode(PLATFORM_X_KEY, 'é'))
  })
})

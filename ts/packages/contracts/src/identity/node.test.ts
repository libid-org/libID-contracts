import { concat, sha256, toHex } from 'viem'
import { describe, expect, it } from 'vitest'

import { normalize } from './handle.js'
import { foldedHandleNode, handleNode, idNode } from './node.js'
import {
  HandleError,
  IdError,
  PLATFORM_GITHUB_KEY,
  PLATFORM_X,
  PLATFORM_X_KEY,
  platform,
  type RefusalKind,
} from './platforms.js'
import { HANDLE_VECTORS, type HandleExpected, ID_VECTORS, type IdExpected } from './vectors.js'

/// What `f` answers, or the `refusal` of the `kind` error it threw.
function attempt<T>(
  kind: typeof HandleError | typeof IdError,
  f: () => T,
): T | { ok: false; refusal: RefusalKind } {
  try {
    return f()
  } catch (e) {
    if (!(e instanceof kind)) throw e
    return { ok: false, refusal: e.kind }
  }
}

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
  it('answer every handle vector as the table states', () => {
    for (const [i, v] of HANDLE_VECTORS.entries()) {
      const got = attempt(
        HandleError,
        (): HandleExpected => ({
          ok: true,
          handle: normalize(v.input, platform(v.platform)!.rules),
          handleNode: handleNode(v.platform, v.input),
        }),
      )
      expect(got, `vector ${i}`).toEqual(v.expected)
    }
  })

  it('answer every id vector as the table states', () => {
    for (const [i, v] of ID_VECTORS.entries()) {
      const got = attempt(
        IdError,
        (): IdExpected => ({ ok: true, idNode: idNode(v.platform, v.input) }),
      )
      expect(got, `id vector ${i}`).toEqual(v.expected)
    }
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

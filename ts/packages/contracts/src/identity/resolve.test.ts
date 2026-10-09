import {
  type Address,
  BaseError,
  ContractFunctionRevertedError,
  type PublicClient,
  zeroAddress,
  zeroHash,
} from 'viem'
import { describe, expect, it, vi } from 'vitest'

import { PLATFORM_X_KEY } from './handleVectors.js'
import { handleNode, idNode } from './node.js'
import {
  identitiesOf,
  identityCount,
  platformId,
  publishedHandleOf,
  type RegistryReader,
  resolveHandle,
  resolveHandleAndId,
  resolveId,
} from './resolve.js'

const CONTRACT = '0x1111111111111111111111111111111111111111' as Address
const ALICE = '0x2222222222222222222222222222222222222222' as Address

function reader(readContract: ReturnType<typeof vi.fn>): RegistryReader {
  return {
    client: { readContract } as unknown as PublicClient,
    address: CONTRACT,
  }
}

/// A registry whose `resolveHandleNodeAndId` answers `holder` for any node.
function registry(holder: Address = zeroAddress, idAgrees = false) {
  return vi.fn().mockResolvedValue([holder, idAgrees])
}

/// Every argument the RPC was sent, flattened.
function sent(readContract: ReturnType<typeof vi.fn>): unknown[] {
  return readContract.mock.calls.flatMap(([request]) => request.args)
}

const X = platformId(PLATFORM_X_KEY)
const ID_42 = idNode(PLATFORM_X_KEY, '42')
const ID_43 = idNode(PLATFORM_X_KEY, '43')
const ALICE_NODE = handleNode(PLATFORM_X_KEY, 'alice')
const OLD_NODE = handleNode(PLATFORM_X_KEY, 'alice_old')

describe('resolving a handle', () => {
  /// The contract stores under the hash of the platform key, and the keys are
  /// generated from handles.json — so this and the chain agree by construction
  /// rather than by somebody keeping two lists in step.
  it('derives the platform id from the generated platform key', () => {
    expect(X).toMatch(/^0x[0-9a-f]{64}$/)
    expect(platformId(PLATFORM_X_KEY)).toBe(X)
    expect(platformId('dyaka.identity.platform.github')).not.toBe(X)
  })

  /// Only the node reaches the RPC; the id is hashed here.
  it('reads the holder that proved an id node', async () => {
    const readContract = vi.fn().mockResolvedValue(ALICE)
    expect(await resolveId(reader(readContract), ID_42)).toBe(ALICE)

    expect(readContract.mock.calls[0][0]).toMatchObject({
      address: CONTRACT,
      functionName: 'resolveId',
      args: [ID_42],
    })
  })

  it('reads the holder that last proved a handle', async () => {
    const readContract = registry(ALICE)
    expect(await resolveHandle(reader(readContract), X, 'alice')).toBe(ALICE)
  })

  /// An unbound handle is absent, not the zero address. Handing a caller
  /// `0x000…0` invites sending funds to it.
  it('reports an unbound handle as null rather than the zero address', async () => {
    const readContract = vi.fn().mockResolvedValue(zeroAddress)
    expect(await resolveId(reader(readContract), ID_42)).toBeNull()
    expect(await resolveHandle(reader(registry()), X, 'nobody')).toBeNull()
  })

  /// The handle is normalized and hashed here, under the rules the registry
  /// applies, so only its node reaches the RPC.
  it('sends the handle node, never the handle', async () => {
    const readContract = registry(ALICE)
    await resolveHandle(reader(readContract), X, 'Alice')

    expect(readContract.mock.calls[0][0]).toMatchObject({
      functionName: 'resolveHandleNodeAndId',
      args: [X, ALICE_NODE, zeroHash],
    })
    expect(sent(readContract)).not.toContain('Alice')
    expect(sent(readContract)).not.toContain('alice')
  })

  it('finds the platform whatever the case of its id hex', async () => {
    const upper = `0x${X.slice(2).toUpperCase()}` as const
    const readContract = registry(ALICE)
    expect(await resolveHandle(reader(readContract), upper, 'alice')).toBe(ALICE)
    expect(readContract.mock.calls[0][0].args[1]).toBe(ALICE_NODE)
  })
})

describe('resolving a holder back to a handle', () => {
  it('reads the published handle', async () => {
    const readContract = vi.fn().mockResolvedValue('alice')
    expect(await publishedHandleOf(reader(readContract), ALICE, X)).toBe('alice')

    expect(readContract.mock.calls[0][0]).toMatchObject({
      functionName: 'publishedHandleOf',
      args: [ALICE, X],
    })
  })

  /// `publishedHandleOf` is forward-checked on chain, so a stale handle
  /// arrives here as empty. ENS asks integrators to run that check themselves
  /// and warns that skipping it shows a primary name that no longer resolves
  /// back; this cannot skip it.
  it('gives no published handle once the handle has moved on', async () => {
    const readContract = vi.fn().mockResolvedValue('')
    expect(await publishedHandleOf(reader(readContract), ALICE, X)).toBeNull()
  })
})

describe('checking a handle against an id', () => {
  it('agrees when both point at one holder', async () => {
    const readContract = registry(ALICE, true)

    expect(await resolveHandleAndId(reader(readContract), X, 'alice', ID_42)).toEqual({
      holder: ALICE,
      idAgrees: true,
    })
    expect(readContract).toHaveBeenCalledTimes(1)
    expect(sent(readContract)).toEqual([X, ALICE_NODE, ID_42])
  })

  /// The case the two mappings exist for. The handle still resolves — and the
  /// transfer must still be allowed to go there, because that is what the
  /// handle now means — but the caller learns its id is out of date and can
  /// say so before anybody signs.
  it('still resolves the handle when the id disagrees', async () => {
    const resolution = await resolveHandleAndId(reader(registry(ALICE, false)), X, 'alice', ID_42)

    expect(resolution.holder).toBe(ALICE)
    expect(resolution.idAgrees).toBe(false)
  })

  it('reports no holder for a handle nobody has proved', async () => {
    const resolution = await resolveHandleAndId(reader(registry()), X, 'nobody', ID_42)

    expect(resolution.holder).toBeNull()
    expect(resolution.idAgrees).toBe(false)
  })

  it('treats a handle the rules reject as unbound', async () => {
    const readContract = registry()

    expect(await resolveHandleAndId(reader(readContract), X, 'not a handle', ID_42)).toEqual({
      holder: null,
      idAgrees: false,
    })
    // The zero node: the platform check runs, and nothing is bound there.
    expect(sent(readContract)).toEqual([X, zeroHash, ID_42])
  })
})

describe('listing the identities a holder proved', () => {
  it('reads how many identities a holder has', async () => {
    const readContract = vi.fn().mockResolvedValue(2n)
    expect(await identityCount(reader(readContract), ALICE)).toBe(2n)

    expect(readContract.mock.calls[0][0]).toMatchObject({
      address: CONTRACT,
      functionName: 'identityCount',
      args: [ALICE],
    })
  })

  it('reads a page by index and size', async () => {
    const readContract = vi.fn().mockResolvedValue([])
    expect(await identitiesOf(reader(readContract), ALICE, 10n, 5n)).toEqual([])

    expect(readContract.mock.calls[0][0]).toMatchObject({
      address: CONTRACT,
      functionName: 'identitiesOf',
      args: [ALICE, 10n, 5n],
    })
  })

  /// Each struct arrives as an `Identity` with exactly its four fields.
  it('maps the struct array into identities', async () => {
    const readContract = vi.fn().mockResolvedValue([
      { platformId: X, idNode: ID_42, handleNode: ALICE_NODE, handleCurrent: true },
      { platformId: X, idNode: ID_43, handleNode: OLD_NODE, handleCurrent: false },
    ])

    expect(await identitiesOf(reader(readContract), ALICE, 0n, 10n)).toStrictEqual([
      { platformId: X, idNode: ID_42, handleNode: ALICE_NODE, handleCurrent: true },
      { platformId: X, idNode: ID_43, handleNode: OLD_NODE, handleCurrent: false },
    ])
  })
})

/// A revert as viem hands it over: a `ContractFunctionRevertedError` reachable
/// through the thrown error's `walk`.
function revertingWith(errorName: string): BaseError {
  const reverted = Object.create(
    ContractFunctionRevertedError.prototype,
  ) as ContractFunctionRevertedError
  Object.assign(reverted, { data: { errorName, args: [] } })

  const outer = new BaseError('reverted')
  outer.walk = ((fn?: (e: unknown) => boolean) =>
    fn ? (fn(reverted) ? reverted : null) : reverted) as BaseError['walk']
  return outer
}

describe('a handle that cannot be normalized', () => {
  /// Nobody holds a string that is not a handle on that platform, and the
  /// contract says so with a zero address rather than a revert — which is what
  /// a search box needs, since the alternative is a rejected promise on every
  /// keystroke that has not finished being typed.
  it('reads as unbound', async () => {
    const readContract = registry()

    expect(await resolveHandle(reader(readContract), X, 'not a handle')).toBeNull()
    // The zero node: the platform check runs, and nothing is bound there.
    expect(sent(readContract)).toEqual([X, zeroHash, zeroHash])
  })

  /// An unconfigured platform is a deployment mistake, not an answer about a
  /// handle. Reporting it as "unbound" would hide it behind a plausible result.
  it('lets an unconfigured platform surface', async () => {
    const readContract = vi.fn().mockRejectedValue(revertingWith('UnknownPlatform'))

    await expect(resolveHandle(reader(readContract), X, 'alice')).rejects.toThrow()
  })
})

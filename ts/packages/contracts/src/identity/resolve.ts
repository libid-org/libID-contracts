/// Reads identities from the `IdentityRegistry` through view calls.
///
/// The caller passes the client and the contract address; the package carries
/// no network configuration.

import { type Address, keccak256, type PublicClient, toHex, zeroAddress, zeroHash } from 'viem'

import { identityRegistryAbi } from '../abis/identityRegistry.js'
import { HandleError } from './platforms.js'
import { PLATFORMS } from './platforms.js'
import { handleNode } from './node.js'

/// A platform key (`'x'`, `'github'`, ...). A value typed as hex fails to
/// compile: an id passed as a key would hash into a platform nothing binds.
export type PlatformKey<K extends string> = K extends `0x${string}` ? never : K

/// A platform id is `keccak256` of its platform key, as `CeremonyProfile`
/// derives it.
export function platformId<K extends string>(platformKey: PlatformKey<K>): `0x${string}` {
  return keccak256(toHex(platformKey))
}

export interface RegistryReader {
  client: PublicClient
  /// The deployed `IdentityRegistry` contract.
  address: Address
}

/// One view call. The cast is there because viem's `PublicClient`, without its
/// chain type parameters, types `authorizationList` as required even for a read.
function read<T>(
  reader: RegistryReader,
  functionName: string,
  args: readonly unknown[],
): Promise<T> {
  return (
    reader.client as unknown as {
      readContract: (request: Record<string, unknown>) => Promise<T>
    }
  ).readContract({
    authorizationList: undefined,
    address: reader.address,
    abi: identityRegistryAbi,
    functionName,
    args,
  })
}

/// The holder that proved this id node (`idNode(platformKey, id)`), or `null`.
export async function resolveId(
  reader: RegistryReader,
  idNode: `0x${string}`,
): Promise<Address | null> {
  const holder = await read<Address>(reader, 'resolveId', [idNode])
  return holder === zeroAddress ? null : holder
}

/// The generated platforms, keyed by platform id.
const PLATFORM_BY_ID = new Map(PLATFORMS.map((p) => [platformId(p.key), p]))

export interface HandleAndIdResolution {
  /// The handle's holder, or `null`.
  holder: Address | null
  /// True only when the id node is the account that last proved the handle.
  /// False when another account proved it since, even one in the same wallet.
  idAgrees: boolean
}

/// Resolve a handle and report whether an id node still agrees with it.
/// Read it before signing to warn the payer; do not let it block a transfer.
/// Only the handle's node is sent. Text no circuit hashes is sent as the zero
/// node and resolves to `{holder: null, idAgrees: false}`. Reverts such as
/// `UnknownPlatform` propagate; a platform missing from this package's table
/// throws.
export async function resolveHandleAndId(
  reader: RegistryReader,
  id: `0x${string}`,
  handle: string,
  idNode: `0x${string}`,
): Promise<HandleAndIdResolution> {
  const keys = PLATFORM_BY_ID.get(id.toLowerCase() as `0x${string}`)
  let node: `0x${string}` = zeroHash
  if (keys !== undefined) {
    try {
      node = handleNode(keys.key, handle)
    } catch (e) {
      if (!(e instanceof HandleError)) throw e
    }
  }
  // The chain goes first, so a platform it does not know reverts UnknownPlatform there.
  const [holder, idAgrees] = await read<[Address, boolean]>(reader, 'resolveHandleNodeAndId', [
    id,
    node,
    idNode,
  ])
  if (keys === undefined) throw new Error(`platform ${id} is not in this package's handle table`)
  return { holder: holder === zeroAddress ? null : holder, idAgrees }
}

/// The holder that last proved this handle, or `null`. Only the handle's node
/// is sent; text no circuit hashes also answers `null`. Reverts such as
/// `UnknownPlatform` propagate.
export async function resolveHandle(
  reader: RegistryReader,
  platformId: `0x${string}`,
  handle: string,
): Promise<Address | null> {
  return (await resolveHandleAndId(reader, platformId, handle, zeroHash)).holder
}

/// The handle to show for a holder, or `null`. Forward-checked on chain:
/// empty once the stored handle resolves somewhere else.
export async function publishedHandleOf(
  reader: RegistryReader,
  holder: Address,
  platformId: `0x${string}`,
): Promise<string | null> {
  const handle = await read<string>(reader, 'publishedHandleOf', [holder, platformId])
  return handle.length === 0 ? null : handle
}

/// One identity a holder proved, as the holder's list reports it.
export interface Identity {
  /// The platform the identity is on, as `platformId` derives it.
  platformId: `0x${string}`
  /// The node of the id.
  idNode: `0x${string}`
  /// The node of the handle this identity proved most recently.
  handleNode: `0x${string}`
  /// True while the handle node still points back at this identity.
  handleCurrent: boolean
}

/// How many identities a holder has, on every platform together.
export async function identityCount(reader: RegistryReader, holder: Address): Promise<bigint> {
  return read<bigint>(reader, 'identityCount', [holder])
}

/// The holder's identities at indices `[from, from + limit)`, clipped to the list.
/// Order is arbitrary and changes on removal: read every page against one block.
export async function identitiesOf(
  reader: RegistryReader,
  holder: Address,
  from: bigint,
  limit: bigint,
): Promise<Identity[]> {
  const page = await read<readonly Identity[]>(reader, 'identitiesOf', [holder, from, limit])
  return page.map(({ platformId, idNode, handleNode, handleCurrent }) => ({
    platformId,
    idNode,
    handleNode,
    handleCurrent,
  }))
}

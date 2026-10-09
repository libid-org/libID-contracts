/// Reading identities from the chain.
///
/// Everything here is a view call. Binding an identity needs a ceremony payload
/// and a wallet; reading one needs neither, which is the point — any product
/// can resolve a handle without touching the ceremony that bound it.
///
/// The client and the contract address are arguments rather than imports. This
/// package ships separately from the repository it currently lives in, so it
/// carries no configuration of its own and reaches for nothing outside itself.

import { type Address, keccak256, type PublicClient, toHex, zeroAddress } from 'viem'

import { identityRegistryAbi } from '../abis/identityRegistry.js'
import type { Rules } from './handle.js'

/// A platform key (`'x'`, `'github'`, ...), refusing at compile time a value
/// typed as hex: an id passed where a key belongs would be hashed again into a
/// platform nothing binds.
export type PlatformKey<K extends string> = K extends `0x${string}` ? never : K

/// A platform id is `keccak256` of its platform key. The keys are generated
/// from `handles.json`, so this and the contract agree by construction.
export function platformId<K extends string>(platformKey: PlatformKey<K>): `0x${string}` {
  return keccak256(toHex(platformKey))
}

export interface RegistryReader {
  client: PublicClient
  /// The deployed `IdentityRegistry` contract.
  address: Address
}

/// One view call.
///
/// Routed through a narrow cast for one reason:
/// viem's `PublicClient`, without its chain type parameters, types
/// `authorizationList` as required even for a read. The alternative is to
/// spread that noise across every call site here.
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

/// The platform's normalization rules (`IdentityRegistry.rulesOf`).
export async function rulesOf(reader: RegistryReader, platformId: `0x${string}`): Promise<Rules> {
  const rules = await read<Rules>(reader, 'rulesOf', [platformId])
  return {
    maxLength: Number(rules.maxLength),
    isEmail: rules.isEmail,
    allowUnderscore: rules.allowUnderscore,
    allowHyphen: rules.allowHyphen,
  }
}

/// The holder that proved this id node (`idNode(platformKey, id)`), or `null`.
export async function resolveId(
  reader: RegistryReader,
  idNode: `0x${string}`,
): Promise<Address | null> {
  const holder = await read<Address>(reader, 'resolveId', [idNode])
  return holder === zeroAddress ? null : holder
}

/// The holder that last proved this handle, or `null`. The handle is
/// normalized on chain, and text the rules refuse also answers `null`;
/// reverts such as `UnknownPlatform` propagate.
export async function resolveHandle(
  reader: RegistryReader,
  platformId: `0x${string}`,
  handle: string,
): Promise<Address | null> {
  const holder = await read<Address>(reader, 'resolveHandle', [platformId, handle])
  return holder === zeroAddress ? null : holder
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

export interface HandleAndIdResolution {
  /// The handle's holder, or `null`.
  holder: Address | null
  /// True only when the id node resolves to that same holder; false means
  /// the handle was proved again since the caller learned the pair.
  idAgrees: boolean
}

/// Resolve a handle and report whether an id node still agrees with it.
/// Read it before signing, to warn the payer; do not let it block a transfer.
export async function resolveHandleAndId(
  reader: RegistryReader,
  platformId: `0x${string}`,
  handle: string,
  idNode: `0x${string}`,
): Promise<HandleAndIdResolution> {
  const [holder, idAgrees] = await read<[Address, boolean]>(reader, 'resolveHandleAndId', [
    platformId,
    handle,
    idNode,
  ])

  return { holder: holder === zeroAddress ? null : holder, idAgrees }
}

/// One identity a holder proved, as the holder's list reports it.
export interface Identity {
  /// The platform the identity is on, as `platformId` derives it.
  platformId: `0x${string}`
  /// The node of the id. The id itself is never on chain.
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

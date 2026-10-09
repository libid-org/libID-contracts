/// Reading identities from the chain.
///
/// Everything here is a view call. Binding an identity needs a ceremony payload
/// and a wallet; reading one needs neither, which is the point — any product
/// can resolve a handle without touching the ceremony that bound it.
///
/// The client and the contract address are arguments rather than imports. This
/// package ships separately from the repository it currently lives in, so it
/// carries no configuration of its own and reaches for nothing outside itself.

import { type Address, keccak256, type PublicClient, toHex, zeroAddress, zeroHash } from 'viem'

import { identityRegistryAbi } from '../abis/identityRegistry.js'
import { HandleError, type Rules } from './handle.js'
import { PLATFORMS } from './handleVectors.js'
import { handleNode } from './node.js'

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

/// The platform's normalization rules as the registry answers them
/// (`IdentityRegistry.rulesOf`): the generated `handles.json` constants.
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

/// `IdentityRegistry.resolveHandleNodeAndId` for a handle as typed: the handle
/// is normalized and hashed here, with the registry's rules and tag, and only
/// its node is sent. Text the rules refuse is sent as the zero node, which
/// nothing is bound under, so the registry's platform check still runs.
async function resolveNodes(
  reader: RegistryReader,
  id: `0x${string}`,
  handle: string,
  idNode: `0x${string}`,
): Promise<HandleAndIdResolution> {
  const keys = PLATFORMS.find((p) => platformId(p.key) === id)
  let node: `0x${string}` = zeroHash
  if (keys !== undefined) {
    try {
      node = handleNode(keys.key, handle)
    } catch (e) {
      if (!(e instanceof HandleError)) throw e
    }
  }
  const [holder, idAgrees] = await read<[Address, boolean]>(reader, 'resolveHandleNodeAndId', [
    id,
    node,
    idNode,
  ])
  if (keys === undefined) throw new Error(`platform ${id} is not in this package's handle table`)
  return { holder: holder === zeroAddress ? null : holder, idAgrees }
}

/// The holder that last proved this handle, or `null`.
///
/// The handle is normalized and hashed here, with the rules the registry
/// applies, and only its node is sent: a caller may pass what was typed —
/// including something that is not a handle at all. Text the platform's rules
/// refuse answers `null`, the same answer as a handle nobody has proved, and
/// the one a search box wants.
///
/// A revert propagates. `UnknownPlatform` in particular means `handles.json`
/// names no such platform or no verifier serves it yet, and answering
/// "unbound" would bury a deployment mistake under a plausible result.
export async function resolveHandle(
  reader: RegistryReader,
  platformId: `0x${string}`,
  handle: string,
): Promise<Address | null> {
  return (await resolveNodes(reader, platformId, handle, zeroHash)).holder
}

/// The handle to show for a holder, or `null`.
///
/// Forward-checked on chain: empty once the stored handle resolves somewhere
/// else. ENS asks integrators to perform that check themselves and warns that
/// skipping it displays an ENS primary name that no longer resolves back; here
/// it cannot be skipped, because the contract does it. A revert propagates:
/// `UnknownPlatform` means `handles.json` names no such platform.
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
  /// True only when the id node resolves to that same holder.
  ///
  /// False means the caller's `(handle, id)` pair comes from two moments:
  /// somebody proved the handle after the caller learned who held it. That is
  /// staleness, not corruption.
  idAgrees: boolean
}

/// Resolve a handle and report whether an id node still agrees with it.
///
/// **Read this before signing, and do not let it block a transfer.** A handle
/// that will not route is not a handle: sending to a handle means sending to
/// whoever proved it last, which is what the handle now means. What the flag is
/// for is telling whoever is paying that the identity they think they are
/// paying is not the one that has the handle today — a decision they can only
/// make beforehand.
///
/// Both halves are needed. A handle on its own has nothing to disagree with.
///
/// Only nodes are sent, as `resolveHandle` sends them. A handle the
/// platform's rules reject resolves to `{holder: null, idAgrees: false}`, the
/// same as one nobody has proved.
export async function resolveHandleAndId(
  reader: RegistryReader,
  platformId: `0x${string}`,
  handle: string,
  idNode: `0x${string}`,
): Promise<HandleAndIdResolution> {
  return resolveNodes(reader, platformId, handle, idNode)
}

/// One identity a holder proved, as the holder's list reports it.
export interface Identity {
  /// The platform the identity is on, as `platformId` derives it.
  platformId: `0x${string}`
  /// The node of the id. The id itself is never on chain.
  idNode: `0x${string}`
  /// The node of the handle this identity proved most recently. The handle is
  /// on chain only if its holder published it (`publishedHandleOf`).
  handleNode: `0x${string}`
  /// True while the handle node still points back at this identity.
  ///
  /// False once another identity proves the same handle: the node stays as
  /// the last thing this identity was known as, and the flag says not to route
  /// by it.
  handleCurrent: boolean
}

/// How many identities a holder has, on every platform together.
export async function identityCount(reader: RegistryReader, holder: Address): Promise<bigint> {
  return read<bigint>(reader, 'identityCount', [holder])
}

/// A page of a holder's identities, on every platform together:
/// the indices `[from, from + limit)` of its list, counted from zero and
/// clipped to the list. A `from` past the end answers an empty page. A reader
/// that wants one platform filters a page by `platformId`.
///
/// Order is arbitrary and changes when an identity leaves the list, so two
/// pages read across a removal may overlap or skip. A reader that needs every
/// identity reads `identityCount` and the pages against one block.
///
/// A list is as long as its holder made it, and a call's gas is not. A caller
/// enumerating a holder it did not choose keeps `limit` small and pages.
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

/// Reading identities from the chain.
///
/// Everything here is a view call. Binding an identity needs a ceremony payload
/// and a wallet; reading one needs neither, which is the point — any product
/// can resolve a handle without touching the ceremony that bound it.
///
/// The client and the contract address are arguments rather than imports. This
/// package ships separately from the repository it currently lives in, so it
/// carries no configuration of its own and reaches for nothing outside itself.

import {
  type Address,
  type ContractFunctionArgs,
  type ContractFunctionName,
  type ContractFunctionReturnType,
  keccak256,
  type PublicClient,
  toHex,
  zeroAddress,
} from 'viem'

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

type RegistryAbi = typeof identityRegistryAbi
type ReadOnly = 'view' | 'pure'
type RegistryRead = ContractFunctionName<RegistryAbi, ReadOnly>
type ReadResult<N extends RegistryRead> = ContractFunctionReturnType<RegistryAbi, ReadOnly, N>

/// One view call, typed from the generated ABI: a function name the contract
/// does not have, wrong arguments, or a return shape read the wrong way fail
/// to compile.
///
/// The client goes through a narrow cast for one reason: viem's
/// `PublicClient`, without its chain type parameters, types
/// `authorizationList` as required even for a read. The name, the arguments
/// and the result keep the ABI's types.
function read<N extends RegistryRead>(
  reader: RegistryReader,
  functionName: N,
  args: ContractFunctionArgs<RegistryAbi, ReadOnly, N>,
): Promise<ReadResult<N>> {
  return (
    reader.client as unknown as {
      readContract: (request: Record<string, unknown>) => Promise<ReadResult<N>>
    }
  ).readContract({
    authorizationList: undefined,
    address: reader.address,
    abi: identityRegistryAbi,
    functionName,
    args,
  })
}

/// The contract's zero address is "nobody".
function orNull(holder: Address): Address | null {
  return holder === zeroAddress ? null : holder
}

/// The platform's normalization rules as configured on chain now
/// (`IdentityRegistry.rulesOf`).
export async function rulesOf(reader: RegistryReader, platformId: `0x${string}`): Promise<Rules> {
  const rules = await read(reader, 'rulesOf', [platformId])
  return {
    maxLength: Number(rules.maxLength),
    stripLeadingAt: rules.stripLeadingAt,
    isEmail: rules.isEmail,
    allowUnderscore: rules.allowUnderscore,
    allowHyphen: rules.allowHyphen,
  }
}

/// The holder that proved this id, or `null`.
export async function resolveId(
  reader: RegistryReader,
  platformId: `0x${string}`,
  id: string,
): Promise<Address | null> {
  const holder = await read(reader, 'resolveId', [platformId, id])
  return orNull(holder)
}

/// The holder that last proved this handle, or `null`.
///
/// The handle is normalized on chain before it is looked up, so a caller may
/// pass what was typed — including something that is not a handle at all.
/// The contract is total in the handle: a string the platform's rules refuse
/// answers the zero address, which is the same answer as a handle nobody has
/// proved, and the one a search box wants.
///
/// A revert propagates. `UnknownPlatform` in particular means the platform is
/// not configured, and answering "unbound" would bury a deployment mistake
/// under a plausible result.
export async function resolveHandle(
  reader: RegistryReader,
  platformId: `0x${string}`,
  handle: string,
): Promise<Address | null> {
  const holder = await read(reader, 'resolveHandle', [platformId, handle])
  return orNull(holder)
}

/// A holder and the moment the platform stated it.
export interface Binding {
  /// The holder, or `null`.
  holder: Address | null
  /// When the platform stated the binding, in seconds on the scale every
  /// platform shares. `0n` when nobody proved it.
  observedAt: bigint
}

/// The holder that proved this id and when, in one call
/// (`IdentityRegistry.idBindingOf`).
export async function idBindingOf(
  reader: RegistryReader,
  platformId: `0x${string}`,
  id: string,
): Promise<Binding> {
  const [holder, observedAt] = await read(reader, 'idBindingOf', [platformId, id])
  return { holder: orNull(holder), observedAt }
}

/// The holder that last proved this handle and when, in one call
/// (`IdentityRegistry.handleBindingOf`).
///
/// Read the way `resolveHandle` reads: normalized on chain, and a string the
/// rules refuse answers `{holder: null, observedAt: 0n}`. A handle its
/// identity renamed away from answers `holder: null` beside the `observedAt`
/// of the proof that last held it.
export async function handleBindingOf(
  reader: RegistryReader,
  platformId: `0x${string}`,
  handle: string,
): Promise<Binding> {
  const [holder, observedAt] = await read(reader, 'handleBindingOf', [platformId, handle])
  return { holder: orNull(holder), observedAt }
}

/// The handle an identity proved most recently.
export interface HandleOfId {
  /// As normalized on chain when it was proved.
  handle: string
  /// True while the handle node still points back at this identity, as
  /// `Identity.handleCurrent`. It reads the nodes, not the rules: after the
  /// platform's rules narrow so this handle no longer normalizes, it stays
  /// true while `resolveHandle`, `handleBindingOf` and `idOfHandle` answer
  /// `null` for the handle. Route by those, not by this flag.
  current: boolean
}

/// The handle an id proved most recently, or `null` for an id never proved
/// (`IdentityRegistry.handleOfId`).
export async function handleOfId(
  reader: RegistryReader,
  platformId: `0x${string}`,
  id: string,
): Promise<HandleOfId | null> {
  const [handle, current] = await read(reader, 'handleOfId', [platformId, id])
  return handle.length === 0 ? null : { handle, current }
}

/// The id of the identity that holds a handle now, or `null`
/// (`IdentityRegistry.idOfHandle`). Normalized on chain; a string the rules
/// refuse, and a handle its identity renamed away from, answer `null`.
export async function idOfHandle(
  reader: RegistryReader,
  platformId: `0x${string}`,
  handle: string,
): Promise<string | null> {
  const id = await read(reader, 'idOfHandle', [platformId, handle])
  return id.length === 0 ? null : id
}

/// The handle to show for a holder, or `null`.
///
/// Forward-checked on chain: empty once the stored handle resolves somewhere
/// else. ENS asks integrators to perform that check themselves and warns that
/// skipping it displays an ENS primary name that no longer resolves back; here
/// it cannot be skipped, because the contract does it.
export async function publishedHandleOf(
  reader: RegistryReader,
  holder: Address,
  platformId: `0x${string}`,
): Promise<string | null> {
  const handle = await read(reader, 'publishedHandleOf', [holder, platformId])
  return handle.length === 0 ? null : handle
}

export interface HandleAndIdResolution {
  /// The handle's holder, or `null`.
  holder: Address | null
  /// True only when the id resolves to that same holder.
  ///
  /// False means the caller's `(handle, id)` pair comes from two moments:
  /// somebody proved the handle after the caller learned who held it. That is
  /// staleness, not corruption.
  idAgrees: boolean
}

/// Resolve a handle and report whether an id still agrees with it.
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
/// A handle the platform's rules reject resolves to `{holder: null, idAgrees:
/// false}`, the same as one nobody has proved — see `resolveHandle`.
export async function resolveHandleAndId(
  reader: RegistryReader,
  platformId: `0x${string}`,
  handle: string,
  id: string,
): Promise<HandleAndIdResolution> {
  const [holder, idAgrees] = await read(reader, 'resolveHandleAndId', [platformId, handle, id])

  return { holder: orNull(holder), idAgrees }
}

/// One identity a holder proved, as the holder's list reports it.
export interface Identity {
  /// The platform the identity is on, as `platformId` derives it.
  platformId: `0x${string}`
  /// The id, byte for byte as the platform issued it.
  id: string
  /// The handle this identity proved most recently, as normalized on chain.
  handle: string
  /// True while the handle node still points back at this identity.
  ///
  /// False once another identity proves the same handle: the string stays as
  /// the last thing this identity was known as, and the flag says not to route
  /// by it.
  handleCurrent: boolean
}

/// How many identities a holder has, on every platform together.
export async function identityCount(reader: RegistryReader, holder: Address): Promise<bigint> {
  return read(reader, 'identityCount', [holder])
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
  const page = await read(reader, 'identitiesOf', [holder, from, limit])
  return page.map(({ platformId, id, handle, handleCurrent }) => ({
    platformId,
    id,
    handle,
    handleCurrent,
  }))
}

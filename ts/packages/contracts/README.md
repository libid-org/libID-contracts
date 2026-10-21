# @libid/contracts

Typed, viem-ready ABIs for the libid identity stack (NotaryService,
CeremonyProofVerifier, GoogleJwtRoots, IdentityRegistry, HandleEscrow,
HandleResolver, LibidFactory, WTIA9), the errors a bind can revert with, a call
builder for every state-changing function, and the identity helper layer:
handle normalization, node derivation and resolution.

`src/abis/` and `src/calls/` are generated from the forge artifacts
(`solidity/out`) by `scripts/codegen.mjs` and are not committed. Each ABI is
exported `as const satisfies Abi`, so viem infers argument and return types,
and each call builder takes its arguments from that ABI.
`scripts/regen-identity-handles.py` generates the platform table
(`src/platforms/platforms.ts`) and the test vectors (`src/platforms/vectors.ts`,
not published) from the pinned libID-circuits release's `platforms.json` and
`handles.json`, vendored into `solidity/contracts/circuits/`.

```sh
pnpm add @libid/contracts viem
```

`viem` is an optional peer. The root export, `calls` and `identity` import it.
`ceremony` and `platforms` load without it.

## Reading a contract with viem

```ts
import { createPublicClient, http } from 'viem'
import { googleJwtRootsAbi, identityRegistryAbi } from '@libid/contracts/abis'
import { handleNode, idNode, PLATFORM_X_KEY, platformId } from '@libid/contracts/identity'

const client = createPublicClient({ transport: http(RPC_URL) })

// Fully typed: viem infers the argument and return types from the ABI. The
// handle and the id are hashed here, so only their nodes reach the RPC.
const [holder, idAgrees] = await client.readContract({
  address: IDENTITY_REGISTRY,
  abi: identityRegistryAbi,
  functionName: 'resolveHandleNodeAndId',
  args: [
    platformId(PLATFORM_X_KEY),
    handleNode(PLATFORM_X_KEY, 'alice'),
    idNode(PLATFORM_X_KEY, '42'),
  ],
})

// The two generations of Google's key set the list holds.
const [current, previous] = await client.readContract({
  address: GOOGLE_JWT_ROOTS,
  abi: googleJwtRootsAbi,
  functionName: 'currentKeys',
})
```

## Building a call

One builder per state-changing function, namespaced by contract since names
like `initialize` repeat. A builder returns the call as data, to send directly,
batch, or wrap in a smart wallet's `execute`.

```ts
import { calls } from '@libid/contracts/calls'

const call = calls.identityRegistry.publish(IDENTITY_REGISTRY, platformId, 'alice')
// { to: `0x…`, data: `0x…` }

await wallet.sendTransaction(call)
```

Arguments are typed from the ABI, so a wrong type or a missing argument fails
to compile rather than reverting on chain. Payable functions take `value`
before their arguments and set it on the returned call:

```ts
// A JWKS rotation pays the Notary Fee: read it with `quoteRotation` first.
const rotate = calls.googleJwtRoots.rotate(roots, fee, attestedData, proof)
// { to: `0x…`, value: fee, data: `0x…` }
```

## Resolving a handle

```ts
import {
  identitiesOf,
  identityCount,
  idNode,
  platformId,
  primaryHandleOf,
  resolveHandle,
  resolveHandleAndId,
  PLATFORM_X_KEY,
} from '@libid/contracts/identity'

const reader = { client, address: IDENTITY_REGISTRY }
const x = platformId(PLATFORM_X_KEY)

// The holder that last proved a handle, or null. Pass the text as typed: it is
// folded and hashed locally. Text nobody proved, such as `@alice`, answers null.
const holder = await resolveHandle(reader, x, 'Alice')

// Before sending funds: is this id still the account that proved the handle?
const { idAgrees } = await resolveHandleAndId(reader, x, 'alice', idNode(PLATFORM_X_KEY, '42'))

// The one handle a holder displays, on whichever platform, forward-checked on chain.
const primary = await primaryHandleOf(reader, holder!)
// { platformId: x, handle: 'alice' } or null

// Every identity the holder proved, on every platform, a page at a time.
// Order is arbitrary and shifts on removal: read the count and pages at one block.
const total = await identityCount(reader, holder!)
const identities = await identitiesOf(reader, holder!, 0n, 50n)
// [{ platformId: x, idNode: '0x…', handleNode: '0x…', handleCurrent: true }, …]
// Nodes only; the handle text is on chain only when published.
```

## Binding an identity

`bind` takes the platform, this chain's verifier version for it, the payload
the ceremony produced, the handle to disclose, whether that handle becomes
the wallet's primary handle, and the service fee with its receiver. The
registry checks a disclosed handle against the node the proof bound and logs
it in `HandleRevealed`. The value is what `quoteBind` returns for the same pair
plus the fee, which goes to the receiver; a bind with no fee passes `0n` and
the zero address. The payload's transaction data is `abi.encode(target)` under
the operation domain `keccak256("libid.bind-identity")`, so one payload binds
on every chain. An EOA sends the call directly, a smart wallet wraps it in its
own execute:

```ts
import { calls } from '@libid/contracts/calls'

const github = platformId(PLATFORM_GITHUB_KEY)
const fee = await client.readContract({
  address: IDENTITY_REGISTRY,
  abi: identityRegistryAbi,
  functionName: 'quoteBind',
  args: [github, 1],
})
const call = calls.identityRegistry.bind(
  IDENTITY_REGISTRY, fee + serviceFee, github, 1, payload, 'octocat', true, serviceFee, feeReceiver,
)
// call = { to, value, data } — sign and send from the address the payload names.
// The handle is '' to keep the bind unlisted; `true` makes it the wallet's one
// primary handle on any platform, `false` only reveals it.
// calls.identityRegistry.bindPrivately(IDENTITY_REGISTRY, fee + serviceFee, github, 1, payload, serviceFee, feeReceiver)
// is the same with no handle.
// calls.identityRegistry.reveal(IDENTITY_REGISTRY, github, 'octocat') reveals a held handle later.
```

The payload is one `abi.encode`d struct in the shape its Platform Verifier
decodes. `encodeTlsNotaryProof` builds the X and GitHub payload,
`encodeGoogleProof` the Google one:

```ts
import { encodeTlsNotaryProof } from '@libid/contracts'

const payload = encodeTlsNotaryProof({
  ceremonyVersion: 1,
  operationDomain, authorizationNonce, transactionData,
  tokenSession, identitySession,   // { attestedData, proof } each
  idNode, handleNode,
  proof,
})
```

A refused bind reverts with the error of whichever contract on its route
refused it: the registry, the Proof Verifier, a Platform Verifier, the Notary
Service or a Honk verifier. `bindErrorsAbi` carries all of them:

```ts
import { decodeErrorResult } from 'viem'
import { bindErrorsAbi } from '@libid/contracts/abis'

const { errorName, args } = decodeErrorResult({ abi: bindErrorsAbi, data: revertData })
// 'HandleNotProved', [disclosed, proved]: the handle bind disclosed is not the proved one.
```

The Honk verifiers raise errors such as `SumcheckFailed()` that their own ABI
omits. `honkVerifierErrorsAbi` declares them under bb's names, and
`bindErrorsAbi` includes it.

## Normalizing a handle locally

`@libid/contracts/platforms` holds the platform table, the checks the
circuits apply to handles and ids, and node derivation, and loads without viem.
`@libid/contracts/identity` re-exports it and adds the registry reads, which
need viem.

Only A–Z fold to a–z. Text no circuit hashes throws
`HandleError`: empty text, a byte outside printable ASCII, a quote, a
backslash, or more bytes than the circuit's buffer.

```ts
import { checkId, normalize, PLATFORM_X_KEY, RULES_X, HandleError } from '@libid/contracts/platforms'

normalize('Alice_1', RULES_X) // 'alice_1'
normalize(' @Alice_1 ', RULES_X) // ' @alice_1 ': nothing is trimmed or stripped
normalize('Ali"ce', RULES_X) // throws HandleError: a quote is refused
checkId(PLATFORM_X_KEY, '2244994945') // passes; checkId(PLATFORM_X_KEY, 'x1') throws IdError
```

On chain only the fold runs; text the circuits refuse has no binding, so it
resolves to nobody.

## Deriving a handle node

A node is `SHA256(tag || value)`, as the platform's circuit outputs it: the
normalized handle under the handle tag, the id as the platform sent it under
the user-id tag. Nodes are unsalted, so anyone can test a guess against one.
Both functions take the platform key, not its id:

```ts
import { checkId, handleNode, idNode, PLATFORM_GOOGLE_KEY } from '@libid/contracts/platforms'

// HandleEscrow.deposit, handleBinding, escrowed, claim, refund
const node = handleNode(PLATFORM_GOOGLE_KEY, 'Alice@Gmail.com')
// idBinding, resolveId, resolveHandleAndId
const id = idNode(PLATFORM_GOOGLE_KEY, '100000000000000000001')
// Throws IdError for an id no circuit would hash; ids are never normalized.
checkId(PLATFORM_GOOGLE_KEY, '100000000000000000001')
```

## Development

```sh
cd solidity && forge build   # codegen reads the artifacts
pnpm -C ts install
pnpm -C ts codegen           # generate src/abis/ + src/calls/ (gitignored; required first)
pnpm -C ts build             # tsc → dist/ (ESM + .d.ts)
pnpm -C ts test              # vitest
pnpm -C ts lint && pnpm -C ts fmt:check
```

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
(`src/identity/platforms.ts`) and the test vectors (`src/identity/vectors.ts`,
not published) from the pinned libID-circuits release's `platforms.json` and
`handles.json`, vendored into `solidity/contracts/circuits/`.

```sh
pnpm add @libid/contracts viem
```

`viem` is an optional peer. The root export, `calls` and `identity` import it;
a consumer of `@libid/contracts/ceremony` alone can leave it out.

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

const call = calls.identityRegistry.unpublish(IDENTITY_REGISTRY, platformId)
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
  publishedHandleOf,
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

// The handle a holder displays, forward-checked on chain.
const handle = await publishedHandleOf(reader, holder!, x)

// Every identity the holder proved, on every platform, a page at a time.
// Order is arbitrary and shifts on removal: read the count and pages at one block.
const total = await identityCount(reader, holder!)
const identities = await identitiesOf(reader, holder!, 0n, 50n)
// [{ platformId: x, idNode: '0x…', handleNode: '0x…', handleCurrent: true }, …]
// Nodes only; the handle text is on chain only when published.
```

## Binding an identity

`bind` takes the platform, this chain's verifier version for it, the payload
the ceremony produced, and the handle to publish. The registry checks a
published handle against the node the proof bound. The value is what
`quoteBind` returns for the same pair. An EOA sends the call directly, a smart
wallet wraps it in its own execute:

```ts
import { calls } from '@libid/contracts/calls'

const github = platformId(PLATFORM_GITHUB_KEY)
const fee = await client.readContract({
  address: IDENTITY_REGISTRY,
  abi: identityRegistryAbi,
  functionName: 'quoteBind',
  args: [github, 1],
})
const call = calls.identityRegistry.bind(IDENTITY_REGISTRY, fee, github, 1, payload, '')
// call = { to, value, data } — sign and send from the address the payload names.
// The last argument is the handle to publish, or '' to keep the bind private;
// calls.identityRegistry.bindPrivately(IDENTITY_REGISTRY, fee, github, 1, payload) is the same with no handle.
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

Only A–Z fold to a–z. Text no circuit hashes throws
`HandleError`: empty text, a byte outside printable ASCII, a quote, a
backslash, or more bytes than the circuit's buffer.

```ts
import { normalize, RULES_X, HandleError } from '@libid/contracts/identity'

normalize('Alice_1', RULES_X) // 'alice_1'
normalize(' @Alice_1 ', RULES_X) // ' @alice_1 ': nothing is trimmed or stripped
normalize('Ali"ce', RULES_X) // throws HandleError: a quote is refused
```

On chain only the fold runs; text the circuits refuse has no binding, so it
resolves to nobody.

## Deriving a handle node

A node is `SHA256(tag || value)`, as the platform's circuit outputs it: the
normalized handle under the handle tag, the id as the platform sent it under
the user-id tag. Nodes are unsalted, so anyone can test a guess against one.
Both functions take the platform key, not its id:

```ts
import { checkId, handleNode, idNode, PLATFORM_GOOGLE_KEY } from '@libid/contracts/identity'

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

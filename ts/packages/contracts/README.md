# @libid/contracts

Typed, viem-ready ABIs for the libid identity stack (NotaryService,
CeremonyProofVerifier, GoogleJwtRoots, IdentityRegistry, HandleEscrow,
HandleResolver, LibidFactory, WTIA9), the errors a bind can revert with, a call
builder for every state-changing function, and the identity helper layer:
handle normalization, node derivation and resolution.

Both `src/abis/` and `src/calls/` are generated from the forge artifacts
(`solidity/out`) by `scripts/codegen.mjs`, and neither is committed — CI
regenerates them before every build, test and publish. Each ABI is exported
`as const satisfies Abi`, so viem infers argument and return types from it, and
each call builder reads its arguments off that ABI, so adding a write function
to a contract produces its wrapper instead of requiring someone to remember to
write one. The handle vector table in `src/identity/handleVectors.ts` is
generated from `solidity/contracts/handles/handles.json` by
`scripts/regen-identity-handles.py`.

```sh
pnpm add @libid/contracts viem
```

`viem` is an optional peer. The root export, `calls` and `identity` import it;
`@libid/contracts/ceremony` imports nothing, so a consumer of that subpath alone
can leave it out.

## Reading a contract with viem

```ts
import { createPublicClient, http } from 'viem'
import { googleJwtRootsAbi, identityRegistryAbi } from '@libid/contracts/abis'

const client = createPublicClient({ transport: http(RPC_URL) })

// Fully typed: viem infers the argument and return types from the ABI.
const holder = await client.readContract({
  address: IDENTITY_REGISTRY,
  abi: identityRegistryAbi,
  functionName: 'resolveHandle',
  args: [platformId, 'alice'],
})

// The two generations of Google's key set the list holds.
const [current, previous] = await client.readContract({
  address: GOOGLE_JWT_ROOTS,
  abi: googleJwtRootsAbi,
  functionName: 'currentKeys',
})
```

## Building a call

One builder per state-changing function, namespaced by contract because
function names like `initialize` are on almost all of them. A builder returns
the call as data — no provider, no signer — so you decide how it is submitted:
directly, batched, or through a smart wallet's `execute`.

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

// The holder that last proved a handle, or null. Pass what was typed: it is
// normalized and hashed here, with the registry's rules, and only the node
// reaches the RPC. Case folds, and text the rules refuse (an `@`, a space)
// answers null like a handle nobody proved.
const holder = await resolveHandle(reader, x, 'Alice')

// Before sending funds: does the id still agree with the handle?
const { idAgrees } = await resolveHandleAndId(reader, x, 'alice', idNode(PLATFORM_X_KEY, '42'))

// The handle a holder displays, forward-checked on chain.
const handle = await publishedHandleOf(reader, holder!, x)

// Every identity the holder proved, on every platform, a page at a time.
// Order is arbitrary, and a page read across a removal may overlap or skip:
// read the count and the pages against one block when every identity matters.
const total = await identityCount(reader, holder!)
const identities = await identitiesOf(reader, holder!, 0n, 50n)
// [{ platformId: x, idNode: '0x…', handleNode: '0x…', handleCurrent: true }, …]
// Nodes, never the id or handle: those are on chain only if published.
```

## Binding an identity

A binding is one of the generated builders: the platform, this chain's verifier
version for it, and the opaque payload the ceremony produced. The payload
carries the handle to publish, or none to leave it undisclosed: its Platform
Verifier checks a disclosed handle against the node the proof bound. The value
is what `quoteBind` returns for the same pair. An EOA sends it directly, a smart
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
const call = calls.identityRegistry.bind(IDENTITY_REGISTRY, fee, github, 1, payload)
// call = { to, value, data } — sign and send from the address the payload names.
```

The payload is one struct, `abi.encode`d, in the shape its Platform Verifier
decodes. `encodeTlsNotaryProof` builds the X and GitHub one and
`encodeGoogleProof` the Google one; both read the struct types from the
generated `ceremonyPayloadsAbi`:

```ts
import { encodeTlsNotaryProof } from '@libid/contracts'

const payload = encodeTlsNotaryProof({
  ceremonyVersion: 1,
  operationDomain, authorizationNonce, transactionData,
  tokenSession, identitySession,   // { attestedData, proof } each
  idNode, handleNode,
  handle: '',                      // or the handle to publish
  proof,
})
```

A refused bind reverts with an error from whichever contract on its route
refused it. `bindErrorsAbi` carries all of them — the registry's, the Proof
Verifier's, the three Platform Verifiers', the Notary Service's and the Honk
verifiers' — so one call names any of them:

```ts
import { decodeErrorResult } from 'viem'
import { bindErrorsAbi } from '@libid/contracts/abis'

const { errorName, args } = decodeErrorResult({ abi: bindErrorsAbi, data: revertData })
// 'HandleNotProved', [disclosed, proved]: the payload's handle is not the proved one.
```

The Honk verifiers raise their failures (`SumcheckFailed()` and the like)
from bb's generated assembly, with no entry in their own ABI;
`honkVerifierErrorsAbi` declares them under bb's names, and `bindErrorsAbi`
includes it.

## Normalizing a handle locally

A–Z fold to a–z and nothing else changes: no byte is trimmed and no `@` is
stripped. Text the rules refuse throws rather than being repaired.

```ts
import { normalize, RULES_X, HandleError } from '@libid/contracts/identity'

normalize('Alice_1', RULES_X) // 'alice_1'
normalize(' @Alice_1 ', RULES_X) // throws HandleError: a space and an `@` are refused
// On chain the same refusal is `UnusableHandle(problem)`, where `problem` is `kind + 1`
// (`HandleNormalizer.Problem`, whose 0 is `None`).
```

## Deriving a handle node

Hash locally, so the handle text never reaches an RPC. A node is
`SHA256(tag || value)`, the one the platform's circuit outputs: the handle
normalized under the platform's handle tag, the id exactly as the platform
sent it under its user-id tag. The hash is unsalted, so anyone can test a
guess against a node. Both take the platform key, not its id:

```ts
import { checkId, handleNode, idNode, PLATFORM_GOOGLE_KEY } from '@libid/contracts/identity'

// HandleEscrow.deposit, handleBinding, escrowed, claim, refund
const node = handleNode(PLATFORM_GOOGLE_KEY, 'Alice@Gmail.com')
// idBinding, resolveId, resolveHandleAndId
const id = idNode(PLATFORM_GOOGLE_KEY, '100000000000000000001')
// Throws HandleError for an id no circuit would hash; ids are never normalized.
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

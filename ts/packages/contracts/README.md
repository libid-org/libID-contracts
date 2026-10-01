# @libid/contracts

Typed, viem-ready ABIs for the libid identity stack (NotaryService,
CeremonyProofVerifier, GoogleJwtRoots, IdentityRegistry, LibidFactory, WTIA9), a
call builder for every state-changing function, and the identity helper layer:
handle normalization and resolution.

Both `src/abis/` and `src/calls/` are generated from the forge artifacts
(`solidity/out`) by `scripts/codegen.mjs`, and neither is committed — CI
regenerates them before every build, test and publish. Each ABI is exported
`as const satisfies Abi`, so viem infers argument and return types from it, and
each call builder reads its arguments off that ABI, so adding a write function
to a contract produces its wrapper instead of requiring someone to remember to
write one. The handle vector table in `src/identity/handleVectors.ts` is
generated from `solidity/contracts/identity/handles.json` by
`scripts/regen-identity-handles.py`.

```sh
pnpm add @libid/contracts viem
```

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
  platformId,
  publishedHandleOf,
  resolveHandle,
  resolveHandleAndId,
  PLATFORM_X_KEY,
} from '@libid/contracts/identity'

const reader = { client, address: IDENTITY_REGISTRY }
const x = platformId(PLATFORM_X_KEY)

// The holder that last proved a handle, or null. Pass what was typed —
// normalization happens on chain.
const holder = await resolveHandle(reader, x, '@Alice')

// Before sending funds: does the id still agree with the handle?
const { idAgrees } = await resolveHandleAndId(reader, x, 'alice', '42')

// The handle a holder displays, forward-checked on chain.
const handle = await publishedHandleOf(reader, holder!, x)

// Every identity the holder proved, on every platform, a page at a time.
// Order is arbitrary, and a page read across a removal may overlap or skip:
// read the count and the pages against one block when every identity matters.
const total = await identityCount(reader, holder!)
const identities = await identitiesOf(reader, holder!, 0n, 50n)
// [{ platformId: x, id: '42', handle: 'alice', handleCurrent: true }, …]
```

## Binding an identity

A binding is one of the generated builders: the platform, this chain's verifier
version for it, the opaque payload the ceremony produced, and whether to
publish the handle. The value is what `quoteBind` returns for the same pair.
An EOA sends it directly, a smart wallet wraps it in its own execute:

```ts
import { calls } from '@libid/contracts/calls'

const fee = await client.readContract({
  address: IDENTITY_REGISTRY,
  abi: identityRegistryAbi,
  functionName: 'quoteBind',
  args: [platformId(PLATFORM_GITHUB_KEY), 1],
})
const call = calls.identityRegistry.bind(IDENTITY_REGISTRY, fee, platformId(PLATFORM_GITHUB_KEY), 1, payload, true)
// call = { to, value, data } — sign and send from the address the payload names.
```

## Normalizing a handle locally

```ts
import { normalize, RULES_X, HandleError } from '@libid/contracts/identity'

normalize(' @Alice_1 ', RULES_X) // 'alice_1'
// Throws HandleError (with a kind matching the on-chain error) on refusal.
```

## Deriving a handle node

Hash locally, so the handle text never reaches an RPC:

```ts
import { handleHash, handleNode, platformId, PLATFORM_GOOGLE_KEY, rulesOf } from '@libid/contracts/identity'

const google = platformId(PLATFORM_GOOGLE_KEY)
const hash = handleHash('Alice@Gmail.com', await rulesOf(reader, google)) // HandleEscrow.deposit
const node = handleNode(google, hash) // handleBinding, escrowed, claim, refund
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

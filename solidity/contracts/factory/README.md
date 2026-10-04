# Deterministic deployment factory

One guarantee: **a protocol contract's address is a function of its name
and its environment's deployer key alone** — `address = f(admin, name)` —
the same on every EVM network that deployer deploys to, before anything is
deployed there, forever. Not a function of transaction order, deployer
nonces, bytecode versions, or constructor arguments. One deployer key per
environment (testnet, mainnet) gives one address table per environment.

```
Arachnid CREATE2 deployer (0x4e59b4…956C, keyless, same address everywhere)
  │  fixed salt keccak("libid.factory.impl.v1") + frozen impl init code
  ├──▶ LibidFactory implementation
  │  fixed salt keccak("libid.factory.v1") + frozen proxy init code (admin)
  └──▶ LibidFactory proxy  ← the environment's factory, same address on every chain
         │  CREATE3, salt = keccak(bytes(name)), owner-gated
         └──▶ every protocol proxy: address = f(factory, name) = f(admin, name)
```

## Why CREATE3, not raw CREATE2

CREATE2 folds the init-code hash into the address: deploy a proxy with a new
implementation address or different initData and it lands somewhere else,
so cross-network parity would require freezing every contract's init code
forever. CREATE3 ([`Create3.sol`](./Create3.sol), the well-known
solmate-shaped pattern) adds one indirection — CREATE2 a tiny *constant*
proxy keyed by the salt, which CREATE-deploys the target at its nonce 1 — and
the bytecode drops out of the formula entirely. Protocol evolution (new impl
versions, changed initData, even a different contract under an existing name
on a *new* network) never moves an address.

Deploy **proxies** through the factory ([`LibidFactory.deploy`](./LibidFactory.sol)
with `creationCode = ERC1967Proxy creation code ++ abi.encode(impl, initData)`).
Implementations go via plain CREATE — their addresses are referenced only by
their proxy and don't need to be deterministic.

## Why the admin is baked in (atomic initialization)

The factory's own proxy init code is **frozen**
([`FactoryDeployer.proxyInitCode(admin)`](./FactoryDeployer.sol)):
ERC1967Proxy creation code ++ `abi.encode(implAddress,
abi.encodeCall(initialize, (admin)))`. The admin is the environment's
deployer key, the only input that varies, so the same key gets the same
CREATE2 address everywhere, and the proxy initializes *inside its own
deployment transaction*: at no block height does an uninitialized factory
exist, so there is nothing to front-run. The raw implementation is bricked
with `_disableInitializers()`.

The admin is chosen once per environment: changing it afterwards is a new
factory at a new address, with a new address table behind it.

## Bootstrap: the keyless CREATE2 deployer is the only path

The factory is deployed through [Arachnid's deterministic-deployment
proxy](https://github.com/Arachnid/deterministic-deployment-proxy) at
`0x4e59b44847b379578588920cA78FbF26c0B4956C`. That proxy was itself deployed
from a keyless one-time account (a presigned pre-EIP-155 transaction whose
signature was fixed before any key existed), so it has the same address on
every chain. On a chain where it is missing, it is installable by anyone:
fund `0x3fab184622dc19b6109349b94811493bf2a45362` with exactly 0.01 ETH
(100 gwei × 100 000 gas) and broadcast the well-known raw transaction —
`FactoryGenesis::ensure` in `rust/contracts/src/factory.rs` automates the whole
sequence (install deployer if absent → deploy impl → deploy proxy).

**There is deliberately no fallback path.** Any other deployment route (e.g.
a genesis key at nonce 0) would produce a *different* factory address and
silently defeat the cross-network guarantee. Network onboarding requirement:
the canonical CREATE2 deployer must be present or installable. A chain that
enforces EIP-155 on all transactions (cannot accept the presigned install tx)
and doesn't ship the deployer in genesis **cannot host the deterministic
factory** — `FactoryGenesis::ensure` fails hard, and the network must be
reconsidered. Chains that changed CREATE2/CREATE address derivation
(zkSync-Era-style) are out of scope for address parity. First supported
network: **Eden testnet** (chain 3735928814), where the deployer is already
present.

## The frozen-init-code invariant

`implInitCode()` and `proxyInitCode(admin)` must **never change** for a
given admin: they are pinned by the LibidFactory/ERC1967Proxy sources and
the compiler settings (solc 0.8.33, via_ir, 200 runs, no CBOR metadata). `test/FactoryDeployer.t.sol` asserts they match the built
artifacts byte-for-byte, which are in turn vendored for the Rust bootstrap —
one set of bytes everywhere. Behavior changes to the live factory go through
its UUPS upgrade (address and records are kept). A change that *does* alter
the init code — new sources you want deployed as the genesis bytes — is a
**v2 factory**: new salts (`libid.factory{,.impl}.v2`), a new
canonical address, and a migration story; never a silent replacement of v1.

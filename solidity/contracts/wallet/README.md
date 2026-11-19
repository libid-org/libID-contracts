# WebWallet

An account whose sessions belong to linked platform identities. A factory
wallet sits at an address fixed by one identity and a salt. An existing key
can run the same code through EIP-7702.

`WebWallet` is built on OpenZeppelin v5.7.0 `Account` (EntryPoint v0.9) and
has its own `execute`. Its state lives in the wallet's own storage, in
ERC-7201 namespaces under `libid.*`, keyed by an epoch. The code it runs is a
numbered release that `WalletFactory` publishes. A wallet moves to a newer
release only by its own root operation.

Every external a wallet answers is declared in `IWebWallet.sol`, with its
reverts. The other `I*.sol` files beside this one describe the factory, the
registry and the forwarder.

## Contracts

| Contract | Role | Upgrade |
|---|---|---|
| `WebWallet` | One release: execution, UserOperations, ERC-1271, `reset`, and the routing of identity entries to `IdentityAdmin` | none; wallets move to a newer release by `bump` |
| `IdentityAdmin` | Identities, sessions, logins, app lists and root operations. `WebWallet` runs it through DELEGATECALL | none; part of a release |
| `SessionRules` | What an operation below quorum may do, and the allowances it charges. `WebWallet` delegatecalls it internally; it is never routed | none; part of a release |
| `WalletProxy` | A factory wallet: routes every call with calldata by the release slot, and takes plain ETH | none |
| `WalletForwarder` | An EIP-7702 key's delegate: routes by the release slot, and sends `reset` to the factory's latest release | none, ownerless |
| `WalletFactory` | Publishes numbered releases; deploys wallets with `Create3` | UUPS, owner |
| `WalletRegistry` | Verifies a `libid.webwallet.*` proof for the calling wallet and spends its digest | UUPS, owner |

`IdentityAdmin` and `SessionRules` revert `NotDelegated` when called at their
own address.

### Storage

| Namespace | Holds |
|---|---|
| `libid.webwallet.release` | The release slot: `implementation \| version << 160`, one word |
| `libid.webwallet.state` | `epoch`, then `epochs[epoch]`: the genesis, threshold, root delay, sessions, links, counters, root queue and app lists |
| `libid.transient.webwallet.lock` | The lock over `execute`, `reset`, `executeRoot` and the key's root-only calls (transient) |
| `libid.transient.webwallet.entryPointBlocked` | Set by a bump for the rest of the transaction (transient) |
| `libid.transient.webwallet.dataStep` | Set while a bump runs the data steps (transient) |

A wallet keeps nothing outside these namespaces. Moving the epoch drops
every session, link and setting at once. `epoch()` reads it. A factory
wallet's epoch is zero.

### Frozen interfaces

Code that outlives a release calls these, so every release keeps them:

- The release slot and its packing. `WalletProxy`, `WalletForwarder` and
  every release read it.
- The `libid.webwallet.state` layout. Fields are only appended;
  `WalletStorage.storage-layout` checks it in CI.
- The three transient slots. A bump in one release sets them and the next
  release reads them.
- `IWalletFactory.latest()`, its selector and its two-word answer. The
  forwarder and `WalletProxy` read it.
- `IWalletFactory.release(uint64)`. A bump reads it.
- `IWalletRegistry.check`, its selector and the `Checked` layout. Every
  release calls it.
- `reset(bytes)`. The forwarder routes that selector.
- `VERSION()` and `runDataSteps(uint64)` on a release. The bump running in
  the old release calls them on the new one. `publish` also reads
  `VERSION()`, `FACTORY()` and `REGISTRY()`.

`WalletAbi.t.sol` pins the slots, the frozen selectors and the
`latest()` and `Checked` layouts.

## Deployment

Each constructor takes the address of what it calls, so the order is:

1. `WalletRegistry()`, the implementation, then its proxy under the
   `LibidFactory` name `"WalletRegistry"`, initialized with its owner and the
   Proof Verifier.
2. `WalletFactory(registryProxy)`, the implementation, then its proxy under
   the name `"WalletFactory"`, initialized with its owner.
3. `IdentityAdmin` and `SessionRules`.
4. `WebWallet(factoryProxy, registryProxy, 1, identityAdmin, sessionRules)`.
5. `factory.publish(webWallet)`, by the owner.
6. `WalletForwarder(factoryProxy)`.

The registry comes before the factory implementation: the factory keeps the
registry as the immutable `REGISTRY`.

The registry's owner points it at another Proof Verifier with
`setProofVerifier` (`ProofVerifierConfigured`). One-fee onboarding needs
`IdentityRegistry` and `WalletRegistry` to name the same Proof Verifier: the
bind is free only through the verifier that verified the link.

This repo deploys neither proxy. Giving the registry and the factory the same
owner is a requirement on the deployment, and nothing here checks it.

`publish(implementation)` reverts unless the implementation has code
(`ImplementationWithoutCode`), reports `VERSION() == latest + 1`
(`WrongReleaseVersion`), `FACTORY() == factory` (`WrongReleaseFactory`) and
`REGISTRY() == factory.REGISTRY()` (`WrongReleaseRegistry`). A version is
never published twice. A release does not deploy unless its `IdentityAdmin`
and `SessionRules` have code (`TargetWithoutCode`); `publish` does not check
them further.

A later release is `WebWallet(factory, registry, n, identityAdmin,
sessionRules)` with the next `n`, published the same way.

## Onboarding

### Factory wallets

`factory.walletAddress(platformId, idNode, salt)` gives the address before
the wallet exists. Salt 0 is `identityOf(platformId, idNode)`, salt n
`keccak256(abi.encode(platformId, idNode, n))`.

One transaction, sent by anyone, creates the wallet and runs its first
batch. K is the user's new session key. K signs the batch for the predicted
address before it exists.

```solidity
address w = factory.walletAddress(platformId, idNode, salt);
bytes memory linkData = abi.encode(block.chainid, w, k, policyHashOf(adminPolicy));

Execution[] memory calls = new Execution[](4);
// K becomes the genesis identity's admin session, active at once.
calls[0] = Execution(w, linkFee,
    abi.encodeCall(IWebWallet.linkIdentity, (platformId, verifierVersion, listPayload, linkData, adminPolicy)));
// The link verified this proof, so the bind attaches no value and pays no second fee.
calls[1] = Execution(address(identities), 0,
    abi.encodeCall(IdentityRegistry.bindPrivately, (platformId, verifierVersion, listPayload, 0, address(0))));
calls[2] = Execution(address(escrow), 0, abi.encodeCall(HandleEscrow.claim, (handleNode, tokens, w)));
// The relayer's repayment.
calls[3] = Execution(relayer, linkFee, "");

bytes memory executionCalldata = abi.encode(calls);
// K signs Execute(AUTHORIZED_MODE, executionCalldata, linkFee, at, 0, deadline, callGas)
// under the domain of the release w will run, salt 0: see the signing version below.
bytes memory data = abi.encode(executionCalldata, linkFee, deadline, callGas, abi.encode(authorization));

factory.createAndExecute{value: linkFee}(platformId, idNode, salt, AUTHORIZED_MODE, data);
```

- `createWallet` deploys a `WalletProxy` at the address if it has no code.
  The proxy writes the factory's latest release to its slot and runs
  `initialize`, which records the genesis `(platformId, idNode, salt)` and
  links that identity. It adds no session. Anyone may create a wallet; it
  grants nothing.
- `createAndExecute` then calls the wallet's `execute(mode, data)` with
  `msg.value`. The batch passes the same check as any other batch.
- The signing version is the release the wallet runs. When `w` already has
  code, anyone may have created it under an earlier release: read
  `IWebWallet(w).release()` and sign under its version. Only when `w` has no
  code does `createWallet` write `factory.latest()`, so sign under that
  version. A signature under any other version fails as
  `ExecutionNotSigned`, as it does when a release is published before the
  transaction lands: sign again.
- `listPayload` is one sign-in proving an Operation List
  (`libid.operations`) with a `bind-identity` entry for `w` and a
  `link-identity` entry for `linkData`. The same payload serves the link and
  the bind.
- The genesis bootstrap: `linkIdentity` adds the proven key as a session
  only on a factory wallet, only for the genesis identity, only with an
  admin policy, and only while the wallet never had a session. That session
  has `activeAt` 0, so it can sign the batch that adds it. It is the only
  session that can. Any other key in a link reverts `LinkSessionRefused`.
- Any failure reverts the whole transaction, the deployment included, and
  leaves nonce 0 unused. The same signature can be sent again until its
  deadline.

Later sessions come from the wallet's own `addSession`, or from logins.

### EIP-7702 accounts

An existing key delegates to `WalletForwarder` and calls `reset` on its own
address, in one type-4 transaction that the key sends itself:

```solidity
// Type 4, from the key, to the key's own address.
// authorizationList: the key's authorization for this chain id and WalletForwarder.
Execution[] memory calls = new Execution[](2);
// Link only: the transaction data carries an empty key and policy hash 0.
calls[0] = Execution(account, linkFee,
    abi.encodeCall(IWebWallet.linkIdentity, (platformId, verifierVersion, payload, "", policy)));
// The first session, signing from the next second.
calls[1] = Execution(account, 0,
    abi.encodeCall(IWebWallet.addSession, (identityOf(platformId, idNode), sessionKey, adminPolicy)));

IWebWallet(account).reset(abi.encode(calls));
```

- `reset(bytes executionCalldata)` runs only when
  `msg.sender == tx.origin == address(this)`: the key's own top-level
  transaction. The forwarder checks this before it reads the factory, and
  the release checks it again. It also refuses inside a batch and inside
  `executeRoot`. Every refusal is `ResetRefused`.
- `reset` moves the epoch to
  `keccak256(abi.encode(oldEpoch, blockhash(block.number - 1), block.timestamp))`,
  which drops all state, writes the factory's latest release to the slot,
  and runs `executionCalldata` as a batch with no signature check.
- The account pays: the key pays the gas, and the account's balance pays
  the link fee. There is no sponsored path. A relayer cannot send `reset`.
- An EIP-7702 account has no genesis. A link never carries a key. The first
  session comes from the key's `addSession`, and signs from the next second.
  A login cannot add the first session (`FirstSessionRefused`).
- Before `reset` the slot is empty: an empty call returns, and any other
  call reverts `NotSetUp`, UserOperations included.
- A plain ETH transfer with the 2,300-gas stipend arrives before and after
  setup. At the forwarder's own address every call reverts `NotDelegated`.

## Execution

`execute(bytes32 mode, bytes executionCalldata)` takes two kinds of mode.
One lock covers both, so a batch cannot call `execute` again
(`Locked`).

### AUTHORIZED batches

`AUTHORIZED_MODE` is batch call type, default exec type and mode selector
`bytes4(keccak256("libid.webwallet.authorized"))`. Anyone may submit it. The
data is:

```solidity
abi.encode(bytes executionCalldata, uint256 value, uint48 deadline, uint256 callGas, bytes authorization)
// authorization = abi.encode(IWebWallet.Authorization)
```

The wallet:

1. requires `executionCalldata` to be exactly `abi.encode(Execution[])` of
   the calls it decodes to, else `NoncanonicalBatch`;
2. requires `msg.value == value`, else `WrongBatchValue`;
3. reads and consumes its EntryPoint nonce under key 0
   (`EntryPointMissing` when the EntryPoint has no code on the chain);
4. reads the threshold and its EIP-712 domain separator;
5. requires `deadline` nonzero and not passed (`ExecutionExpired`);
6. runs the calls. Before each it requires `gasleft() * 63 / 64` of at least
   `callGas + CALL_OVERHEAD`, else `InsufficientCallGas`. A call to
   `address(0)` is a call to the wallet;
7. checks the signatures against the sessions as the calls left them
   (`ExecutionNotSigned`), the rules below quorum (`ExecutionNotAllowed`),
   and that the block time is inside the signers' window
   (`ExecutionOutsideWindow`).

Signers sign the EIP-712 hash of

```
Execute(bytes32 mode,bytes executionCalldata,uint256 value,uint48 at,uint256 nonce,uint48 deadline,uint256 callGas)
```

with `mode = AUTHORIZED_MODE`, `at = authorization.at`, and `nonce` the full
key-0 nonce before the batch. A session signs only after the second it was
added in. The genesis bootstrap is the one exception.

The threshold and the domain are read before the calls. A batch that changes
either does not help its own check. A batch that revokes or unlinks its own
signer fails it.

Any failure reverts everything, the nonce included, so a failed batch stays
valid until its deadline. Signing another batch at the same nonce does not
cancel it. Only a batch or UserOperation that uses the nonce, or the
deadline, does.

Below quorum the batch is checked by `SessionRules` with no gas charge and no
paymaster. Its value is charged to `NATIVE_TOKEN`.

### The default mode

Mode selector 0, single or batch call type, default or try exec type. The
caller is checked first. It must be:

- the EntryPoint, whose validation checked the operation. After a bump in
  the same transaction it reverts `EntryPointBlocked`;
- or an EIP-7702 account itself, that is, its key. A factory wallet never
  takes it from itself.

Anyone else gets `AccountUnauthorized`. From an allowed caller, any other
mode reverts `UnsupportedMode`. The batch must be canonical.

### UserOperations

- `userOp.signature` is `abi.encode(IWebWallet.Authorization)`.
- Signers sign the EIP-712 hash of `UserOperation(bytes32 userOpHash)` under
  the wallet's domain.
- `callData` must be `execute` in the default mode. Validation refuses
  every nonzero mode selector, `AUTHORIZED_MODE` included.
- Any nonce key works. AUTHORIZED batches share key 0.
- A malformed signature returns `SIG_VALIDATION_FAILED` rather than
  reverting.
- The signers' window goes back to the EntryPoint in the validation data.

### ERC-1271 and ERC-7739

`isValidSignature(hash, signature)`:

- On an EIP-7702 account, a 65-byte ECDSA signature of `hash` by the key
  itself is valid. Dapps keep accepting the key's signatures. Only while the
  account carries a delegation.
- Otherwise `signature` is an ERC-7739 nested signature under
  `eip712Domain()`: `PersonalSign`, or `TypedDataSign` followed by the app
  separator, contents hash and contents type. Its signature part is
  `abi.encode(Authorization)`, with `at` 0. Only `signatures` and
  `domainProof` are read.
- At quorum any signed hash is valid. Below quorum only a `TypedDataSign`
  whose app separator is proved under the governing session's `domainsRoot`.
- Signers sign inside their window.
- `isValidSignature(0x7739…7739, "")` answers `0x77390001`.
- A malformed signature answers `0xffffffff`.

### The signing domain

Every wallet signature is over one EIP-712 domain:

```
EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)
name              "WebWallet"
version           the release's VERSION, in decimal: "1", "2", ...
chainId           block.chainid
verifyingContract the wallet
salt              keccak256(abi.encode(epoch(), rootEpoch))
```

`eip712Domain()` reports these five fields (`0x1f`); read the salt there. A
bump changes the version, and a `reset` or a move of the
[root epoch](#root-operations) changes the salt, so each retires every
signature made before it: `Execute`, UserOperations and ERC-1271 alike. A
batch waiting for a co-signer dies when the threshold changes.

## Sessions

A session key is an ERC-7913 signer: a 20-byte address, recovered with
ECDSA, or `verifier || key`. A shorter key reverts `InvalidKey`. A session
belongs to one linked identity.

```solidity
struct Policy {
    uint48 validAfter;
    uint48 validUntil; // 0: no end
    bool admin;
    uint8 signers;     // signatures an operation below quorum takes; 0 counts as 1
    Rules rules;
}
```

- `addSession(identity, key, policy)` is the wallet's own call, for a linked
  identity. The session signs from the next second.
- `revokeSession(key)` is the wallet's own call. Revoking the last admin
  session is a root operation (`RootOperationRequired`). Revoking an admin
  session added before this second voids every queued root operation.
- An admin session never expires: `admin` with a nonzero `validUntil`
  reverts `AdminSessionExpires`.
- Policy bounds at bit 47 or above revert `PolicyOutOfRange`: EntryPoint v0.9
  reads that bit as a block-number flag.
- `sessionOf(key)` returns a live session, else zeros. A session dies when
  its identity is unlinked or its sessions are removed by login.
- `policyHashOf(policy)` (in `WalletStorage.sol`) is what a proof commits.

### Quorum

`threshold()` is how many distinct platforms of admin sessions an operation
needs to be at quorum. It is 1 by default. Many sessions on one platform
count once.

- At quorum, every signature is over the hash itself, and no rule applies.
- Below quorum, the first signature's session governs. Each signer signs
  `keccak256(abi.encode(hash, at, keccak256(governingKey)))`. Reordering the
  signatures changes which session governs, so it invalidates them.
- Below quorum, the operation takes exactly the governing session's
  `signers` signatures, from as many distinct platforms. Above threshold 1,
  none of them may be a session added by login.
- `setThreshold(t)` is a root operation. It reverts `ThresholdTooHigh` when
  `t` exceeds the platforms holding an admin session.
- A revoke may not leave admin sessions on fewer platforms than the
  threshold, unless it leaves none.
- An unlink lowers the threshold to the platforms still linked, not to the
  platforms still holding an admin session.

### Below quorum

Only the governing session's `Rules` apply. The other signers' windows still
narrow the operation's.

- An operation has at least one call.
- A call to the wallet, to `address(0)`, to the registry or to the EntryPoint
  is refused: those are admin operations.
- Every call needs `calls[i]`, a proof of the leaf
  `(target, selector, calls[i].maxValue)` under `scopeRoot`, with
  `value <= maxValue`. `scopeRoot == 0` allows no call.
- Native value is charged to `NATIVE_TOKEN` (`0xEeee…EEeE`). With no entry
  its limit is 0.
- ERC-20 `transfer(to, amount)` and `approve(spender, amount)` charge
  `amount` to the target. `transferFrom`, a spending selector on a target
  with no allowance, and any other selector on a target with one are
  refused. Other selectors on a target with no allowance are charged
  nothing. ERC-721 `approve` and `transferFrom` share ERC-20's selectors.
- A UserOperation with a paymaster needs `paymasterProof` under
  `paymastersRoot` and is charged no gas. `paymastersRoot == 0` allows no
  paymaster. Without one, its maximum gas cost,
  `(verificationGasLimit + callGasLimit + preVerificationGas) * maxFeePerGas`,
  is charged to `NATIVE_TOKEN`.

Leaves are OpenZeppelin double-hashed,
`keccak256(bytes.concat(keccak256(abi.encode(...))))`, under sorted-pair
roots:

| Root | Leaf |
|---|---|
| `scopeRoot` | `(address target, bytes4 selector, uint256 maxValue)` |
| `domainsRoot` | `(bytes32 appSeparator)` |
| `paymastersRoot` | `(address paymaster)` |

Calldata shorter than four bytes has selector `0x00000000`.

### Allowances and `at`

- Allowances are listed by strictly ascending token, each with a `period`
  below 2^47, else `BadAllowance`.
- A UserOperation's allowances are charged in validation, even when its
  execution reverts.
- The period is `at - at % period`, or the session's whole life when
  `period == 0`. A charging operation's window is that period intersected
  with the session's.
- A charge needs `at != 0`. An operation that charges nothing ignores `at`.
- Counters are keyed by `(key, rulesHash, token)`. A key added again with
  the same rules keeps its spend.
- Sign with `at` set to the block time. A charging operation's `validUntil`
  is its period's end. Bundlers may refuse an operation close to its
  `validUntil`; near a period's end, wait for the next period.
- `allowanceOf(key, token)` reads a live session's counter.

## Logins

A login is a proof of a linked identity. Anyone may submit it to the wallet,
with the fee `registry.quote(platformId, verifierVersion)` attached, directly
or as a call in a batch. The wallet calls `WalletRegistry.check`, which
verifies the proof, requires that it names this chain, the calling wallet
and the policy, spends its digest (`DigestSpent` on reuse), and returns the
identity, the key and the app. The wallet applies the result.

- `addSessionByLogin(platformId, verifierVersion, payload, data, policy)`
  (`libid.webwallet.add-session`) adds a session of a linked identity with no
  admin signature. It is `byProof`, signs from the next second, and must
  pass the identity's app list (`AppNotListed`). A wallet that never had a
  session takes no session by login (`FirstSessionRefused`).
- `removeSessionsByLogin(...)` (`libid.webwallet.remove-sessions`) kills
  every session of the identity and voids every queued root operation. With
  an empty key it unlinks the identity, unless it is the genesis, and lowers
  the threshold to the platforms still linked. It never refuses for the last
  admin. With a key it keeps the link and adds the key as
  `addSessionByLogin` does, app list included.
- `linkIdentity(...)` (`libid.webwallet.link-identity`) is the wallet's own
  call.

A proof's transaction data is

```solidity
abi.encode(uint256 chainId, address wallet, bytes sessionKey, bytes32 policyHash)
```

canonically encoded, with `policyHash = policyHashOf(policy)`. An empty key
carries policy hash 0. Under an Operation List (`libid.operations`) the
proof commits `keccak256` of these bytes in a `libid.webwallet.*` entry and
the call passes them as `data`. A proof of one operation passes empty
`data`.

The registry checks the operation's domain, so a link proof cannot serve as
a login. A key that calls `check` directly spends its own proof and records
nothing.

Watch `SessionAdded` with `byProof` set, `SessionsRemovedByLogin`,
`AppListSet` and `RootQueued` to alert the owner. Sessions cannot be listed
from storage.

An indexer follows the settings by their events: `ThresholdSet`, also
emitted when an unlink lowers the threshold, `RootDelaySet`, and `Bumped`
for a release change. `EpochReset` marks a `reset`: everything indexed for
the account before it is gone.

### App lists

`setAppList(identity, apps)` is the wallet's own call. Each entry is
`keccak256(clientIdentifier)`. The list is per identity.

- An empty list, the default, admits any app.
- A list governs adds only: `addSessionByLogin`, and a removal with a key.
  A removal without a key is accepted from any app.
- A removal by login leaves the list.
- `appList(identity)` reads it.

Client identifiers are public. A list stops apps on other domains, not
someone holding the user's live browser login.

## Root operations

`queueRoot(data)` is the wallet's own call. It takes a closed set:

- `bump(uint64 version)`;
- `setThreshold(uint8)`;
- `setRootDelay(uint32)`;
- `unlink(bytes32 identity)`;
- `revokeSession(bytes key)`, needed for the last admin session.

Anything else reverts `RootOperationNotAllowed`. The id is
`keccak256(data)`. The operation is ready at
`now + max(rootDelay, 1)`, so it never matures in the second it was queued.
The root delay is 0 by default and at most 365 days. `setRootDelay` is
itself a root operation, so a change waits out the current delay.

`executeRoot(id)` is open to anyone once the operation matured. It refuses
while the lock is held, so it never runs inside a batch. An operation is
void, `RootOperationVoid`, when the release moved or the root epoch moved
since it was queued. The root epoch moves when an admin session added before
this second is revoked, an identity is unlinked, its sessions are removed
by login, or the threshold changes. `rootReadyAt(id)` reads 0 for a void or unknown operation.
`cancelRoot(id)` is the wallet's own call.

Outside `executeRoot`, `bump`, `setThreshold`, `setRootDelay` and `unlink`
revert `RootOperationRequired`. The one exception is an EIP-7702 account's
key, in its own top-level transaction outside a batch, which runs them at
once.

### Bump

- `queueRoot(bump(v))` resolves `v == 0` to the factory's latest release,
  requires `v` above the current version (`ReleaseNotAbove`) and published
  (`ReleaseMismatch`), and stores the release's implementation in the queued
  operation. `rootOperation(id)` shows it for the whole delay.
- When it executes, the bump requires that `factory.release(current)` is
  still the current implementation, and that `factory.release(v)` is still
  the stored one, with code and `VERSION() == v`. Else `ReleaseMismatch`.
- It writes the release slot, blocks the EntryPoint's `execute` for the rest
  of the transaction, and calls the new release's `runDataSteps(from)`.
- Data steps run only inside a bump (`DataStepRefused` otherwise). A
  release's `runDataSteps(from)` runs the steps of every release after
  `from` up to its own, once, even across skipped versions. Release 1 has
  none. A data step that moves the epoch copies the genesis forward.
- After a bump the domain's version changes, so signatures made before it
  are refused. Root operations queued before it are void.
- The key's direct `bump(v)` takes an explicit `v`; `bump(0)` reverts.

## A lost wallet

A factory wallet an attacker holds at quorum is lost. The way out is a new
wallet for the same genesis at a new salt. Anyone can create it, and only a
proof of the genesis identity can give it its first session. The client:

1. picks the lowest salt whose wallet never had a session: no code at
   `factory.walletAddress(platformId, idNode, salt)`, or `hadSession()` false;
2. onboards it with the genesis bootstrap;
3. links the other platforms again, and sets the app lists and the threshold;
4. binds each handle again with a fresh login: a bind gives the handle to the
   newest proof's holder, and `HandleEscrow` pays only the current one.

Find a user's current wallet as the identity's `IdentityRegistry` holder,
not by scanning salts. Funds sent to the old address stay there; send by
handle. `genesisIdentity()` returns the salt beside the genesis.

An EIP-7702 account has no genesis and no new-salt counterpart.
`genesisIdentity()` returns zeros, and a removal by login can unlink every
identity. Its key starts over with `reset`.

## EIP-7702 accounts

An EIP-7702 account keeps its address, balances, approvals and handles, and
gains identity links, sessions, AUTHORIZED batches and UserOperations. It
follows a bump like a factory wallet.

**The key keeps full control.** It can send any transaction, sign anything,
point the address at other code, or clear the delegation. In its own
top-level transaction it runs the default mode, `reset`, and `bump`,
`setThreshold`, `setRootDelay` and `unlink` with no delay. Quorum, the root
delay and session rules bind every signer except the key. Identity recovery
covers a lost key, not a stolen one. Keep the key offline after onboarding.

**Linking extends trust.** Once linked, the account's existing balance is
under the parties in [Trust](#trust) too. At threshold 1 with an empty app
list, a phished login from any app adds a session at quorum. Set
[app lists](#app-lists).

**`reset` disarms.** Delegating away and back without `reset` resumes every
session. To drop them, call `reset`, with an empty batch if there is nothing
to run. Revoking with the key is not enough: its `revokeSession` of the last
admin session reverts `RootOperationRequired`.

**Send the authorization and `reset` together.** Until `reset` writes the
slot, the forwarder routes by whatever the slot holds, and code delegated to
earlier can have written it. Put the authorization and `reset` in one
transaction. A `reset` that reverts leaves the delegation in place: retry
it, or clear the delegation.

**Send `reset` privately.** The new epoch depends on the previous block hash
and the block time. Code that runs in the same block before `reset` can
predict it and plant state there.

**Move assets after an untrusted delegate.** Code you delegated to earlier
can have left token approvals behind. `reset` drops the wallet's state, not
approvals the address gave. After delegating to code you do not trust, move
the assets to a fresh address.

**Sign authorizations narrowly.** Sign for this chain id and the key's
correct nonce, never chain id 0. When the key sends the type-4 transaction
itself, the transaction uses its current nonce, so the authorization takes
the next one.

**Indexing.** The factory emits nothing for these accounts. Find them by
`IdentityLinked`, the session events and `EpochReset`, or by their
delegation code (`0xef0100 || walletForwarder`).

## Bundlers

- Validation reads only the account's own storage, never the factory, the
  registry, the clock or transient storage (ERC-7562). The rule checks run
  in `SessionRules` through DELEGATECALL, so they touch the wallet's slots.
- `WalletFactory` cannot serve as `initCode`: ERC-7562 lets the deployment
  CREATE2 deploy only the sender, and `Create3` deploys an intermediate
  contract. Create wallets with a plain transaction. A UserOperation can be
  signed for the predicted address before the wallet exists.

## Trust

A wallet trusts the parties below, with no timelock.

- **The factory's owner** publishes releases and upgrades `WalletFactory`.
  The owner's releases become the code of every wallet created after them,
  funds already sent to its address included, and of every EIP-7702 account
  at its next `reset`. A wallet that exists moves to a new release only by
  its own `bump`, after its root delay.
- **The registry's owner** is the factory's owner: the deployment
  initializes both proxies with the same owner. That owner can upgrade
  `WalletRegistry`. An upgraded registry can return any `Checked`, so it can
  add admin sessions to any wallet that has a session, on every linked
  identity, with no delay.
- **The Proof Verifier's owner** already has that power. `WalletRegistry`
  trusts the `CeremonyProofVerifier` proxy, whose owner can `setVerifier`
  and upgrade it, and so route a platform to a verifier that accepts any
  proof. Each Platform Verifier's owner can upgrade it or change its trust
  roots (`setTrustRoots`, and `setJwtRoots` for OIDC platforms).
- **The notary is the trust root.** A notary signature makes a login proof
  valid on every platform: X and GitHub proofs carry notarized sessions, and
  the Google and Telegram keys come from notarized readings.
  `NotaryService`'s owner chooses the keys (`setNotary`) and can upgrade it.
  The owners of `GoogleJwtRoots` and `TelegramJwtRoots` choose which Notary
  Service their readings come from (`setNotaryService`), and can upgrade
  them.

Each of these can make a login proof valid, and so give a wallet a session
that signs from the next second.

## Accepted risks

- **One phished login.** At threshold 1 with no app list, a session added by
  login may carry an admin policy, so one phished login, from any app, takes
  the wallet. The owner's removal by login does not win it back: the
  attacker can set an app list on the owner's identity and keep a session
  of a second identity of their own. Set the app list in the onboarding
  batch, and raise the threshold.
- **A first session from any genesis proof.** Any app that receives a proof
  of the genesis identity naming its own key, from any OAuth client, can
  give a factory wallet that never had a session its first session.
- **ERC-1271 below quorum is not charged.** A session's ERC-1271 signature
  for a listed app domain is not charged to its allowances. Do not list
  Permit2 or a token's permit domain for a limited session: the session
  could then sign away the approved balance. The same holds for other
  typed data that moves value, such as Seaport, CoW or 1inch orders.
- **Unparsed spending.** Below quorum, spending through a selector the
  allowances do not parse, such as a router pulling a standing approval, is
  bounded only by the scope.
- **A removal from an unlisted app.** A login removal without a key is
  accepted from any app. It kills the identity's sessions, unlinks a
  non-genesis identity, lowers the threshold and voids the queued root
  operations. The owner links it again and queues them again.
- **An unlink below the threshold.** An unlink or a removal by login lowers
  the threshold only to the platforms still linked, and can leave admin
  sessions on fewer platforms than the threshold. Keep the threshold at
  most the number of platforms minus 1.
- **At k of n**, the wallet stays the user's until k platforms are phished.
- **A matured bump mid-bundle.** Anyone can run a matured bump through
  `executeRoot`, from another sender's UserOperation in the middle of a
  bundle. The wallet's UserOperations already validated in that bundle then
  revert `EntryPointBlocked`, and the wallet pays their gas. Once per bump.
- **Revocation and the bundle.** A revocation does not stop a UserOperation
  validated earlier in the same bundle. Only a bump does.
- **Same-block epoch prediction** on EIP-7702 accounts: send `reset`
  privately.
- **A `reset` that reverts** leaves the delegation in place: send the
  authorization and `reset` in one transaction, and retry or clear the
  delegation after a revert.
- **Leftover approvals** from code delegated to earlier: move the assets
  after an untrusted delegate.
- **A copied login.** A login proof placed in a signed batch can be copied
  out and submitted alone by anyone: its session is added, and the batch
  then reverts `DigestSpent`. A link is the wallet's own call and cannot be
  copied out this way.
- **Re-adding a key with different rules** starts its counters fresh.
  Adding a session is an admin operation.
- **No pause.** The JWT roots cannot drop a leaked key at once, and
  `WalletRegistry` has no pause. During a leak anyone could add sessions to
  every wallet with a linked identity on that platform.
- **A fixed EntryPoint.** `entryPoint()` is v0.9. A later EntryPoint takes a
  new release and a bump per wallet.
- **Nonce key 0.** AUTHORIZED batches of every signer share nonce key 0. A
  limited session can submit its own in-scope batch at the current nonce
  and so void an admin's signed batch, again and again, at almost no cost:
  the AUTHORIZED path charges no gas. No funds or control are at risk. The
  admin can send a UserOperation under another nonce key, or revoke the
  session.
- **Stateful verifiers.** An ERC-7913 verifier used for a session key must
  not read state the wallet can write: an AUTHORIZED batch asks the verifier
  after its calls ran. OpenZeppelin's `ERC7913WebAuthnVerifier` is
  stateless.
- **Token paymasters.** A token paymaster the session lists takes its fee
  outside the allowances.
- **Approvals outlive sessions.** Approvals a session made outlive its
  revocation.
- **Root delay 0.** The root delay is 0 by default, so a root operation
  matures one second after `queueRoot`, too soon for any alert. A wallet
  that holds value should raise it with `setRootDelay`.

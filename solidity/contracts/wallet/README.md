# WebWallet

An ERC-7579 account per platform identity, at an address fixed by that
identity and a salt. Sessions are ERC-7913 keys added by an OAuth login or by
the wallet itself, and a login removes them.
Each function's behaviour and reverts are in the NatSpec of the `I*.sol`
interfaces beside this file.

| Contract | Role | Upgrade |
|---|---|---|
| `WalletFactory` | Deploys wallets with `Create3` at `(platformId, idNode, salt)`: salt 0 is `identityOf(platformId, idNode)`, salt n `keccak256(abi.encode(platformId, idNode, n))` | UUPS, owner |
| `WebWallet` | The account (OpenZeppelin v5.7.0, EntryPoint v0.9) | UUPS, by the wallet's own root operation |
| `IdentityValidator` | Identities, sessions, threshold and root operations of every wallet | none |
| `IdentityAdmin` | The validator's writes: installs, links, sessions and root operations; deployed by `IdentityValidator`'s constructor and run through DELEGATECALL on its storage | none |
| `SessionRules` | What an operation may do, and the allowances it charges; deployed by `IdentityValidator`'s constructor and run through DELEGATECALL on its storage | none |
| `WalletRegistry` | Turns a `libid.webwallet.*` proof into a link, a session or a removal; keeps each wallet's app lists | none |

## Onboarding

One relayer transaction creates the wallet and runs its first batch:

```solidity
// K, Alice's new session key, signs the batch for the wallet's address before it exists.
factory.createAndExecute{value: linkFee}(
    platformId, idNode, salt, AUTHORIZED_MODE, abi.encode(calls, linkFee, deadline, callGas, abi.encode(authorization))
);
// calls: registry.linkIdentity{value: linkFee}(platformId, v, listPayload, linkData, policy), // K, the first session
//        identities.bindPrivately(platformId, v, listPayload, 0, address(0)),                // free: verified above
//        escrow.claim(handleNode, tokens, w),
//        relayer.call{value: linkFee}(""),                                                    // the relayer's refund
//        validator.addSession(identity, botKey, botPolicy)                                    // optional
```

`listPayload` is one sign-in proving an Operation List of the `bind-identity`
entry for `w` and the `link-identity` entry for `linkData`, the
`abi.encode(chainId, w, K, policyHash)` it hashes, so the same payload serves
both calls. The link pays the Notary Fee. The bind, a later call of the same
batch, attaches no value, so `CeremonyProofVerifier` returns the claim the link
verified; with `quoteBind` attached it would verify again. The value rule is
`IProofVerifier.verify`'s.
`createAndExecute` creates the wallet if it has no code, then calls its
`execute(mode, data)` with `msg.value`. It grants nothing: the batch passes the same end
check as any direct batch. Any failure reverts the whole transaction, the
deploy included, and leaves the nonce unused, so the same signature can be
sent again until its deadline.

## First session

The factory links the genesis identity when it creates the wallet; it adds no
session. The first session comes from the wallet's own `linkIdentity` of the
genesis identity, with an admin policy, from a proof of any OAuth client. It
is active at once
(`activeAt` 0), so it can sign the batch that adds it. While the wallet never
had a session, any other session a link would add reverts
`FirstSessionRefused`, and so does `addSessionByLogin`. Only the wallet calls
`linkIdentity`.

`Session.activeAt` is when the session starts signing: it signs only after
that second.

- Any session but the first: `block.timestamp`, so it signs from the next
  second.
- The first session: 0.

So the first session is the only one that can sign the batch that adds it.

## Sessions by login

A login is a proof of a linked identity, which anyone may submit to
`WalletRegistry` with the Notary Fee, directly or as a call in the wallet's
own batch.

- `addSessionByLogin` (`libid.webwallet.add-session`) adds a session of that
  identity with no admin signature. It is `byProof` and signs from the next
  second. Above threshold 1 a `byProof` session never acts below quorum: its
  operations need admin signers that reach the threshold. At threshold 1 it
  co-signs like any other session. A wallet that never had a session takes
  no session by login.
- `removeSessionsByLogin` (`libid.webwallet.remove-sessions`, the same
  transaction data as an add) kills every session of the identity and voids
  every queued root operation.
  - With an empty key (and a zero policy hash) it unlinks the identity
    unless it is the genesis, which stays linked. The threshold drops to
    `min(threshold, platforms still linked)`. It never reverts for the last
    admin: the user signs in again to add one back.
  - With a key it keeps the link and the threshold, then adds the key as
    `addSessionByLogin` does. One sign-in proof is spent once, so this is
    how one login both clears an identity's sessions and signs in again.
- Either may be an entry of an Operation List.
- Every count is of distinct platforms: many sessions on one platform still
  count once toward the threshold.

### App lists

`WalletRegistry.setAppList(identity, apps)` sets, for the calling wallet,
the apps whose logins may add or remove the identity's sessions: each entry
is `keccak256(clientIdentifier)`. An empty list, the default, accepts any
app. The registry is an admin target, so the wallet sets a list at quorum. A
removal by login leaves the list. Client ids are public: a
list stops apps on other domains, not someone holding the user's live
browser login. A migration starts with no list.

## A lost wallet

A wallet an attacker holds at quorum is lost. The way out is a new wallet for
the same genesis at a new salt; anyone can create it, and only a login of the
genesis can give it its first session. The client:

1. picks the lowest salt whose wallet never had a session
   (`validator.hadSession(factory.walletAddress(platformId, idNode, salt))`);
2. onboards it with the genesis's own `linkIdentity`;
3. relinks the other platforms, and sets the app lists and the threshold;
4. binds each handle again with a fresh login: a bind gives the handle to
   the newest proof's holder, and `HandleEscrow` pays only the current one.

Find a user's current wallet as the identity's `IdentityRegistry` holder, not
by scanning salts. Funds sent to the old address stay there; send by handle.
`genesisIdentity(wallet)` returns the salt beside the genesis.

## Execution

One `execute(bytes32 mode, bytes data)`, ERC-7579's, takes two kinds of mode:

- A default mode (selector 0, single or batch, no delegatecall): from the
  EntryPoint only, whose validation already checked the operation. Not from
  the wallet itself either.
  Validation refuses a batch that is not exactly `abi.encode(Execution[])`
  of the calls it decodes to.
- `AUTHORIZED_MODE`, exactly the word of batch call type, default exec type,
  selector `bytes4(keccak256("libid.webwallet.authorized"))` and zero
  payload: from anyone. `data` is
  `abi.encode(bytes executionCalldata, uint256 value, uint48 deadline, uint256 callGas, bytes authorization)`,
  with `authorization = abi.encode(Authorization)`. The wallet:
  1. requires `executionCalldata` to be exactly `abi.encode(Execution[])`
     of the calls it decodes to, else `NoncanonicalBatch`: the signers sign
     those bytes alone, so no call may be read from outside them;
  2. requires `msg.value == value`, else `WrongValue`;
  3. consumes the EntryPoint nonce under key
     `uint192(uint160(validator)) << 32`, which UserOperations share;
  4. reads `threshold(wallet)` and its own EIP-712 domain separator;
  5. runs the batch, requiring before each call `gasleft() * 63 / 64` of at
     least `callGas` plus `CALL_OVERHEAD` (`IWebWallet.sol`), so every call
     gets at least `callGas` (EIP-150 forwards at most 63/64 of the gas
     left), else `InsufficientCallGas`. `CALL_OVERHEAD` is checked for
     calls of up to 64 KiB of call data; a larger call may get a little less;
  6. calls the validator's
     `checkExecution(mode, executionCalldata, value, deadline, callGas, authorization, nonce, threshold, domainSeparator)`,
     with the domain separator it read before the batch.

  Any failure reverts everything, the nonce included. So a failed batch
  stays valid until its deadline. Signing another batch at the same nonce
  does not cancel it: only a batch or UserOperation that uses the nonce, or
  the deadline passing, does.

Any other mode reverts: `UnsupportedModeSelector` from the EntryPoint,
`AccountUnauthorized` from anyone else. EntryPoint validation refuses every
non-zero selector, `AUTHORIZED_MODE` included. One reentrancy lock covers
both modes, so a batch cannot call the wallet's `execute`.
`supportsExecutionMode` is true for the default single and batch modes and
for `AUTHORIZED_MODE`.

Signers sign the EIP-712 hash of
`Execute(bytes32 mode,bytes executionCalldata,uint256 value,uint48 at,uint256 nonce,uint48 deadline,uint256 callGas)`
under the wallet's EIP-712 domain before the batch (name `WebWallet`,
version `1`, the chain id and the wallet's address), with `mode = AUTHORIZED_MODE`,
`at = Authorization.at` and `nonce` the full EntryPoint nonce before it was
consumed. Below quorum each signs
`keccak256(abi.encode(hash, at, keccak256(governingKey)))`, as for a
UserOperation. `checkExecution` requires `deadline` nonzero and not passed,
runs the signer and rule checks of `validateUserOp` at the threshold read on
entry, charges value to `NATIVE_TOKEN` below quorum (no gas charge, no
paymaster), then requires the block time inside the signers' window narrowed
to the periods charged. Its errors are `ExecutionExpired`,
`ExecutionNotSigned`, `ExecutionNotAllowed` and `ExecutionOutsideWindow`.

The check reads the threshold, the nonce and the domain from before the
calls, and the sessions as the calls left them. A batch that executes
`setThreshold`, revokes a signer or migrates the validator does not help its
own check; one that revokes or unlinks its own signer cannot pass it. One
that upgrades the wallet is checked under the domain its signers signed.

The direct path needs EntryPoint v0.9 deployed at its canonical address:
the nonce lives there. Without it the direct path reverts
`EntryPointMissing(entryPoint)`.

## Signatures

- A session key is an ERC-7913 signer: a 20-byte address, recovered with
  ECDSA, or `verifier || key`.
- `userOp.signature` is `abi.encode(IIdentityValidator.Authorization)`. Its
  signatures are over the EntryPoint's `userOpHash`; below quorum, each is
  over `keccak256(abi.encode(userOpHash, at, keccak256(governingKey)))`, where
  the governing key is the first signature's. Reordering the signatures
  changes which session governs, so it invalidates them.
- An ERC-1271 signature is the validator's address followed by an ERC-7739
  nested signature under the wallet's `eip712Domain()`: `PersonalSign`, or
  `TypedDataSign` followed by the app separator, contents hash and contents
  type. Its signature part is `abi.encode(Authorization)`, of which only
  `signatures` and `domainProof` are read. Signers sign inside their window;
  below quorum each signs the nested hash bound as above, with `at` 0.
- `isValidSignature(0x7739…7739, "")` answers `0x77390001` (ERC-7739
  detection).
- A proof's transaction data, for the link and add-session domains, is
  `abi.encode(uint256 chainId, address wallet, bytes sessionKey, bytes32 policyHash)`,
  canonically encoded, with `policyHash = policyHashOf(policy)`. An empty key
  with a zero policy hash links only. Under `libid.operations` the proof's
  Operation List commits `keccak256` of these bytes in a `libid.webwallet.*`
  entry, and the call passes them as `data`; a proof of one operation passes
  empty `data`.

## Sessions below quorum

Admin sessions of `threshold` distinct platforms are unrestricted. Below it
the first signature's session governs. Its policy's `signers` (0 counts as 1)
is how many signatures the operation takes, each from a different platform,
its own included. Every signer is a live session of the wallet, admin or
not, and above threshold 1 none is a session by login. Only the governing
session's `Rules` apply; the other signers' windows still narrow the
operation's. Below quorum
nothing is accepted for an admin operation, and:

- An operation has at least one execution.
- Every execution needs `calls[i]`, a proof of the leaf
  `(target, selector, calls[i].maxValue)` under `scopeRoot`, with
  `value <= maxValue`. `scopeRoot == 0` allows no call.
- Native `value` is charged to `NATIVE_TOKEN` (0xEeee…EEeE). With no entry
  its limit is 0.
- ERC-20 `transfer(to, amount)` and `approve(spender, amount)` charge
  `amount` to the target. `transferFrom`, a spending selector on a target
  with no allowance, and any other selector on a target with one are
  refused. Any other selector on a target with no allowance is charged
  nothing: ERC-721 `safeTransferFrom` and `setApprovalForAll` in scope pass,
  while ERC-721 `approve` and `transferFrom` share ERC-20's selectors.
- ERC-1271 accepts only `TypedDataSign`, with the app separator proved under
  `domainsRoot`.

### Leaves

Leaves are OpenZeppelin double-hashed,
`keccak256(bytes.concat(keccak256(abi.encode(...))))`, under sorted-pair
roots:

| Root | Leaf |
|---|---|
| `scopeRoot` | `(address target, bytes4 selector, uint256 maxValue)` |
| `domainsRoot` | `(bytes32 appSeparator)` |
| `paymastersRoot` | `(address paymaster)` |

Calldata shorter than four bytes has selector `0x00000000`. A `0x00000000`
leaf is the fallback and plain-send leaf: it matches empty calldata, 1–3
bytes, and calldata starting `0x00000000`.

### Gas

An operation with a paymaster needs `paymasterProof`, a proof of the
paymaster under `paymastersRoot`, and is charged no gas.
`paymastersRoot == 0` allows no paymaster. Without one, the operation's
maximum gas cost,
`(verificationGasLimit + callGasLimit + preVerificationGas) * maxFeePerGas`,
is charged to `NATIVE_TOKEN` with its value.

### Allowances and `at`

- Allowances are listed by strictly ascending token address, each with a
  `period` below 2^47; otherwise adding the session reverts `BadAllowance`.
- Allowances are charged in validation, even when the execution reverts.
- The period is `at - at % period`, or the session's whole life when
  `period == 0`. A charging operation's validity window is that period
  intersected with the session's.
- A charge needs `at != 0` and, under a nonzero period, a period ending
  below 2^47. An operation charging nothing ignores `at`.
- Counters are keyed by `(key, rulesHash, token)`: a key re-added with the
  same rules keeps its spend.
- Choosing `at`: the block time when signing. A charging operation's
  `validUntil` is its period's end, and bundlers such as Rundler refuse an
  operation within about 60 s of its `validUntil`. In a period's last
  minute, wait for the next period and sign then.

## Bundlers

- Validation reads no clock and touches only slots keyed by the account
  (ERC-7562). The rule checks run in `SessionRules` through DELEGATECALL, so
  they read and write the validator's own slots. Session windows go back to the EntryPoint packed in the
  validation data, so a bundler drops an operation outside them.
- A policy bound at bit 47 or above is refused when the session is added:
  EntryPoint v0.9 reads that bit as a block-number flag.
- `WalletFactory` cannot serve as `initCode`: ERC-7562 [OP-031] lets the one
  CREATE2 of deployment deploy only the sender, and `Create3` deploys an
  intermediate proxy. Create wallets with a plain transaction.

## Install data and validator migration

- Install data has one layout,
  `abi.encode(bytes32 platformId, bytes32 idNode, uint256 salt, bytes key, Policy policy)`.
  The factory installs with an empty key: the genesis identity, linked by
  the install, and no session. It cannot be unlinked. The validator
  installs only on the factory's wallet of that genesis and salt.
- The validator cannot be uninstalled, and a wallet installs only the
  validator its implementation names. A fix to the validator therefore
  arrives as one root operation of the old validator,
  `upgradeToAndCall(newImplementation, abi.encodeCall(IWebWallet.migrate, (data)))`
  with `data = abi.encode(platformId, idNode, salt, key, policy)`: the wallet's
  admin session, added by the install and signing from the next second. That
  sets `hadSession`, so the new install never takes a first session.
  `migrate` reverts `MigrationWithoutSession` when the data adds none. The
  carried session must be admin.
- `migrate` installs the new implementation's validator. It is a
  `reinitializer` that only an installed validator may call, so it runs
  once, inside the upgrade; an implementation that migrates again raises its
  version.
- `platformId`, `idNode` and `salt` in that data must be the wallet's: every
  install reverts `NotFactoryWallet` unless the wallet is
  `walletFactory().walletAddress(platformId, idNode, salt)`, so a migration
  cannot rename the genesis.
- A migration is a fresh install: links, sessions and the root delay start
  empty. The user relinks platforms and sets app lists again at quorum.
- `upgradeToAndCall` goes only to the factory's `walletImplementation()` when
  it executes, and reverts `NotFactoryImplementation` otherwise.
- After the upgrade the old validator stays installed but keeps no power:
  the wallet accepts UserOperations, ERC-1271 signatures, module changes and
  upgrades only from the validator its implementation names. Root operations
  queued on the old validator, before or after the migration, and executed
  after it gain nothing:
  - `installModule`, `uninstallModule` and `upgradeToAndCall` revert
    `NotValidator`;
  - `migrate` reverts `InvalidInitialization`: the wallet already ran it;
  - the old validator's own operations, such as `setThreshold` or
    `revokeSession`, run, but change only that validator's records.

## Deployment

`IdentityValidator` learns the factory without an owner. Its constructor
takes the address of the `WalletFactory` proxy, which does not exist yet:
the proxy is deployed later under a `LibidFactory` name, whose address
`LibidFactory.predict(name)` gives in advance. The order is:

1. `WalletRegistry(proofVerifier, libidFactory.predict("WalletFactory"))`,
   which deploys the `IdentityValidator`, which deploys `IdentityAdmin` and
   `SessionRules`;
2. `WebWallet(registry.identityValidator())`;
3. `WalletFactory(walletImplementation)`;
4. `libidFactory.deploy("WalletFactory", proxyCreationCode)`, the proxy
   initialized with its owner.

Check `validator.walletFactory() == factory` after step 4: with any other
address, every wallet creation reverts.

## Root operations

Install, uninstall, upgrade, `setThreshold`, `unlink`,
revoking the last admin session and changing the root delay are queued
with `queueRoot` and executed by anyone with `executeRoot` once
`rootDelay` has passed, and never in the second they were queued:
`readyAt = now + max(rootDelay, 1)`, so no batch queues and executes one.
The root delay is 0 by default, at most 365 days, and set only by
`setRootDelay` as a root operation, so a raise too waits the current delay.
Revoking an active admin session, unlinking an identity or removing its
sessions by login voids every root operation queued before it.

`setThreshold` and a revoke that would leave the threshold above the
platforms holding an admin session revert `ThresholdTooHigh`, unless they
leave none. An unlink instead lowers the threshold to the platforms still
linked, and may leave no admin session. An admin session never
expires: a policy with `admin` and a non-zero `validUntil` reverts
`AdminSessionExpires`.

## Trust

A wallet trusts the parties below, with no timelock, until libID and the
registry are decentralized. Each of the first three can make a login proof
valid, and so give a wallet a session that signs from the next second.

- **The proof verifiers' owners.** `WalletRegistry` trusts the
  `CeremonyProofVerifier` proxy, whose owner can `setVerifier` and upgrade
  it, and so route a platform to a verifier that accepts any proof. Each
  Platform Verifier's owner can upgrade it or change its trust roots
  (`setTrustRoots`, and `setJwtRoots` for Google and Telegram).
- **The notary signing keys.** A notary signature makes a login proof valid
  on X, GitHub, Google and Telegram alike: X and GitHub proofs carry
  notarized sessions, and the Google and Telegram keys come from notarized
  readings. `NotaryService`'s owner chooses the keys (`setNotary`) and can
  upgrade it.
- **The JWT-root owners.** The owners of `GoogleJwtRoots` and
  `TelegramJwtRoots` choose which Notary Service their readings must come
  from (`setNotaryService`), and can upgrade them.
- **The factory's owner** upgrades `WalletFactory`, and so chooses the code
  of every wallet not yet created, funds already sent to its address
  included. Wallets already created keep theirs: the owner names the only
  implementation they may upgrade to, but an upgrade takes the wallet's own
  root operation. The owner can block upgrades by moving the factory on. The
  validator's genesis check asks the factory's `walletAddress`, so it is only
  as sound as that owner.

## Accepted risks

- Any app that receives a proof of the genesis identity naming its own key,
  from any OAuth client, can give a wallet that never had a session its first
  session, and so control it.
- Below quorum, a listed app domain whose typed data moves value (EIP-2612
  `permit`, Permit2, Seaport, CoW, 1inch orders) lets the session sign it
  past its allowances.
- Below quorum, spending through a selector the allowances do not parse,
  such as a router pulling a standing approval, is bounded only by the
  scope.
- Re-adding a key with a different rules hash starts its counters fresh.
  Adding a session is an admin operation.
- A phished login of a linked identity, from an app its list admits,
  removes its sessions and voids the owner's queued root operations; the
  owner queues them again.
- At k of n, the wallet stays the user's until k platforms are phished, and
  a login removal can unlink all but the genesis. Keep the threshold at most
  the number of platforms minus 1, so a lost genesis still leaves a quorum.
- The JWT roots cannot drop a leaked key at once, and `WalletRegistry` has no
  pause: during a leak anyone could add sessions to every wallet with a
  linked identity on that platform (not exercised: it needs a leaked key).
- `entryPoint()` is fixed to v0.9: a later EntryPoint costs one root upgrade
  per wallet.
- Direct batches of every signer share one nonce sequence, under key
  `uint192(uint160(validator)) << 32`. A limited session can submit its own
  in-scope batch at the current nonce and so void an admin's signed direct
  batch, again and again, at almost no cost: the direct path charges no gas.
  No funds or control are at risk. The admin can send a UserOperation under
  another nonce key of the validator, or revoke the session.
- An ERC-7913 verifier used for a session key must not read state the
  wallet can write: the direct path asks the verifier after the batch ran.
  OpenZeppelin's `ERC7913WebAuthnVerifier` is stateless.
- A token paymaster the session lists takes its fee outside the
  allowances.
- Approvals a session made outlive its revocation.
- Sessions cannot be listed from storage. Watch `SessionAddedByLogin`,
  `SessionsRemovedByLogin` and `RootQueued` to alert the owner: the
  root-operation wait protects only an owner who is told.

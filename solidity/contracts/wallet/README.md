# WebWallet

An ERC-7579 account per platform identity, at an address fixed by that
identity. Sessions are ERC-7913 keys added by proof or by the wallet itself.
Each function's behaviour and reverts are in the NatSpec of the `I*.sol`
interfaces beside this file.

| Contract | Role | Upgrade |
|---|---|---|
| `WalletFactory` | Deploys wallets with `Create3`, `salt = identityOf(platformId, idNode)` | UUPS, owner |
| `WebWallet` | The account (OpenZeppelin v5.7.0, EntryPoint v0.9) | UUPS, by the wallet's own root operation |
| `IdentityValidator` | Identities, sessions, threshold and root operations of every wallet | none |
| `WalletRegistry` | Turns a `libid.webwallet.*` proof into a link or a session | none |
| `ClaimExecutor` | Binds a wallet's identity and claims its escrow, for anyone | none |

## The claim

The wallet links its genesis identity when it is created, so a claim takes one
proof, a `bind-identity` proof naming the wallet:

```solidity
address w = factory.createWallet(platformId, idNode);               // anyone; returns w if it exists
executor.bind{value: identities.quoteBind(platformId, v)}(w, platformId, v, bindPayload);
executor.claimToSelf(w, handleNode, tokens);                         // pays the wallet, whoever sends it
```

- `createWallet` returns the existing wallet when called again, so a wallet
  created first by someone else does not stop a claim.
- `bind` and `claimToSelf` are not idempotent: a bind proof or an escrow
  claim applied first by someone else reverts the relayer's transaction.
  Either way the outcome is the same wallet bound and paid. A relayer that
  batches the three calls should let each fail on its own.
- The claim adds no session. The first session comes from a
  `link-identity` proof of the genesis identity, or an `add-session` proof:
  while the wallet never had a session, either is active at once.

## Signatures

- A session key is an ERC-7913 signer: a 20-byte address, recovered with
  ECDSA, or `verifier || key`.
- `userOp.signature` is `abi.encode(IIdentityValidator.SessionSignature[])`
  over the EntryPoint's `userOpHash`.
- An ERC-1271 signature is the validator's address followed by an ERC-7739
  nested signature under the wallet's `eip712Domain()`: `PersonalSign`, or
  `TypedDataSign` followed by the app separator, contents hash and contents
  type. Its signature part is `abi.encode(SessionSignature[])`. Only admin
  sessions sign, inside their window.
- `isValidSignature(0x7739…7739, "")` answers `0x77390001` (ERC-7739
  detection).
- A proof's transaction data, for both `libid.webwallet.*` domains, is
  `abi.encode(uint256 chainId, address wallet, bytes sessionKey, bytes32 policyHash)`,
  canonically encoded, with `policyHash = policyHashOf(policy)`. An empty key
  with a zero policy hash links only.

## Bundlers

- Validation reads no clock and touches only slots keyed by the account
  (ERC-7562). Session windows go back to the EntryPoint packed in the
  validation data, so a bundler drops an operation outside them.
- A policy bound at bit 47 or above is refused when the session is added:
  EntryPoint v0.9 reads that bit as a block-number flag.
- `WalletFactory` cannot serve as `initCode`: ERC-7562 [OP-031] lets the one
  CREATE2 of deployment deploy only the sender, and `Create3` deploys an
  intermediate proxy. Create wallets with a plain transaction.

## Install data and validator migration

- The factory installs the validator with `abi.encode(platformId, idNode)`:
  the genesis identity, linked by the install. It cannot be unlinked.
- The validator cannot be uninstalled, and a wallet installs only the
  validator its implementation names. A fix to the validator therefore
  arrives as one root operation of the old validator,
  `upgradeToAndCall(newImplementation, abi.encodeCall(IWebWallet.migrate, (data)))`
  with `data = abi.encode(platformId, idNode, key, policy)`: the wallet's
  admin session, added by the install. That sets `hadSession`, so nobody can
  take the new install with a first proof. The carried session must be admin.
- `migrate` installs the new implementation's validator, and its executor
  unless installed. It is a `reinitializer` that only an installed validator
  may call, so it runs once, inside the upgrade; an implementation that
  migrates again raises its version.
- `platformId` and `idNode` in that data must be the wallet's current
  genesis identity, `genesisIdentity(wallet)` on the old validator. The new
  validator cannot check it: it knows neither the old validator nor the
  factory. Getting it right is the migrating owner's responsibility.
- After the upgrade the old validator stays installed but keeps no power:
  the wallet accepts UserOperations, ERC-1271 signatures, module changes and
  upgrades only from the validator its implementation names. Root operations
  queued on the old validator, before or after the migration, revert
  `NotValidator`.

## Root operations

Install, uninstall, upgrade, `setThreshold`, `unlink`, `setRecoveryFrozen`,
revoking the last admin session and lowering the recovery delay are queued
with `queueRoot` and executed by anyone with `executeRoot` once
`recoveryDelay` (48 h to 365 days) has passed. Revoking an active admin
session, or unlinking an identity, voids every root operation queued before
it.

## Trust

- **The proof verifier's owner.** `WalletRegistry` trusts the
  `CeremonyProofVerifier` proxy, whose `setVerifier` and upgrade are
  owner-only. That owner can route a platform to a verifier that accepts any
  proof: an active session on every wallet that never had one, and a session
  live after the delay on every other. Before wallets hold funds, that owner
  belongs behind a Safe and a timelock longer than `MIN_RECOVERY_DELAY`.
- **The factory's owner** upgrades `WalletFactory`, and so chooses the code
  of every wallet not yet created, funds already sent to its address
  included. Wallets already created keep theirs. Before launch it belongs
  behind a Safe and a timelock.
- **A first proof.** While a wallet never had a session, a genesis link proof
  from any OAuth client adds an active session. An app that ran "Sign in"
  for the identity holds such a proof.

## Accepted risks

- A newer session added by proof for the same identity replaces the pending
  one, so a holder of a phished proof can restart the owner's recovery
  clock as often as it can mint proofs. Only an owner who still holds an
  active admin session can stop it, by freezing the identity's recovery.
- The JWT roots cannot drop a leaked key at once, and `WalletRegistry` has no
  pause: during a leak anyone could add pending sessions to every wallet with
  a linked identity on that platform (not exercised: it needs a leaked key).
- `entryPoint()` is fixed to v0.9: a later EntryPoint costs one root upgrade
  per wallet.
- Sessions cannot be listed from storage. Watch `SessionAddedByProof` and
  `RootQueued` to alert the owner: every wait protects only an owner who is
  told.

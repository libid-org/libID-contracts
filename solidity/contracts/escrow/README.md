# HandleEscrow

Send value to an X or GitHub handle or a Google account's email address before
its holder has proved it in `IdentityRegistry`. The address that proves the
handle claims it. Until then each sender can take its own contribution back
once its refund date has come. A handle somebody already holds is paid
straight through. Each function's behaviour and reverts are in the NatSpec of
`HandleEscrow.sol`.

```solidity
escrow.deposit{value: amount}(platformId, handleNode, escrow.NATIVE(), amount);
escrow.claim(handleNode, tokens, recipient);   // the handle's holder
escrow.refund(handleNode, token, recipient);   // the sender, from refundableAt, while unclaimed
```

## Who owns a deposit

- A deposit belongs to `msg.sender`, the only address that can refund it, to
  any recipient it names. The paying account controls its refund.
- Deposits made through a contract anyone can call (Multicall3, a public
  router or forwarder) share that contract's contribution. Anyone who can
  make that contract call `refund` can take them, and anyone can keep them
  locked indefinitely with a small deposit through it before each
  `REFUND_GRACE` ends.
- A contract that pays for several users holds one contribution for all of
  them. It must track and pass on refunds itself, and one user's top-up
  re-locks the whole contribution.

## Refund dates

- A contribution is refundable from its `refundableAt`. A refund before then
  reverts `RefundLocked(handleNode, token, sender, refundableAt)`.
- Each deposit sets its sender's `refundableAt` to `REFUND_GRACE` (30 days)
  from now, for the sender's whole contribution to that handle and token. A
  top-up re-locks what the sender already has there.
- Only the sender's own deposits move its date, so a deposit stays claimable
  for at least `REFUND_GRACE`.
- `contribution(handleNode, token, sender)` returns the amount and
  `refundableAt`.
- A claim takes everything held and ends every sender's contribution to that
  handle and token. A later deposit starts afresh.

## Private or public

- `deposit(platformId, handleNode, …)` keeps the handle out of the calldata
  and the logs. The calldata names the platform.
- `depositToHandle(platformId, handle, …)` puts the handle in the calldata,
  and `HandleRevealed`, the event every libid contract writes for handle
  text, logs it folded. It credits the same node, so one
  claim takes both kinds. Text other than the handle as the platform sends it
  (`@alice`, a space) lands on a node nobody can prove; only its sender gets
  it back, from its `refundableAt` like any deposit. The same holds for a
  mistyped node and for one on a platform that stops binding.

## Integrating

- `NATIVE`, the EIP-7528 address `0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE`,
  names the chain's own coin in calls and events. Any other token without
  code reverts `BadToken`.
- `handleNode` is `SHA256(handle tag || folded handle)`, the node the
  platform's circuit binds. Compute it locally with `handleNode` from
  `@libid/contracts/platforms` or `handle_node` from `libid-identity`;
  `IdentityRegistry.handleNodeOf` over RPC sends the handle to the provider.
- A refund and a claim race once the refund date has passed: escrowed value
  is refundable until claimed, and refunds work whatever the platform's state.
- `Deposited`, `Claimed` and `Refunded` name their round. A claim closes its
  round, so a `Refunded` belongs to the `Deposited` of its round and a
  `Claimed` took what that round still held. Only `HandleRevealed` names a
  platform: otherwise join on the node with `IdentityRegistry.IdentityBound`.
- Pay-through goes to whoever holds the handle when the transaction lands,
  recycled handles included, and a forward cannot be refunded. A holder that
  rejects ETH cannot be paid in ETH; a holder contract can burn its payers'
  gas.
- Each token is one pool. After a negative rebase the last withdrawal in that
  token fails. A token that charges its sender on `transfer` deposits but
  never pays out: every claim and refund reverts `OverDebited` until an
  upgrade. A token that blocklists the escrow freezes its slots. Value sent
  outside `deposit` is never swept.
- Indexers should allow-list tokens: anyone can emit `Deposited` for a token
  they wrote.

## Deploying

- `initialize` reverts `RegistryNotNodeKeyed` unless the registry's
  `nodeKeyed()` returns true, and reverts on the call against a registry
  without it.
- The registry is fixed at `initialize`, with no setter. Deploy the escrow
  once the registry has its final address; only an upgrade moves it.

## Privacy and trust

A node keeps the handle text out of the sender's calldata, but it is an
unsalted tagged SHA-256, so anyone can test a guess against it. The bind's
attestation makes the id's and the handle's byte lengths public. GitHub ids
are sequential, so a GitHub id node is in effect public. A claim reveals
nothing more: the binding is keyed by the same node. A binding that publishes
no handle keeps it undisclosed, not unlinkable: every use of a node links to
every other.

Claims follow `handleBinding`, so every key that can change its answer can
take escrowed value through an ordinary binding: the owners of
`IdentityRegistry`, `CeremonyProofVerifier`, `NotaryService`, the Platform
Verifiers and `GoogleJwtRoots`, the trusted notary keys, and the platforms
themselves. The escrow's owner can upgrade it.

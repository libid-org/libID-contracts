# HandleEscrow

Send value to an X or GitHub handle or a Google account address before its
holder has proved it in `IdentityRegistry`. The address that proves the handle
claims it; until then each deposit's `refundTo` can take its own contribution
back. A handle somebody already holds is paid straight through. Each
function's behaviour and reverts are in the NatSpec of `HandleEscrow.sol`.

```solidity
escrow.deposit{value: amount}(platformId, handleNode, escrow.NATIVE(), amount, refundTo);
escrow.claim(handleNode, tokens, recipient);   // the handle's holder
escrow.refund(handleNode, token, recipient);   // refundTo, while unclaimed
```

## Private or public

- `deposit(platformId, handleNode, …)` keeps the handle out of the calldata
  and the logs. The calldata names the platform.
- `depositToHandle(platformId, handle, …)` puts the handle in the calldata,
  and `DepositedToHandle` logs it folded. It credits the same node, so one
  claim takes both kinds. Text other than the handle as the platform sends it
  (`@alice`, a space) lands on a node nobody can prove; only `refundTo` gets
  it back.

## Integrating

- `refundTo` is the payer's own address. A router passing itself locks the
  refund.
- `NATIVE`, the EIP-7528 address `0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE`,
  names the chain's own coin in calls and events. Any other token without
  code reverts `BadToken`.
- `handleNode` is `SHA256(handle tag || folded handle)`, the node the
  platform's circuit binds. Compute it locally with `handleNode` from
  `@libid/contracts` or `handle_node` from `libid-identity`;
  `IdentityRegistry.handleNodeOf` over RPC sends the handle to the provider.
- A refund and a claim race: escrowed value is refundable until claimed, and
  refunds work whatever the platform's state.
- `Deposited`, `Claimed` and `Refunded` name their round. A claim closes its
  round, so a `Refunded` belongs to the `Deposited` of its round and a
  `Claimed` took what that round still held. Only `DepositedToHandle` names a
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

- `initialize` reverts `RegistryLacks` unless the registry answers the
  `IIdentityRegistry` views in shape and `nodeKeyed()` returns true.
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

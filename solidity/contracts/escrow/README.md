# HandleEscrow

Send value to an X or GitHub handle or a Gmail address before its holder has
proved it in `IdentityRegistry`. The address that proves the handle claims it;
until then each deposit's `refundTo` can take its own contribution back. A
handle somebody already holds is paid straight through.

```solidity
escrow.deposit{value: amount}(handleNode, escrow.NATIVE(), amount, refundTo);
escrow.claim(handleNode, tokens, recipient);   // the handle's holder
escrow.refund(handleNode, token, recipient);   // refundTo, while unclaimed
```

## Integrating

- `refundTo` is the payer's own address. A router passing itself locks the
  refund.
- `NATIVE`, the EIP-7528 address `0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE`,
  names the chain's own coin in `deposit`, `claim`, `refund` and every event.
- `handleNode` is `SHA256(handle tag || normalized handle)`, the node the
  platform's circuit binds the handle under. Compute it locally with
  `@libid/contracts` or `libid-identity` (`handleNode`);
  `IdentityRegistry.handleNodeOf` over RPC sends the handle to the provider. A
  wrong node funds a slot only `refundTo` can recover.
- Escrowed value is refundable until claimed; a refund and a claim race.
- `Deposited`, `Claimed` and `Refunded` name their round. A claim closes the
  round it names and the next deposit opens the next, so a `Refunded` belongs
  to the `Deposited` of its round and a `Claimed` took what that round still
  held. No escrow event names a platform: join on the node with
  `IdentityRegistry.IdentityBound`, or recompute it from a known handle.
- Pay-through goes to whoever holds the handle when the transaction lands,
  recycled handles included. Show `handleBinding(node).observedAt` first. A
  holder that rejects ETH cannot be paid in ETH; a holder contract can burn
  its payers' gas.
- Each token is one pool. Rebasing tokens are unsupported: after a negative
  rebase the last withdrawal in that token fails. A token that charges its
  sender on `transfer` deposits but never pays out: every claim and refund
  reverts `OverDebited`, and only an upgrade can release it. A token that
  blocklists the escrow freezes its slots; value sent outside `deposit` is
  never swept.
- Refunds work whatever the platform's state. A node on a platform that no
  longer binds escrows like any other and can only be refunded.
- Indexers should allow-list tokens: anyone can emit `Deposited` for a token
  they wrote.

## Deploying

- `initialize` reverts `RegistryLacks` unless the registry answers
  `handleBinding`, and `nodeKeyed()` with true, which only the registry that
  keys identities by node does. The escrow is deployed against that registry;
  one deployed against the registry before it is not upgraded onto it.
- The escrow keeps that `IdentityRegistry` for life. There is no setter, so no
  key can point claims elsewhere; deploy the escrow once the registry sits at
  its final address, and move it later only by upgrade.

## Privacy and trust

A node keeps the handle text out of the sender's calldata, but it is an
unsalted tagged SHA-256, so anyone can test a guess against it. The bind's
attestation also makes the id's and the handle's byte lengths public, in its
commitment offsets. GitHub ids are sequential, so a GitHub id node is in effect
public. Claiming adds nothing: the holder's binding is keyed by the same node.
A binding that publishes no handle keeps it undisclosed, not unlinkable: every
use of a node links to every other.

Every key that can change what `handleBinding` answers can take escrowed value
through an ordinary identity binding: the `IdentityRegistry`,
`CeremonyProofVerifier`, `NotaryService`, Platform Verifier and
`GoogleJwtRoots` owners, the trusted notary keys, and the platforms
themselves. The escrow's owner can upgrade it.

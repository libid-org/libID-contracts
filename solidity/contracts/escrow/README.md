# HandleEscrow

Send value to an X or GitHub handle or a Gmail address before its holder has
proved it in `IdentityRegistry`. The address that proves the handle claims it;
until then each deposit's `refundTo` can take its own contribution back. A
handle somebody already holds is paid straight through.

```solidity
escrow.deposit{value: amount}(platformId, handleHash, escrow.NATIVE(), amount, refundTo);
escrow.claim(handleNode, tokens, recipient);   // the handle's holder
escrow.refund(handleNode, token, recipient);   // refundTo, while unclaimed
```

## Integrating

- `refundTo` is the payer's own address. A router passing itself locks the
  refund.
- `NATIVE`, the EIP-7528 address `0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE`,
  names the chain's own coin in `deposit`, `claim`, `refund` and every event.
- `handleHash` is `keccak256` of the handle normalized under the chain's
  current rules (`IdentityRegistry.rulesOf`). Hash locally: `handleHashOf` over
  RPC sends the handle to the provider. A wrong hash funds a slot only
  `refundTo` can recover. Take `handleNode` from `Deposited`.
- Escrowed value is refundable until claimed; a refund and a claim race.
- `Deposited`, `Claimed` and `Refunded` name their round. A claim closes the
  round it names and the next deposit opens the next, so a `Refunded` belongs
  to the `Deposited` of its round and a `Claimed` took what that round still
  held. `Claimed` and `Refunded` name no platform: join on the node with
  `Deposited` or `IdentityRegistry.IdentityBound`.
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
- Refunds work whatever the platform's rules or `acceptsBindings` say.
- Indexers should allow-list tokens: anyone can emit `Deposited` for a token
  they wrote.

## Deploying

- Upgrade the deployed `IdentityRegistry` first: `initialize` reverts
  `RegistryLacks` unless it answers `handleBinding`, `acceptsBindings` and
  `handleNodeOfHash`.
- The escrow keeps that `IdentityRegistry` for life. There is no setter, so no
  key can point claims elsewhere; deploy the escrow once the registry sits at
  its final address, and move it later only by upgrade.

## Privacy and trust

A hash keeps the handle out of the sender's calldata but is not secret: anyone
can hash a guess. A Google recipient claims through today's Google profile,
which puts the email on chain in plaintext.

Every key that can change what `handleBinding` answers can take escrowed value
through an ordinary identity binding: the `IdentityRegistry`,
`CeremonyProofVerifier`, `NotaryService`, Platform Verifier and
`GoogleJwtRoots` owners, the trusted notary keys, and the platforms
themselves. The escrow's owner can upgrade it.

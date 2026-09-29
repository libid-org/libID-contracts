# HandleEscrow

Send value to an X or GitHub handle or a Gmail address before its owner has
proved it in `IdentityNames`. The wallet that proves the handle claims it;
until then each deposit's `refundTo` can take its own contribution back. A
handle somebody already holds is paid straight through.

```solidity
escrow.deposit{value: amount}(platformId, handleHash, escrow.NATIVE(), amount, refundTo, expectedHolder);
escrow.claim(handleNode, tokens, recipient);   // the handle's holder
escrow.refund(handleNode, token, recipient);   // refundTo, while unclaimed
```

## Integrating

- `NATIVE` is EIP-7528's `0xEeee…EEeE`; the zero address is refused as a token.
- `expectedHolder` is the holder the sender saw: zero accepts either branch,
  `UNHELD` only escrows, an address only pays that holder. Pass it: a handle
  that changes hands between signing and mining then reverts `UnexpectedHolder`
  instead of paying whoever holds it.
- `refundTo` is the end user. A router passing itself locks the refund.
- `handleHash` is `keccak256` of the handle normalized under the chain's
  current rules (`IdentityNames.rulesOf`). Hash locally: `handleHashOf` over
  RPC sends the handle to the provider. A wrong hash funds a slot only
  `refundTo` can recover. Take `handleNode` from `Deposited`.
- Escrowed value is refundable until claimed; a refund and a claim race.
- Events carry `platformId` and `round`, the round the value was booked in: a
  claim closes the round, and later deposits book into the next one.
- A holder that rejects ETH cannot be paid in ETH; a holder contract can burn
  its payers' gas.
- Each token is one pool. Unsupported, with value frozen rather than moved to
  another slot: rebasing tokens (after a negative rebase the last withdrawal
  fails), tokens charging their fee to the sender on top of the amount (every
  claim and refund reverts `OverDebited`), and tokens that blocklist the
  escrow. Value sent outside `deposit` is never swept.
- Refunds work whatever the platform's rules or `acceptsClaims` say.
- Indexers should allow-list tokens: anyone can emit `Deposited` for a token
  they wrote.

## Deployment

`names` is fixed at `initialize`, with no setter by design. Deploy the escrow
only once `IdentityNames` sits at its final canonical address (it has moved
once, to `libid.IdentityNames.2`). If it moves again, the escrow needs an
upgrade with a reinitializer.

## Privacy and trust

A hash keeps the handle out of the sender's calldata but is not secret: anyone
can hash a guess. A Google recipient claims through today's Google profile,
which puts the email on chain in plaintext.

Every key that can change what `byHandle` answers can take escrowed value
through an ordinary identity claim: the `IdentityNames`,
`CeremonyProofVerifier`, `NotaryService`, Platform Verifier and
`GoogleJwtRoots` owners, the trusted notary keys, and the platforms
themselves. The escrow's owner can upgrade it.

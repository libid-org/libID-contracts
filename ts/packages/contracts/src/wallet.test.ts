import { keccak256, toHex } from 'viem'
import { describe, expect, it } from 'vitest'

import { belowQuorumHash, type SessionPolicy, policyHashOf, rulesHashOf } from './wallet.js'

// PolicyEncodingTest's vectors, which `cast` computes outside Solidity.
const POLICY: SessionPolicy = {
  validAfter: 10,
  validUntil: 20,
  admin: false,
  signers: 2,
  rules: {
    scopeRoot: keccak256(toHex('s')),
    domainsRoot: keccak256(toHex('d')),
    paymastersRoot: keccak256(toHex('p')),
    allowances: [
      { token: '0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE', amount: 10n ** 18n, period: 86_400 },
    ],
  },
}

describe('session-policy hashes', () => {
  it('match the Solidity vectors', () => {
    expect(rulesHashOf(POLICY.rules)).toBe(
      '0x91a60d66d4b51055570ae803ab60eeb97f5719221a31686eb83fba2cd2169b20',
    )
    expect(policyHashOf(POLICY)).toBe(
      '0xc51a04460ba256d1efcef52fde677904487eed95b705a198c65d40178196f7e8',
    )
    expect(belowQuorumHash(keccak256(toHex('op')), 1234)).toBe(
      '0x8c0f295ba05cf4321f217414c5e4fb63b06d09e3e32556f3c183b88ebac155a4',
    )
  })
})

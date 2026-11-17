import { keccak256, toHex } from 'viem'
import { describe, expect, it } from 'vitest'

import {
  belowQuorumHash,
  policyHashOf,
  rulesHashOf,
  type SessionPolicy,
  sortAllowances,
} from './wallet.js'

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
    expect(
      belowQuorumHash(keccak256(toHex('op')), 1234, '0x0000000000000000000000000000000000001234'),
    ).toBe('0xf63e6147bfa910f2dab04a6910a61fbf42066f204e2344c197c154c1b5a6e8dc')
  })
})

describe('allowances', () => {
  const rules = (...tokens: `0x${string}`[]) => ({
    ...POLICY.rules,
    allowances: tokens.map((token, i) => ({ token, amount: BigInt(i), period: 1 })),
  })
  // A < B as numbers, B < A as checksummed strings.
  const A = '0x00000000000000000000000000000000000000a0'
  const B = '0x00000000000000000000000000000000000000B0'

  it('sort by token', () => {
    const sorted = rules(A, B)
    const unsorted = { ...sorted, allowances: [...sorted.allowances].reverse() }
    const given = structuredClone(unsorted)
    expect(rulesHashOf(unsorted)).not.toBe(rulesHashOf(sorted))
    expect(unsorted).toEqual(given)
    expect(sortAllowances(unsorted)).toEqual(sorted)
    expect(unsorted).toEqual(given)
    expect(policyHashOf({ ...POLICY, rules: sortAllowances(unsorted) })).toBe(
      policyHashOf({ ...POLICY, rules: sorted }),
    )
  })
})

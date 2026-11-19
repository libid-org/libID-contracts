import { readFileSync } from 'node:fs'
import { type Address, type Hex, keccak256, toHex } from 'viem'
import { describe, expect, it } from 'vitest'

import {
  AUTHORIZED_MODE,
  authorizedData,
  belowQuorumHash,
  DIRECT_NONCE_KEY,
  EXECUTE_TYPES,
  encodeAuthorization,
  executeDigest,
  policyHashOf,
  rulesHashOf,
  type SessionPolicy,
  sortAllowances,
  userOperationDigest,
} from './wallet.js'

// WalletPolicyTest.test_hashesFollowTheSpec's vectors, which `cast` computes outside Solidity.
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
  })
})

// direct-execute-vector.json, written by `cast` alone; WalletAbiTest.test_theClientVector checks it too.
interface Vector {
  authorizedMode: Hex
  executeTypehash: Hex
  chainId: number
  wallet: Address
  version: number
  nonce: number
  executionCalldata: Hex
  value: number
  at: number
  deadline: number
  callGas: number
  sessionKey: Hex
  signature: Hex
  callMaxValue: number
  callProof: Hex
  domainProof: Hex
  paymasterProof: Hex
  authorizationHash: Hex
  dataHash: Hex
  digest: Hex
  belowQuorumHash: Hex
  userOpHash: Hex
  userOpDigest: Hex
}

const VECTOR = JSON.parse(
  readFileSync(
    new URL(
      '../../../../solidity/contracts/wallet/test/fixtures/direct-execute-vector.json',
      import.meta.url,
    ),
    'utf8',
  ),
) as Vector

describe('the client helpers', () => {
  it('match the vector', () => {
    const v = VECTOR
    expect(AUTHORIZED_MODE).toBe(v.authorizedMode)
    const type = `Execute(${EXECUTE_TYPES.Execute.map((f) => `${f.type} ${f.name}`).join(',')})`
    expect(keccak256(toHex(type))).toBe(v.executeTypehash)

    const message = {
      executionCalldata: v.executionCalldata,
      value: BigInt(v.value),
      at: v.at,
      // Nonce key 0: the full nonce is the sequence.
      nonce: (DIRECT_NONCE_KEY << 64n) | BigInt(v.nonce),
      deadline: v.deadline,
      callGas: BigInt(v.callGas),
    }
    const authorization = {
      signatures: [{ key: v.sessionKey, signature: v.signature }],
      calls: [{ maxValue: BigInt(v.callMaxValue), proof: [v.callProof] }],
      domainProof: [v.domainProof],
      paymasterProof: [v.paymasterProof],
    }
    expect(keccak256(encodeAuthorization({ ...authorization, at: v.at }))).toBe(v.authorizationHash)
    expect(keccak256(authorizedData(message, authorization))).toBe(v.dataHash)

    const digest = executeDigest(message, v.chainId, v.wallet, v.version)
    expect(digest).toBe(v.digest)
    expect(belowQuorumHash(digest, v.at, v.sessionKey)).toBe(v.belowQuorumHash)
    expect(userOperationDigest(v.userOpHash, v.chainId, v.wallet, v.version)).toBe(v.userOpDigest)
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
    expect(sortAllowances(unsorted)).toEqual(sorted)
    expect(unsorted).toEqual(given)
  })
})

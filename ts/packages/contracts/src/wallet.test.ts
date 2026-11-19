import { readFileSync } from 'node:fs'
import { type Address, type Hex, keccak256, toHex, zeroHash } from 'viem'
import { describe, expect, it } from 'vitest'

import {
  ADD_SESSION_DOMAIN,
  AUTHORIZED_MODE,
  authorizedData,
  belowQuorumHash,
  DIRECT_NONCE_KEY,
  EXECUTE_TYPES,
  encodeAuthorization,
  executeDigest,
  LINK_IDENTITY_DOMAIN,
  policyHashOf,
  REMOVE_SESSIONS_DOMAIN,
  rulesHashOf,
  type SessionPolicy,
  sortAllowances,
  userOperationDigest,
  walletSalt,
  walletTransactionData,
} from './wallet.js'

// WalletPolicyTest.test_hashesFollowTheSpec's vectors, which `cast` computes outside Solidity; the
// client vector's transaction data commits this policy too.
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
  epoch: Hex
  rootEpoch: number
  salt: Hex
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
  epochZeroDigest: Hex
  belowQuorumHash: Hex
  userOpHash: Hex
  userOpDigest: Hex
  linkIdentityDomain: Hex
  addSessionDomain: Hex
  removeSessionsDomain: Hex
  policyHash: Hex
  keyedTransactionData: Hex
  keylessTransactionData: Hex
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

    expect(walletSalt(v.epoch, v.rootEpoch)).toBe(v.salt)
    const digest = executeDigest(message, v.chainId, v.wallet, v.version, v.salt)
    expect(digest).toBe(v.digest)
    expect(executeDigest(message, v.chainId, v.wallet, v.version, walletSalt(zeroHash, 0))).toBe(
      v.epochZeroDigest,
    )
    expect(belowQuorumHash(digest, v.at, v.sessionKey)).toBe(v.belowQuorumHash)
    expect(userOperationDigest(v.userOpHash, v.chainId, v.wallet, v.version, v.salt)).toBe(
      v.userOpDigest,
    )
  })

  it('match the operation domains and transaction data of the vector', () => {
    const v = VECTOR
    for (const [constant, name, expected] of [
      [LINK_IDENTITY_DOMAIN, 'libid.webwallet.link-identity', v.linkIdentityDomain],
      [ADD_SESSION_DOMAIN, 'libid.webwallet.add-session', v.addSessionDomain],
      [REMOVE_SESSIONS_DOMAIN, 'libid.webwallet.remove-sessions', v.removeSessionsDomain],
    ] as const) {
      expect(constant).toBe(keccak256(toHex(name)))
      expect(constant).toBe(expected)
    }
    expect(policyHashOf(POLICY)).toBe(v.policyHash)
    expect(walletTransactionData(v.chainId, v.wallet, v.sessionKey, POLICY)).toBe(
      v.keyedTransactionData,
    )
    expect(walletTransactionData(v.chainId, v.wallet, '0x', POLICY)).toBe(v.keylessTransactionData)
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

import { readFileSync } from 'node:fs'
import { type Address, type Hex, keccak256, toHex } from 'viem'
import { describe, expect, it } from 'vitest'

import {
  AUTHORIZED_MODE,
  authorizedData,
  belowQuorumHash,
  directNonceKey,
  EXECUTE_TYPEHASH,
  executeDigest,
  policyHashOf,
  rulesHashOf,
  type SessionPolicy,
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

// The vector ExecuteVectorTest checks too.
interface DirectExecuteVector {
  authorizedMode: Hex
  executeTypehash: Hex
  validator: Address
  nonceKey: Hex
  nonce: Hex
  executionCalldata: Hex
  at: number
  deadline: number
  callGas: number
  sessionKey: Hex
  signature: Hex
  dataHash: Hex
  chainId: number
  wallet: Address
  digest: Hex
}

const VECTOR = JSON.parse(
  readFileSync(
    new URL(
      '../../../../solidity/contracts/wallet/test/fixtures/direct-execute-vector.json',
      import.meta.url,
    ),
    'utf8',
  ),
) as DirectExecuteVector

describe('the direct execute', () => {
  it('matches the Solidity vector', () => {
    const v = VECTOR
    expect(AUTHORIZED_MODE).toBe(v.authorizedMode)
    expect(AUTHORIZED_MODE.slice(0, 4)).toBe('0x01')
    expect(AUTHORIZED_MODE.slice(14, 22)).toBe(
      keccak256(toHex('libid.webwallet.authorized')).slice(2, 10),
    )
    expect(EXECUTE_TYPEHASH).toBe(v.executeTypehash)

    const key = directNonceKey(v.validator)
    expect(key).toBe(BigInt(v.nonceKey))
    const nonce = (key << 64n) | 7n
    expect(nonce).toBe(BigInt(v.nonce))

    const message = {
      executionCalldata: v.executionCalldata,
      at: v.at,
      nonce,
      deadline: v.deadline,
      callGas: BigInt(v.callGas),
    }
    const data = authorizedData(message, {
      signatures: [{ key: v.sessionKey, signature: v.signature }],
      calls: [],
      domainProof: [],
      paymasterProof: [],
    })
    expect(keccak256(data)).toBe(v.dataHash)
    const digest = executeDigest(message, v.chainId, v.wallet)
    expect(digest).toBe(v.digest)
  })
})

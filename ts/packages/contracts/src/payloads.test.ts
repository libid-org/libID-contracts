import { readFileSync } from 'node:fs'
import { type Hex, keccak256, size } from 'viem'
import { describe, expect, it } from 'vitest'

import {
  decodeGoogleProof,
  decodeTlsNotaryProof,
  encodeGoogleProof,
  encodeTlsNotaryProof,
  type GoogleProof,
  type TlsNotaryProof,
} from './payloads.js'

// The Solidity suite's fixtures; `x-ceremony-payload.json` pins solc's encoding.
const fixtures = new URL('../../../../solidity/contracts/ceremony/test/fixtures/', import.meta.url)
const read = (name: string) => JSON.parse(readFileSync(new URL(name, fixtures), 'utf8'))

function xPayload(): { payload: TlsNotaryProof; pinned: { keccak256: Hex; length: number } } {
  const session = read('x-ceremony-session.json')
  const proof = read('x-ceremony-session-proof.json')
  const extra = read('x-ceremony-payload.json')
  return {
    payload: {
      ceremonyVersion: Number(session.ceremony_version),
      operationDomain: session.operation_domain,
      authorizationNonce: session.authorization_nonce,
      transactionData: session.transaction_data,
      tokenSession: {
        attestedData: session.token.attested_data,
        proof: session.token.notary_signature,
      },
      identitySession: {
        attestedData: session.identity.attested_data,
        proof: session.identity.notary_signature,
      },
      idNode: extra.id_node,
      handleNode: extra.handle_node,
      handle: extra.handle,
      proof: proof.proof,
    },
    pinned: { keccak256: extra.keccak256, length: extra.length },
  }
}

describe('encodeTlsNotaryProof', () => {
  it('encodes the X fixture to the bytes solc encodes', () => {
    const { payload, pinned } = xPayload()
    const encoded = encodeTlsNotaryProof(payload)
    expect(size(encoded)).toBe(pinned.length)
    expect(keccak256(encoded)).toBe(pinned.keccak256)
  })

  it('round-trips through the struct ABI', () => {
    const { payload } = xPayload()
    const decoded = decodeTlsNotaryProof(encodeTlsNotaryProof(payload))
    expect(decoded).toEqual(payload)
  })
})

describe('encodeGoogleProof', () => {
  it('round-trips through the struct ABI', () => {
    const payload: GoogleProof = {
      ceremonyVersion: 1,
      operationDomain: `0x${'11'.repeat(32)}`,
      authorizationNonce: `0x${'22'.repeat(32)}`,
      transactionData: '0x0102',
      clientIdentifier: '0x6175640a',
      publicInputs: [`0x${'33'.repeat(32)}`, `0x${'44'.repeat(32)}`],
      handle: 'alice@gmail.com',
      proof: '0xdeadbeef',
    }
    expect(decodeGoogleProof(encodeGoogleProof(payload))).toEqual(payload)
  })
})

import { readFileSync } from 'node:fs'
import { type Hex, keccak256, size, toHex } from 'viem'
import { describe, expect, it } from 'vitest'

import {
  decodeGoogleProof,
  GooglePublicInputMismatch,
  googleProofFields,
  decodeTlsNotaryProof,
  encodeGoogleProof,
  encodeTlsNotaryProof,
  type GoogleProof,
  type TlsNotaryProof,
} from './payloads.js'

// The Solidity suite's fixtures; `x-ceremony-payload.json` pins solc's encoding.
const fixtures = new URL('../../../../solidity/contracts/ceremony/test/fixtures/', import.meta.url)

/** One session's notarized bytes and the notary's signature over them. */
interface AttestationFixture {
  attested_data: Hex
  notary_signature: Hex
}

/** `x-ceremony-session.json`, read for the payload fields. */
interface SessionFixture {
  ceremony_version: number
  operation_domain: Hex
  authorization_nonce: Hex
  transaction_data: Hex
  token: AttestationFixture
  identity: AttestationFixture
}

/** `x-ceremony-session-proof.json`, read for the proof. */
interface ProofFixture {
  proof: Hex
}

/** `x-ceremony-payload.json`: the nodes and the encoding solc pins. */
interface PayloadFixture {
  id_node: Hex
  handle_node: Hex
  keccak256: Hex
  length: number
}

/** `google-ceremony-proof.json`: the oidc-google public inputs and the audience. */
interface GoogleProofFixture {
  public_inputs: Hex[]
  client_identifier: string
}

function read<T>(name: string): T {
  return JSON.parse(readFileSync(new URL(name, fixtures), 'utf8')) as T
}

function xPayload(): { payload: TlsNotaryProof; pinned: { keccak256: Hex; length: number } } {
  const session = read<SessionFixture>('x-ceremony-session.json')
  const proof = read<ProofFixture>('x-ceremony-session-proof.json')
  const extra = read<PayloadFixture>('x-ceremony-payload.json')
  return {
    payload: {
      ceremonyVersion: session.ceremony_version,
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
      idNode: `0x${'33'.repeat(32)}`,
      handleNode: `0x${'44'.repeat(32)}`,
      exp: 1_800_000_000n,
      modulus: Array.from(
        { length: 18 },
        (): Hex => `0x${'55'.repeat(32)}`,
      ) as unknown as GoogleProof['modulus'],
      proof: '0xdeadbeef',
    }
    expect(decodeGoogleProof(encodeGoogleProof(payload))).toEqual(payload)
  })
})

describe('googleProofFields', () => {
  const fixture = read<GoogleProofFixture>('google-ceremony-proof.json')
  const inputs = fixture.public_inputs
  const clientIdentifier = toHex(fixture.client_identifier)
  // The digest the fixture's token signed as its `nonce`.
  const digest = toHex(Uint8Array.from(inputs.slice(0, 32), (b) => Number(BigInt(b))))

  it('reads the nodes, exp and modulus the oidc-google circuit output', () => {
    const fields = googleProofFields(inputs, { digest, clientIdentifier })
    // hashlib.sha256(b"libid.google.user-id100000000000000000001")
    expect(fields.idNode).toBe('0x5e13b7e56f17994a08b7464e5c5c5758228d6816db0a0af9bbd73f65335fcec8')
    // hashlib.sha256(b"libid.google.handlefixture@example.com")
    expect(fields.handleNode).toBe(
      '0xfbda24950a7bc55993b7aacc3acbde636931dbb45f04c1ff6f6909027962885f',
    )
    expect(fields.exp).toBe(1_893_456_000n)
    expect(fields.modulus).toEqual(inputs.slice(39))
  })

  it('names the input a payload would fail the proof on', () => {
    const wrong = `0x${'00'.repeat(32)}` as Hex
    const field = (f: () => unknown) => {
      try {
        f()
      } catch (e) {
        return e instanceof GooglePublicInputMismatch ? e.field : e
      }
    }
    expect(field(() => googleProofFields(inputs, { digest: wrong, clientIdentifier }))).toBe(
      'digest',
    )
    expect(field(() => googleProofFields(inputs, { digest, clientIdentifier: '0x00' }))).toBe(
      'audience',
    )
    expect(field(() => googleProofFields(inputs.slice(1), { digest, clientIdentifier }))).toBe(
      'count',
    )
  })
})

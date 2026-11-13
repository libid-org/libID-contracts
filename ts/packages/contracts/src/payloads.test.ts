import { readFileSync } from 'node:fs'
import { type Hex, keccak256, size, toHex } from 'viem'
import { describe, expect, it } from 'vitest'

import {
  decodeOidcProof,
  decodeTlsNotaryProof,
  encodeOidcProof,
  encodeOperationList,
  encodeTlsNotaryProof,
  GooglePublicInputMismatch,
  type OidcProof,
  OidcPublicInputMismatch,
  oidcProofFields,
  type TlsNotaryProof,
} from './payloads.js'

// The Solidity suite's fixtures; `x-ceremony-payload.json` pins solc's encoding.
const fixtures = new URL('../../../../solidity/contracts/ceremony/test/fixtures/', import.meta.url)
const circuitFixtures = new URL(
  '../../../../solidity/contracts/circuits/test/fixtures/',
  import.meta.url,
)

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

/** An OIDC circuit fixture: its public inputs and the audience. */
interface OidcProofFixture {
  public_inputs: Hex[]
  client_identifier: string
}

function read<T>(name: string, dir: URL = fixtures): T {
  return JSON.parse(readFileSync(new URL(name, dir), 'utf8')) as T
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

describe('encodeOidcProof', () => {
  it('round-trips through the struct ABI', () => {
    const payload: OidcProof = {
      ceremonyVersion: 1,
      operationDomain: `0x${'11'.repeat(32)}`,
      authorizationNonce: `0x${'22'.repeat(32)}`,
      transactionData: '0x0102',
      clientIdentifier: '0x6175640a',
      idNode: `0x${'33'.repeat(32)}`,
      handleNode: `0x${'44'.repeat(32)}`,
      time: 1_800_000_000n,
      modulus: Array.from(
        { length: 18 },
        (): Hex => `0x${'55'.repeat(32)}`,
      ) as unknown as OidcProof['modulus'],
      proof: '0xdeadbeef',
    }
    expect(decodeOidcProof(encodeOidcProof(payload))).toEqual(payload)
  })
})

describe('encodeOperationList', () => {
  // ceremony-common §5, the Operation List vector, one word per line.
  const vector = `0x${[
    '0000000000000000000000000000000000000000000000000000000000000020',
    '0000000000000000000000000000000000000000000000000000000000000002',
    '0000000000000000000000000000000000000000000000000000000000000040',
    '00000000000000000000000000000000000000000000000000000000000000c0',
    '4d59cd4487de0a5957f8c83addaac7a1238175aa5c29eeea2fbef57a8f5165ac',
    '0000000000000000000000000000000000000000000000000000000000000040',
    '0000000000000000000000000000000000000000000000000000000000000020',
    '0000000000000000000000001111111111111111111111111111111111111111',
    '6b8fd3a153cb2bc403041d7ca7d029d031243d8143d49a248230df9dd07fb723',
    '0000000000000000000000000000000000000000000000000000000000000040',
    '0000000000000000000000000000000000000000000000000000000000000001',
    'ff00000000000000000000000000000000000000000000000000000000000000',
  ].join('')}`

  it('encodes the spec vector', () => {
    const encoded = encodeOperationList([
      {
        domain: keccak256(toHex('libid.bind-identity')),
        data: `0x${'00'.repeat(12)}${'11'.repeat(20)}`,
      },
      { domain: keccak256(toHex('libid.test.a')), data: '0xff' },
    ])
    expect(encoded).toBe(vector)
  })
})

describe('oidcProofFields on google/v1', () => {
  const fixture = read<OidcProofFixture>('google-ceremony-proof.json')
  const inputs = fixture.public_inputs
  const clientIdentifier = toHex(fixture.client_identifier)
  // The digest the fixture's token signed as its `nonce`.
  const digest = toHex(Uint8Array.from(inputs.slice(0, 32), (b) => Number(BigInt(b))))

  it('reads the nodes, exp as time and modulus the oidc-google circuit output', () => {
    const fields = oidcProofFields(inputs, { digest, clientIdentifier })
    // hashlib.sha256(b"libid.google.user-id100000000000000000001")
    expect(fields.idNode).toBe('0x5e13b7e56f17994a08b7464e5c5c5758228d6816db0a0af9bbd73f65335fcec8')
    // hashlib.sha256(b"libid.google.handlefixture@example.com")
    expect(fields.handleNode).toBe(
      '0xfbda24950a7bc55993b7aacc3acbde636931dbb45f04c1ff6f6909027962885f',
    )
    expect(fields.time).toBe(1_893_456_000n)
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
    expect(field(() => oidcProofFields(inputs, { digest: wrong, clientIdentifier }))).toBe('digest')
    expect(field(() => oidcProofFields(inputs, { digest, clientIdentifier: '0x00' }))).toBe(
      'audience',
    )
    expect(field(() => oidcProofFields(inputs.slice(1), { digest, clientIdentifier }))).toBe(
      'count',
    )
  })
})

describe('oidcProofFields on telegram/v1', () => {
  const fixture = read<OidcProofFixture>('oidc-telegram-proof.json', circuitFixtures)
  const inputs = fixture.public_inputs
  const clientIdentifier = toHex(fixture.client_identifier)
  const digest = toHex(Uint8Array.from(inputs.slice(0, 32), (b) => Number(BigInt(b))))

  it('reads the nodes, iat as time and modulus the oidc-telegram circuit output', () => {
    const fields = oidcProofFields(inputs, { digest, clientIdentifier })
    // hashlib.sha256(b"libid.telegram.user-id7051836294")
    expect(fields.idNode).toBe('0x9ff44e615ff14505c3a406e9931e2442ad4f56f3fb5b12e91c143fa6384a3a4c')
    // hashlib.sha256(b"libid.telegram.handlebrynn_qx")
    expect(fields.handleNode).toBe(
      '0xf6416e7788cea1d8d9d7ada243b2f998a33296b61db647298ce61722c04c925b',
    )
    expect(fields.time).toBe(1_893_452_400n)
    expect(fields.modulus).toEqual(inputs.slice(39))
  })

  it('refuses another bot as the audience, under the Google name too', () => {
    const call = () => oidcProofFields(inputs, { digest, clientIdentifier: toHex('7000000002') })
    expect(call).toThrow(OidcPublicInputMismatch)
    expect(call).toThrow(GooglePublicInputMismatch)
  })
})

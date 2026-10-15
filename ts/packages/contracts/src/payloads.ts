/// The payloads `IdentityRegistry.bind` carries to a Platform Verifier,
/// encoded with the tuple types `ceremonyPayloadsAbi` carries, no selector.

import {
  type AbiParameterToPrimitiveType,
  decodeAbiParameters,
  encodeAbiParameters,
  type Hex,
  hexToBigInt,
  hexToBytes,
  numberToHex,
  sha256,
} from 'viem'

import { ceremonyPayloadsAbi } from './abis/ceremonyPayloads.js'

type PayloadFunction = Extract<(typeof ceremonyPayloadsAbi)[number], { type: 'function' }>
type PayloadName = PayloadFunction['name']
type Inputs<N extends PayloadName> = Extract<PayloadFunction, { name: N }>['inputs']

function inputs<N extends PayloadName>(name: N): Inputs<N> {
  const item = ceremonyPayloadsAbi.find((entry) => entry.type === 'function' && entry.name === name)
  if (!item) throw new Error(`ceremonyPayloadsAbi has no ${name}`)
  return item.inputs as Inputs<N>
}

const TLS_NOTARY_PROOF = inputs('tlsNotaryProof')
const GOOGLE_PROOF = inputs('googleProof')

/// `TlsNotaryVerifierBase.TlsNotaryProof`: the `x/v1` and `github/v1` payload.
export type TlsNotaryProof = AbiParameterToPrimitiveType<(typeof TLS_NOTARY_PROOF)[0]>

/// `GooglePlatformVerifier.GoogleProof`: the `google/v1` payload.
export type GoogleProof = AbiParameterToPrimitiveType<(typeof GOOGLE_PROOF)[0]>

/// The `x/v1` or `github/v1` payload, as the verifier decodes it.
export function encodeTlsNotaryProof(payload: TlsNotaryProof): Hex {
  return encodeAbiParameters(TLS_NOTARY_PROOF, [payload])
}

/// A TLSNotary payload back into its fields. Throws on bytes that are not one.
export function decodeTlsNotaryProof(data: Hex): TlsNotaryProof {
  return decodeAbiParameters(TLS_NOTARY_PROOF, data)[0]
}

/// The `google/v1` payload, as the verifier decodes it.
export function encodeGoogleProof(payload: GoogleProof): Hex {
  return encodeAbiParameters(GOOGLE_PROOF, [payload])
}

/// A Google payload back into its fields. Throws on bytes that are not one.
export function decodeGoogleProof(data: Hex): GoogleProof {
  return decodeAbiParameters(GOOGLE_PROOF, data)[0]
}

/// The `google/v1` payload fields the verifier builds its public inputs from.
export type GoogleProofFields = Pick<GoogleProof, 'idNode' | 'handleNode' | 'exp' | 'modulus'>

/// The oidc-google public input that disagrees with the payload: the verifier
/// would fail the proof, so a client checks before sending.
export class GooglePublicInputMismatch extends Error {
  constructor(readonly field: 'count' | 'digest' | 'audience') {
    super(
      `the proof's ${field} public input${field === 'count' ? 's do' : ' does'} not match the payload`,
    )
    this.name = 'GooglePublicInputMismatch'
  }
}

/// The payload fields from the prover's 57 oidc-google public inputs
/// (REQ-PLAT-16B), after checking the digest the token's `nonce` carried and
/// the audience against what the verifier builds them from.
export function googleProofFields(
  publicInputs: readonly Hex[],
  expected: { digest: Hex; clientIdentifier: Hex },
): GoogleProofFields {
  if (publicInputs.length !== 57) throw new GooglePublicInputMismatch('count')
  const field = (i: number) => hexToBigInt(publicInputs[i] as Hex)
  const node = (i: number) => numberToHex((field(i) << 128n) | field(i + 1), { size: 32 })
  const digest = hexToBytes(expected.digest)
  if (digest.some((b, i) => field(i) !== BigInt(b))) throw new GooglePublicInputMismatch('digest')
  if (node(32) !== sha256(expected.clientIdentifier))
    throw new GooglePublicInputMismatch('audience')
  return {
    idNode: node(34),
    handleNode: node(36),
    exp: field(38),
    modulus: publicInputs.slice(39, 57) as unknown as GoogleProof['modulus'],
  }
}

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
const OIDC_PROOF = inputs('oidcProof')

/// `TlsNotaryVerifierBase.TlsNotaryProof`: the `x/v1` and `github/v1` payload.
export type TlsNotaryProof = AbiParameterToPrimitiveType<(typeof TLS_NOTARY_PROOF)[0]>

/// `OidcPlatformVerifierBase.OidcProof`: the `google/v1` and `telegram/v1`
/// payload. `time` is Google's `exp` or Telegram's `iat`.
export type OidcProof = AbiParameterToPrimitiveType<(typeof OIDC_PROOF)[0]>

/// The `x/v1` or `github/v1` payload, as the verifier decodes it.
export function encodeTlsNotaryProof(payload: TlsNotaryProof): Hex {
  return encodeAbiParameters(TLS_NOTARY_PROOF, [payload])
}

/// A TLSNotary payload back into its fields. Throws on bytes that are not one.
export function decodeTlsNotaryProof(data: Hex): TlsNotaryProof {
  return decodeAbiParameters(TLS_NOTARY_PROOF, data)[0]
}

/// The `google/v1` or `telegram/v1` payload, as the verifier decodes it.
export function encodeOidcProof(payload: OidcProof): Hex {
  return encodeAbiParameters(OIDC_PROOF, [payload])
}

/// An OIDC payload back into its fields. Throws on bytes that are not one.
export function decodeOidcProof(data: Hex): OidcProof {
  return decodeAbiParameters(OIDC_PROOF, data)[0]
}

/// The OIDC payload fields a verifier builds its public inputs from.
export type OidcProofFields = Pick<OidcProof, 'idNode' | 'handleNode' | 'time' | 'modulus'>

/// The OIDC public input that disagrees with the payload: the verifier
/// would fail the proof, so a client checks before sending.
export class OidcPublicInputMismatch extends Error {
  constructor(readonly field: 'count' | 'digest' | 'audience') {
    super(
      `the proof's ${field} public input${field === 'count' ? 's do' : ' does'} not match the payload`,
    )
    this.name = 'OidcPublicInputMismatch'
  }
}

/// Another name for `OidcPublicInputMismatch`: `instanceof` matches, and
/// the thrown error's `.name` is `'OidcPublicInputMismatch'`.
/// @deprecated Use `OidcPublicInputMismatch`; code that compares `.name`
/// to `'GooglePublicInputMismatch'` no longer matches.
export const GooglePublicInputMismatch = OidcPublicInputMismatch
/// @deprecated Use `OidcPublicInputMismatch`.
export type GooglePublicInputMismatch = OidcPublicInputMismatch

/// The payload fields from the prover's 57 OIDC public inputs
/// (REQ-PLAT-16B), after checking the digest the token's `nonce` carried and
/// the audience against what the verifier builds them from.
export function oidcProofFields(
  publicInputs: readonly Hex[],
  expected: { digest: Hex; clientIdentifier: Hex },
): OidcProofFields {
  if (publicInputs.length !== 57) throw new OidcPublicInputMismatch('count')
  const field = (i: number) => hexToBigInt(publicInputs[i] as Hex)
  const node = (i: number) => numberToHex((field(i) << 128n) | field(i + 1), { size: 32 })
  const digest = hexToBytes(expected.digest)
  if (digest.some((b, i) => field(i) !== BigInt(b))) throw new OidcPublicInputMismatch('digest')
  if (node(32) !== sha256(expected.clientIdentifier)) throw new OidcPublicInputMismatch('audience')
  return {
    idNode: node(34),
    handleNode: node(36),
    time: field(38),
    modulus: publicInputs.slice(39, 57) as unknown as OidcProof['modulus'],
  }
}

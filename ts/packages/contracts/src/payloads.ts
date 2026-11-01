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
const TELEGRAM_PROOF = inputs('telegramProof')

/// `TlsNotaryVerifierBase.TlsNotaryProof`: the `x/v1` and `github/v1` payload.
export type TlsNotaryProof = AbiParameterToPrimitiveType<(typeof TLS_NOTARY_PROOF)[0]>

/// `GooglePlatformVerifier.GoogleProof`: the `google/v1` payload.
export type GoogleProof = AbiParameterToPrimitiveType<(typeof GOOGLE_PROOF)[0]>

/// `TelegramPlatformVerifier.TelegramProof`: the `telegram/v1` payload.
export type TelegramProof = AbiParameterToPrimitiveType<(typeof TELEGRAM_PROOF)[0]>

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

/// The `telegram/v1` payload, as the verifier decodes it.
export function encodeTelegramProof(payload: TelegramProof): Hex {
  return encodeAbiParameters(TELEGRAM_PROOF, [payload])
}

/// A Telegram payload back into its fields. Throws on bytes that are not one.
export function decodeTelegramProof(data: Hex): TelegramProof {
  return decodeAbiParameters(TELEGRAM_PROOF, data)[0]
}

/// The signed time an OIDC circuit exposes: Google's `exp`, Telegram's `iat`.
export type OidcTimeField = 'exp' | 'iat'

/// The OIDC payload fields a verifier builds its public inputs from, the
/// signed time under the profile's name.
export type OidcProofFields<T extends OidcTimeField> = Pick<
  GoogleProof,
  'idNode' | 'handleNode' | 'modulus'
> & { [K in T]: bigint }

/// The `google/v1` payload fields the verifier builds its public inputs from.
export type GoogleProofFields = OidcProofFields<'exp'>

/// The `telegram/v1` payload fields the verifier builds its public inputs from.
export type TelegramProofFields = OidcProofFields<'iat'>

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
/// the audience against what the verifier builds them from. The audience is
/// Google's `clientIdentifier` or Telegram's bot id; `time` names the signed
/// time the circuit exposes.
export function oidcProofFields<T extends OidcTimeField>(
  publicInputs: readonly Hex[],
  expected: { digest: Hex; audience: Hex },
  time: T,
): OidcProofFields<T> {
  if (publicInputs.length !== 57) throw new OidcPublicInputMismatch('count')
  const field = (i: number) => hexToBigInt(publicInputs[i] as Hex)
  const node = (i: number) => numberToHex((field(i) << 128n) | field(i + 1), { size: 32 })
  const digest = hexToBytes(expected.digest)
  if (digest.some((b, i) => field(i) !== BigInt(b))) throw new OidcPublicInputMismatch('digest')
  if (node(32) !== sha256(expected.audience)) throw new OidcPublicInputMismatch('audience')
  return {
    idNode: node(34),
    handleNode: node(36),
    [time]: field(38),
    modulus: publicInputs.slice(39, 57) as unknown as GoogleProof['modulus'],
  } as OidcProofFields<T>
}

/// `oidcProofFields` for `google/v1`, timed by `exp`.
export function googleProofFields(
  publicInputs: readonly Hex[],
  expected: { digest: Hex; clientIdentifier: Hex },
): GoogleProofFields {
  return oidcProofFields(
    publicInputs,
    { digest: expected.digest, audience: expected.clientIdentifier },
    'exp',
  )
}

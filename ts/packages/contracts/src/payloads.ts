/// The payloads `IdentityRegistry.bind` carries to a Platform Verifier, typed
/// and encoded from the verifiers' own struct definitions.
///
/// `bind` takes a payload as opaque bytes; the Platform Verifier the route ends
/// at `abi.decode`s it as one struct. `ICeremonyPayloads` declares a function
/// taking each struct, so the generated `ceremonyPayloadsAbi` carries their
/// exact tuple types, and these encoders read them from it rather than from a
/// second copy here. A payload is the encoding of the function's one argument,
/// without a selector.

import {
  type AbiParameterToPrimitiveType,
  decodeAbiParameters,
  encodeAbiParameters,
  type Hex,
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

/// `TlsNotaryProof` (`ceremony/CeremonyPayloads.sol`): the `x/v1` and `github/v1` payload.
export type TlsNotaryProof = AbiParameterToPrimitiveType<(typeof TLS_NOTARY_PROOF)[0]>

/// `GoogleProof` (`ceremony/CeremonyPayloads.sol`): the `google/v1` payload.
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

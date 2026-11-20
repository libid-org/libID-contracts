/// Operation Lists (chain profiles §3.3): one ceremony committing an entry
/// for each of several Consumers.

import { encodeAbiParameters, type Hex, keccak256, parseAbiParameters, toHex } from 'viem'

/// `keccak256("libid.operations")`, the operation domain of an Operation List.
export const OPERATIONS_DOMAIN: Hex = keccak256(toHex('libid.operations'))

/// One entry: a Consumer's operation domain and the transaction data that
/// domain fixes.
export type OperationEntry = { domain: Hex; data: Hex }

const OPERATION_LIST = parseAbiParameters('(bytes32 domain, bytes32 dataHash)[]')

/// The transaction data under `OPERATIONS_DOMAIN`: `abi.encode(Operation[])`
/// of each entry's domain and `keccak256(data)`. No `data` is in the list: each
/// Consumer's call carries its own entry's, or rebuilds it.
export function encodeOperationList(entries: readonly OperationEntry[]): Hex {
  return encodeAbiParameters(OPERATION_LIST, [
    entries.map(({ domain, data }) => ({ domain, dataHash: keccak256(data) })),
  ])
}

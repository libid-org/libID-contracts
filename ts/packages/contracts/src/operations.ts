/// Operation Lists (chain profiles §3.3): one ceremony's transaction data
/// carrying an entry for each of several Consumers. One action is a one-entry
/// list: a bind is `encodeOperationList([bindOperation(account)])` under
/// `OPERATIONS_DOMAIN`.

import {
  type Address,
  encodeAbiParameters,
  type Hex,
  keccak256,
  parseAbiParameters,
  toHex,
} from 'viem'

/// `keccak256("libid.operations")`, the operation domain of an Operation List.
export const OPERATIONS_DOMAIN: Hex = keccak256(toHex('libid.operations'))

/// `keccak256("libid.bind-identity")`, the identity registry's entry domain.
export const BIND_DOMAIN: Hex = keccak256(toHex('libid.bind-identity'))

/// One entry: a Consumer's operation domain and the data that domain fixes.
export type Operation = { domain: Hex; data: Hex }

const OPERATION_LIST = parseAbiParameters('(bytes32 domain, bytes data)[]')

/// The transaction data under `OPERATIONS_DOMAIN`: `abi.encode(Operation[])`.
export function encodeOperationList(entries: readonly Operation[]): Hex {
  return encodeAbiParameters(OPERATION_LIST, [entries])
}

/// The identity registry's entry: bind the proved identity to `account`, the
/// account that calls `bind`.
export function bindOperation(account: Address): Operation {
  return {
    domain: BIND_DOMAIN,
    data: encodeAbiParameters(parseAbiParameters('address'), [account]),
  }
}

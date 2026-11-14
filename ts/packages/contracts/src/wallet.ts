/// The session-policy hashes of `IIdentityValidator.sol`, what each signer
/// signs below quorum, and the direct `execute`'s mode, digest, nonce key and
/// data. Types follow `identityValidatorAbi`.

import {
  type AbiParameterToPrimitiveType,
  type Address,
  encodeAbiParameters,
  type Hex,
  hashTypedData,
  keccak256,
  parseAbiParameters,
  toHex,
} from 'viem'

import { identityValidatorAbi } from './abis/identityValidator.js'

type AddSession = Extract<
  (typeof identityValidatorAbi)[number],
  { type: 'function'; name: 'addSession' }
>
type PolicyParameter = AddSession['inputs'][2]

const POLICY = (() => {
  const item = identityValidatorAbi.find(
    (entry) => entry.type === 'function' && entry.name === 'addSession',
  )
  if (!item) throw new Error('identityValidatorAbi has no addSession')
  return (item as AddSession).inputs[2]
})()
const RULES = POLICY.components[4]

type DecodeAuthorization = Extract<
  (typeof identityValidatorAbi)[number],
  { type: 'function'; name: 'decodeAuthorization' }
>

const AUTHORIZATION = (() => {
  const item = identityValidatorAbi.find(
    (entry) => entry.type === 'function' && entry.name === 'decodeAuthorization',
  )
  if (!item) throw new Error('identityValidatorAbi has no decodeAuthorization')
  return (item as DecodeAuthorization).outputs[0]
})()

/// `IIdentityValidator.Authorization`.
export type SessionAuthorization = AbiParameterToPrimitiveType<DecodeAuthorization['outputs'][0]>

/// `IIdentityValidator.Policy`.
export type SessionPolicy = AbiParameterToPrimitiveType<PolicyParameter>

/// `IIdentityValidator.Rules`.
export type SessionRules = SessionPolicy['rules']

/// `rulesHashOf(rules)`: stored in the session record, it keys the session's
/// allowance counters.
export function rulesHashOf(rules: SessionRules): Hex {
  return keccak256(
    encodeAbiParameters(RULES.components, [
      rules.scopeRoot,
      rules.domainsRoot,
      rules.paymastersRoot,
      rules.allowances,
    ]),
  )
}

/// `policyHashOf(policy)`: the policy hash a proof commits.
export function policyHashOf(policy: SessionPolicy): Hex {
  return keccak256(
    encodeAbiParameters(parseAbiParameters('uint48, uint48, bool, uint8, bytes32'), [
      policy.validAfter,
      policy.validUntil,
      policy.admin,
      policy.signers,
      rulesHashOf(policy.rules),
    ]),
  )
}

/// What each signer signs below quorum:
/// `keccak256(abi.encode(hash, at, keccak256(governingKey)))`, where the
/// governing key is the first signature's. For an operation, `hash` is its
/// `userOpHash` and `at` picks the allowance period, which the EntryPoint
/// enforces as the operation's validity window. For a direct `execute`, `hash`
/// is its EIP-712 `Execute` digest and `at` the one it signs. For ERC-1271,
/// `hash` is the ERC-7739 nested hash and `at` is 0.
export function belowQuorumHash(hash: Hex, at: number, governingKey: Hex): Hex {
  return keccak256(
    encodeAbiParameters(parseAbiParameters('bytes32, uint48, bytes32'), [
      hash,
      at,
      keccak256(governingKey),
    ]),
  )
}

/// `AUTHORIZED_MODE` of `IWebWallet.sol`, the direct path's mode: the batch
/// call type, the default exec type, the selector
/// `bytes4(keccak256("libid.webwallet.authorized"))` and a zero payload.
export const AUTHORIZED_MODE: Hex =
  '0x01000000000018f4a5a900000000000000000000000000000000000000000000'

/// The typed-data types of what a direct `execute` signs.
export const EXECUTE_TYPES = {
  Execute: [
    { name: 'mode', type: 'bytes32' },
    { name: 'executionCalldata', type: 'bytes' },
    { name: 'at', type: 'uint48' },
    { name: 'nonce', type: 'uint256' },
    { name: 'deadline', type: 'uint48' },
    { name: 'callGas', type: 'uint256' },
  ],
} as const

/// `Execute(bytes32 mode,bytes executionCalldata,uint48 at,uint256 nonce,uint48 deadline,uint256 callGas)`.
export const EXECUTE_TYPE = `Execute(${EXECUTE_TYPES.Execute.map((f) => `${f.type} ${f.name}`).join(',')})`

export const EXECUTE_TYPEHASH: Hex = keccak256(toHex(EXECUTE_TYPE))

/// What a direct `execute` signs, besides `mode`, which is always
/// `AUTHORIZED_MODE`: `at` is `Authorization.at`, and `nonce` is the wallet's
/// full EntryPoint nonce under `directNonceKey` before the batch.
export type ExecuteMessage = {
  executionCalldata: Hex
  at: number
  nonce: bigint
  deadline: number
  callGas: bigint
}

/// The EIP-712 hash the signers of a direct `execute` sign, under the
/// wallet's domain: name `WebWallet`, version `1`, `chainId` and `wallet`.
/// Below quorum each signer signs `belowQuorumHash` of it.
export function executeDigest(
  execute: ExecuteMessage,
  chainId: number | bigint,
  wallet: Address,
): Hex {
  return hashTypedData({
    domain: { name: 'WebWallet', version: '1', chainId, verifyingContract: wallet },
    types: EXECUTE_TYPES,
    primaryType: 'Execute',
    message: { ...execute, mode: AUTHORIZED_MODE },
  })
}

/// The EntryPoint nonce key of the direct path for a wallet whose validator
/// is `validator`: `uint192(uint160(validator)) << 32`. UserOperations share it.
export function directNonceKey(validator: Address): bigint {
  return BigInt(validator) << 32n
}

/// `data` of `execute(AUTHORIZED_MODE, data)` for `message`:
/// `abi.encode(executionCalldata, deadline, callGas, abi.encode(authorization))`,
/// the authorization's `at` the message's.
export function authorizedData(
  message: ExecuteMessage,
  authorization: Omit<SessionAuthorization, 'at'>,
): Hex {
  return encodeAbiParameters(parseAbiParameters('bytes, uint48, uint256, bytes'), [
    message.executionCalldata,
    message.deadline,
    message.callGas,
    encodeAbiParameters([AUTHORIZATION], [{ ...authorization, at: message.at }]),
  ])
}

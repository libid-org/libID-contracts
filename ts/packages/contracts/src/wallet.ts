/// The session-policy hashes of `IIdentityValidator.sol`, what each signer
/// signs below quorum, and the direct `execute`'s mode, digest, nonce key and
/// data, signed by sessions or by an EIP-7702 account's key. Types follow `identityValidatorAbi`.

import {
  type AbiParameterToPrimitiveType,
  type Address,
  encodeAbiParameters,
  type Hex,
  hashTypedData,
  keccak256,
  parseAbiParameters,
  size,
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

/// The rules with their allowances sorted into the strictly ascending token
/// order the validator requires. Sort before hashing and building calls.
export function sortAllowances(rules: SessionRules): SessionRules {
  const allowances = [...rules.allowances].sort((a, b) => {
    const [x, y] = [BigInt(a.token), BigInt(b.token)]
    return x < y ? -1 : x > y ? 1 : 0
  })
  return { ...rules, allowances }
}

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
    { name: 'value', type: 'uint256' },
    { name: 'at', type: 'uint48' },
    { name: 'nonce', type: 'uint256' },
    { name: 'deadline', type: 'uint48' },
    { name: 'callGas', type: 'uint256' },
  ],
} as const

/// `Execute(bytes32 mode,bytes executionCalldata,uint256 value,uint48 at,uint256 nonce,uint48 deadline,uint256 callGas)`.
export const EXECUTE_TYPE = `Execute(${EXECUTE_TYPES.Execute.map((f) => `${f.type} ${f.name}`).join(',')})`

export const EXECUTE_TYPEHASH: Hex = keccak256(toHex(EXECUTE_TYPE))

/// What a direct `execute` signs, besides `mode`, which is always
/// `AUTHORIZED_MODE`: `value` is the `msg.value` the batch must be sent with,
/// `at` is `Authorization.at`, and `nonce` is the wallet's
/// full EntryPoint nonce under `directNonceKey` before the batch.
export type ExecuteMessage = {
  executionCalldata: Hex
  value: bigint
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
/// `abi.encode(executionCalldata, value, deadline, callGas, abi.encode(authorization))`,
/// the authorization's `at` the message's.
export function authorizedData(
  message: ExecuteMessage,
  authorization: Omit<SessionAuthorization, 'at'>,
): Hex {
  return encodeAbiParameters(parseAbiParameters('bytes, uint256, uint48, uint256, bytes'), [
    message.executionCalldata,
    message.value,
    message.deadline,
    message.callGas,
    encodeAbiParameters([AUTHORIZATION], [{ ...authorization, at: message.at }]),
  ])
}

/// What an EIP-7702 account's key signs for its onboarding batch:
/// `executeDigest` with `at` 0.
export function keyDigest(
  execute: Omit<ExecuteMessage, 'at'>,
  chainId: number | bigint,
  wallet: Address,
): Hex {
  return executeDigest({ ...execute, at: 0 }, chainId, wallet)
}

/// `data` of `execute(AUTHORIZED_MODE, data)` signed by the account's key:
/// `abi.encode(executionCalldata, value, deadline, callGas, signature)`,
/// `signature` the 65-byte `r || s || v` over `keyDigest`.
export function keySignedData(message: Omit<ExecuteMessage, 'at'>, signature: Hex): Hex {
  if (size(signature) !== 65) throw new Error(`a key signature is 65 bytes, not ${size(signature)}`)
  return encodeAbiParameters(parseAbiParameters('bytes, uint256, uint48, uint256, bytes'), [
    message.executionCalldata,
    message.value,
    message.deadline,
    message.callGas,
    signature,
  ])
}

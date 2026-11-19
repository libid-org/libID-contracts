/// What a WebWallet's signers sign: the session-policy hashes of
/// `WalletStorage.sol`, the below-quorum hash, the nested UserOperation hash,
/// and an `AUTHORIZED_MODE` batch's digest and data. Types follow `webWalletAbi`.

import {
  type AbiParameterToPrimitiveType,
  type Address,
  encodeAbiParameters,
  type Hex,
  hashTypedData,
  keccak256,
  parseAbiParameter,
  parseAbiParameters,
} from 'viem'

import { webWalletAbi } from './abis/webWallet.js'

type AddSession = Extract<(typeof webWalletAbi)[number], { type: 'function'; name: 'addSession' }>

const POLICY = (() => {
  const item = webWalletAbi.find(
    (entry) => entry.type === 'function' && entry.name === 'addSession',
  )
  if (!item) throw new Error('webWalletAbi has no addSession')
  return (item as AddSession).inputs[2]
})()
const RULES = POLICY.components[4]

/// `IWebWallet.Authorization`, which no external's ABI carries.
const AUTHORIZATION = parseAbiParameter(
  '((bytes key, bytes signature)[] signatures, uint48 at, (uint256 maxValue, bytes32[] proof)[] calls, bytes32[] domainProof, bytes32[] paymasterProof)',
)

/// `IWebWallet.Authorization`.
export type SessionAuthorization = AbiParameterToPrimitiveType<typeof AUTHORIZATION>

/// `IWebWallet.Policy`.
export type SessionPolicy = AbiParameterToPrimitiveType<AddSession['inputs'][2]>

/// `IWebWallet.Rules`.
export type SessionRules = SessionPolicy['rules']

/// The rules with their allowances sorted into the strictly ascending token
/// order the wallet requires. Sort before hashing and building calls.
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
/// governing key is the first signature's. For a UserOperation, `hash` is
/// `userOperationDigest`; for an `AUTHORIZED_MODE` batch, `executeDigest`;
/// for ERC-1271, the ERC-7739 nested hash, at 0.
export function belowQuorumHash(hash: Hex, at: number, governingKey: Hex): Hex {
  return keccak256(
    encodeAbiParameters(parseAbiParameters('bytes32, uint48, bytes32'), [
      hash,
      at,
      keccak256(governingKey),
    ]),
  )
}

/// `abi.encode(authorization)`: a UserOperation's signature, the inner
/// signature of an ERC-1271 check (at 0), and the last field of `authorizedData`.
export function encodeAuthorization(authorization: SessionAuthorization): Hex {
  return encodeAbiParameters([AUTHORIZATION], [authorization])
}

/// `AUTHORIZED_MODE` of `IWebWallet.sol`: the batch call type, the default
/// exec type, the selector `bytes4(keccak256("libid.webwallet.authorized"))`
/// and a zero payload.
export const AUTHORIZED_MODE: Hex =
  '0x01000000000018f4a5a900000000000000000000000000000000000000000000'

/// The EntryPoint nonce key an `AUTHORIZED_MODE` batch consumes.
/// UserOperations may use any key.
export const DIRECT_NONCE_KEY = 0n

/// The wallet's EIP-712 domain: name `WebWallet`, the release's version as a
/// decimal string, `chainId`, and the wallet's address. A bump to another
/// release changes it.
export function walletDomain(chainId: number | bigint, wallet: Address, version: number | bigint) {
  return { name: 'WebWallet', version: version.toString(), chainId, verifyingContract: wallet }
}

/// What the signers of `userOpHash` sign: `UserOperation(bytes32 userOpHash)`
/// under `walletDomain`. Below quorum, `belowQuorumHash` of it.
export function userOperationDigest(
  userOpHash: Hex,
  chainId: number | bigint,
  wallet: Address,
  version: number | bigint,
): Hex {
  return hashTypedData({
    domain: walletDomain(chainId, wallet, version),
    types: { UserOperation: [{ name: 'userOpHash', type: 'bytes32' }] },
    primaryType: 'UserOperation',
    message: { userOpHash },
  })
}

/// The typed-data types of what an `AUTHORIZED_MODE` batch signs.
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

/// What an `AUTHORIZED_MODE` batch signs, besides `mode`: `value` is the
/// `msg.value` it must be sent with, `at` is `Authorization.at`, and `nonce`
/// the wallet's EntryPoint nonce under `DIRECT_NONCE_KEY` before the batch.
export type ExecuteMessage = {
  executionCalldata: Hex
  value: bigint
  at: number
  nonce: bigint
  deadline: number
  callGas: bigint
}

/// The EIP-712 hash the signers of an `AUTHORIZED_MODE` batch sign, under
/// `walletDomain`. Below quorum each signer signs `belowQuorumHash` of it.
export function executeDigest(
  execute: ExecuteMessage,
  chainId: number | bigint,
  wallet: Address,
  version: number | bigint,
): Hex {
  return hashTypedData({
    domain: walletDomain(chainId, wallet, version),
    types: EXECUTE_TYPES,
    primaryType: 'Execute',
    message: { ...execute, mode: AUTHORIZED_MODE },
  })
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
    encodeAuthorization({ ...authorization, at: message.at }),
  ])
}

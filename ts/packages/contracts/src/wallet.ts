/// The session-policy hashes of `IIdentityValidator.sol`, and what each
/// signer signs below quorum. Types follow `identityValidatorAbi`.

import {
  type AbiParameterToPrimitiveType,
  encodeAbiParameters,
  type Hex,
  keccak256,
  parseAbiParameters,
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
/// enforces as the operation's validity window. For ERC-1271, `hash` is the
/// ERC-7739 nested hash and `at` is 0.
export function belowQuorumHash(hash: Hex, at: number, governingKey: Hex): Hex {
  return keccak256(
    encodeAbiParameters(parseAbiParameters('bytes32, uint48, bytes32'), [
      hash,
      at,
      keccak256(governingKey),
    ]),
  )
}

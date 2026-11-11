/// The session-policy hashes of `IIdentityValidator.sol`, and what a lone
/// session signs below quorum. Types follow `identityValidatorAbi`.

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
const RULES = POLICY.components[3]

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
    encodeAbiParameters(parseAbiParameters('uint48, uint48, bool, bytes32'), [
      policy.validAfter,
      policy.validUntil,
      policy.admin,
      rulesHashOf(policy.rules),
    ]),
  )
}

/// What a lone session signs below quorum: `keccak256(abi.encode(userOpHash, at))`.
/// `at` picks the allowance period, which the EntryPoint enforces as the
/// operation's validity window.
export function belowQuorumHash(userOpHash: Hex, at: number): Hex {
  return keccak256(encodeAbiParameters(parseAbiParameters('bytes32, uint48'), [userOpHash, at]))
}

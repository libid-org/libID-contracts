import { decodeAbiParameters, keccak256, parseAbiParameters, toHex } from 'viem'
import { describe, expect, it } from 'vitest'

import { BIND_DOMAIN, bindOperation, encodeOperationList, OPERATIONS_DOMAIN } from './index.js'

describe('encodeOperationList', () => {
  // chain profiles §3.3, the Operation List vector, one word per line.
  const vector = `0x${[
    '0000000000000000000000000000000000000000000000000000000000000020',
    '0000000000000000000000000000000000000000000000000000000000000002',
    '0000000000000000000000000000000000000000000000000000000000000040',
    '00000000000000000000000000000000000000000000000000000000000000c0',
    '4d59cd4487de0a5957f8c83addaac7a1238175aa5c29eeea2fbef57a8f5165ac',
    '0000000000000000000000000000000000000000000000000000000000000040',
    '0000000000000000000000000000000000000000000000000000000000000020',
    '0000000000000000000000001111111111111111111111111111111111111111',
    '6b8fd3a153cb2bc403041d7ca7d029d031243d8143d49a248230df9dd07fb723',
    '0000000000000000000000000000000000000000000000000000000000000040',
    '0000000000000000000000000000000000000000000000000000000000000001',
    'ff00000000000000000000000000000000000000000000000000000000000000',
  ].join('')}`

  it('encodes the spec vector', () => {
    const encoded = encodeOperationList([
      bindOperation('0x1111111111111111111111111111111111111111'),
      { domain: keccak256(toHex('libid.test.a')), data: '0xff' },
    ])
    expect(encoded).toBe(vector)
  })

  it('names the domains by their hashes', () => {
    expect(OPERATIONS_DOMAIN).toBe(
      '0x60b329d7366897b03545eb9f63f4a707253258ee2e1cd0ba3a8973aa4959e967',
    )
    expect(BIND_DOMAIN).toBe('0x4d59cd4487de0a5957f8c83addaac7a1238175aa5c29eeea2fbef57a8f5165ac')
  })

  it('a bind is a one-entry list that decodes to its account', () => {
    const [entries] = decodeAbiParameters(
      parseAbiParameters('(bytes32 domain, bytes data)[]'),
      encodeOperationList([bindOperation('0x1111111111111111111111111111111111111111')]),
    )
    expect(entries).toHaveLength(1)
    expect(entries[0].domain).toBe(BIND_DOMAIN)
    expect(entries[0].data).toBe(`0x${'00'.repeat(12)}${'11'.repeat(20)}`)
  })
})

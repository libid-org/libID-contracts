import { encodeAbiParameters, keccak256, parseAbiParameters, toHex } from 'viem'
import { describe, expect, it } from 'vitest'

import { encodeOperationList, OPERATIONS_DOMAIN } from './index.js'

describe('encodeOperationList', () => {
  // chain profiles §3.3, the Operation List vector, one word per line.
  const vector = `0x${[
    '0000000000000000000000000000000000000000000000000000000000000020',
    '0000000000000000000000000000000000000000000000000000000000000002',
    '4d59cd4487de0a5957f8c83addaac7a1238175aa5c29eeea2fbef57a8f5165ac',
    'aafae41182fdefb0af836c3b506e127c7f229f33360c66de1139f4b0316f09d8',
    '6b8fd3a153cb2bc403041d7ca7d029d031243d8143d49a248230df9dd07fb723',
    '8b1a944cf13a9a1c08facb2c9e98623ef3254d2ddb48113885c3e8e97fec8db9',
  ].join('')}`

  it('encodes the spec vector', () => {
    expect(OPERATIONS_DOMAIN).toBe(
      '0x60b329d7366897b03545eb9f63f4a707253258ee2e1cd0ba3a8973aa4959e967',
    )
    const encoded = encodeOperationList([
      {
        domain: keccak256(toHex('libid.bind-identity')),
        data: encodeAbiParameters(parseAbiParameters('address'), [
          '0x1111111111111111111111111111111111111111',
        ]),
      },
      { domain: keccak256(toHex('libid.test.a')), data: '0xff' },
    ])
    expect(encoded).toBe(vector)
  })
})

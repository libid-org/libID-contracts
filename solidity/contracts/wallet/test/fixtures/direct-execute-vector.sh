#!/usr/bin/env bash
# Writes direct-execute-vector.json from cast alone: the type strings written out, keccak over abi-encode.
# No libID code computes it. Run: ./direct-execute-vector.sh > direct-execute-vector.json
set -euo pipefail

MODE=0x01000000000018f4a5a900000000000000000000000000000000000000000000
EXECUTE_TYPEHASH=$(cast keccak "Execute(bytes32 mode,bytes executionCalldata,uint256 value,uint48 at,uint256 nonce,uint48 deadline,uint256 callGas)")
USER_OP_TYPEHASH=$(cast keccak "UserOperation(bytes32 userOpHash)")
DOMAIN_TYPEHASH=$(cast keccak "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)")
CHAIN=8453; WALLET=0x0000000000000000000000000000000000001234; VERSION=2; EPOCH=$(cast keccak "epoch")
NONCE=7; CALLS=0xc0ffee; VALUE=12345; AT=1000; DEADLINE=2000; CALL_GAS=200000
KEY=0x1234; SIG=0x5678; MAX_VALUE=5
CALL_PROOF=$(cast keccak "call leaf"); DOMAIN_PROOF=$(cast keccak "domain leaf"); PAYMASTER_PROOF=$(cast keccak "paymaster leaf")
USER_OP_HASH=$(cast keccak "op")

# The domain separator at epoch $1, the salt.
sep() { cast keccak "$(cast abi-encode "f(bytes32,bytes32,bytes32,uint256,address,bytes32)" "$DOMAIN_TYPEHASH" "$(cast keccak WebWallet)" "$(cast keccak "$VERSION")" $CHAIN $WALLET "$1")"; }
SEP=$(sep "$EPOCH")
typed() { cast keccak "$(cast concat-hex 0x1901 "$SEP" "$1")"; }
STRUCT=$(cast keccak "$(cast abi-encode "f(bytes32,bytes32,bytes32,uint256,uint48,uint256,uint48,uint256)" "$EXECUTE_TYPEHASH" $MODE "$(cast keccak $CALLS)" $VALUE $AT $NONCE $DEADLINE $CALL_GAS)")
DIGEST=$(typed "$STRUCT")
EPOCH_ZERO_DIGEST=$(cast keccak "$(cast concat-hex 0x1901 "$(sep 0x0000000000000000000000000000000000000000000000000000000000000000)" "$STRUCT")")
USER_OP_DIGEST=$(typed "$(cast keccak "$(cast abi-encode "f(bytes32,bytes32)" "$USER_OP_TYPEHASH" "$USER_OP_HASH")")")
AUTH=$(cast abi-encode "f(((bytes,bytes)[],uint48,(uint256,bytes32[])[],bytes32[],bytes32[]))" \
  "([($KEY,$SIG)],$AT,[($MAX_VALUE,[$CALL_PROOF])],[$DOMAIN_PROOF],[$PAYMASTER_PROOF])")
DATA=$(cast abi-encode "f(bytes,uint256,uint48,uint256,bytes)" $CALLS $VALUE $DEADLINE $CALL_GAS "$AUTH")
BELOW=$(cast keccak "$(cast abi-encode "f(bytes32,uint48,bytes32)" "$DIGEST" $AT "$(cast keccak $KEY)")")

cat <<JSON
{
  "authorizedMode": "$MODE",
  "executeTypehash": "$EXECUTE_TYPEHASH",
  "userOperationTypehash": "$USER_OP_TYPEHASH",
  "chainId": $CHAIN,
  "wallet": "$WALLET",
  "version": $VERSION,
  "epoch": "$EPOCH",
  "nonce": $NONCE,
  "executionCalldata": "$CALLS",
  "value": $VALUE,
  "at": $AT,
  "deadline": $DEADLINE,
  "callGas": $CALL_GAS,
  "sessionKey": "$KEY",
  "signature": "$SIG",
  "callMaxValue": $MAX_VALUE,
  "callProof": "$CALL_PROOF",
  "domainProof": "$DOMAIN_PROOF",
  "paymasterProof": "$PAYMASTER_PROOF",
  "authorizationHash": "$(cast keccak "$AUTH")",
  "dataHash": "$(cast keccak "$DATA")",
  "digest": "$DIGEST",
  "epochZeroDigest": "$EPOCH_ZERO_DIGEST",
  "belowQuorumHash": "$BELOW",
  "userOpHash": "$USER_OP_HASH",
  "userOpDigest": "$USER_OP_DIGEST"
}
JSON

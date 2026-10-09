// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, Vm} from "forge-std/Test.sol";

import {AttestationBuilder} from "../../ceremony/test/AttestationBuilder.sol";

/// @notice The scan a private bind is held to: no byte run of the id or the
///         handle, raw or folded, in a log or a storage word it wrote.
///
/// @dev "Private" means not disclosed, not unguessable: anyone holding a
///      candidate can hash it and look it up. What a private bind must not do
///      is put the id or the handle on chain itself.
abstract contract PrivacyScan is Test {
    /// The id, the handle as the platform sent it, and the handle folded:
    /// the bytes a private bind must leave nowhere.
    function _secrets() internal pure virtual returns (string[3] memory);

    /// Whether `data` carries the id, the handle as sent, or the handle folded.
    function _containsAny(bytes memory data) internal pure returns (bool) {
        string[3] memory secrets = _secrets();
        for (uint256 i = 0; i < secrets.length; ++i) {
            if (AttestationBuilder.contains(data, bytes(secrets[i]))) return true;
        }
        return false;
    }

    /// No log's topics, read as one run, or data carries a secret.
    function _assertLogsHideTheSecrets(Vm.Log[] memory logs) internal pure {
        assertGt(logs.length, 0, "nothing was logged to scan");
        for (uint256 i = 0; i < logs.length; ++i) {
            bytes memory topics;
            for (uint256 t = 0; t < logs[i].topics.length; ++t) {
                topics = bytes.concat(topics, logs[i].topics[t]);
            }
            assertFalse(_containsAny(topics), string.concat("an id or handle in the topics of log ", vm.toString(i)));
            assertFalse(
                _containsAny(logs[i].data), string.concat("an id or handle in the data of log ", vm.toString(i))
            );
        }
    }

    /// No storage word `target` wrote since `vm.record` carries a secret.
    /// Returns how many words were scanned.
    function _assertStorageHidesTheSecrets(address target) internal view returns (uint256 scanned) {
        (, bytes32[] memory writes) = vm.accesses(target);
        for (uint256 i = 0; i < writes.length; ++i) {
            assertFalse(
                _containsAny(abi.encode(vm.load(target, writes[i]))),
                string.concat("a storage slot carries an id or handle: ", vm.toString(writes[i]))
            );
        }
        return writes.length;
    }
}

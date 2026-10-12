// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, Vm} from "forge-std/Test.sol";

import {AttestationBuilder} from "../../ceremony/test/AttestationBuilder.sol";

/// @notice The scan a private bind is held to: no byte run of the id or the
///         handle, raw or folded, in its logs or the storage words it wrote
///         on any contract, each read as one run.
abstract contract PrivacyScan is Test {
    /// The id, the handle as sent, and the handle folded.
    function _secrets() internal pure virtual returns (string[3] memory);

    /// Whether `data` carries the id, the handle as sent, or the handle folded.
    function _containsAny(bytes memory data) internal pure returns (bool) {
        string[3] memory secrets = _secrets();
        for (uint256 i = 0; i < secrets.length; ++i) {
            if (AttestationBuilder.contains(data, bytes(secrets[i]))) return true;
        }
        return false;
    }

    /// No secret in every log's topics and data, joined into one run.
    function _assertLogsHideTheSecrets(Vm.Log[] memory logs) internal pure {
        assertGt(logs.length, 0, "nothing was logged to scan");
        assertFalse(_containsAny(_loggedRun(logs)), "an id or handle in the logs");
    }

    /// No secret in every storage word written since `vm.startStateDiffRecording`,
    /// on any contract, joined into one run; returns the count scanned.
    function _assertStorageHidesTheSecrets(Vm.AccountAccess[] memory accesses) internal pure returns (uint256 scanned) {
        bytes memory run;
        (run, scanned) = _writtenRun(accesses);
        assertFalse(_containsAny(run), "a storage word carries an id or handle");
    }

    /// Every log's topics and data, in order, as one run.
    function _loggedRun(Vm.Log[] memory logs) internal pure returns (bytes memory run) {
        for (uint256 i = 0; i < logs.length; ++i) {
            for (uint256 t = 0; t < logs[i].topics.length; ++t) {
                run = bytes.concat(run, logs[i].topics[t]);
            }
            run = bytes.concat(run, logs[i].data);
        }
    }

    /// Every storage word written and kept, in order, as one run, so a secret
    /// split across two words is still one match.
    function _writtenRun(Vm.AccountAccess[] memory accesses) internal pure returns (bytes memory run, uint256 words) {
        for (uint256 i = 0; i < accesses.length; ++i) {
            Vm.StorageAccess[] memory sa = accesses[i].storageAccesses;
            for (uint256 j = 0; j < sa.length; ++j) {
                if (!sa[j].isWrite || sa[j].reverted) continue;
                run = bytes.concat(run, sa[j].newValue);
                ++words;
            }
        }
    }
}

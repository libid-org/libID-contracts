// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";

/// @notice The accepted rows of the vendored `handles.json`, read from the file itself.
library HandleTable {
    Vm private constant VM = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    string internal constant PATH = "contracts/circuits/handles.json";

    struct Row {
        string platform;
        string input;
        string output;
        bytes32 handleNode;
    }

    /// Every vector with an output, in file order.
    function accepted() internal view returns (Row[] memory rows) {
        string memory json = VM.readFile(PATH);
        uint256 n;
        for (uint256 i = 0; VM.keyExistsJson(json, _row(i)); ++i) {
            if (VM.keyExistsJson(json, string.concat(_row(i), ".output"))) ++n;
        }
        rows = new Row[](n);
        n = 0;
        for (uint256 i = 0; VM.keyExistsJson(json, _row(i)); ++i) {
            string memory at = _row(i);
            if (!VM.keyExistsJson(json, string.concat(at, ".output"))) continue;
            rows[n++] = Row({
                platform: VM.parseJsonString(json, string.concat(at, ".platform")),
                input: VM.parseJsonString(json, string.concat(at, ".input")),
                output: VM.parseJsonString(json, string.concat(at, ".output")),
                handleNode: VM.parseJsonBytes32(json, string.concat(at, ".handleNode"))
            });
        }
    }

    function _row(uint256 i) private pure returns (string memory) {
        return string.concat(".vectors[", VM.toString(i), "]");
    }
}

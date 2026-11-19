// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IWalletFactory} from "../IWalletFactory.sol";
import {IWalletRegistry} from "../IWalletRegistry.sol";
import {IWebWallet} from "../IWebWallet.sol";
import {WalletBase} from "./WalletBase.sol";

/// @notice Sizes, the interface against the compiled selectors, the target table, and the pinned slots.
contract WalletAbiTest is WalletBase {
    string[7] internal CONTRACTS = [
        "WebWallet",
        "IdentityAdmin",
        "SessionRules",
        "WalletProxy",
        "WalletFactory",
        "WalletRegistry",
        "WalletForwarder"
    ];
    /// Above this, WebWallet moves its views and `isValidSignature` to a third target (S1 size probe).
    uint256 internal constant THIRD_TARGET_ABOVE = 23_500;

    function _artifact(string memory name) internal pure returns (string memory) {
        return string.concat("out/", name, ".sol/", name, ".json");
    }

    function _selectors(string memory name) internal view returns (bytes4[] memory s) {
        string[] memory sigs = vm.parseJsonKeys(vm.readFile(_artifact(name)), ".methodIdentifiers");
        s = new bytes4[](sigs.length);
        for (uint256 i; i < sigs.length; ++i) {
            s[i] = bytes4(keccak256(bytes(sigs[i])));
        }
    }

    function _has(bytes4[] memory set, bytes4 s) internal pure returns (bool) {
        for (uint256 i; i < set.length; ++i) {
            if (set[i] == s) return true;
        }
        return false;
    }

    function _hasViews() internal view returns (bool) {
        return vm.exists(_artifact("WalletViews"));
    }

    /// Acceptance 1: every contract fits EIP-170.
    function test_everyContractFitsEip170() public view {
        for (uint256 i; i < CONTRACTS.length; ++i) {
            string memory id = string.concat(CONTRACTS[i], ".sol:", CONTRACTS[i]);
            assertLe(vm.getDeployedCode(id).length, 24_576, CONTRACTS[i]);
        }
        if (_hasViews()) assertLe(vm.getDeployedCode("WalletViews.sol:WalletViews").length, 24_576, "WalletViews");
    }

    /// The S1 decision: a WebWallet above the threshold has a WalletViews target.
    function test_aLargeWalletHasAThirdTarget() public view {
        if (vm.getDeployedCode("WebWallet.sol:WebWallet").length > THIRD_TARGET_ABOVE) {
            assertTrue(_hasViews(), "WebWallet is over the third-target threshold");
        }
    }

    /// `IWebWallet` is exactly the implementation's externals plus its targets' routed selectors, and no selector
    /// is in two of them.
    function test_theInterfaceMatchesTheImplementationAndTargets() public view {
        bytes4[] memory api = _selectors("IWebWallet");
        string[3] memory parts = ["WebWallet", "IdentityAdmin", "WalletViews"];
        bytes4[][] memory sets = new bytes4[][](3);
        uint256 n = _hasViews() ? 3 : 2;
        for (uint256 p; p < n; ++p) {
            sets[p] = _selectors(parts[p]);
            for (uint256 i; i < sets[p].length; ++i) {
                bytes4 s = sets[p][i];
                assertTrue(_has(api, s), string.concat(parts[p], " external not in IWebWallet"));
                for (uint256 q; q < p; ++q) {
                    assertFalse(_has(sets[q], s), string.concat(parts[p], " clashes with ", parts[q]));
                }
            }
        }
        for (uint256 i; i < api.length; ++i) {
            bool found;
            for (uint256 p; p < n && !found; ++p) {
                found = _has(sets[p], api[i]);
            }
            assertTrue(found, "IWebWallet declares a selector nothing implements");
        }
    }

    /// Each target refuses a call at its own address.
    function test_targetsRefuseDirectCalls() public {
        address[2] memory targets = [identityAdmin, sessionRules];
        string[2] memory ids = ["IdentityAdmin", "SessionRules"];
        for (uint256 t; t < targets.length; ++t) {
            bytes4[] memory s = _selectors(ids[t]);
            assertGt(s.length, 0, ids[t]);
            for (uint256 i; i < s.length; ++i) {
                (bool ok, bytes memory err) = targets[t].call(abi.encodePacked(s[i], new bytes(256)));
                assertFalse(ok, string.concat(ids[t], " answered a direct call"));
                assertEq(bytes4(err), IWebWallet.NotDelegated.selector, ids[t]);
            }
        }
    }

    /// Acceptance 10: namespaces against their ERC-7201 derivations, and the slots on a live wallet.
    function test_slotsAreTheirErc7201Derivations() public {
        string[5] memory ids = [
            "libid.webwallet.release",
            "libid.webwallet.state",
            "libid.transient.webwallet.lock",
            "libid.transient.webwallet.entryPointBlocked",
            "libid.transient.webwallet.dataStep"
        ];
        bytes32[5] memory slots = [RELEASE_SLOT, STATE_SLOT, LOCK_SLOT, EP_BLOCKED_SLOT, DATA_STEP_SLOT];
        for (uint256 i; i < ids.length; ++i) {
            bytes32 d = keccak256(abi.encode(uint256(keccak256(bytes(ids[i]))) - 1)) & ~bytes32(uint256(0xff));
            assertEq(d, slots[i], ids[i]);
        }
        address w = _claim();
        // `{address implementation; uint64 version}` packed into one word.
        assertEq(vm.load(w, RELEASE_SLOT), bytes32(uint256(uint160(impl1)) | (uint256(1) << 160)), "release word");
        assertEq(vm.load(w, STATE_SLOT), IWebWallet(w).epoch(), "the state namespace starts with the epoch");
    }

    /// The selectors other releases and the forwarder call are frozen.
    function test_frozenSelectors() public pure {
        assertEq(IWalletRegistry.check.selector, bytes4(0xd69684bd), "registry check");
        assertEq(IWalletFactory.latest.selector, bytes4(0x52bfe789), "factory latest");
        assertEq(IWalletFactory.release.selector, bytes4(0x41fbbc31), "factory release");
        assertEq(IWebWallet.reset.selector, bytes4(0x12a20190), "reset");
    }
}

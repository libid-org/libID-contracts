// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IWalletFactory} from "../IWalletFactory.sol";
import {
    ADD_SESSION_DOMAIN,
    IWalletRegistry,
    LINK_IDENTITY_DOMAIN,
    REMOVE_SESSIONS_DOMAIN
} from "../IWalletRegistry.sol";
import {AUTHORIZED_MODE, IIdentityAdmin, IWalletCore, IWebWallet} from "../IWebWallet.sol";
import {SessionRules} from "../SessionRules.sol";
import {WalletBase} from "./WalletBase.sol";

/// Answers every call with `ROUTED`, to stand in for IdentityAdmin.
contract RoutedStub {
    bytes32 internal constant ROUTED = keccak256("routed to IdentityAdmin");

    fallback() external payable {
        bytes32 r = ROUTED;
        assembly {
            mstore(0, r)
            return(0, 32)
        }
    }
}

/// @notice Sizes, the target table, and the pinned slots.
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

    /// `_target`'s table: every `IIdentityAdmin` selector, which `test_theTargetTableIsIIdentityAdmin` checks.
    function _adminSelectors() internal pure returns (bytes4[26] memory) {
        return [
            IIdentityAdmin.genesisIdentity.selector,
            IIdentityAdmin.linkIdentity.selector,
            IIdentityAdmin.addSessionByLogin.selector,
            IIdentityAdmin.removeSessionsByLogin.selector,
            IIdentityAdmin.addSession.selector,
            IIdentityAdmin.revokeSession.selector,
            IIdentityAdmin.setAppList.selector,
            IIdentityAdmin.sessionOf.selector,
            IIdentityAdmin.isLinked.selector,
            IIdentityAdmin.appList.selector,
            IIdentityAdmin.allowanceOf.selector,
            IIdentityAdmin.generationOf.selector,
            IIdentityAdmin.linkedPlatforms.selector,
            IIdentityAdmin.hadSession.selector,
            IIdentityAdmin.queueRoot.selector,
            IIdentityAdmin.cancelRoot.selector,
            IIdentityAdmin.executeRoot.selector,
            IIdentityAdmin.rootOperation.selector,
            IIdentityAdmin.rootReadyAt.selector,
            IIdentityAdmin.threshold.selector,
            IIdentityAdmin.rootDelay.selector,
            IIdentityAdmin.rootEpoch.selector,
            IIdentityAdmin.bump.selector,
            IIdentityAdmin.setThreshold.selector,
            IIdentityAdmin.setRootDelay.selector,
            IIdentityAdmin.unlink.selector
        ];
    }

    function _isAdmin(bytes4 selector) internal pure returns (bool) {
        bytes4[26] memory admin = _adminSelectors();
        for (uint256 i; i < admin.length; ++i) {
            if (admin[i] == selector) return true;
        }
        return false;
    }

    /// Acceptance 1: every contract fits EIP-170.
    function test_everyContractFitsEip170() public view {
        for (uint256 i; i < CONTRACTS.length; ++i) {
            string memory id = string.concat(CONTRACTS[i], ".sol:", CONTRACTS[i]);
            assertLe(vm.getDeployedCode(id).length, 24_576, CONTRACTS[i]);
        }
    }

    /// `_target` routes every `IIdentityAdmin` selector to IdentityAdmin, and SessionRules' to none. The table's
    /// selectors are distinct and XOR to `IIdentityAdmin`'s interface id, so the list is the interface.
    function test_theTargetTableIsIIdentityAdmin() public {
        bytes4[26] memory admin = _adminSelectors();
        bytes4 id;
        for (uint256 i; i < admin.length; ++i) {
            for (uint256 j; j < i; ++j) {
                assertNotEq(admin[i], admin[j], "a selector listed twice");
            }
            id ^= admin[i];
        }
        assertEq(id, type(IIdentityAdmin).interfaceId, "the table is not IIdentityAdmin");
        address w = _routedWallet();
        for (uint256 i; i < admin.length; ++i) {
            assertTrue(_routed(w, admin[i]), "an IIdentityAdmin selector is not in _target");
        }
        assertFalse(_routed(w, SessionRules.allowed.selector), "SessionRules.allowed routed");
        assertFalse(_routed(w, SessionRules.allowedExecution.selector), "SessionRules.allowedExecution routed");
    }

    /// No selector outside `IIdentityAdmin` reaches IdentityAdmin.
    function testFuzz_noOtherSelectorRoutes(bytes4 selector) public {
        vm.assume(!_isAdmin(selector));
        assertFalse(_routed(_routedWallet(), selector), "routed");
    }

    /// A wallet whose IdentityAdmin answers `ROUTED`.
    function _routedWallet() internal returns (address w) {
        w = _claim();
        vm.etch(identityAdmin, address(new RoutedStub()).code);
    }

    function _routed(address w, bytes4 selector) internal returns (bool) {
        (bool ok, bytes memory r) = w.call(abi.encodePacked(selector, new bytes(256)));
        return ok && r.length == 32 && bytes32(r) == keccak256("routed to IdentityAdmin");
    }

    /// A selector no entry has reverts by name.
    function test_anUnknownSelectorRevertsByName() public {
        address w = _claim();
        (bool ok, bytes memory err) = w.call(abi.encodePacked(bytes4(0xdeadbeef), new bytes(64)));
        assertFalse(ok, "answered");
        assertEq(err, abi.encodeWithSelector(IWebWallet.UnknownSelector.selector, bytes4(0xdeadbeef)), "error");
    }

    /// A release whose IdentityAdmin or SessionRules has no code does not deploy.
    function test_aReleaseNeedsCodeAtItsTargets() public {
        address none = makeAddr("no code");
        bytes memory code = vm.getCode("WebWallet.sol:WebWallet");
        vm.expectRevert(abi.encodeWithSelector(IWebWallet.TargetWithoutCode.selector, none));
        this.create(bytes.concat(code, abi.encode(factory, registry, 2, none, sessionRules)));
        vm.expectRevert(abi.encodeWithSelector(IWebWallet.TargetWithoutCode.selector, none));
        this.create(bytes.concat(code, abi.encode(factory, registry, 2, identityAdmin, none)));
        assertGt(
            this.create(bytes.concat(code, abi.encode(factory, registry, 2, identityAdmin, sessionRules))).code.length,
            0
        );
    }

    /// Deploys `initcode`; a revert bubbles.
    function create(bytes memory initcode) external returns (address d) {
        assembly ("memory-safe") {
            d := create(0, add(initcode, 0x20), mload(initcode))
            if iszero(d) {
                returndatacopy(0, 0, returndatasize())
                revert(0, returndatasize())
            }
        }
    }

    /// Each target refuses a call at its own address.
    function test_targetsRefuseDirectCalls() public {
        bytes4[26] memory admin = _adminSelectors();
        for (uint256 i; i < admin.length; ++i) {
            _refusesDirect(identityAdmin, admin[i]);
        }
        _refusesDirect(sessionRules, SessionRules.allowed.selector);
        _refusesDirect(sessionRules, SessionRules.allowedExecution.selector);
    }

    function _refusesDirect(address t, bytes4 selector) internal {
        (bool ok, bytes memory err) = t.call(abi.encodePacked(selector, new bytes(256)));
        assertFalse(ok, "a target answered a direct call");
        assertEq(bytes4(err), IWebWallet.NotDelegated.selector, "not NotDelegated");
    }

    /// Acceptance 10: namespaces against their ERC-7201 derivations, and the slots on a live wallet.
    function test_slotsAreTheirErc7201Derivations() public {
        string[6] memory ids = [
            "libid.webwallet.release",
            "libid.webwallet.state",
            "libid.transient.webwallet.lock",
            "libid.transient.webwallet.entryPointBlocked",
            "libid.transient.webwallet.dataStep",
            "libid.transient.webwallet.loginsFirst"
        ];
        bytes32[6] memory slots =
            [RELEASE_SLOT, STATE_SLOT, LOCK_SLOT, EP_BLOCKED_SLOT, DATA_STEP_SLOT, LOGINS_FIRST_SLOT];
        for (uint256 i; i < ids.length; ++i) {
            assertEq(_erc7201(ids[i]), slots[i], ids[i]);
        }
        address w = _claim();
        // `{address implementation; uint64 version}` packed into one word.
        assertEq(vm.load(w, RELEASE_SLOT), bytes32(uint256(uint160(impl1)) | (uint256(1) << 160)), "release word");
        assertEq(vm.load(w, STATE_SLOT), IWebWallet(w).epoch(), "the state namespace starts with the epoch");
    }

    /// The selectors other releases and the forwarder call are frozen.
    function test_frozenSelectors() public pure {
        assertEq(IWalletRegistry.check.selector, bytes4(0xfd606387), "registry check");
        assertEq(IWalletFactory.latest.selector, bytes4(0x52bfe789), "factory latest");
        assertEq(IWalletFactory.release.selector, bytes4(0x41fbbc31), "factory release");
        assertEq(IWalletCore.reset.selector, bytes4(0x12a20190), "reset");
    }

    /// Acceptance 10: the mode and domains against their strings, the factory's and the registry's namespaces on
    /// the live proxies, and the return layouts other releases decode.
    function test_pinnedValuesAndLayouts() public {
        bytes32 selector = bytes32(bytes4(keccak256("libid.webwallet.authorized"))) >> 48;
        assertEq(AUTHORIZED_MODE, bytes32(uint256(0x01) << 248) | selector, "AUTHORIZED_MODE");
        assertEq(LINK_IDENTITY_DOMAIN, keccak256("libid.webwallet.link-identity"), "link domain");
        assertEq(ADD_SESSION_DOMAIN, keccak256("libid.webwallet.add-session"), "add domain");
        assertEq(REMOVE_SESSIONS_DOMAIN, keccak256("libid.webwallet.remove-sessions"), "remove domain");

        // `{uint64 latest; mapping(uint64 => address) releases}`; `latest()` answers two words.
        bytes32 f = _erc7201("libid.storage.WalletFactory");
        assertEq(vm.load(address(factory), f), bytes32(uint256(1)), "the factory's latest");
        bytes32 at1 = keccak256(abi.encode(uint256(1), uint256(f) + 1));
        assertEq(vm.load(address(factory), at1), bytes32(uint256(uint160(impl1))), "the factory's release 1");
        (, bytes memory latest) = address(factory).staticcall(abi.encodeCall(IWalletFactory.latest, ()));
        assertEq(latest, abi.encode(impl1, uint256(1)), "latest() layout");

        // `check` answers `Checked` as one tuple; the digest is spent at `spentDigests[digest]`.
        bytes memory payload = _linkPayload(mallory, X, MALLORY, _key(MALLORY_PK), _admin());
        vm.prank(mallory);
        (bool ok, bytes memory checked) = address(registry)
            .call(abi.encodeCall(IWalletRegistry.check, (LINK, X, V1, payload, mallory, _ph(_admin()))));
        assertTrue(ok, "check");
        bytes memory expected = abi.encodePacked(
            uint256(0x20), _identity(X, MALLORY), uint256(0x60), uint256(0xa0), uint256(20), bytes32(_key(MALLORY_PK))
        );
        assertEq(checked, abi.encodePacked(expected, uint256(6), bytes32("client")), "Checked layout");
        bytes32 spent = keccak256(abi.encode(_digestOf(payload), _erc7201("libid.storage.WalletRegistry")));
        assertEq(vm.load(address(registry), spent), bytes32(uint256(1)), "the registry's spent digest");
    }

    /// Acceptance 11: `fixtures/direct-execute-vector.json`, written by `cast` alone, against the encodings the
    /// suites sign with. The Rust and TypeScript helper tests read it too.
    function test_theClientVector() public {
        string memory j = vm.readFile("contracts/wallet/test/fixtures/direct-execute-vector.json");
        assertEq(AUTHORIZED_MODE, vm.parseJsonBytes32(j, ".authorizedMode"), "AUTHORIZED_MODE");
        assertEq(EXECUTE_TYPEHASH, vm.parseJsonBytes32(j, ".executeTypehash"), "Execute typehash");
        assertEq(USER_OP_TYPEHASH, vm.parseJsonBytes32(j, ".userOperationTypehash"), "UserOperation typehash");
        vm.chainId(vm.parseJsonUint(j, ".chainId"));
        address w = vm.parseJsonAddress(j, ".wallet");
        uint64 version = uint64(vm.parseJsonUint(j, ".version"));
        bytes32 epoch = vm.parseJsonBytes32(j, ".epoch");
        bytes32 salt = vm.parseJsonBytes32(j, ".salt");
        assertEq(keccak256(abi.encode(epoch, uint32(vm.parseJsonUint(j, ".rootEpoch")))), salt, "salt");
        uint48 at = uint48(vm.parseJsonUint(j, ".at"));

        IWalletCore.SessionSignature[] memory s = new IWalletCore.SessionSignature[](1);
        s[0] = IWalletCore.SessionSignature(vm.parseJsonBytes(j, ".sessionKey"), vm.parseJsonBytes(j, ".signature"));
        IWalletCore.CallProof[] memory c = new IWalletCore.CallProof[](1);
        c[0] = IWalletCore.CallProof(vm.parseJsonUint(j, ".callMaxValue"), new bytes32[](1));
        c[0].proof[0] = vm.parseJsonBytes32(j, ".callProof");
        bytes32[] memory domainProof = new bytes32[](1);
        bytes32[] memory paymasterProof = new bytes32[](1);
        (domainProof[0], paymasterProof[0]) =
        (vm.parseJsonBytes32(j, ".domainProof"), vm.parseJsonBytes32(j, ".paymasterProof"));
        bytes memory auth = abi.encode(IWalletCore.Authorization(s, at, c, domainProof, paymasterProof));
        assertEq(keccak256(auth), vm.parseJsonBytes32(j, ".authorizationHash"), "Authorization, no prefix");

        bytes memory calls = vm.parseJsonBytes(j, ".executionCalldata");
        (uint256 value, uint48 deadline, uint256[] memory callGas) = (
            vm.parseJsonUint(j, ".value"),
            uint48(vm.parseJsonUint(j, ".deadline")),
            vm.parseJsonUintArray(j, ".callGas")
        );
        bytes memory data = abi.encode(calls, value, deadline, callGas, auth);
        assertEq(keccak256(data), vm.parseJsonBytes32(j, ".dataHash"), "AUTHORIZED data");
        // Nonce key 0: the full nonce is the sequence.
        bytes32 execute = keccak256(
            abi.encode(
                EXECUTE_TYPEHASH,
                AUTHORIZED_MODE,
                keccak256(calls),
                value,
                at,
                vm.parseJsonUint(j, ".nonce"),
                deadline,
                keccak256(abi.encodePacked(callGas))
            )
        );
        bytes32 digest = _typed(w, version, salt, execute);
        assertEq(digest, vm.parseJsonBytes32(j, ".digest"), "Execute digest");
        assertEq(
            _typed(w, version, keccak256(abi.encode(bytes32(0), uint32(0))), execute),
            vm.parseJsonBytes32(j, ".epochZeroDigest"),
            "Execute digest, epoch 0"
        );
        assertEq(
            keccak256(abi.encode(digest, at, keccak256(s[0].key))),
            vm.parseJsonBytes32(j, ".belowQuorumHash"),
            "below-quorum hash"
        );
        bytes32 userOpHash = vm.parseJsonBytes32(j, ".userOpHash");
        assertEq(
            _typed(w, version, salt, keccak256(abi.encode(USER_OP_TYPEHASH, userOpHash))),
            vm.parseJsonBytes32(j, ".userOpDigest"),
            "nested userOpHash"
        );
    }

    /// The vector's operation domains and link or login transaction data, which the registry accepts for its wallet.
    function test_theTransactionDataVector() public {
        string memory j = vm.readFile("contracts/wallet/test/fixtures/direct-execute-vector.json");
        assertEq(LINK_IDENTITY_DOMAIN, vm.parseJsonBytes32(j, ".linkIdentityDomain"), "link domain");
        assertEq(ADD_SESSION_DOMAIN, vm.parseJsonBytes32(j, ".addSessionDomain"), "add domain");
        assertEq(REMOVE_SESSIONS_DOMAIN, vm.parseJsonBytes32(j, ".removeSessionsDomain"), "remove domain");
        vm.chainId(vm.parseJsonUint(j, ".chainId"));
        address w = vm.parseJsonAddress(j, ".wallet");
        address submitter = vm.parseJsonAddress(j, ".submitter");
        bytes memory key = vm.parseJsonBytes(j, ".sessionKey");
        bytes32 policyHash = vm.parseJsonBytes32(j, ".policyHash");
        bytes memory keyed = vm.parseJsonBytes(j, ".keyedTransactionData");
        bytes memory keyless = vm.parseJsonBytes(j, ".keylessTransactionData");
        assertEq(keyed, abi.encode(block.chainid, w, submitter, key, policyHash), "keyed");
        assertEq(keyless, abi.encode(block.chainid, w, submitter, "", bytes32(0)), "keyless");

        bytes memory payload = _payload(X, ALICE, ADD, keyed);
        vm.prank(w);
        assertEq(registry.check(ADD, X, V1, payload, submitter, policyHash).key, key, "the registry's key");
        payload = _payload(X, ALICE, LINK, keyless);
        vm.prank(w);
        assertEq(registry.check(LINK, X, V1, payload, submitter, policyHash).key, bytes(""), "a link's key");
    }

    function _erc7201(string memory id) internal pure returns (bytes32) {
        return keccak256(abi.encode(uint256(keccak256(bytes(id))) - 1)) & ~bytes32(uint256(0xff));
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Execution} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";

import {AttestationBuilder} from "../../ceremony/test/AttestationBuilder.sol";
import {operationList} from "../../ceremony/test/OperationListVector.sol";
import {CeremonyAuthorization} from "../../ceremony/CeremonyAuthorization.sol";
import {ICeremony} from "../../ceremony/ICeremony.sol";
import {INotaryService} from "../../ceremony/INotaryService.sol";
import {IPlatformVerifier} from "../../ceremony/IPlatformVerifier.sol";
import {IProofVerifier} from "../../ceremony/IProofVerifier.sol";
import {NotaryService} from "../../ceremony/NotaryService.sol";
import {IHonkVerifier} from "../../ceremony/PlatformVerifierBase.sol";
import {TlsNotaryVerifierBase} from "../../ceremony/TlsNotaryVerifierBase.sol";
import {XPlatformVerifier} from "../../ceremony/XPlatformVerifier.sol";
import {IdentityRegistry} from "../../identity/IdentityRegistry.sol";
import {AUTHORIZED_MODE, CALL_OVERHEAD, IIdentityAdmin, IWebWallet} from "../IWebWallet.sol";
import {WalletBase} from "./WalletBase.sol";

/// @notice Acceptance 2: one `createAndExecute` onboards on one real X list proof: link K and bind the handle.
/// @dev The fixture's token session is re-signed by its test notary key with each new digest's code_verifier; the
///      circuit's own verifier checks the proof.
contract WalletRealProofTest is WalletBase {
    string constant SESSION = "contracts/ceremony/test/fixtures/x-ceremony-session.json";
    uint256 constant NOTARY_KEY = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    uint16 constant VX = 2;

    string session;
    string proof;
    bytes32 idNode;
    bytes32 handleNode;
    IdentityRegistry identities;

    function setUp() public override {
        super.setUp();
        session = vm.readFile(SESSION);
        proof = vm.readFile("contracts/ceremony/test/fixtures/x-ceremony-session-proof.json");
        bytes32[] memory inputs = vm.parseJsonBytes32Array(proof, ".public_inputs");
        (idNode, handleNode) = (AttestationBuilder.nodeAt(inputs, 8), AttestationBuilder.nodeAt(inputs, 10));
        address notary = address(
            new ERC1967Proxy(
                address(new NotaryService()),
                abi.encodeCall(NotaryService.initialize, (owner, vm.addr(NOTARY_KEY), 0.001 ether))
            )
        );
        address x = address(
            new ERC1967Proxy(
                address(new XPlatformVerifier()),
                abi.encodeCall(
                    XPlatformVerifier.initialize,
                    (
                        owner,
                        INotaryService(notary),
                        IHonkVerifier(vm.deployCode("BearerLinkHonkVerifier.sol:BearerLinkHonkVerifier"))
                    )
                )
            )
        );
        identities = IdentityRegistry(
            address(
                new ERC1967Proxy(address(new IdentityRegistry()), abi.encodeCall(IdentityRegistry.initialize, (owner)))
            )
        );
        vm.startPrank(owner);
        proofVerifier.setVerifier(X, VX, IPlatformVerifier(x));
        identities.setProofVerifier(IProofVerifier(address(proofVerifier)));
        vm.stopPrank();
        vm.warp(vm.parseJsonUint(session, ".created_at") + 60);
    }

    /// The fixture's proof for `domain` and `data`.
    function _real(bytes32 domain, bytes memory data) internal view returns (bytes memory) {
        uint16 version = uint16(vm.parseJsonUint(session, ".ceremony_version"));
        bytes32 nonce = vm.parseJsonBytes32(session, ".authorization_nonce");
        bytes memory oldVerifier =
            CeremonyAuthorization.codeVerifier(vm.parseJsonBytes32(session, ".authorization_digest"), nonce);
        bytes memory newVerifier =
            CeremonyAuthorization.codeVerifier(CeremonyAuthorization.digest(domain, version, nonce, data), nonce);
        ICeremony.Attestation memory token = AttestationBuilder.fixtureSession(session, ".token");
        uint256 at = AttestationBuilder.indexOf(token.attestedData, oldVerifier);
        require(at != type(uint256).max, "verifier not in the record");
        for (uint256 i; i < newVerifier.length; ++i) {
            token.attestedData[at + i] = newVerifier[i];
        }
        token.proof = AttestationBuilder.sign(NOTARY_KEY, token.attestedData);
        return abi.encode(
            TlsNotaryVerifierBase.TlsNotaryProof({
                ceremonyVersion: version,
                operationDomain: domain,
                authorizationNonce: nonce,
                transactionData: data,
                tokenSession: token,
                identitySession: AttestationBuilder.fixtureSession(session, ".identity"),
                idNode: idNode,
                handleNode: handleNode,
                proof: vm.parseJsonBytes(proof, ".proof")
            })
        );
    }

    /// The real onboarding's batch for `w`, its Notary Fee in `w`: link K, then bind the handle.
    function _realOnboarding(address w) internal returns (Execution[] memory x) {
        bytes memory linkData = _txData(w, _key(ALICE_PK), _ph(_admin()));
        bytes memory list = _real(OPERATIONS, operationList(BIND, abi.encode(w), LINK, linkData));
        uint256 fee = registry.quote(X, VX);
        vm.deal(w, fee);
        x = new Execution[](2);
        x[0] = _x(w, fee, abi.encodeCall(IIdentityAdmin.linkIdentity, (X, VX, list, _admin())));
        // The link verified this proof, so the bind pays no second Notary Fee.
        x[1] = _x(address(identities), 0, abi.encodeCall(IdentityRegistry.bindPrivately, (X, VX, list, 0, address(0))));
    }

    /// forge-config: gas.isolate = true
    function test_oneCreateAndExecuteOnboardsOnOneRealListProof() public {
        address w = factory.walletAddress(X, idNode, 0);
        bytes memory data = _signedAt(w, 1, _pks(ALICE_PK), abi.encode(_realOnboarding(w)), false);
        vm.prank(relayer, relayer);
        factory.createAndExecute(X, idNode, 0, AUTHORIZED_MODE, data);
        Vm.Gas memory used = vm.lastFrameGas();

        assertEq(identities.resolveId(idNode), w, "not bound");
        IIdentityAdmin.Session memory k = IWebWallet(w).sessionOf(_key(ALICE_PK));
        assertTrue(k.admin && k.identity == _identity(X, idNode), "K is not the genesis session");
        // forge-lint: disable-next-line(unsafe-typecast)
        uint256 gas = used.gasTotalUsed - uint64(used.gasRefunded);
        vm.snapshotValue("wallet-claim", "createAndExecute onboarding(real X proof, operation list)", gas);
    }

    /// Runs `createAndExecute` on `data` with `gas`, then undoes it. Returns whether it ran, the gas it took and what
    /// it returned.
    function _tryOnboarding(bytes memory data, uint256 gas)
        internal
        returns (bool ok, uint256 used, bytes memory returned)
    {
        uint256 state = vm.snapshotState();
        bytes memory call = abi.encodeCall(factory.createAndExecute, (X, idNode, 0, AUTHORIZED_MODE, data));
        vm.prank(relayer, relayer);
        uint256 left = gasleft();
        (ok, returned) = address(factory).call{gas: gas}(call);
        used = left - gasleft();
        vm.revertToState(state);
    }

    /// The least gas above `lo` that `data` runs on.
    function _leastGas(bytes memory data, uint256 lo) internal returns (uint256 hi) {
        hi = 30e6;
        (bool runs,,) = _tryOnboarding(data, hi);
        assertTrue(runs, "control");
        while (lo + 1 < hi) {
            uint256 mid = (lo + hi) / 2;
            (runs,,) = _tryOnboarding(data, mid);
            (lo, hi) = runs ? (lo, mid) : (mid, hi);
        }
    }

    /// The least gas the real onboarding runs on, each call's floor 1.25 times its gas as a relayer quotes it: the
    /// gas of the batch's prefix that ends with it, less the prefix before it. The empty prefix stops at the
    /// signature check, which K, not yet linked, fails. Against it, the dearest floor for every call. The crate's
    /// bound on the gas that gives each call its floor covers the least gas.
    function test_theRealOnboardingsLeastGas() public {
        address w = factory.walletAddress(X, idNode, 0);
        Execution[] memory x = _realOnboarding(w);
        uint256[] memory floors = new uint256[](x.length);
        uint256[] memory before = new uint256[](x.length);
        (uint256 last, uint256 dearest) = (0, 0);
        for (uint256 k; k <= x.length; ++k) {
            Execution[] memory cut = new Execution[](k);
            for (uint256 i; i < k; ++i) {
                cut[i] = x[i];
            }
            bytes memory data = _signedAt(w, 1, _pks(ALICE_PK), abi.encode(cut), false, new uint256[](k));
            (bool ok, uint256 used, bytes memory returned) = _tryOnboarding(data, 30e6);
            bool unsigned = k == 0 && bytes4(returned) == IWebWallet.ExecutionNotSigned.selector;
            assertTrue(ok || unsigned, "a prefix did not run");
            if (k > 0) floors[k - 1] = ((used - last) * 5 + 3) / 4;
            if (k > 0 && floors[k - 1] > dearest) dearest = floors[k - 1];
            if (k < x.length) before[k] = used;
            last = used;
        }
        uint256 each = _leastGas(_signedAt(w, 1, _pks(ALICE_PK), abi.encode(x), false, floors), last / 2);
        uint256 bound;
        for (uint256 i; i < floors.length; ++i) {
            uint256 b = _scaled(before[i], 3) + _scaled(floors[i] + CALL_OVERHEAD, 4);
            if (b > bound) bound = b;
        }
        assertGe(bound, each, "the bound is below the least gas");
        for (uint256 i; i < floors.length; ++i) {
            floors[i] = dearest;
        }
        uint256 one = _leastGas(_signedAt(w, 1, _pks(ALICE_PK), abi.encode(x), false, floors), last / 2);
        assertLt(each, one, "a floor per call needs as much gas as the dearest floor for each");
        vm.snapshotValue(
            "wallet-claim", "createAndExecute onboarding(real X proof) least frame gas, each call's floor", each
        );
        vm.snapshotValue(
            "wallet-claim", "createAndExecute onboarding(real X proof) least frame gas, dearest floor", one
        );
    }

    /// `gas × (64/63)^frames`, rounded up: what `frames` nested calls need to pass `gas` on.
    function _scaled(uint256 gas, uint256 frames) internal pure returns (uint256) {
        return (gas * 64 ** frames + 63 ** frames - 1) / 63 ** frames;
    }

    /// The same onboarding on a stub proof: the wallet's share of the gas, plus the stub's store of the whole payload.
    /// forge-config: gas.isolate = true
    function test_oneCreateAndExecuteOnboardsOnOneStubListProof() public {
        address w = factory.walletAddress(X, idNode, 0);
        bytes memory linkData = _txData(w, _key(ALICE_PK), _ph(_admin()));
        bytes memory list = _payload(X, idNode, OPERATIONS, operationList(BIND, abi.encode(w), LINK, linkData));
        Execution[] memory x = new Execution[](2);
        x[0] = _x(w, 0, abi.encodeCall(IIdentityAdmin.linkIdentity, (X, V1, list, _admin())));
        x[1] = _x(address(identities), 0, abi.encodeCall(IdentityRegistry.bindPrivately, (X, V1, list, 0, address(0))));
        bytes memory data = _signedAt(w, 1, _pks(ALICE_PK), abi.encode(x), false);
        vm.prank(relayer, relayer);
        factory.createAndExecute(X, idNode, 0, AUTHORIZED_MODE, data);
        Vm.Gas memory used = vm.lastFrameGas();

        assertEq(identities.resolveId(idNode), w, "not bound");
        // forge-lint: disable-next-line(unsafe-typecast)
        uint256 gas = used.gasTotalUsed - uint64(used.gasRefunded);
        vm.snapshotValue("wallet-claim", "createAndExecute onboarding(stub proof, operation list)", gas);
    }
}

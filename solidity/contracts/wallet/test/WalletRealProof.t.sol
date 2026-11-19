// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Execution} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";

import {AttestationBuilder} from "../../ceremony/test/AttestationBuilder.sol";
import {HonkStub} from "../../ceremony/test/HonkStub.sol";
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
import {AUTHORIZED_MODE, IWebWallet} from "../IWebWallet.sol";
import {WalletBase} from "./WalletBase.sol";

/// @notice Acceptance 2: one `createAndExecute` onboards on one real X list proof: link K and bind the handle.
/// @dev The fixture's token session is re-signed by its test notary key with each new digest's code_verifier.
contract WalletRealProofTest is WalletBase {
    string constant SESSION = "contracts/ceremony/test/fixtures/x-ceremony-session.json";
    uint256 constant NOTARY_KEY = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    bytes32 constant OPERATIONS = 0x60b329d7366897b03545eb9f63f4a707253258ee2e1cd0ba3a8973aa4959e967;
    bytes32 constant BIND = 0x4d59cd4487de0a5957f8c83addaac7a1238175aa5c29eeea2fbef57a8f5165ac;
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
                    (owner, INotaryService(notary), IHonkVerifier(HonkStub.deploy(HonkStub.BEARER_LINK)))
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

    /// forge-config: gas.isolate = true
    function test_oneCreateAndExecuteOnboardsOnOneRealListProof() public {
        address w = factory.walletAddress(X, idNode, 0);
        bytes memory linkData = _txData(w, _key(ALICE_PK), _ph(_admin()));
        bytes memory list = _real(OPERATIONS, operationList(BIND, abi.encode(w), LINK, linkData));
        uint256 fee = registry.quote(X, VX);
        vm.deal(w, fee);
        Execution[] memory x = new Execution[](2);
        x[0] = _x(w, fee, abi.encodeCall(IWebWallet.linkIdentity, (X, VX, list, linkData, _admin())));
        // The link verified this proof, so the bind pays no second Notary Fee.
        x[1] = _x(address(identities), 0, abi.encodeCall(IdentityRegistry.bindPrivately, (X, VX, list, 0, address(0))));
        bytes memory data = _signedAt(w, 1, _pks(ALICE_PK), abi.encode(x), false);
        vm.prank(relayer, relayer);
        factory.createAndExecute(X, idNode, 0, AUTHORIZED_MODE, data);
        Vm.Gas memory used = vm.lastFrameGas();

        assertEq(identities.resolveId(idNode), w, "not bound");
        IWebWallet.Session memory k = IWebWallet(w).sessionOf(_key(ALICE_PK));
        assertTrue(k.admin && k.identity == _identity(X, idNode), "K is not the genesis session");
        // forge-lint: disable-next-line(unsafe-typecast)
        uint256 gas = used.gasTotalUsed - uint64(used.gasRefunded);
        vm.snapshotValue("wallet-claim", "createAndExecute onboarding(real X proof, operation list)", gas);
    }
}

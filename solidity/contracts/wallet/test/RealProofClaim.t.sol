// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {AttestationBuilder} from "../../ceremony/test/AttestationBuilder.sol";
import {HonkStub} from "../../ceremony/test/HonkStub.sol";
import {CeremonyAuthorization} from "../../ceremony/CeremonyAuthorization.sol";
import {ICeremony} from "../../ceremony/ICeremony.sol";
import {INotaryService} from "../../ceremony/INotaryService.sol";
import {IPlatformVerifier} from "../../ceremony/IPlatformVerifier.sol";
import {NotaryService} from "../../ceremony/NotaryService.sol";
import {IHonkVerifier} from "../../ceremony/PlatformVerifierBase.sol";
import {TlsNotaryVerifierBase} from "../../ceremony/TlsNotaryVerifierBase.sol";
import {XPlatformVerifier} from "../../ceremony/XPlatformVerifier.sol";
import {NATIVE_TOKEN} from "../../escrow/HandleEscrow.sol";
import {IIdentityValidator} from "../IIdentityValidator.sol";
import {Relay} from "./ClaimExecutor.t.sol";
import {WalletTestBase} from "./WalletTestBase.sol";

/// The claim and a session by proof through the real X verifier, NotaryService and Honk verifier.
/// @dev The fixture's token session is re-signed by its own test notary key with the code_verifier
///      of each new digest; the identity session and the Honk proof are the fixture's.
contract RealProofClaimTest is WalletTestBase {
    string constant SESSION = "contracts/ceremony/test/fixtures/x-ceremony-session.json";
    string constant PROOF = "contracts/ceremony/test/fixtures/x-ceremony-session-proof.json";
    uint256 constant NOTARY_KEY = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    uint256 constant NOTARY_FEE = 0.001 ether;
    uint16 constant VX = 2;

    string session;
    string proof;
    bytes32 idNode;
    bytes32 handleNode;

    function setUp() public override {
        super.setUp();
        session = vm.readFile(SESSION);
        proof = vm.readFile(PROOF);
        bytes32[] memory inputs = vm.parseJsonBytes32Array(proof, ".public_inputs");
        idNode = AttestationBuilder.nodeAt(inputs, 8);
        handleNode = AttestationBuilder.nodeAt(inputs, 10);

        address notary = address(
            new ERC1967Proxy(
                address(new NotaryService()),
                abi.encodeCall(NotaryService.initialize, (owner, vm.addr(NOTARY_KEY), NOTARY_FEE))
            )
        );
        address x = address(
            new ERC1967Proxy(
                address(new XPlatformVerifier()),
                abi.encodeCall(
                    XPlatformVerifier.initialize,
                    (owner, INotaryService(notary), IHonkVerifier(vm.deployCode(HonkStub.BEARER_LINK)))
                )
            )
        );
        vm.prank(owner);
        proofVerifier.setVerifier(X, VX, IPlatformVerifier(x));
        vm.warp(vm.parseJsonUint(session, ".created_at") + 60);
        vm.deal(relayer, 1 ether);
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

        TlsNotaryVerifierBase.TlsNotaryProof memory p;
        p.ceremonyVersion = version;
        p.operationDomain = domain;
        p.authorizationNonce = nonce;
        p.transactionData = data;
        p.tokenSession = token;
        p.identitySession = AttestationBuilder.fixtureSession(session, ".identity");
        p.idNode = idNode;
        p.handleNode = handleNode;
        p.proof = vm.parseJsonBytes(proof, ".proof");
        return abi.encode(p);
    }

    /// The claim in one relayer transaction: create, bind with one real proof, claim to the wallet.
    function _claimReal() internal returns (address w, uint256 gas) {
        w = factory.walletAddress(X, idNode);
        escrow.deposit{value: 0.01 ether}(X, handleNode, NATIVE_TOKEN, 0.01 ether);
        bytes memory bind = _real(BIND, abi.encode(w));
        uint256 fee = identities.quoteBind(X, VX);
        Relay relay = new Relay();
        vm.prank(relayer);
        relay.claim{value: fee}(factory, executor, X, VX, idNode, handleNode, bind);
        gas = vm.lastFrameGas().gasTotalUsed;
        assertEq(identities.resolveId(idNode), w, "not bound");
        assertEq(w.balance, 0.01 ether, "not claimed");
    }

    function test_aClaimWithARealProof() public {
        (, uint256 gas) = _claimReal();
        // The frame's gas, written only by `FOUNDRY_PROFILE=gas forge test`.
        vm.snapshotValue("wallet-claim", "Relay.claim(real X proof)", gas);
    }

    /// The claimed wallet's first session, by a second real proof: active at once.
    function test_aFirstSessionByARealProof() public {
        (address w,) = _claimReal();
        IIdentityValidator.Policy memory p = _admin();
        bytes memory add = _real(ADD, _txData(w, _key(ALICE_PK), _ph(p)));
        uint256 fee = registry.quote(X, VX);
        vm.prank(relayer);
        registry.addSessionByProof{value: fee}(X, VX, add, p);
        emit log_named_uint("addSessionByProof frame gas", vm.lastFrameGas().gasTotalUsed);
        assertLe(validator.sessionOf(w, _key(ALICE_PK)).activeAt, _now(), "the first session waits");
        _handle(_signed(_op(w, 0, _hit()), _pks(ALICE_PK)));
        assertEq(target.calls(), 1, "the session could not act");
    }
}

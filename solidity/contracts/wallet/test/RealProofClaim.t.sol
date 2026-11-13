// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Execution} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
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
import {IHandleEscrow} from "../../escrow/IHandleEscrow.sol";
import {IIdentityRegistry} from "../../identity/IIdentityRegistry.sol";
import {StubPlatformVerifier} from "../../identity/test/StubPlatformVerifier.sol";
import {IIdentityValidator} from "../IIdentityValidator.sol";
import {IWalletRegistry} from "../IWalletRegistry.sol";
import {AUTHORIZED_MODE} from "../IWebWallet.sol";
import {ExecuteBase} from "./DirectExecute.t.sol";
import {operationList} from "./WalletTestBase.sol";

/// Onboarding in one `createAndExecute` through the real X verifier, NotaryService and Honk verifier, and a
/// session by proof after it.
/// @dev The fixture's token session is re-signed by its own test notary key with the code_verifier
///      of each new digest; the identity session and the Honk proof are the fixture's.
contract RealProofClaimTest is ExecuteBase {
    string constant SESSION = "contracts/ceremony/test/fixtures/x-ceremony-session.json";
    string constant PROOF = "contracts/ceremony/test/fixtures/x-ceremony-session-proof.json";
    uint256 constant NOTARY_KEY = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    uint256 constant NOTARY_FEE = 0.001 ether;
    uint256 constant CLAIMED = 0.01 ether;
    uint256 constant BOT_PK = 0xB07;
    uint16 constant VX = 2;
    uint16 constant VSTUB = 3;
    /// The fixture's OAuth client.
    bytes constant X_CLIENT = "myClient-1";

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
        StubPlatformVerifier paid = new StubPlatformVerifier(X, NOTARY_FEE);
        paid.setNodes(idNode, handleNode);
        vm.startPrank(owner);
        proofVerifier.setVerifier(X, VX, IPlatformVerifier(x));
        proofVerifier.setVerifier(X, VSTUB, IPlatformVerifier(address(paid)));
        vm.stopPrank();
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

    /// A stub proof for `domain` and `data`.
    function _stubbed(bytes32 domain, bytes memory data) internal pure returns (bytes memory) {
        return abi.encode(
            StubPlatformVerifier.StubPayload({
                ceremonyVersion: 1,
                operationDomain: domain,
                authorizationNonce: bytes32(uint256(1)),
                transactionData: data
            })
        );
    }

    /// The Operation List a proof of `version` carries for Alice's new wallet: bind it, and link K.
    function _list(uint16 version) internal view returns (bytes memory) {
        address w = factory.walletAddress(X, idNode);
        bytes memory data = operationList(BIND, abi.encode(w), LINK, _txData(w, _key(ALICE_PK), _ph(_admin())));
        return version == VX ? _real(OPERATIONS, data) : _stubbed(OPERATIONS, data);
    }

    /// The relayer onboards Alice with one list proof in one `createAndExecute`: the batch K signs links K,
    /// binds the handle, claims the escrow, repays the relayer and adds a bot's session.
    function _onboard(uint16 version, bytes memory list) internal returns (address w, uint256 gas) {
        w = factory.walletAddress(X, idNode);
        escrow.deposit{value: CLAIMED}(X, handleNode, NATIVE_TOKEN, CLAIMED);
        uint256 linkFee = registry.quote(X, version);
        uint256 bindFee = identities.quoteBind(X, version);
        address[] memory tokens = new address[](1);
        tokens[0] = NATIVE_TOKEN;
        Execution[] memory x = new Execution[](5);
        x[0] =
            _x(address(registry), linkFee, abi.encodeCall(IWalletRegistry.linkIdentity, (X, version, list, _admin())));
        x[1] = _x(
            address(identities),
            bindFee,
            abi.encodeCall(IIdentityRegistry.bindPrivately, (X, version, list, 0, address(0)))
        );
        x[2] = _x(address(escrow), 0, abi.encodeCall(IHandleEscrow.claim, (handleNode, tokens, w)));
        x[3] = _x(relayer, linkFee + bindFee, "");
        x[4] = _x(
            address(validator),
            0,
            abi.encodeCall(IIdentityValidator.addSession, (_identity(X, idNode), _key(BOT_PK), _hitOnly()))
        );
        bytes memory calls = abi.encode(x);
        uint256 n = uint256(uint160(address(validator))) << 96;
        bytes memory auth = _aliceFor(w, calls, n);
        vm.prank(relayer, relayer);
        factory.createAndExecute{value: linkFee + bindFee}(X, idNode, AUTHORIZED_MODE, _data(calls, auth));
        gas = vm.lastFrameGas().gasTotalUsed;

        assertEq(identities.resolveId(idNode), w, "not bound");
        assertEq(w.balance, CLAIMED - linkFee - bindFee, "not claimed");
        assertEq(relayer.balance, 1 ether, "the relayer is not repaid");
        IIdentityValidator.Session memory k = validator.sessionOf(w, _key(ALICE_PK));
        assertTrue(k.admin && k.activeAt == 0, "K is not the first session");
        assertEq(validator.sessionOf(w, _key(BOT_PK)).activeAt, _now(), "no bot session");
    }

    function test_oneCreateAndExecuteOnboardsOnOneRealListProof() public {
        (, uint256 gas) = _onboard(VX, _list(VX));
        // The frame's gas, written only by `FOUNDRY_PROFILE=gas forge test`.
        vm.snapshotValue("wallet-claim", "createAndExecute onboarding(real X proof, operation list)", gas);
    }

    function test_oneCreateAndExecuteOnboardsOnOneStubListProof() public {
        (, uint256 gas) = _onboard(VSTUB, _list(VSTUB));
        // The frame's gas, written only by `FOUNDRY_PROFILE=gas forge test`.
        vm.snapshotValue("wallet-claim", "createAndExecute onboarding(stub proof, operation list)", gas);
    }

    /// Once the wallet had a session, a second real proof adds a session that waits the recovery delay.
    function test_aSessionByARealProof() public {
        (address w,) = _onboard(VX, _list(VX));
        IIdentityValidator.Policy memory p = _admin();
        bytes memory add = _real(ADD, _txData(w, _key(ALICE2_PK), _ph(p)));
        uint256 fee = registry.quote(X, VX);
        vm.prank(relayer);
        registry.addSessionByProof{value: fee}(X, VX, add, p);
        assertEq(validator.sessionOf(w, _key(ALICE2_PK)).activeAt, _now() + validator.recoveryDelay(w), "not pending");
    }
}

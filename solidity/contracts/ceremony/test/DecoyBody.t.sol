// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {HonkStub} from "./HonkStub.sol";
import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {AttestationBuilder} from "./AttestationBuilder.sol";
import {CeremonyAuthorization} from "../CeremonyAuthorization.sol";
import {CeremonyProfile} from "../CeremonyProfile.sol";
import {ICeremony} from "../ICeremony.sol";
import {INotaryService} from "../INotaryService.sol";
import {NotaryService} from "../NotaryService.sol";
import {IHonkVerifier} from "../PlatformVerifierBase.sol";
import {TlsNotaryVerifierBase} from "../TlsNotaryVerifierBase.sol";
import {XPlatformVerifier} from "../XPlatformVerifier.sol";

/// @notice A token request whose real body is committed and a decoy body is revealed after it.
contract DecoyBodyTest is Test {
    using AttestationBuilder for AttestationBuilder.Direction;

    XPlatformVerifier verifier;
    NotaryService notary;
    uint256 quote;

    address constant OWNER = address(0xA11CE);
    uint256 constant KEY = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    uint256 constant FEE = 0.001 ether;
    uint64 constant T0 = 1_770_000_000;
    bytes32 constant DOMAIN = keccak256(bytes("libid.bind-identity"));
    bytes32 constant AUTH_NONCE = bytes32(uint256(0x5555555555555555555555555555555555555555555555555555555555555555));
    /// The digest the fixtures are made for, derived in `setUp`.
    bytes32 digest;
    bytes32 constant TOKEN_C = bytes32(uint256(0x1111));
    bytes32 constant ID_C = bytes32(uint256(0x2222));

    function setUp() public {
        digest = CeremonyAuthorization.digest(DOMAIN, 1, AUTH_NONCE, _txData());
        vm.warp(T0 + 10);
        NotaryService ni = new NotaryService();
        notary = NotaryService(
            address(new ERC1967Proxy(address(ni), abi.encodeCall(NotaryService.initialize, (OWNER, vm.addr(KEY), FEE))))
        );
        address honkAddr = HonkStub.deploy(HonkStub.BEARER_LINK);
        XPlatformVerifier vi = new XPlatformVerifier();
        verifier = XPlatformVerifier(
            address(
                new ERC1967Proxy(
                    address(vi),
                    abi.encodeCall(
                        XPlatformVerifier.initialize, (OWNER, INotaryService(address(notary)), IHonkVerifier(honkAddr))
                    )
                )
            )
        );
        quote = verifier.quote();
        vm.deal(address(this), 10 ether);
    }

    /// head revealed | REAL refresh-grant body COMMITTED | decoy body revealed
    function _decoyToken() private view returns (ICeremony.Attestation memory) {
        bytes memory decoy = abi.encodePacked(
            "grant_type=authorization_code&client_id=trustedApp&code_verifier=",
            CeremonyAuthorization.codeVerifier(digest, AUTH_NONCE)
        );
        // The head's content-length covers the committed body and the decoy.
        bytes memory head = abi.encodePacked(
            "POST /2/oauth2/token HTTP/1.1\r\nhost: api.x.com\r\n",
            "content-type: application/x-www-form-urlencoded\r\naccept: application/json\r\n",
            "connection: close\r\ncontent-length: ",
            vm.toString(90 + decoy.length),
            "\r\n\r\n"
        );
        uint32 h = uint32(head.length);
        uint32 r = h + 90; // the real body x.com actually parsed
        uint32 l = r + uint32(decoy.length);

        AttestationBuilder.Direction memory sent = AttestationBuilder.Direction({
            revealed: AttestationBuilder.two(
                AttestationBuilder.Range({start: 0, value: head}), AttestationBuilder.Range({start: r, value: decoy})
            ),
            commitments: AttestationBuilder.one(
                AttestationBuilder.Commitment({start: h, end: r, value: bytes32(uint256(0xDEC0))})
            ),
            length: l
        });

        bytes memory anchor = '"access_token":"';
        uint32 a0 = 17;
        uint32 a1 = a0 + uint32(anchor.length);
        uint32 b1 = a1 + 20;
        uint32 q1 = b1 + 1;
        AttestationBuilder.Direction memory recv = AttestationBuilder.Direction({
            revealed: AttestationBuilder.two(
                AttestationBuilder.Range({start: a0, value: anchor}), AttestationBuilder.Range({start: b1, value: '"'})
            ),
            commitments: AttestationBuilder.two(
                AttestationBuilder.Commitment({start: a1, end: b1, value: TOKEN_C}),
                AttestationBuilder.Commitment({start: q1, end: q1 + 10, value: bytes32(uint256(9))})
            ),
            length: q1 + 10
        });

        bytes memory att = AttestationBuilder.encode(CeremonyProfile.AUTHORITY_X_API, T0, sent, recv);
        return ICeremony.Attestation({attestedData: att, proof: AttestationBuilder.sign(KEY, att)});
    }

    function _identity() private pure returns (ICeremony.Attestation memory) {
        bytes memory head = "GET /2/users/me HTTP/1.1\r\nhost: api.x.com\r\nauthorization: Bearer ";
        bytes memory bearer = "VICTIMBEARERTOKEN";
        bytes memory tail = "\r\nconnection: close\r\n\r\n";
        uint32 s0 = uint32(head.length);
        uint32 e0 = s0 + uint32(bearer.length);
        uint32 l = e0 + uint32(tail.length);
        AttestationBuilder.Direction memory sent = AttestationBuilder.Direction({
            revealed: AttestationBuilder.two(
                AttestationBuilder.Range({start: 0, value: head}), AttestationBuilder.Range({start: e0, value: tail})
            ),
            commitments: AttestationBuilder.one(AttestationBuilder.Commitment({start: s0, end: e0, value: ID_C})),
            length: l
        });
        // Id and handle committed, the anchors around them revealed.
        AttestationBuilder.Direction memory recv;
        recv.commit('{"data":{', bytes32(uint256(0x5555)))
            .reveal('"id":"')
            .commit("2244994945", bytes32(uint256(0x3333)))
            .reveal('","username":"')
            .commit("victim", bytes32(uint256(0x4444)))
            .reveal('"')
            .commit("}}", bytes32(uint256(0x5555)));
        bytes memory att = AttestationBuilder.encode(CeremonyProfile.AUTHORITY_X_API, T0, sent, recv);
        return ICeremony.Attestation({attestedData: att, proof: AttestationBuilder.sign(KEY, att)});
    }

    function _txData() private pure returns (bytes memory) {
        return abi.encode(address(0xBEEF));
    }

    function _submission() private view returns (TlsNotaryVerifierBase.TlsNotaryProof memory s) {
        s.ceremonyVersion = 1;
        s.operationDomain = DOMAIN;
        s.authorizationNonce = AUTH_NONCE;
        s.transactionData = _txData();
        s.proof = hex"00";
        s.tokenSession = _decoyToken();
        s.identitySession = _identity();
    }

    function run(TlsNotaryVerifierBase.TlsNotaryProof memory s)
        external
        payable
        returns (ICeremony.VerifiedClaim memory)
    {
        return verifier.verify{value: msg.value}(abi.encode(s));
    }

    /// @dev Coverage tiles, so only the token request layout check refuses it.
    function test_aCommittedBodyWithARevealedDecoyIsRejected() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _submission();
        vm.expectPartialRevert(TlsNotaryVerifierBase.WrongTokenRequestLayout.selector);
        this.run{value: quote}(s);
    }
}

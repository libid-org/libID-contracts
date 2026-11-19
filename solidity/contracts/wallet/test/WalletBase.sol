// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, Vm} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IEntryPoint, PackedUserOperation} from "@openzeppelin/contracts/interfaces/IERC4337.sol";
import {Execution} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";

import {CeremonyAuthorization} from "../../ceremony/CeremonyAuthorization.sol";
import {CeremonyProfile} from "../../ceremony/CeremonyProfile.sol";
import {CeremonyProofVerifier} from "../../ceremony/CeremonyProofVerifier.sol";
import {IPlatformVerifier} from "../../ceremony/IPlatformVerifier.sol";
import {IProofVerifier} from "../../ceremony/IProofVerifier.sol";
import {LibidFactory} from "../../factory/LibidFactory.sol";
import {StubPlatformVerifier} from "../../identity/test/StubPlatformVerifier.sol";
import {IWalletFactory} from "../IWalletFactory.sol";
import {IWalletRegistry} from "../IWalletRegistry.sol";
import {AUTHORIZED_MODE, IWebWallet} from "../IWebWallet.sol";

/// Records who called it.
contract CallTarget {
    uint256 public calls;
    address public last;

    function hit() external payable {
        calls++;
        last = msg.sender;
    }
}

/// `getUserOpHash` of EntryPoint v0.9, which OpenZeppelin's interface leaves out.
interface IUserOpHash {
    function getUserOpHash(PackedUserOperation calldata op) external view returns (bytes32);
}

/// @notice The wallet stack on stub Platform Verifiers and EntryPoint v0.9 at its canonical address.
/// @dev Production contracts are deployed by artifact name, so this compiles before they exist.
///      `_release` is where the implementation's constructor arguments live.
abstract contract WalletBase is Test {
    address internal constant EP = 0x433709009B8330FDa32311DF1C2AFA402eD8D009;

    // cast keccak of the domain strings.
    bytes32 internal constant LINK = 0xb76778e70fe9491d05f3d66a477c7f1cb97c40b477b88d0c00442e80bcc4e15c;
    bytes32 internal constant ADD = 0xadc0929729a450db24efd5992bbc0f04693c7d8e9d706da31c8cca0a429d1d59;
    // cast keccak "libid.webwallet.remove-sessions", "libid.operations", "libid.bind"
    bytes32 internal constant REMOVE = 0x7cabdd831000d819c7b2ae4f79b4d6b566aa21992764e735f944b1459cb43c1b;
    bytes32 internal constant OPERATIONS = 0x60b329d7366897b03545eb9f63f4a707253258ee2e1cd0ba3a8973aa4959e967;
    bytes32 internal constant BIND = 0x4d59cd4487de0a5957f8c83addaac7a1238175aa5c29eeea2fbef57a8f5165ac;
    // cast keccak "Execute(bytes32 mode,bytes executionCalldata,uint256 value,uint48 at,uint256 nonce,uint48 deadline,uint256 callGas)"
    bytes32 internal constant EXECUTE_TYPEHASH = 0x6158eac44095e4b05d0f638c3e232c7f3a2dc8872b50069fc5cfe697b4fb8cf2;
    // cast keccak "UserOperation(bytes32 userOpHash)"
    bytes32 internal constant USER_OP_TYPEHASH = 0xfc7b070108d04ee052d98f0eb394be32e2271d51fb81ec12ed483b3e5c633795;
    bytes32 internal constant PERSONAL_SIGN = 0x983e65e5148e570cd828ead231ee759a8d7958721a768f93bc4483ba005c32de;

    // cast index-erc7201 of each namespace.
    bytes32 internal constant RELEASE_SLOT = 0xe1dba8fb066a3b169f681c6818aeab86343e7484c7e0cee1cbf00e41a55c2800;
    bytes32 internal constant STATE_SLOT = 0x2fefcc1cd2f12f011dc78ce30301455eb7a4a027395fa8fbcaed6284d99cf200;
    bytes32 internal constant LOCK_SLOT = 0xc9e10f29671c1e91671796ae10cf0910e186e77a658823020379090d44874400;
    bytes32 internal constant EP_BLOCKED_SLOT = 0xd9893535c4c4b5cd665ca764f2da4f77d7dc5ab6d2372696ca69936a0c362100;
    bytes32 internal constant DATA_STEP_SLOT = 0x634693ff7eb334934b2860ed0d3d3a4ad5bfbd5aa7959baa8bf9f0bcd8c88000;

    bytes32 internal constant MODE_SINGLE = bytes32(0);
    bytes32 internal constant MODE_BATCH = bytes32(uint256(0x01) << 248);

    bytes32 internal constant X = CeremonyProfile.PLATFORM_X;
    bytes32 internal constant GITHUB = CeremonyProfile.PLATFORM_GITHUB;
    bytes32 internal constant ALICE = keccak256("alice's X id node");
    bytes32 internal constant BOB = keccak256("bob's GitHub id node");
    bytes32 internal constant MALLORY = keccak256("mallory's X id node");
    uint16 internal constant V1 = 1;
    uint256 internal constant CALL_GAS = 200_000;
    bytes32 internal constant MAIL = keccak256("a Mail");
    string internal constant MAIL_TYPE = "Mail(address to)";

    uint256 internal constant ALICE_PK = 0xA11CE;
    uint256 internal constant ALICE2_PK = 0xA11CE2;
    uint256 internal constant BOB_PK = 0xB0B;
    uint256 internal constant BOT_PK = 0xB07;
    uint256 internal constant MALLORY_PK = 0xBAD;

    LibidFactory internal names;
    CeremonyProofVerifier internal proofVerifier;
    StubPlatformVerifier internal xStub;
    StubPlatformVerifier internal githubStub;
    IWalletRegistry internal registry;
    IWalletFactory internal factory;
    address internal identityAdmin;
    address internal sessionRules;
    address internal impl1;
    CallTarget internal target;

    address internal owner = makeAddr("owner");
    address internal relayer = makeAddr("relayer");
    address internal mallory = makeAddr("mallory");
    address internal bundler = makeAddr("bundler");

    uint256 private proofNonce;

    function setUp() public virtual {
        string memory json = vm.readFile("contracts/wallet/test/fixtures/entrypoint-v0.9.json");
        vm.etch(EP, vm.parseJsonBytes(json, ".entryPoint.code"));
        vm.etch(vm.parseJsonAddress(json, ".senderCreator.address"), vm.parseJsonBytes(json, ".senderCreator.code"));

        proofVerifier = CeremonyProofVerifier(
            address(
                new ERC1967Proxy(
                    address(new CeremonyProofVerifier()), abi.encodeCall(CeremonyProofVerifier.initialize, (owner))
                )
            )
        );
        xStub = new StubPlatformVerifier(X, 0);
        githubStub = new StubPlatformVerifier(GITHUB, 0);
        vm.startPrank(owner);
        proofVerifier.setVerifier(X, V1, IPlatformVerifier(address(xStub)));
        proofVerifier.setVerifier(GITHUB, V1, IPlatformVerifier(address(githubStub)));
        vm.stopPrank();

        names = LibidFactory(
            address(new ERC1967Proxy(address(new LibidFactory()), abi.encodeCall(LibidFactory.initialize, (owner))))
        );
        bytes memory init = abi.encodeCall(IWalletRegistry.initialize, (owner, IProofVerifier(address(proofVerifier))));
        address registryImpl = deployCode("WalletRegistry.sol:WalletRegistry");
        vm.prank(owner);
        registry = IWalletRegistry(names.deploy("WalletRegistry", _proxyCode(registryImpl, init)));
        address factoryImpl = _factoryImpl();
        vm.prank(owner);
        factory = IWalletFactory(
            names.deploy("WalletFactory", _proxyCode(factoryImpl, abi.encodeCall(IWalletFactory.initialize, (owner))))
        );

        identityAdmin = deployCode("IdentityAdmin.sol:IdentityAdmin");
        sessionRules = deployCode("SessionRules.sol:SessionRules");
        impl1 = _publish(1);
        target = new CallTarget();
        // Stub observation times lie in the past.
        vm.warp(1_800_000_000);
    }

    function _proxyCode(address implementation, bytes memory init) private pure returns (bytes memory) {
        return abi.encodePacked(type(ERC1967Proxy).creationCode, abi.encode(implementation, init));
    }

    /// A WalletFactory implementation for `registry`.
    function _factoryImpl() internal returns (address) {
        return deployCode("WalletFactory.sol:WalletFactory", abi.encode(address(registry)));
    }

    /// A WebWallet implementation of `version` for `factory_`.
    function _releaseFor(address factory_, uint64 version) internal virtual returns (address) {
        return deployCode(
            "WebWallet.sol:WebWallet", abi.encode(factory_, address(registry), version, identityAdmin, sessionRules)
        );
    }

    function _publish(uint64 version) internal returns (address impl) {
        impl = _releaseFor(address(factory), version);
        vm.prank(owner);
        factory.publish(impl);
    }

    // ─── Identities, policies and proofs ────────────────────────────

    function _identity(bytes32 platformId, bytes32 idNode) internal pure returns (bytes32) {
        return keccak256(abi.encode(platformId, idNode));
    }

    /// The policy hash, its rules hash expanded word by word.
    function _ph(IWebWallet.Policy memory p) internal pure returns (bytes32) {
        IWebWallet.Allowance[] memory a = p.rules.allowances;
        bytes memory words =
            abi.encodePacked(p.rules.scopeRoot, p.rules.domainsRoot, p.rules.paymastersRoot, uint256(0x80), a.length);
        for (uint256 i; i < a.length; ++i) {
            words = abi.encodePacked(words, uint256(uint160(a[i].token)), uint256(a[i].amount), uint256(a[i].period));
        }
        return keccak256(abi.encode(p.validAfter, p.validUntil, p.admin, p.signers, keccak256(words)));
    }

    function _admin() internal pure returns (IWebWallet.Policy memory p) {
        p.admin = true;
        p.rules.allowances = new IWebWallet.Allowance[](0);
    }

    /// A non-admin policy whose scope is the one call `target.hit()`.
    function _hitOnly() internal view returns (IWebWallet.Policy memory p) {
        p.rules.allowances = new IWebWallet.Allowance[](0);
        p.rules.scopeRoot =
            keccak256(bytes.concat(keccak256(abi.encode(address(target), CallTarget.hit.selector, uint256(0)))));
    }

    function _key(uint256 pk) internal pure returns (bytes memory) {
        return abi.encodePacked(vm.addr(pk));
    }

    function _txData(address w, bytes memory key, bytes32 policyHash) internal view returns (bytes memory) {
        return abi.encode(vm.getChainId(), w, key, policyHash);
    }

    /// A stub payload proving `idNode` on `platformId` for `domain` and `data`. Writes the stub.
    function _payload(bytes32 platformId, bytes32 idNode, bytes32 domain, bytes memory data)
        internal
        returns (bytes memory)
    {
        _stub(platformId).setNodes(idNode, keccak256("some handle node"));
        return abi.encode(
            StubPlatformVerifier.StubPayload({
                ceremonyVersion: 1,
                operationDomain: domain,
                authorizationNonce: bytes32(++proofNonce),
                transactionData: data
            })
        );
    }

    function _stub(bytes32 platformId) internal view virtual returns (StubPlatformVerifier) {
        return platformId == GITHUB ? githubStub : xStub;
    }

    /// The digest a stub payload commits to, from the ceremony's own formula.
    function _digestOf(bytes memory payload) internal pure returns (bytes32) {
        StubPlatformVerifier.StubPayload memory p = abi.decode(payload, (StubPlatformVerifier.StubPayload));
        return
            CeremonyAuthorization.digest(p.operationDomain, p.ceremonyVersion, p.authorizationNonce, p.transactionData);
    }

    /// `w`'s self-call linking `(platformId, idNode)` with session `key` under `p`; an empty key links only.
    function _linkX(address w, bytes32 platformId, bytes32 idNode, bytes memory key, IWebWallet.Policy memory p)
        internal
        returns (Execution memory)
    {
        return _linkWith(w, platformId, _linkPayload(w, platformId, idNode, key, p), p);
    }

    /// A link proof for `w`; a link only carries policy hash 0.
    function _linkPayload(address w, bytes32 platformId, bytes32 idNode, bytes memory key, IWebWallet.Policy memory p)
        internal
        returns (bytes memory)
    {
        return _payload(platformId, idNode, LINK, _txData(w, key, key.length == 0 ? bytes32(0) : _ph(p)));
    }

    function _linkWith(address w, bytes32 platformId, bytes memory payload, IWebWallet.Policy memory p)
        internal
        pure
        returns (Execution memory)
    {
        return _x(w, 0, abi.encodeCall(IWebWallet.linkIdentity, (platformId, V1, payload, "", p)));
    }

    /// A login proof for `w` adding `key` under `p`.
    function _loginPayload(address w, bytes32 platformId, bytes32 idNode, bytes memory key, IWebWallet.Policy memory p)
        internal
        returns (bytes memory)
    {
        return _payload(platformId, idNode, ADD, _txData(w, key, _ph(p)));
    }

    // ─── Batches ────────────────────────────────────────────────────

    function _x(address to, uint256 value, bytes memory data) internal pure returns (Execution memory) {
        return Execution({target: to, value: value, callData: data});
    }

    function _hitX() internal view returns (Execution memory) {
        return _x(address(target), 0, abi.encodeCall(CallTarget.hit, ()));
    }

    function _one(Execution memory a) internal pure returns (bytes memory) {
        Execution[] memory x = new Execution[](1);
        x[0] = a;
        return abi.encode(x);
    }

    function _two(Execution memory a, Execution memory b) internal pure returns (bytes memory) {
        Execution[] memory x = new Execution[](2);
        (x[0], x[1]) = (a, b);
        return abi.encode(x);
    }

    /// The AUTHORIZED batches' EntryPoint nonce: key 0.
    function _nonce(address w) internal view returns (uint256) {
        return IEntryPoint(EP).getNonce(w, 0);
    }

    /// `w`'s EIP-712 domain separator under release `version` and `salt`, written from the spec.
    function _domain(address w, uint64 version, bytes32 salt) internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"
                ),
                keccak256("WebWallet"),
                keccak256(bytes(vm.toString(uint256(version)))),
                vm.getChainId(),
                w,
                salt
            )
        );
    }

    /// `w`'s domain salt, `keccak256(abi.encode(epoch, rootEpoch))`, read from its storage: the epoch, then
    /// `epochs[epoch]`, whose slot 3 holds the root epoch at byte offset 6.
    function _salt(address w) internal view returns (bytes32) {
        bytes32 epoch = vm.load(w, STATE_SLOT);
        bytes32 state = keccak256(abi.encode(epoch, uint256(STATE_SLOT) + 1));
        uint32 rootEpoch = uint32(uint256(vm.load(w, bytes32(uint256(state) + 3))) >> 48);
        return keccak256(abi.encode(epoch, rootEpoch));
    }

    function _typed(address w, uint64 version, bytes32 structHash) internal view returns (bytes32) {
        return _typed(w, version, _salt(w), structHash);
    }

    function _typed(address w, uint64 version, bytes32 salt, bytes32 structHash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked(hex"1901", _domain(w, version, salt), structHash));
    }

    /// `pks` sign `h` at `at`; below quorum, each signs `h` bound to `at` and the first key, with `calls`.
    function _auth(uint256[] memory pks, bytes32 h, uint48 at, bool below, uint256 calls)
        internal
        pure
        returns (bytes memory)
    {
        bytes32 signed = below ? keccak256(abi.encode(h, at, keccak256(_key(pks[0])))) : h;
        IWebWallet.SessionSignature[] memory s = new IWebWallet.SessionSignature[](pks.length);
        for (uint256 i; i < pks.length; ++i) {
            (uint8 v, bytes32 r, bytes32 sv) = vm.sign(pks[i], signed);
            s[i] = IWebWallet.SessionSignature({key: _key(pks[i]), signature: abi.encodePacked(r, sv, v)});
        }
        IWebWallet.CallProof[] memory p = new IWebWallet.CallProof[](calls);
        for (uint256 i; i < calls; ++i) {
            p[i].proof = new bytes32[](0);
        }
        return abi.encode(
            IWebWallet.Authorization({
                signatures: s, at: at, calls: p, domainProof: new bytes32[](0), paymasterProof: new bytes32[](0)
            })
        );
    }

    function _pks(uint256 a) internal pure returns (uint256[] memory r) {
        r = new uint256[](1);
        r[0] = a;
    }

    function _pks(uint256 a, uint256 b) internal pure returns (uint256[] memory r) {
        r = new uint256[](2);
        (r[0], r[1]) = (a, b);
    }

    /// `AUTHORIZED_MODE` data of `calls` signed by `pks` under `version`'s domain at `w`'s next nonce.
    function _signedAt(address w, uint64 version, uint256[] memory pks, bytes memory calls, bool below)
        internal
        view
        returns (bytes memory)
    {
        uint48 at = uint48(_now());
        uint48 deadline = uint48(_now() + 1 hours);
        bytes32 s = keccak256(
            abi.encode(
                EXECUTE_TYPEHASH, AUTHORIZED_MODE, keccak256(calls), uint256(0), at, _nonce(w), deadline, CALL_GAS
            )
        );
        uint256 n = below ? abi.decode(calls, (Execution[])).length : 0;
        return abi.encode(calls, uint256(0), deadline, CALL_GAS, _auth(pks, _typed(w, version, s), at, below, n));
    }

    function _signed(address w, uint256[] memory pks, bytes memory calls) internal view returns (bytes memory) {
        return _signedAt(w, IWebWallet(w).VERSION(), pks, calls, false);
    }

    /// Alice's signed batch, relayed.
    function _run(address w, bytes memory calls) internal {
        bytes memory data = _signed(w, _pks(ALICE_PK), calls);
        vm.prank(relayer);
        IWebWallet(w).execute(AUTHORIZED_MODE, data);
    }

    /// Alice's wallet at salt 0: its genesis bootstrap links her identity with her admin session.
    function _claim() internal returns (address w) {
        w = _claimAs(X, ALICE, 0, ALICE_PK);
    }

    function _claimAs(bytes32 platformId, bytes32 idNode, uint256 salt, uint256 pk) internal returns (address) {
        return _claimAs(platformId, idNode, salt, pk, _admin());
    }

    /// The bootstrap adds `pk`'s session under `p`.
    function _claimAs(bytes32 platformId, bytes32 idNode, uint256 salt, uint256 pk, IWebWallet.Policy memory p)
        internal
        returns (address w)
    {
        vm.prank(relayer);
        w = factory.createWallet(platformId, idNode, salt);
        bytes memory calls = _one(_linkX(w, platformId, idNode, _key(pk), p));
        bytes memory data = _signed(w, _pks(pk), calls);
        vm.prank(relayer);
        IWebWallet(w).execute(AUTHORIZED_MODE, data);
        vm.deal(w, 1 ether);
    }

    // ─── UserOperations ─────────────────────────────────────────────

    function _op(address w, bytes memory callData) internal view returns (PackedUserOperation memory) {
        return PackedUserOperation({
            sender: w,
            nonce: _nonce(w),
            initCode: "",
            callData: callData,
            accountGasLimits: bytes32((uint256(1_000_000) << 128) | 1_000_000),
            preVerificationGas: 100_000,
            gasFees: bytes32((uint256(1 gwei) << 128) | 1 gwei),
            paymasterAndData: "",
            signature: ""
        });
    }

    /// `pks` sign the EntryPoint's hash of `op` nested under `version`'s domain.
    function _signOp(PackedUserOperation memory op, uint64 version, uint256[] memory pks)
        internal
        view
        returns (PackedUserOperation memory)
    {
        bytes32 h = IUserOpHash(EP).getUserOpHash(op);
        op.signature = _auth(
            pks, _typed(op.sender, version, keccak256(abi.encode(USER_OP_TYPEHASH, h))), uint48(_now()), false, 0
        );
        return op;
    }

    function _hitCall() internal view returns (bytes memory) {
        return abi.encodeCall(
            IWebWallet.execute,
            (MODE_SINGLE, abi.encodePacked(address(target), uint256(0), abi.encodeCall(CallTarget.hit, ())))
        );
    }

    function _handle(PackedUserOperation[] memory ops) internal {
        for (uint256 i; i < ops.length; ++i) {
            vm.deal(ops[i].sender, ops[i].sender.balance + 1 ether);
        }
        vm.prank(bundler, bundler);
        IEntryPoint(EP).handleOps(ops, payable(bundler));
    }

    function _ops(PackedUserOperation memory op) internal pure returns (PackedUserOperation[] memory ops) {
        ops = new PackedUserOperation[](1);
        ops[0] = op;
    }

    /// `handleOps` refuses `op` in validation, whether `validateUserOp` fails or reverts.
    function _refusedOp(PackedUserOperation memory op) internal {
        vm.deal(op.sender, op.sender.balance + 1 ether);
        vm.prank(bundler, bundler);
        try IEntryPoint(EP).handleOps(_ops(op), payable(bundler)) {
            revert("accepted in validation");
        } catch (bytes memory err) {
            bytes4 s = bytes4(err);
            assertTrue(
                s == IEntryPoint.FailedOp.selector || s == IEntryPoint.FailedOpWithRevert.selector, "not FailedOp"
            );
        }
    }

    // ─── ERC-1271 ───────────────────────────────────────────────────

    /// Whether `pk`'s ERC-7739 PersonalSign of `h` under `version`'s domain is valid at `w`.
    function _valid1271(address w, uint64 version, uint256 pk, bytes32 h) internal view returns (bool) {
        bytes32 signed = _typed(w, version, keccak256(abi.encode(PERSONAL_SIGN, h)));
        return
            IWebWallet(w).isValidSignature(h, _auth(_pks(pk), signed, uint48(_now()), false, 0)) == bytes4(0x1626ba7e);
    }

    // ─── Root operations ────────────────────────────────────────────

    /// Alice's batch queues `data` at `w`; returns its id from `RootQueued`.
    function _queue(address w, bytes memory data) internal returns (bytes32 id) {
        vm.recordLogs();
        _run(w, _one(_x(w, 0, abi.encodeCall(IWebWallet.queueRoot, (data)))));
        Vm.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 i; i < logs.length; ++i) {
            if (logs[i].emitter == w && logs[i].topics[0] == IWebWallet.RootQueued.selector) return logs[i].topics[1];
        }
        revert("no RootQueued");
    }

    /// Past `readyAt = queued + max(rootDelay, 1)`.
    function _mature(address w) internal {
        uint256 delay = IWebWallet(w).rootDelay();
        vm.warp(_now() + (delay == 0 ? 1 : delay));
    }

    /// Queues `data`, waits out the delay, and has a relayer execute it.
    function _root(address w, bytes memory data) internal returns (bytes32 id) {
        id = _queue(w, data);
        _mature(w);
        vm.prank(relayer);
        IWebWallet(w).executeRoot(id);
    }

    // ─── State ──────────────────────────────────────────────────────

    /// No storage write of a frame that did not revert changed a value.
    function _assertNoWrites(Vm.AccountAccess[] memory acc, string memory why) internal pure {
        for (uint256 i; i < acc.length; ++i) {
            if (acc[i].reverted) continue;
            for (uint256 j; j < acc[i].storageAccesses.length; ++j) {
                Vm.StorageAccess memory s = acc[i].storageAccesses[j];
                if (s.isWrite && !s.reverted && s.previousValue != s.newValue) revert(string.concat("wrote: ", why));
            }
        }
    }

    /// The block time; `block.timestamp` can be cached across `vm.warp` under via-IR.
    function _now() internal view returns (uint256) {
        return vm.getBlockTimestamp();
    }
}

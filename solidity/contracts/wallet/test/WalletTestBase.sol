// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IEntryPoint, PackedUserOperation} from "@openzeppelin/contracts/interfaces/IERC4337.sol";
import {IERC7579Execution} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";

import {CeremonyProfile} from "../../ceremony/CeremonyProfile.sol";
import {CeremonyProofVerifier} from "../../ceremony/CeremonyProofVerifier.sol";
import {IPlatformVerifier} from "../../ceremony/IPlatformVerifier.sol";
import {IProofVerifier} from "../../ceremony/IProofVerifier.sol";
import {OperationList} from "../../ceremony/OperationList.sol";
import {HandleEscrow} from "../../escrow/HandleEscrow.sol";
import {LibidFactory} from "../../factory/LibidFactory.sol";
import {NATIVE_TOKEN} from "../../NativeToken.sol";
import {IdentityRegistry} from "../../identity/IdentityRegistry.sol";
import {StubPlatformVerifier} from "../../identity/test/StubPlatformVerifier.sol";
import {IIdentityValidator} from "../IIdentityValidator.sol";
import {IWalletFactory} from "../IWalletFactory.sol";
import {IWalletRegistry} from "../IWalletRegistry.sol";
import {IWebWallet} from "../IWebWallet.sol";

/// The Operation List of two entries, `abi.encode(Operation[])`.
function operationList(bytes32 d0, bytes memory data0, bytes32 d1, bytes memory data1) pure returns (bytes memory) {
    OperationList.Operation[] memory e = new OperationList.Operation[](2);
    e[0] = OperationList.Operation({domain: d0, data: data0});
    e[1] = OperationList.Operation({domain: d1, data: data1});
    return abi.encode(e);
}

/// Records who called it.
contract CallTarget {
    uint256 public calls;
    address public last;

    function hit() external payable {
        calls++;
        last = msg.sender;
    }
}

/// Run by delegatecall, it marks the caller's slot 0x1234.
contract SlotMarker {
    function mark() external {
        assembly {
            sstore(0x1234, 1)
        }
    }
}

/// An ERC-7913 verifier that accepts every signature.
contract AcceptingVerifier {
    function verify(bytes calldata, bytes32, bytes calldata) external pure returns (bytes4) {
        return AcceptingVerifier.verify.selector;
    }
}

/// `getUserOpHash` of EntryPoint v0.9, which OpenZeppelin's interface leaves out.
interface IUserOpHash {
    function getUserOpHash(PackedUserOperation calldata op) external view returns (bytes32);
}

/// The spec's Merkle trees, built by hand: double-hashed leaves under sorted-pair nodes.
abstract contract Trees {
    function _leaf(address t, bytes4 selector, uint256 maxValue) internal pure returns (bytes32) {
        return keccak256(bytes.concat(keccak256(abi.encode(t, selector, maxValue))));
    }

    function _domainLeaf(bytes32 separator) internal pure returns (bytes32) {
        return keccak256(bytes.concat(keccak256(abi.encode(separator))));
    }

    function _paymasterLeaf(address paymaster) internal pure returns (bytes32) {
        return keccak256(bytes.concat(keccak256(abi.encode(paymaster))));
    }

    function _pair(bytes32 a, bytes32 b) private pure returns (bytes32) {
        return a < b ? keccak256(abi.encode(a, b)) : keccak256(abi.encode(b, a));
    }

    /// The root of `leaves` and the proof of leaf `index`; an odd last node rises a level.
    function _tree(bytes32[] memory leaves, uint256 index)
        internal
        pure
        returns (bytes32 root, bytes32[] memory proof)
    {
        uint256 n = leaves.length;
        bytes32[] memory level = new bytes32[](n);
        for (uint256 i; i < n; ++i) {
            level[i] = leaves[i];
        }
        bytes32[] memory path = new bytes32[](16);
        uint256 depth;
        while (n > 1) {
            if ((index ^ 1) < n) path[depth++] = level[index ^ 1];
            for (uint256 i; i < n; i += 2) {
                level[i / 2] = i + 1 < n ? _pair(level[i], level[i + 1]) : level[i];
            }
            n = (n + 1) / 2;
            index /= 2;
        }
        proof = new bytes32[](depth);
        for (uint256 i; i < depth; ++i) {
            proof[i] = path[i];
        }
        return (level[0], proof);
    }
}

/// @notice The wallet stack on stub Platform Verifiers and EntryPoint v0.9 at its canonical address.
/// @dev Production contracts are deployed by artifact name, so this compiles before they exist.
///      A filtered `forge test` compiles only what the tests import: run `forge build` first.
///      The EntryPoint is Base mainnet's runtime code, from `fixtures/entrypoint-v0.9.json`.
abstract contract WalletTestBase is Test, Trees {
    address internal constant EP = 0x433709009B8330FDa32311DF1C2AFA402eD8D009;
    bytes32 internal constant IMPL_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    // cast keccak of the spec strings.
    bytes32 internal constant LINK = 0xb76778e70fe9491d05f3d66a477c7f1cb97c40b477b88d0c00442e80bcc4e15c;
    bytes32 internal constant ADD = 0xadc0929729a450db24efd5992bbc0f04693c7d8e9d706da31c8cca0a429d1d59;
    bytes32 internal constant BIND = 0x4d59cd4487de0a5957f8c83addaac7a1238175aa5c29eeea2fbef57a8f5165ac;
    bytes32 internal constant OPERATIONS = 0x60b329d7366897b03545eb9f63f4a707253258ee2e1cd0ba3a8973aa4959e967;
    /// The fixed Mail of `_typedSigBy`: its contents hash and type.
    bytes32 internal constant MAIL = keccak256("a Mail");
    string internal constant MAIL_TYPE = "Mail(address to)";
    bytes32 internal constant PERSONAL_SIGN = 0x983e65e5148e570cd828ead231ee759a8d7958721a768f93bc4483ba005c32de;

    bytes32 internal constant MODE_SINGLE = bytes32(0);
    bytes32 internal constant MODE_BATCH = bytes32(uint256(0x01) << 248);
    bytes32 internal constant MODE_DELEGATE = bytes32(uint256(0xff) << 248);

    bytes32 internal constant X = CeremonyProfile.PLATFORM_X;
    bytes32 internal constant GITHUB = CeremonyProfile.PLATFORM_GITHUB;
    bytes32 internal constant GOOGLE = CeremonyProfile.PLATFORM_GOOGLE;
    bytes32 internal constant ALICE = keccak256("alice's X id node");
    bytes32 internal constant BOB = keccak256("bob's GitHub id node");
    bytes32 internal constant MALLORY = keccak256("mallory's X id node");
    bytes32 internal constant CAROL = keccak256("carol's Google id node");
    uint16 internal constant V1 = 1;
    /// The factory proxy's `LibidFactory` name.
    string internal constant FACTORY_NAME = "WalletFactory";

    uint256 internal constant ALICE_PK = 0xA11CE;
    uint256 internal constant ALICE2_PK = 0xA11CE2;
    uint256 internal constant BOB_PK = 0xB0B;
    uint256 internal constant APP_PK = 0xA99;
    uint256 internal constant MALLORY_PK = 0xBAD;
    uint256 internal constant CAROL_PK = 0xCA401;

    LibidFactory internal names;
    IIdentityValidator internal validator;
    IWalletRegistry internal registry;
    IWalletFactory internal factory;
    address internal walletImpl;
    CeremonyProofVerifier internal proofVerifier;
    StubPlatformVerifier internal xStub;
    StubPlatformVerifier internal githubStub;
    StubPlatformVerifier internal googleStub;
    CallTarget internal target;
    IdentityRegistry internal identities;
    HandleEscrow internal escrow;

    address internal owner = makeAddr("owner");
    address internal relayer = makeAddr("relayer");
    address internal mallory = makeAddr("mallory");
    address internal bundler = makeAddr("bundler");

    uint256 private nonce;

    function setUp() public virtual {
        _deployEntryPoint();
        proofVerifier = CeremonyProofVerifier(
            address(
                new ERC1967Proxy(
                    address(new CeremonyProofVerifier()), abi.encodeCall(CeremonyProofVerifier.initialize, (owner))
                )
            )
        );
        xStub = new StubPlatformVerifier(X, 0);
        githubStub = new StubPlatformVerifier(GITHUB, 0);
        googleStub = new StubPlatformVerifier(GOOGLE, 0);
        identities = IdentityRegistry(
            address(
                new ERC1967Proxy(address(new IdentityRegistry()), abi.encodeCall(IdentityRegistry.initialize, (owner)))
            )
        );
        escrow = HandleEscrow(
            address(
                new ERC1967Proxy(
                    address(new HandleEscrow()), abi.encodeCall(HandleEscrow.initialize, (owner, identities))
                )
            )
        );
        vm.startPrank(owner);
        proofVerifier.setVerifier(X, V1, IPlatformVerifier(address(xStub)));
        proofVerifier.setVerifier(GITHUB, V1, IPlatformVerifier(address(githubStub)));
        proofVerifier.setVerifier(GOOGLE, V1, IPlatformVerifier(address(googleStub)));
        identities.setProofVerifier(IProofVerifier(address(proofVerifier)));
        vm.stopPrank();

        // The deployment's order: the registry and its validator name the factory proxy before it exists.
        names = LibidFactory(
            address(new ERC1967Proxy(address(new LibidFactory()), abi.encodeCall(LibidFactory.initialize, (owner))))
        );
        registry = _newRegistry(names.predict(FACTORY_NAME));
        validator = IIdentityValidator(registry.identityValidator());
        walletImpl = _walletImpl();
        bytes memory proxy = _factoryProxy(_factoryImpl(walletImpl));
        vm.prank(owner);
        factory = IWalletFactory(names.deploy(FACTORY_NAME, proxy));
        target = new CallTarget();

        // Stub observation times lie in the past.
        vm.warp(1_800_000_000);
    }

    /// A WalletRegistry, and its validator, for the wallets of `walletFactory`.
    function _newRegistry(address walletFactory) internal returns (IWalletRegistry) {
        return IWalletRegistry(
            deployCode("WalletRegistry.sol:WalletRegistry", abi.encode(address(proofVerifier), walletFactory))
        );
    }

    /// The creation code of a WalletFactory proxy owned by `owner`.
    function _factoryProxy(address implementation) internal view returns (bytes memory) {
        return abi.encodePacked(
            type(ERC1967Proxy).creationCode,
            abi.encode(implementation, abi.encodeCall(IWalletFactory.initialize, (owner)))
        );
    }

    function _walletImpl() internal returns (address) {
        return deployCode("WebWallet.sol:WebWallet", abi.encode(address(validator)));
    }

    function _factoryImpl(address walletImplementation) internal returns (address) {
        return deployCode("WalletFactory.sol:WalletFactory", abi.encode(walletImplementation));
    }

    /// The EntryPoint and the SenderCreator its immutables name, each at its own address.
    function _deployEntryPoint() private {
        string memory json = vm.readFile("contracts/wallet/test/fixtures/entrypoint-v0.9.json");
        assertEq(vm.parseJsonAddress(json, ".entryPoint.address"), EP, "fixture address");
        vm.etch(EP, vm.parseJsonBytes(json, ".entryPoint.code"));
        vm.etch(vm.parseJsonAddress(json, ".senderCreator.address"), vm.parseJsonBytes(json, ".senderCreator.code"));
    }

    // ─── Identities and proofs ──────────────────────────────────────

    function _identity(bytes32 platformId, bytes32 idNode) internal pure returns (bytes32) {
        return keccak256(abi.encode(platformId, idNode));
    }

    /// The rules hash, expanded word by word from the spec's encoding.
    function _rh(IIdentityValidator.Rules memory r) internal pure returns (bytes32) {
        IIdentityValidator.Allowance[] memory a = r.allowances;
        bytes memory words = abi.encodePacked(r.scopeRoot, r.domainsRoot, r.paymastersRoot, uint256(0x80), a.length);
        for (uint256 i; i < a.length; ++i) {
            words = abi.encodePacked(words, uint256(uint160(a[i].token)), uint256(a[i].amount), uint256(a[i].period));
        }
        return keccak256(words);
    }

    function _ph(IIdentityValidator.Policy memory p) internal pure returns (bytes32) {
        return keccak256(abi.encode(p.validAfter, p.validUntil, p.admin, p.signers, _rh(p.rules)));
    }

    function _noRules() internal pure returns (IIdentityValidator.Rules memory r) {
        r.allowances = new IIdentityValidator.Allowance[](0);
    }

    function _admin() internal pure returns (IIdentityValidator.Policy memory) {
        return IIdentityValidator.Policy({validAfter: 0, validUntil: 0, admin: true, signers: 0, rules: _noRules()});
    }

    function _app() internal pure returns (IIdentityValidator.Policy memory) {
        return IIdentityValidator.Policy({validAfter: 0, validUntil: 0, admin: false, signers: 0, rules: _noRules()});
    }

    function _key(uint256 pk) internal pure returns (bytes memory) {
        return abi.encodePacked(vm.addr(pk));
    }

    function _stub(bytes32 platformId) internal view returns (StubPlatformVerifier) {
        if (platformId == GITHUB) return githubStub;
        return platformId == GOOGLE ? googleStub : xStub;
    }

    function _txData(address wallet, bytes memory key, bytes32 policyHash) internal view returns (bytes memory) {
        return abi.encode(block.chainid, wallet, key, policyHash);
    }

    /// A stub payload proving `idNode` on `platformId` for `domain` and `data`.
    /// @dev Writes the stub: call before `vm.prank`.
    function _payload(bytes32 platformId, bytes32 idNode, bytes32 domain, bytes memory data)
        internal
        returns (bytes memory)
    {
        _stub(platformId).setNodes(idNode, keccak256("some handle node"));
        return abi.encode(
            StubPlatformVerifier.StubPayload({
                ceremonyVersion: 1, operationDomain: domain, authorizationNonce: bytes32(++nonce), transactionData: data
            })
        );
    }

    function _link(
        address submitter,
        bytes32 platformId,
        bytes32 idNode,
        address wallet,
        bytes memory key,
        IIdentityValidator.Policy memory p
    ) internal returns (bytes32 digest) {
        bytes memory payload = _payload(
            platformId, idNode, LINK, _txData(wallet, key, key.length == 0 ? bytes32(0) : _ph(p))
        );
        vm.prank(submitter);
        registry.linkIdentity(platformId, V1, payload, p);
        return _stub(platformId).lastDigest();
    }

    function _addByProof(
        address submitter,
        bytes32 platformId,
        bytes32 idNode,
        address wallet,
        bytes memory key,
        IIdentityValidator.Policy memory p
    ) internal {
        bytes memory payload = _payload(platformId, idNode, ADD, _txData(wallet, key, _ph(p)));
        vm.prank(submitter);
        registry.addSessionByProof(platformId, V1, payload, p);
    }

    /// Alice's canonical wallet, which linked her first session itself.
    function _claimWith(IIdentityValidator.Policy memory p) internal returns (address w) {
        vm.prank(relayer);
        w = factory.createWallet(X, ALICE);
        _link(w, X, ALICE, w, _key(ALICE_PK), p);
    }

    function _claim() internal returns (address) {
        return _claimWith(_admin());
    }

    // ─── Signatures and UserOperations ──────────────────────────────

    function _pks(uint256 a) internal pure returns (uint256[] memory r) {
        r = new uint256[](1);
        r[0] = a;
    }

    function _pks(uint256 a, uint256 b) internal pure returns (uint256[] memory r) {
        r = new uint256[](2);
        r[0] = a;
        r[1] = b;
    }

    /// An `Authorization` of `pks` over `h`, at the block time, with no call or domain proofs.
    function _sigs(uint256[] memory pks, bytes32 h) internal view returns (bytes memory) {
        return _auth(pks, h, uint48(_now()), new IIdentityValidator.CallProof[](0), new bytes32[](0));
    }

    function _auth(
        uint256[] memory pks,
        bytes32 h,
        uint48 at,
        IIdentityValidator.CallProof[] memory calls,
        bytes32[] memory domainProof
    ) internal pure returns (bytes memory) {
        IIdentityValidator.SessionSignature[] memory s = new IIdentityValidator.SessionSignature[](pks.length);
        for (uint256 i; i < pks.length; ++i) {
            (uint8 v, bytes32 r, bytes32 sv) = vm.sign(pks[i], h);
            s[i] = IIdentityValidator.SessionSignature({key: _key(pks[i]), signature: abi.encodePacked(r, sv, v)});
        }
        return abi.encode(
            IIdentityValidator.Authorization({
                signatures: s, at: at, calls: calls, domainProof: domainProof, paymasterProof: new bytes32[](0)
            })
        );
    }

    /// `s` as an `Authorization` at the block time, with no call or domain proofs.
    function _wrap(IIdentityValidator.SessionSignature[] memory s) internal view returns (bytes memory) {
        return abi.encode(
            IIdentityValidator.Authorization({
                signatures: s,
                at: uint48(_now()),
                calls: new IIdentityValidator.CallProof[](0),
                domainProof: new bytes32[](0),
                paymasterProof: new bytes32[](0)
            })
        );
    }

    function _exec(address to, bytes memory data) internal pure returns (bytes memory) {
        return abi.encodeCall(IERC7579Execution.execute, (MODE_SINGLE, abi.encodePacked(to, uint256(0), data)));
    }

    function _hit() internal view returns (bytes memory) {
        return _exec(address(target), abi.encodeCall(CallTarget.hit, ()));
    }

    function _op(address wallet, uint64 seq, bytes memory callData) internal view returns (PackedUserOperation memory) {
        return PackedUserOperation({
            sender: wallet,
            nonce: (uint256(uint160(address(validator))) << 96) | seq,
            initCode: "",
            callData: callData,
            accountGasLimits: bytes32((uint256(1_000_000) << 128) | 1_000_000),
            preVerificationGas: 100_000,
            gasFees: bytes32((uint256(1 gwei) << 128) | 1 gwei),
            paymasterAndData: "",
            signature: ""
        });
    }

    /// Sign the EntryPoint's own hash of `op`.
    function _signed(PackedUserOperation memory op, uint256[] memory pks)
        internal
        view
        returns (PackedUserOperation memory)
    {
        op.signature = _sigs(pks, IUserOpHash(EP).getUserOpHash(op));
        return op;
    }

    /// Below quorum, sign the EntryPoint's own hash of `op` at the block time, with a scope proof per execution.
    function _signedWith(
        PackedUserOperation memory op,
        uint256[] memory pks,
        IIdentityValidator.CallProof[] memory calls
    ) internal view returns (PackedUserOperation memory) {
        uint48 at = uint48(_now());
        bytes32 signed = _belowQuorum(IUserOpHash(EP).getUserOpHash(op), at, _key(pks[0]));
        op.signature = _auth(pks, signed, at, calls, new bytes32[](0));
        return op;
    }

    /// What every signer signs below quorum: `hash` bound to `at` and the governing session's key.
    function _belowQuorum(bytes32 hash, uint48 at, bytes memory governingKey) internal pure returns (bytes32) {
        return keccak256(abi.encode(hash, at, keccak256(governingKey)));
    }

    /// A scope of the one leaf `(target, hit(), 0)`: its root is the leaf.
    function _hitScope() internal view returns (bytes32) {
        return _leaf(address(target), CallTarget.hit.selector, 0);
    }

    /// A non-admin policy of `_hitScope()`, with a lifetime NATIVE allowance to pay its operations' gas.
    function _hitOnly() internal view returns (IIdentityValidator.Policy memory p) {
        p = _app();
        p.rules.scopeRoot = _hitScope();
        p.rules.allowances = new IIdentityValidator.Allowance[](1);
        p.rules.allowances[0] = IIdentityValidator.Allowance({token: NATIVE_TOKEN, amount: 1 ether, period: 0});
    }

    /// The proofs of `n` executions of `hit()` under `_hitScope()`: each empty.
    function _hitProofs(uint256 n) internal pure returns (IIdentityValidator.CallProof[] memory calls) {
        calls = new IIdentityValidator.CallProof[](n);
        for (uint256 i; i < n; ++i) {
            calls[i].proof = new bytes32[](0);
        }
    }

    function _ops(PackedUserOperation memory op) internal pure returns (PackedUserOperation[] memory ops) {
        ops = new PackedUserOperation[](1);
        ops[0] = op;
    }

    /// What the EntryPoint takes from the sender before execution: its gas limits at its max fee.
    function _prefund(PackedUserOperation memory op) internal pure returns (uint256) {
        uint256 limits = uint256(op.accountGasLimits);
        return ((limits >> 128) + uint128(limits) + op.preVerificationGas) * uint128(uint256(op.gasFees));
    }

    /// Funds the sender with 1 ether of value to send on top of the prefund.
    function _handle(PackedUserOperation memory op) internal {
        vm.deal(op.sender, 1 ether + _prefund(op));
        vm.prank(bundler, bundler);
        IEntryPoint(EP).handleOps(_ops(op), payable(bundler));
    }

    /// `handleOps` refuses `op` in validation.
    function _refused(PackedUserOperation memory op, string memory why) internal {
        vm.deal(op.sender, 1 ether + _prefund(op));
        vm.prank(bundler, bundler);
        try IEntryPoint(EP).handleOps(_ops(op), payable(bundler)) {
            fail(string.concat("accepted: ", why));
        } catch (bytes memory err) {
            // The revert selector is the first four bytes.
            // forge-lint: disable-next-line(unsafe-typecast)
            bytes4 s = bytes4(err);
            assertTrue(
                s == IEntryPoint.FailedOp.selector || s == IEntryPoint.FailedOpWithRevert.selector,
                string.concat("not a validation failure: ", why)
            );
        }
    }

    /// `handleOps` refuses `op` in validation with `FailedOp(0, reason)`.
    function _refusedWith(PackedUserOperation memory op, string memory reason) internal {
        vm.deal(op.sender, 1 ether + _prefund(op));
        vm.prank(bundler, bundler);
        try IEntryPoint(EP).handleOps(_ops(op), payable(bundler)) {
            fail(string.concat("accepted: ", reason));
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, reason), reason);
        }
    }

    /// The validator's answer for `op`, as its sender asks it.
    function _answer(PackedUserOperation memory op) internal returns (uint256) {
        bytes32 h = IUserOpHash(EP).getUserOpHash(op);
        vm.prank(op.sender);
        return validator.validateUserOp(op, h);
    }

    /// The validator refuses `op` and accepts `control`, `op` with the guarded part fixed, from the same
    /// state: the refusal is the guard's, not the signature's.
    function _refusedFor(PackedUserOperation memory op, PackedUserOperation memory control, string memory why)
        internal
    {
        uint256 state = vm.snapshotState();
        assertEq(_answer(op), 1, why);
        vm.revertToState(state);
        assertNotEq(_answer(control), 1, string.concat("control: ", why));
        vm.revertToStateAndDelete(state);
    }

    /// The validator's answer for `callData` signed by `pks`, as the wallet asks it.
    function _validate(address wallet, bytes memory callData, uint256[] memory pks) internal returns (uint256) {
        PackedUserOperation memory op = _op(wallet, 0, callData);
        bytes32 h = keccak256(abi.encode("user op", callData));
        op.signature = _sigs(pks, h);
        vm.prank(wallet);
        return validator.validateUserOp(op, h);
    }

    /// ERC-4337 validation data, packed by hand.
    function _window(uint48 validAfter, uint48 validUntil) internal pure returns (uint256) {
        return (uint256(validAfter) << 208) | (uint256(validUntil) << 160);
    }

    /// The block time; `block.timestamp` can be cached across `vm.warp` under via-IR.
    function _now() internal view returns (uint256) {
        return vm.getBlockTimestamp();
    }

    // ─── Root operations ────────────────────────────────────────────

    function _root(address wallet, address to, bytes memory data) internal {
        vm.prank(wallet);
        validator.queueRoot(to, data);
        vm.warp(_now() + 48 hours);
        validator.executeRoot(wallet, to, data);
    }

    /// Queues a root operation and expects its matured execution to revert with `err`.
    function _rootReverts(address wallet, address to, bytes memory data, bytes memory err) internal {
        vm.prank(wallet);
        validator.queueRoot(to, data);
        vm.warp(_now() + 48 hours);
        vm.expectRevert(err);
        validator.executeRoot(wallet, to, data);
    }

    // ─── ERC-1271 ───────────────────────────────────────────────────

    /// The ERC-7739 PersonalSign hash of `h` under the wallet's own EIP-712 domain.
    function _wrapped(address wallet, bytes32 h) internal view returns (bytes32) {
        return keccak256(abi.encodePacked(hex"1901", _separator(wallet), keccak256(abi.encode(PERSONAL_SIGN, h))));
    }

    /// The wallet's unsalted EIP-712 domain separator.
    function _separator(address wallet) internal view returns (bytes32) {
        (, string memory name, string memory version, uint256 chainId, address verifying,,) =
            IWebWallet(wallet).eip712Domain();
        return keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(name)),
                keccak256(bytes(version)),
                chainId,
                verifying
            )
        );
    }

    function _isValid1271(address wallet, bytes32 h, uint256 pk, bytes32 signed) internal view returns (bool) {
        bytes memory sig = abi.encodePacked(address(validator), _sigs(_pks(pk), signed));
        return IWebWallet(wallet).isValidSignature(h, sig) == bytes4(0x1626ba7e);
    }

    /// `pks`' ERC-7739 `TypedDataSign` below quorum of a fixed Mail for the app separator `app`, with `domainProof`.
    function _typedSigBy(address account, uint256[] memory pks, bytes32 app, bytes32[] memory domainProof)
        internal
        view
        returns (bytes32 h, bytes memory sig)
    {
        bytes32 signed = _belowQuorum(_typedHash(account, app), 0, _key(pks[0]));
        return _typedSigOf(app, _auth(pks, signed, 0, new IIdentityValidator.CallProof[](0), domainProof));
    }

    /// The hash an ERC-7739 `TypedDataSign` of the fixed Mail for `app` signs, nested under `account`'s domain.
    function _typedHash(address account, bytes32 app) internal view returns (bytes32) {
        (, string memory name, string memory version, uint256 chainId, address verifying, bytes32 salt,) =
            IWebWallet(account).eip712Domain();
        bytes32 typehash = keccak256(
            abi.encodePacked(
                "TypedDataSign(Mail contents,string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)",
                MAIL_TYPE
            )
        );
        bytes32 structHash = keccak256(
            abi.encode(typehash, MAIL, keccak256(bytes(name)), keccak256(bytes(version)), chainId, verifying, salt)
        );
        return keccak256(abi.encodePacked(hex"1901", app, structHash));
    }

    /// `auth` as an ERC-7739 `TypedDataSign` of the fixed Mail for `app`, and the app's hash it answers.
    function _typedSigOf(bytes32 app, bytes memory auth) internal view returns (bytes32 h, bytes memory sig) {
        h = keccak256(abi.encodePacked(hex"1901", app, MAIL));
        sig = abi.encodePacked(address(validator), auth, app, MAIL, MAIL_TYPE, uint16(bytes(MAIL_TYPE).length));
    }

    // ─── ERC-7562 ───────────────────────────────────────────────────

    /// `slot` of the validator is `A` or `keccak(A || x) + n`, n <= 128. Needs `vm.startMappingRecording`.
    function _associated(address account, bytes32 slot) internal view returns (bool) {
        bytes32 a = bytes32(uint256(uint160(account)));
        if (slot == a) return true;
        for (uint256 n; n <= 128 && n <= uint256(slot); ++n) {
            (bool found, bytes32 key,) = vm.getMappingKeyAndParentOf(address(validator), bytes32(uint256(slot) - n));
            if (found && key == a) return true;
        }
        return false;
    }
}

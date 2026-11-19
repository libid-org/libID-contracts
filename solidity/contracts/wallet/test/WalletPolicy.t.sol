// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Test.sol";
import {
    IEntryPoint,
    IEntryPointStake,
    IPaymaster,
    PackedUserOperation
} from "@openzeppelin/contracts/interfaces/IERC4337.sol";
import {Execution} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {IERC721} from "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

import {NATIVE_TOKEN} from "../../escrow/HandleEscrow.sol";
import {IWalletRegistry} from "../IWalletRegistry.sol";
import {IWebWallet} from "../IWebWallet.sol";
import {policyHashOf, rulesHashOf} from "../WalletStorage.sol";
import {CallTarget, IUserOpHash} from "./WalletBase.sol";
import {AcceptingVerifier, WalletSuite} from "./WalletSuite.sol";

uint48 constant DAY = 1 days;

contract Token is ERC20 {
    constructor() ERC20("Token", "TKN") {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

/// Takes value only to revert.
contract Sink {
    function boom() external payable {
        revert("boom");
    }
}

/// Pays for every operation, unconditionally.
contract FreePaymaster is IPaymaster {
    function validatePaymasterUserOp(PackedUserOperation calldata, bytes32, uint256)
        external
        pure
        returns (bytes memory, uint256)
    {
        return ("", 0);
    }

    function postOp(PostOpMode, bytes calldata, uint256, uint256) external pure {}
}

/// Takes its maximum cost in a token the sender approved, whatever the operation.
contract TokenPaymaster is IPaymaster {
    Token internal immutable TOKEN;

    constructor(Token token) {
        TOKEN = token;
    }

    function validatePaymasterUserOp(PackedUserOperation calldata op, bytes32, uint256 maxCost)
        external
        returns (bytes memory, uint256)
    {
        TOKEN.transferFrom(op.sender, address(this), maxCost);
        return ("", 0);
    }

    function postOp(PostOpMode, bytes calldata, uint256, uint256) external pure {}
}

/// Counts `hit()` and anything else.
contract HitOrFallback {
    uint256 public hits;
    uint256 public fallbacks;

    function hit() external payable {
        hits++;
    }

    fallback() external {
        fallbacks++;
    }
}

/// @notice Session rules below quorum: call scope, allowances, paymasters, the quorum rule and ERC-1271 domain
///         sets, from 0e2721f's Policy, ScopeEdges, AdminTargets and NoncanonicalUserOpBatch suites.
contract WalletPolicyTest is WalletSuite {
    struct Leaf {
        address target;
        bytes4 selector;
        uint256 maxValue;
    }

    Token internal token;
    Token internal loose;
    Sink internal sink;
    FreePaymaster internal paymaster;
    address internal payee = makeAddr("payee");
    address internal unbounded = makeAddr("unbounded");
    address internal w;
    Leaf[] internal leaves;
    uint48 internal day0;

    function setUp() public override {
        super.setUp();
        token = new Token();
        loose = new Token();
        sink = new Sink();
        paymaster = new FreePaymaster();
        IEntryPoint(EP).depositTo{value: 100 ether}(address(paymaster));
        w = _claim();
        token.mint(w, 1000 ether);
        loose.mint(w, 1000 ether);
        leaves.push(Leaf(address(target), CallTarget.hit.selector, 0.5 ether));
        leaves.push(Leaf(address(token), ERC20.transfer.selector, 0));
        leaves.push(Leaf(address(token), ERC20.approve.selector, 0));
        leaves.push(Leaf(address(token), ERC20.transferFrom.selector, 0));
        leaves.push(Leaf(address(token), Token.mint.selector, 0));
        leaves.push(Leaf(address(loose), ERC20.transfer.selector, 0));
        leaves.push(Leaf(address(sink), Sink.boom.selector, 1 ether));
        leaves.push(Leaf(payee, bytes4(0), 1 ether));
        leaves.push(Leaf(unbounded, bytes4(0), type(uint256).max));
        leaves.push(Leaf(w, IWebWallet.queueRoot.selector, 0));
        day0 = uint48((_now() / DAY + 1) * DAY);
        vm.warp(day0);
    }

    // ─── Rules and sessions ─────────────────────────────────────────

    function _scopeLeaves() internal view returns (bytes32[] memory l) {
        l = new bytes32[](leaves.length);
        for (uint256 i; i < l.length; ++i) {
            l[i] = _leaf(leaves[i].target, leaves[i].selector, leaves[i].maxValue);
        }
    }

    function _scopeRoot() internal view returns (bytes32 root) {
        (root,) = _tree(_scopeLeaves(), 0);
    }

    /// The scope of every leaf, the domain set `domainsRoot`, NATIVE `native` and `token` `tokens` per `period`.
    function _rules(uint128 native, uint128 tokens, uint48 period, bytes32 domainsRoot)
        internal
        view
        returns (IWebWallet.Rules memory r)
    {
        r.scopeRoot = _scopeRoot();
        r.domainsRoot = domainsRoot;
        r.paymastersRoot = _paymasterLeaf(address(paymaster));
        r.allowances = new IWebWallet.Allowance[](2);
        r.allowances[0] = IWebWallet.Allowance({token: NATIVE_TOKEN, amount: native, period: period});
        r.allowances[1] = IWebWallet.Allowance({token: address(token), amount: tokens, period: period});
    }

    function _daily() internal view returns (IWebWallet.Rules memory) {
        return _rules(1 ether, 100 ether, DAY, 0);
    }

    /// `r` with its allowances in ascending token order, as the wallet takes them.
    function _sorted(IWebWallet.Rules memory r) internal pure returns (IWebWallet.Rules memory) {
        IWebWallet.Allowance[] memory a = r.allowances;
        for (uint256 i = 1; i < a.length; ++i) {
            for (uint256 j = i; j > 0 && a[j - 1].token > a[j].token; --j) {
                (a[j - 1], a[j]) = (a[j], a[j - 1]);
            }
        }
        return r;
    }

    /// Adds the session a second ago, so that it signs now.
    function _add(address wallet, bytes32 identity, uint256 pk, bool admin, IWebWallet.Rules memory r) internal {
        _addKey(wallet, identity, _key(pk), IWebWallet.Policy(0, 0, admin, 0, _sorted(r)));
    }

    function _addKey(address wallet, bytes32 identity, bytes memory key, IWebWallet.Policy memory p) internal {
        uint256 t = _now();
        vm.warp(t - 1);
        _addSession(wallet, identity, key, p);
        vm.warp(t);
    }

    function _addApp(uint256 pk, IWebWallet.Rules memory r) internal {
        _add(w, _identity(X, ALICE), pk, false, r);
    }

    function _spent(uint256 pk, address t) internal view returns (uint256) {
        return IWebWallet(w).allowanceOf(_key(pk), t).spent;
    }

    // ─── Executions and operations ──────────────────────────────────

    function _e(address t, uint256 value, bytes memory data) internal pure returns (Execution memory) {
        return Execution({target: t, value: value, callData: data});
    }

    function _ones(Execution memory a) internal pure returns (Execution[] memory x) {
        x = new Execution[](1);
        x[0] = a;
    }

    function _twos(Execution memory a, Execution memory b) internal pure returns (Execution[] memory x) {
        x = new Execution[](2);
        (x[0], x[1]) = (a, b);
    }

    function _pay(uint256 value) internal view returns (Execution[] memory) {
        return _ones(_e(payee, value, ""));
    }

    function _send(Token t, uint256 amount) internal view returns (Execution memory) {
        return _e(address(t), 0, abi.encodeCall(ERC20.transfer, (payee, amount)));
    }

    function _hitE() internal view returns (Execution[] memory) {
        return _ones(_e(address(target), 0, abi.encodeCall(CallTarget.hit, ())));
    }

    function _callData(Execution[] memory x) internal pure returns (bytes memory) {
        if (x.length == 1) {
            return
                abi.encodeCall(
                    IWebWallet.execute, (MODE_SINGLE, abi.encodePacked(x[0].target, x[0].value, x[0].callData))
                );
        }
        return abi.encodeCall(IWebWallet.execute, (MODE_BATCH, abi.encode(x)));
    }

    /// The proof of the scope leaf for `x`'s target and selector; an empty proof when there is none.
    function _proofOf(Execution memory x) internal view returns (IWebWallet.CallProof memory p) {
        // forge-lint: disable-next-line(unsafe-typecast)
        bytes4 selector = x.callData.length < 4 ? bytes4(0) : bytes4(x.callData);
        for (uint256 i; i < leaves.length; ++i) {
            if (leaves[i].target == x.target && leaves[i].selector == selector) {
                (, p.proof) = _tree(_scopeLeaves(), i);
                p.maxValue = leaves[i].maxValue;
                return p;
            }
        }
        p.proof = new bytes32[](0);
    }

    function _proofs(Execution[] memory x) internal view returns (IWebWallet.CallProof[] memory p) {
        p = new IWebWallet.CallProof[](x.length);
        for (uint256 i; i < x.length; ++i) {
            p[i] = _proofOf(x[i]);
        }
    }

    /// `paymaster` pays the gas, so allowances are charged the value alone.
    function _sponsored(PackedUserOperation memory op) internal view returns (PackedUserOperation memory) {
        op.paymasterAndData = abi.encodePacked(address(paymaster), uint128(100_000), uint128(0));
        return op;
    }

    /// Below quorum, `pks`' sponsored operation for the period of `at`.
    function _opWith(uint256[] memory pks, bytes memory callData, IWebWallet.CallProof[] memory calls, uint48 at)
        internal
        view
        returns (PackedUserOperation memory op)
    {
        op = _sponsored(_op(w, callData));
        _signBelow(op, pks, calls, at);
    }

    function _opAtQuorum(uint256[] memory pks, bytes memory callData)
        internal
        view
        returns (PackedUserOperation memory)
    {
        return _signed(_op(w, callData), pks);
    }

    /// Several sessions' sponsored operation for `x`, signing the hash itself, with each execution's proof.
    function _opBy(uint256[] memory pks, Execution[] memory x) internal view returns (PackedUserOperation memory op) {
        op = _sponsored(_op(w, _callData(x)));
        bytes32 h = _signable(w, IUserOpHash(EP).getUserOpHash(op));
        op.signature = _auth(pks, h, uint48(_now()), _proofs(x), new bytes32[](0));
    }

    function _opFor(uint256 pk, Execution[] memory x, uint48 at) internal view returns (PackedUserOperation memory) {
        return _opWith(_pks(pk), _callData(x), _proofs(x), at);
    }

    function _opNow(uint256 pk, Execution[] memory x) internal view returns (PackedUserOperation memory) {
        return _opFor(pk, x, uint48(_now()));
    }

    function _typedSig(address account, uint256 pk, bytes32 app, bytes32[] memory domainProof)
        internal
        view
        returns (bytes32, bytes memory)
    {
        return _typedSigBy(account, _pks(pk), app, domainProof);
    }

    // ─── Encodings ──────────────────────────────────────────────────

    /// The encodings the spec pins, against vectors computed outside Solidity; the trees verify under OpenZeppelin.
    function test_hashesFollowTheSpec() public pure {
        IWebWallet.Allowance[] memory a = new IWebWallet.Allowance[](1);
        a[0] = IWebWallet.Allowance({token: NATIVE_TOKEN, amount: 1 ether, period: DAY});
        IWebWallet.Policy memory p = IWebWallet.Policy({
            validAfter: 10,
            validUntil: 20,
            admin: false,
            signers: 2,
            rules: IWebWallet.Rules({
                scopeRoot: keccak256("s"), domainsRoot: keccak256("d"), paymastersRoot: keccak256("p"), allowances: a
            })
        });
        // cast keccak (cast abi-encode "f(bytes32,bytes32,bytes32,(address,uint128,uint48)[])" ...), then of the policy,
        // "f(uint48,uint48,bool,uint8,bytes32)".
        assertEq(rulesHashOf(p.rules), 0x91a60d66d4b51055570ae803ab60eeb97f5719221a31686eb83fba2cd2169b20, "rules");
        assertEq(policyHashOf(p), 0xc51a04460ba256d1efcef52fde677904487eed95b705a198c65d40178196f7e8, "policyHashOf");
        assertEq(_ph(p), policyHashOf(p), "the test base's policy hash");
        // cast keccak (cast abi-encode "f(bytes32,uint48,bytes32)" (cast keccak op) 1234 (cast keccak 0x…1234))
        assertEq(
            _belowQuorum(keccak256("op"), 1234, abi.encodePacked(address(0x1234))),
            0xf63e6147bfa910f2dab04a6910a61fbf42066f204e2344c197c154c1b5a6e8dc,
            "the below-quorum hash"
        );
        assertEq(
            _leaf(address(0x1234), 0xa9059cbb, 1 ether),
            0xc5e4492e68d976c7dc45dbb80faeb5fbdc26f01081812eb880795e79e0a1e7ed,
            "scope leaf"
        );
        assertEq(
            _domainLeaf(keccak256("app A")),
            0x51c38235383b281a1fd65e7d4bb6ffc60fc412e9449cdbb033958a1a53557330,
            "domain leaf"
        );
        assertEq(
            _paymasterLeaf(address(0x1234)),
            0x29d86d891992a0a891ff8cc9477d178707448d6a8f2f8a15fe1ca735238569e4,
            "paymaster leaf"
        );
        for (uint256 n = 1; n <= 9; ++n) {
            bytes32[] memory l = new bytes32[](n);
            for (uint256 i; i < n; ++i) {
                l[i] = _domainLeaf(bytes32(i));
            }
            for (uint256 i; i < n; ++i) {
                (bytes32 root, bytes32[] memory proof) = _tree(l, i);
                assertTrue(MerkleProof.verify(proof, root, l[i]), "proof");
            }
        }
    }

    // ─── Allowances ─────────────────────────────────────────────────

    /// The period follows `at` and is the validity window: a future, past or overspent period is refused by the
    /// EntryPoint, and the counters are left as they were.
    function test_allowancePeriodsFollowAt() public {
        _addApp(APP_PK, _daily());
        _addApp(MALLORY_PK, _daily());
        vm.warp(day0 - 1);
        _refused(_opFor(APP_PK, _pay(0.6 ether), day0), "a future period");
        assertEq(IWebWallet(w).allowanceOf(_key(APP_PK), NATIVE_TOKEN).periodStart, 0, "a refused period was recorded");
        vm.warp(day0);
        _handle(_opFor(APP_PK, _pay(0.6 ether), day0));
        _refused(_opFor(APP_PK, _pay(0.5 ether), day0), "over the period's limit");
        vm.warp(day0 + DAY - 1);
        _handle(_opFor(APP_PK, _pay(0.4 ether), day0));
        IWebWallet.AllowanceState memory s = IWebWallet(w).allowanceOf(_key(APP_PK), NATIVE_TOKEN);
        assertEq(abi.encode(s), abi.encode(IWebWallet.AllowanceState(1 ether, DAY, day0, 1 ether)), "the whole limit");
        _refused(_opFor(APP_PK, _pay(1), day0), "one wei over");
        _refused(_opFor(APP_PK, _pay(1), day0 + DAY), "the next period, a second early");
        vm.warp(day0 + DAY);
        _refusedWith(_opFor(MALLORY_PK, _pay(0.1 ether), day0), "AA22 expired or not due");
        _handle(_opFor(APP_PK, _pay(1 ether), day0 + DAY + 5));
        s = IWebWallet(w).allowanceOf(_key(APP_PK), NATIVE_TOKEN);
        assertEq(s.periodStart, day0 + DAY, "rolled over");
        assertEq(s.spent, 1 ether, "a fresh period");
        assertEq(payee.balance, 2 ether, "paid");
        _handle(_opFor(APP_PK, _hitE(), day0));
        // Once a later period is charged, an earlier one is refused though its amount fits.
        _handle(_opFor(MALLORY_PK, _pay(0.1 ether), day0 + DAY));
        _refusedFor(
            _opFor(MALLORY_PK, _pay(0.1 ether), day0),
            _opFor(MALLORY_PK, _pay(0.1 ether), day0 + DAY),
            "a closed period"
        );
    }

    function test_periodZeroIsALifetimeCap() public {
        _addApp(APP_PK, _rules(1 ether, 0, 0, 0));
        _handle(_opNow(APP_PK, _pay(0.6 ether)));
        vm.warp(_now() + 3650 days);
        _refused(_opNow(APP_PK, _pay(0.5 ether)), "ten years later, over the cap");
        _handle(_opNow(APP_PK, _pay(0.4 ether)));
        assertEq(_spent(APP_PK, NATIVE_TOKEN), 1 ether, "spent");
    }

    /// A batch is charged its sum; amounts past uint128 or summing past uint256 do not wrap; only `transfer` and
    /// `approve` spend a token with an allowance, and a spending selector needs one.
    function test_spendingIsParsedAndSummed() public {
        _addApp(APP_PK, _daily());
        Execution[12] memory refused = [
            _e(address(0), 0, ""), // replaced below
            _send(token, 1 << 200),
            _send(token, type(uint256).max),
            _e(address(token), 0, abi.encodePacked(ERC20.transfer.selector, abi.encode(payee))),
            _e(address(token), 0, abi.encodeCall(ERC20.transferFrom, (w, payee, 1))),
            _e(address(token), 0, abi.encodeCall(Token.mint, (w, 1))),
            _send(loose, 1),
            _e(address(token), 0, abi.encodeCall(ERC20.approve, (payee, 100 ether + 1))),
            _e(address(0), 0, ""),
            _e(address(0), 0, ""),
            _send(loose, 0),
            _e(address(token), 0, abi.encodePacked(ERC20.transfer.selector, abi.encode(payee), bytes31(0)))
        ];
        string[12] memory why = [
            "two transfers over the limit",
            "2^200",
            "uint256 max",
            "transfer without an amount",
            "transferFrom from the account",
            "another selector on a token with an allowance",
            "a token with no allowance",
            "approve over the limit",
            "two values summing past uint128",
            "two payments over the limit",
            "zero of a token with no allowance",
            "a 67-byte transfer"
        ];
        for (uint256 i; i < refused.length; ++i) {
            Execution[] memory x = _ones(refused[i]);
            if (i == 0) x = _twos(_send(token, 60 ether), _send(token, 60 ether));
            if (i == 8) x = _twos(_e(unbounded, type(uint128).max, ""), _e(unbounded, type(uint128).max, ""));
            if (i == 9) x = _twos(_e(payee, 0.6 ether, ""), _e(payee, 0.6 ether, ""));
            _refused(_opNow(APP_PK, x), why[i]);
        }
        assertEq(_spent(APP_PK, address(token)) + _spent(APP_PK, NATIVE_TOKEN), 0, "a refused operation spent");
        IWebWallet.Rules memory noToken = _daily();
        noToken.allowances[1].token = address(loose);
        _addApp(MALLORY_PK, noToken);
        _refused(
            _opNow(MALLORY_PK, _ones(_e(address(token), 0, abi.encodeCall(ERC20.transferFrom, (w, payee, 1))))),
            "transferFrom on a token with no allowance"
        );
        Execution[] memory all = new Execution[](3);
        all[0] = _send(token, 60 ether);
        all[1] = _e(address(token), 0, abi.encodeCall(ERC20.approve, (payee, 40 ether)));
        all[2] = _e(payee, 1 ether, "");
        _handle(_opNow(APP_PK, all));
        assertEq(_spent(APP_PK, address(token)), 100 ether, "transfer and approve both spend");
        assertEq(_spent(APP_PK, NATIVE_TOKEN), 1 ether, "value spends");
        assertEq(token.balanceOf(payee), 60 ether, "transferred");
        assertEq(token.allowance(w, payee), 40 ether, "approved");
    }

    /// A value past uint128 fits no allowance and is refused before it is summed: two of 2^255 do not overflow.
    function test_aValuePastUint128IsRefused() public {
        IWebWallet.Rules memory r = _daily();
        r.allowances[0].amount = type(uint128).max;
        _addApp(APP_PK, r);
        uint256 v = 1 << 255;
        _refusedFor(
            _opNow(APP_PK, _twos(_e(unbounded, v, ""), _e(unbounded, v, ""))),
            _opNow(APP_PK, _twos(_e(unbounded, 1, ""), _e(unbounded, 1, ""))),
            "2^255 twice"
        );
        _refusedFor(
            _opNow(APP_PK, _ones(_e(unbounded, uint256(type(uint128).max) + 1, ""))),
            _opNow(APP_PK, _ones(_e(unbounded, type(uint128).max, ""))),
            "uint128 max + 1"
        );
    }

    /// The charge is made in validation and stays when the execution reverts.
    function test_aRevertedExecutionStillSpends() public {
        _addApp(APP_PK, _daily());
        _handle(_opNow(APP_PK, _ones(_e(address(sink), 0.4 ether, abi.encodeCall(Sink.boom, ())))));
        assertEq(address(sink).balance, 0, "the execution ran");
        assertEq(_spent(APP_PK, NATIVE_TOKEN), 0.4 ether, "the charge was refunded");
        _refused(_opNow(APP_PK, _pay(0.7 ether)), "over what is left");
    }

    /// Counters are keyed by key and rules: the same rules again keep the spend, new rules start fresh.
    function test_aReAddedKeyKeepsItsSpendOnlyWithTheSameRules() public {
        _addApp(APP_PK, _daily());
        _handle(_opNow(APP_PK, _pay(0.6 ether)));
        _revoke(w, _key(APP_PK));
        assertEq(_spent(APP_PK, NATIVE_TOKEN), 0, "a revoked key has no counter");
        _addApp(APP_PK, _daily());
        assertEq(_spent(APP_PK, NATIVE_TOKEN), 0.6 ether, "the same rules lost the spend");
        _refused(_opNow(APP_PK, _pay(0.5 ether)), "the same rules, over the limit");
        IWebWallet.Policy memory p = IWebWallet.Policy(0, 0, false, 0, _sorted(_daily()));
        assertEq(IWebWallet(w).sessionOf(_key(APP_PK)).policyHash, _ph(p), "policyHash");
        _revoke(w, _key(APP_PK));
        _addApp(APP_PK, _rules(1 ether + 1, 100 ether, DAY, 0));
        assertEq(_spent(APP_PK, NATIVE_TOKEN), 0, "new rules kept the spend");
        _handle(_opNow(APP_PK, _pay(1 ether)));
        _addApp(BOB_PK, _rules(1 ether + 1, 100 ether, DAY, 0));
        _handle(_opNow(BOB_PK, _pay(1 ether)));
        assertEq(_spent(BOB_PK, NATIVE_TOKEN), 1 ether, "another key shares the counter");
    }

    /// ERC-7562: validation reads and writes only the wallet's own storage, for a 64-byte ERC-7913 key.
    function test_validationTouchesOnlyTheWalletsStorage() public {
        bytes memory key = abi.encodePacked(address(new AcceptingVerifier()), keccak256("x"), keccak256("y"));
        _addKey(w, _identity(X, ALICE), key, IWebWallet.Policy(0, 0, false, 0, _sorted(_daily())));
        Execution[] memory x = _twos(_e(payee, 0.1 ether, ""), _send(token, 1 ether));
        IWebWallet.SessionSignature[] memory s = new IWebWallet.SessionSignature[](1);
        s[0] = IWebWallet.SessionSignature({key: key, signature: hex"1234"});
        PackedUserOperation memory op = _op(w, _callData(x));
        op.signature = abi.encode(
            IWebWallet.Authorization({
                signatures: s,
                at: uint48(_now()),
                calls: _proofs(x),
                domainProof: new bytes32[](0),
                paymasterProof: new bytes32[](0)
            })
        );
        vm.startStateDiffRecording();
        vm.prank(EP);
        assertEq(IWebWallet(w).validateUserOp(op, keccak256("op"), 0), _window(day0 - 1, day0 + DAY - 1), "period");
        Vm.AccountAccess[] memory acc = vm.stopAndReturnStateDiff();
        uint256 writes;
        for (uint256 i; i < acc.length; ++i) {
            for (uint256 j; j < acc[i].storageAccesses.length; ++j) {
                assertEq(acc[i].storageAccesses[j].account, w, "storage of another account");
                if (acc[i].storageAccesses[j].isWrite) ++writes;
            }
        }
        assertGt(writes, 0, "validation charged nothing");
        assertEq(IWebWallet(w).allowanceOf(key, address(token)).spent, 1 ether, "token");
    }

    /// EntryPoint v0.9 reads bit 47 as a block-number flag: no `at` may produce a window that sets it.
    function test_atStaysBelowBit47() public {
        _addApp(APP_PK, _daily());
        uint48[3] memory ats = [uint48(1 << 47) - 1, uint48(1 << 47), type(uint48).max];
        for (uint256 i; i < ats.length; ++i) {
            PackedUserOperation memory op = _opFor(APP_PK, _pay(0.1 ether), ats[i]);
            bytes32 opHash = IUserOpHash(EP).getUserOpHash(op);
            vm.prank(EP);
            try IWebWallet(w).validateUserOp(op, opHash, 0) returns (uint256 r) {
                if (r == 1) continue;
                uint48 until = uint48(r >> 160);
                assertTrue(until != 0 && until < 1 << 47, "validUntil");
                assertLt(uint48(r >> 208), 1 << 47, "validAfter");
            } catch {}
        }
        assertEq(_spent(APP_PK, NATIVE_TOKEN), 0, "an out-of-range at was charged");
        // The window opens no earlier than the session's start.
        assertEq(_answer(_opFor(APP_PK, _pay(0.1 ether), 100)), _window(day0 - 1, DAY - 1), "the period from 0");
        _addApp(BOB_PK, _rules(1 ether, 0, uint48(1 << 20), 0));
        assertEq(
            _answer(_opFor(BOB_PK, _pay(0.1 ether), uint48(1 << 47) - 1)),
            _window(uint48(1 << 47) - (1 << 20) - 1, uint48(1 << 47) - 1),
            "the period ending at bit 47"
        );
    }

    /// A repeated or descending token, or a period reaching bit 47, is refused when the session is added.
    function test_badAllowancesRefused() public {
        IWebWallet.Rules memory twice = _daily();
        twice.allowances[1].token = NATIVE_TOKEN;
        IWebWallet.Rules memory far = _daily();
        far.allowances[1].period = uint48(1 << 47);
        _sorted(far);
        vm.prank(w);
        vm.expectRevert(abi.encodeWithSelector(IWebWallet.BadAllowance.selector, NATIVE_TOKEN));
        IWebWallet(w).addSession(_identity(X, ALICE), _key(APP_PK), IWebWallet.Policy(0, 0, false, 0, twice));
        vm.prank(w);
        vm.expectRevert(abi.encodeWithSelector(IWebWallet.BadAllowance.selector, address(token)));
        IWebWallet(w).addSession(_identity(X, ALICE), _key(APP_PK), IWebWallet.Policy(0, 0, false, 0, _daily()));
        IWebWallet.Policy memory p = IWebWallet.Policy(0, 0, false, 0, far);
        bytes memory payload = _loginPayload(w, X, ALICE, _key(APP_PK), p);
        vm.expectRevert(abi.encodeWithSelector(IWebWallet.BadAllowance.selector, address(token)));
        IWebWallet(w).addSessionByLogin(X, V1, payload, "", p);
    }

    /// `at == 0` is refused: in a one-second period it would end the window at 0, which is unbounded.
    function test_atZeroIsRefused() public {
        _addApp(APP_PK, _rules(1 ether, 0, 1, 0));
        assertEq(_answer(_opFor(APP_PK, _pay(0.1 ether), 0)), 1, "at 0");
        assertEq(_answer(_opFor(APP_PK, _pay(0.1 ether), 1)), _window(day0 - 1, 1), "at 1");
    }

    /// Without a paymaster the operation's maximum gas cost is charged to NATIVE with its value; with a listed
    /// paymaster no gas is charged.
    function test_gasIsChargedToTheNativeAllowance() public {
        _addApp(APP_PK, _rules(0, 100 ether, DAY, 0));
        IWebWallet.Rules memory noNative = _daily();
        noNative.allowances[0].token = address(loose);
        _addApp(BOB_PK, noNative);
        _addApp(MALLORY_PK, _daily());
        Execution[] memory hit = _hitE();
        // The session picks fees worth 10 ether and bundles its own operation.
        PackedUserOperation memory drain = _op(w, _callData(hit));
        drain.preVerificationGas = 8_000_000;
        drain.gasFees = bytes32((uint256(1000 gwei) << 128) | 1000 gwei);
        _signBelow(drain, _pks(APP_PK), _proofs(hit), uint48(_now()));
        _refused(drain, "gas over a zero NATIVE allowance");
        _signBelow(drain, _pks(BOB_PK), _proofs(hit), uint48(_now()));
        _refused(drain, "gas with no NATIVE entry");
        IWebWallet.AllowanceState memory zero = IWebWallet(w).allowanceOf(_key(APP_PK), NATIVE_TOKEN);
        assertEq(zero.spent + zero.periodStart, 0, "a refused operation was charged");
        PackedUserOperation memory paid = _op(w, _callData(_pay(0.1 ether)));
        _signBelow(paid, _pks(MALLORY_PK), _proofs(_pay(0)), uint48(_now()));
        uint256 gas = _missingFunds(paid);
        assertEq(_spent(MALLORY_PK, NATIVE_TOKEN), 0.1 ether + gas, "the value and the maximum gas cost");
        uint256 left = 1 ether - 0.1 ether - gas;
        PackedUserOperation memory over = _op(w, _callData(_pay(left - gas + 1)));
        _signBelow(over, _pks(MALLORY_PK), _proofs(_pay(0)), uint48(_now()));
        _refused(over, "the value and gas, one wei over");
        _handle(_opNow(MALLORY_PK, _pay(left)));
        assertEq(_spent(MALLORY_PK, NATIVE_TOKEN), 1 ether, "a sponsored operation was charged gas");
    }

    /// Handles `op` from an empty deposit, and returns the `missingAccountFunds` the EntryPoint recorded.
    function _missingFunds(PackedUserOperation memory op) internal returns (uint256) {
        assertEq(IEntryPoint(EP).balanceOf(op.sender), 0, "the account has a deposit");
        vm.recordLogs();
        _handle(op);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 i; i < logs.length; ++i) {
            if (
                logs[i].emitter == EP && logs[i].topics[0] == keccak256("Deposited(address,uint256)")
                    && logs[i].topics[1] == bytes32(uint256(uint160(op.sender)))
            ) {
                return abi.decode(logs[i].data, (uint256));
            }
        }
        revert("the account paid no prefund");
    }

    /// Below quorum a paymaster the session does not list is refused, and a listed one needs its proof; a
    /// `paymasterAndData` too short to name one is refused. At quorum any paymaster pays.
    function test_anUnlistedPaymasterIsRefused() public {
        TokenPaymaster drain = new TokenPaymaster(token);
        IEntryPoint(EP).depositTo{value: 100 ether}(address(drain));
        vm.prank(w);
        token.approve(address(drain), type(uint256).max);
        bytes32[] memory listed = new bytes32[](2);
        (listed[0], listed[1]) = (_paymasterLeaf(address(paymaster)), _paymasterLeaf(makeAddr("other")));
        IWebWallet.Rules memory r = _daily();
        bytes32[] memory proof;
        (r.paymastersRoot, proof) = _tree(listed, 0);
        _addApp(BOB_PK, r);
        Execution[] memory hit = _hitE();
        PackedUserOperation memory control = _opNow(BOB_PK, hit);
        _withPaymasterProof(control, proof);
        PackedUserOperation memory op = _op(w, _callData(hit));
        op.paymasterAndData = abi.encodePacked(address(drain), uint128(100_000), uint128(0));
        _signBelow(op, _pks(BOB_PK), _proofs(hit), uint48(_now()));
        _withPaymasterProof(op, proof);
        _refusedFor(op, control, "an unlisted paymaster");
        _refused(op, "an unlisted paymaster");
        assertEq(token.balanceOf(address(drain)), 0, "the paymaster took its fee");
        _refusedFor(_opNow(BOB_PK, hit), control, "a listed paymaster without its proof");
        PackedUserOperation memory bad = _op(w, _callData(hit));
        bad.paymasterAndData = abi.encodePacked(address(0), uint128(100_000), uint128(0));
        _signBelow(bad, _pks(BOB_PK), _proofs(hit), uint48(_now()));
        _refusedFor(bad, control, "a zero paymaster");
        bad.paymasterAndData = abi.encodePacked(address(paymaster), uint64(0));
        _signBelow(bad, _pks(BOB_PK), _proofs(hit), uint48(_now()));
        _withPaymasterProof(bad, proof);
        _refusedFor(bad, control, "28 bytes of paymasterAndData");
        _handle(control);
        assertEq(_spent(BOB_PK, NATIVE_TOKEN), 0, "a listed paymaster was charged");
        op = _op(w, _callData(hit));
        op.paymasterAndData = abi.encodePacked(address(drain), uint128(100_000), uint128(0));
        _handle(_signed(op, _pks(ALICE_PK)));
        assertEq(target.calls(), 2, "calls");
    }

    /// Sets `op`'s paymaster proof, which is not signed.
    function _withPaymasterProof(PackedUserOperation memory op, bytes32[] memory proof) internal pure {
        IWebWallet.Authorization memory a = abi.decode(op.signature, (IWebWallet.Authorization));
        a.paymasterProof = proof;
        op.signature = abi.encode(a);
    }

    // ─── Scope ──────────────────────────────────────────────────────

    function test_scopeRefusals() public {
        _addApp(APP_PK, _daily());
        IWebWallet.Rules memory none = _daily();
        none.scopeRoot = 0;
        _addApp(MALLORY_PK, none);
        IWebWallet.Rules memory noNative = _daily();
        noNative.allowances[0].token = address(loose);
        _addApp(BOB_PK, noNative);
        Execution[] memory hit = _hitE();
        bytes memory hitCall = _callData(hit);
        IWebWallet.CallProof[] memory other = _proofs(_pay(1));
        IWebWallet.CallProof[] memory lie = _proofs(hit);
        lie[0].maxValue = 1 ether;
        IWebWallet.CallProof[] memory extra = new IWebWallet.CallProof[](2);
        (extra[0], extra[1]) = (_proofOf(hit[0]), _proofOf(hit[0]));
        PackedUserOperation[8] memory ops = [
            _opNow(APP_PK, _ones(_e(address(target), 0.5 ether + 1, abi.encodeCall(CallTarget.hit, ())))),
            _opWith(_pks(APP_PK), hitCall, other, uint48(_now())),
            _opWith(_pks(APP_PK), hitCall, lie, uint48(_now())),
            _opNow(APP_PK, _ones(_e(address(target), 0, abi.encodeCall(target.calls, ())))),
            _opWith(_pks(APP_PK), hitCall, new IWebWallet.CallProof[](0), uint48(_now())),
            _opWith(_pks(APP_PK), hitCall, extra, uint48(_now())),
            _opNow(MALLORY_PK, hit),
            _opNow(BOB_PK, _pay(1))
        ];
        string[8] memory why = [
            "value above the leaf's maxValue",
            "another leaf's proof",
            "a maxValue not in the leaf",
            "a call outside the scope",
            "no proof",
            "more proofs than executions",
            "scopeRoot 0",
            "value with no NATIVE entry"
        ];
        for (uint256 i; i < ops.length; ++i) {
            _refused(ops[i], why[i]);
        }
        _handle(_opNow(APP_PK, _ones(_e(address(target), 0.5 ether, abi.encodeCall(CallTarget.hit, ())))));
        _handle(_opNow(BOB_PK, hit));
        _handle(_opNow(APP_PK, _pay(0.5 ether)));
        _handle(_opNow(APP_PK, _ones(_e(payee, 0, hex"abcdef"))));
        assertEq(target.calls(), 2, "in-scope calls");
        assertEq(payee.balance, 0.5 ether, "a plain transfer has selector 0");
    }

    /// Below quorum an operation of no executions is refused, even with `scopeRoot == 0`; at quorum it passes.
    function test_anEmptyBatchIsRefusedBelowQuorum() public {
        IWebWallet.Rules memory unscoped = _daily();
        unscoped.scopeRoot = 0;
        _addApp(APP_PK, unscoped);
        bytes memory empty = _callData(new Execution[](0));
        assertEq(_answer(_opWith(_pks(APP_PK), empty, new IWebWallet.CallProof[](0), uint48(_now()))), 1, "below");
        assertEq(_answer(_opAtQuorum(_pks(ALICE_PK), empty)), 0, "at quorum");
    }

    /// A batch whose element offset is negative is no canonical batch: refused in validation, never reverting it.
    function test_aBatchWithANegativeElementOffsetIsRefused() public {
        HitOrFallback t = new HitOrFallback();
        IWebWallet.Policy memory p = _hitGas();
        p.rules.scopeRoot = _leaf(address(t), HitOrFallback.hit.selector, 0);
        _addKey(w, _identity(X, ALICE), _key(APP_PK), p);
        bytes memory execs = abi.encodePacked(
            uint256(0x20),
            uint256(1),
            uint256(0x20),
            uint256(uint160(address(t))),
            uint256(0),
            -int256(0x100),
            uint256(0)
        );
        PackedUserOperation memory op = _op(w, abi.encodeCall(IWebWallet.execute, (MODE_BATCH, execs)));
        _refused(_signedWith(op, _pks(APP_PK), _hitProofs(1)), "a batch read differently by the rules");
        assertEq(t.hits() + t.fallbacks(), 0, "a call ran");
    }

    // ─── Scope edges ────────────────────────────────────────────────

    /// The app session's operation of one call proved by leaf `index` of `l`, signed at `at`.
    function _opOn(bytes32[] memory l, address to, bytes memory data, uint256 index, uint48 at)
        internal
        view
        returns (PackedUserOperation memory op)
    {
        IWebWallet.CallProof[] memory calls = new IWebWallet.CallProof[](1);
        (, calls[0].proof) = _tree(l, index);
        op = _op(w, _exec(to, data));
        _signBelow(op, _pks(APP_PK), calls, at);
    }

    /// Selectors on `nft`, `hit()` on the target, and selector 0 on `payee`, under one app session; its accepted
    /// operations' window.
    function _edges(address nft, bytes4[5] memory selectors) internal returns (bytes32[] memory l, uint256 accepted) {
        l = new bytes32[](7);
        for (uint256 i; i < 5; ++i) {
            l[i] = _leaf(nft, selectors[i], 0);
        }
        (l[5], l[6]) = (_hitScope(), _leaf(payee, bytes4(0), 0));
        IWebWallet.Policy memory p = _hitGas();
        (p.rules.scopeRoot,) = _tree(l, 0);
        p.rules.paymastersRoot = _paymasterLeaf(makeAddr("paymaster"));
        _addSession(w, _identity(X, ALICE), _key(APP_PK), p);
        accepted = _window(uint48(_now()), 0);
    }

    /// A target with no allowance takes any selector in scope but a spending one; selector 0 matches empty calldata,
    /// one to three bytes, and four zero bytes; `at == 0` is refused only when charging; a lifetime charge takes any
    /// nonzero `at`.
    function test_scopeEdges() public {
        address nft = makeAddr("nft");
        bytes4[5] memory s = [
            bytes4(0x42842e0e), // safeTransferFrom(address,address,uint256)
            bytes4(0xb88d4fde), // safeTransferFrom(address,address,uint256,bytes)
            IERC721.setApprovalForAll.selector,
            IERC721.approve.selector,
            IERC721.transferFrom.selector
        ];
        (bytes32[] memory l, uint256 accepted) = _edges(nft, s);
        uint48 t = uint48(_now());
        bytes[5] memory nftData = [
            abi.encodeWithSelector(s[0], w, payee, 1),
            abi.encodeWithSelector(s[1], w, payee, 1, ""),
            abi.encodeCall(IERC721.setApprovalForAll, (payee, true)),
            abi.encodeCall(IERC721.approve, (payee, 1)),
            abi.encodeCall(IERC721.transferFrom, (w, payee, 1))
        ];
        for (uint256 i; i < 3; ++i) {
            assertEq(_answer(_opOn(l, nft, nftData[i], i, t)), accepted, vm.toString(i));
        }
        assertEq(_answer(_opOn(l, nft, nftData[3], 3, t)), 1, "approve");
        assertEq(_answer(_opOn(l, nft, nftData[4], 4, t)), 1, "transferFrom");

        bytes[6] memory zero = [bytes(""), hex"ab", hex"abcd", hex"abcdef", hex"00000000", hex"00000000ffff"];
        for (uint256 i; i < zero.length; ++i) {
            assertEq(_answer(_opOn(l, payee, zero[i], 6, t)), accepted, vm.toString(i));
        }
        assertEq(_answer(_opOn(l, payee, hex"00000001", 6, t)), 1, "a nonzero selector");

        bytes memory hit = abi.encodeCall(CallTarget.hit, ());
        PackedUserOperation memory op = _opOn(l, address(target), hit, 5, 0);
        assertEq(_answer(op), 1, "gas charged at 0");
        IWebWallet.CallProof[] memory calls = abi.decode(op.signature, (IWebWallet.Authorization)).calls;
        op.paymasterAndData = abi.encodePacked(makeAddr("paymaster"), uint128(100_000), uint128(0));
        _signBelow(op, _pks(APP_PK), calls, 0);
        assertEq(_answer(op), accepted, "nothing charged at 0");

        uint256 spent = _spent(APP_PK, NATIVE_TOKEN);
        assertEq(_answer(_opOn(l, address(target), hit, 5, uint48(1 << 47))), accepted, "at 2^47");
        assertGt(_spent(APP_PK, NATIVE_TOKEN), spent, "nothing charged");
    }

    // ─── Admin targets ──────────────────────────────────────────────

    /// Below quorum a call to the wallet, `address(0)`, the registry or the EntryPoint is an admin operation, even
    /// with a scope leaf for it, and a batch takes its widest call.
    function test_adminTargetsAreRefusedBelowQuorum() public {
        bytes memory toWallet = abi.encodeCall(IWebWallet.rootDelay, ());
        bytes memory withdraw = abi.encodeCall(IEntryPointStake.withdrawTo, (payable(payee), 1));
        Leaf[7] memory admin = [
            Leaf(address(0), IWebWallet.execute.selector, 0),
            Leaf(address(registry), bytes4(0), 0),
            Leaf(EP, IEntryPointStake.withdrawTo.selector, 0),
            Leaf(w, IWebWallet.rootDelay.selector, 0),
            Leaf(address(target), CallTarget.hit.selector, 0),
            Leaf(address(target), bytes4(0), 0),
            Leaf(address(target), IWebWallet.execute.selector, 0)
        ];
        delete leaves;
        for (uint256 i; i < admin.length; ++i) {
            leaves.push(admin[i]);
        }
        IWebWallet.Policy memory p = _hitGas();
        p.rules.scopeRoot = _scopeRoot();
        _addSession(w, _identity(X, ALICE), _key(APP_PK), p);

        _refusedFor(_single(address(0), _hitCall()), _single(address(target), _hitCall()), "address(0)");
        _refusedFor(_single(address(registry), ""), _single(address(target), ""), "the registry");
        _refusedFor(_single(EP, withdraw), _single(address(target), ""), "the EntryPoint");
        Execution[] memory x = _twos(_e(w, 0, toWallet), _e(address(target), 0, ""));
        Execution[] memory control = _twos(_e(address(target), 0, abi.encodeCall(CallTarget.hit, ())), x[1]);
        _refusedFor(_batchOp(x), _batchOp(control), "the wallet in a batch");

        // A decoy outside call where a canonical encoding puts the execution; the real one, to the wallet, where
        // the offset points.
        bytes memory decoy = abi.encodePacked(address(target), uint256(0), abi.encodeCall(CallTarget.hit, ()));
        bytes memory real = abi.encodePacked(w, uint256(0), toWallet);
        bytes memory callData = abi.encodePacked(
            IWebWallet.execute.selector, MODE_SINGLE, uint256(0xa0), decoy.length, decoy, bytes8(0), real.length, real
        );
        _refusedFor(
            _opOf(callData, _ones(_e(address(target), 0, abi.encodeCall(CallTarget.hit, ())))),
            _single(address(target), abi.encodeCall(CallTarget.hit, ())),
            "a decoy"
        );
    }

    function _opOf(bytes memory callData, Execution[] memory x) internal view returns (PackedUserOperation memory) {
        return _signedWith(_op(w, callData), _pks(APP_PK), _proofs(x));
    }

    function _single(address to, bytes memory data) internal view returns (PackedUserOperation memory) {
        return _opOf(_exec(to, data), _ones(_e(to, 0, data)));
    }

    function _batchOp(Execution[] memory x) internal view returns (PackedUserOperation memory) {
        return _opOf(abi.encodeCall(IWebWallet.execute, (MODE_BATCH, abi.encode(x))), x);
    }

    // ─── Quorum ─────────────────────────────────────────────────────

    /// At threshold 2 one admin is limited to its rules, admin operations and `PersonalSign` need two, and two
    /// signatures short of quorum are refused.
    function test_belowQuorumAnAdminIsLimitedToItsRules() public {
        bytes32 appA = keccak256("app A");
        bytes32 domains = _domainLeaf(appA);
        _link(w, GITHUB, BOB, "", _admin());
        _add(w, _identity(GITHUB, BOB), BOB_PK, true, _noRules());
        _add(w, _identity(X, ALICE), ALICE2_PK, true, _rules(0.5 ether, 0, DAY, domains));
        _threshold(w, 2);
        Execution[] memory hit = _hitE();
        Execution[] memory delay = _ones(_queueRaise(w));
        Execution[] memory outside = _ones(_e(address(target), 0, abi.encodeCall(target.calls, ())));
        PackedUserOperation[3] memory ops =
            [_opNow(ALICE2_PK, delay), _opNow(ALICE2_PK, _pay(0.6 ether)), _opNow(ALICE_PK, hit)];
        string[3] memory why =
            ["an admin operation in scope, one identity", "over an admin's own allowance", "an admin with no scope"];
        for (uint256 i; i < ops.length; ++i) {
            _refused(ops[i], why[i]);
        }
        _refusedFor(_opBy(_pks(ALICE2_PK, ALICE_PK), hit), _opNow(ALICE2_PK, hit), "two signatures of one identity");
        _handle(_opNow(ALICE2_PK, hit));
        _handle(_opAtQuorum(_pks(ALICE_PK, BOB_PK), _callData(delay)));
        _handle(_opAtQuorum(_pks(ALICE_PK, BOB_PK), _callData(outside)));
        _handle(_opAtQuorum(_pks(ALICE2_PK, BOB_PK), _callData(_pay(0.9 ether))));
        assertNotEq(IWebWallet(w).rootReadyAt(keccak256(_raise())), 0, "quorum is unrestricted");
        assertEq(_spent(ALICE2_PK, NATIVE_TOKEN), 0, "quorum was charged");
        vm.warp(_now() + 1);
        bytes32 h = keccak256("a message");
        assertFalse(_isValid1271(w, h, ALICE_PK, _belowQuorum(_wrapped(w, h), 0, _key(ALICE_PK))), "one admin");
        bytes memory both = _sigs(_pks(ALICE_PK, BOB_PK), _wrapped(w, h));
        assertEq(IWebWallet(w).isValidSignature(h, both), MAGIC, "PersonalSign at quorum");
        (bytes32 typed, bytes memory sig) = _typedSig(w, ALICE2_PK, appA, new bytes32[](0));
        assertEq(IWebWallet(w).isValidSignature(typed, sig), MAGIC, "a listed app, one admin");
    }

    /// At threshold 1 an admin ignores its own rules and is not charged; two app sessions are not a quorum.
    function test_atThresholdOneAnAdminIgnoresItsRules() public {
        _add(w, _identity(X, ALICE), ALICE2_PK, true, _rules(0.1 ether, 0, DAY, 0));
        _addApp(APP_PK, _daily());
        _addApp(BOB_PK, _daily());
        Execution[] memory outside = _ones(_e(address(target), 0, abi.encodeCall(target.calls, ())));
        _handle(_opAtQuorum(_pks(ALICE2_PK), _callData(outside)));
        _handle(_opAtQuorum(_pks(ALICE2_PK), _callData(_pay(0.9 ether))));
        assertEq(_spent(ALICE2_PK, NATIVE_TOKEN), 0, "an unrestricted admin was charged");
        _refusedFor(_opBy(_pks(APP_PK, BOB_PK), _hitE()), _opNow(APP_PK, _hitE()), "two app sessions");
    }

    /// Below quorum `at` is signed: moved to a later period, the signature fails. At quorum it is ignored.
    function test_atIsSignedBelowQuorum() public {
        _addApp(APP_PK, _daily());
        PackedUserOperation memory op = _opFor(APP_PK, _pay(0.1 ether), day0);
        IWebWallet.Authorization memory auth = abi.decode(op.signature, (IWebWallet.Authorization));
        auth.at = day0 + DAY;
        op.signature = abi.encode(auth);
        assertEq(_answer(op), 1, "at moved to the next period");
        auth.at = day0;
        op.signature = abi.encode(auth);
        assertEq(_answer(op), _window(day0 - 1, day0 + DAY - 1), "the signed at");
        op = _opAtQuorum(_pks(ALICE_PK), _callData(_pay(0.1 ether)));
        auth = abi.decode(op.signature, (IWebWallet.Authorization));
        auth.at = day0 + DAY;
        op.signature = abi.encode(auth);
        assertEq(_answer(op), 0, "at quorum");
    }

    // ─── ERC-1271 domain sets ───────────────────────────────────────

    /// Below quorum only `TypedDataSign` for an app proved under `domainsRoot`, bound to the wallet; neither
    /// separator 0 nor `PersonalSign` under the wallet's own separator.
    function test_erc1271DomainSets() public {
        bytes32[3] memory apps = [keccak256("app A"), keccak256("app B"), keccak256("app C")];
        bytes32[] memory listed = new bytes32[](4);
        (listed[0], listed[1], listed[2], listed[3]) =
        (_domainLeaf(apps[0]), _domainLeaf(apps[1]), _domainLeaf(0), _domainLeaf(_domain(w, 1, _epoch(w))));
        (bytes32 domains, bytes32[] memory proofA) = _tree(listed, 0);
        (, bytes32[] memory proofB) = _tree(listed, 1);
        _addApp(APP_PK, _rules(0, 0, DAY, domains));
        _addApp(MALLORY_PK, _daily());
        address w2 = _claimAs(GITHUB, BOB, 0, BOB_PK);
        _add(w2, _identity(GITHUB, BOB), APP_PK, false, _rules(0, 0, DAY, domains));
        vm.warp(_now() + 1);
        (bytes32 h, bytes memory sig) = _typedSig(w, APP_PK, apps[0], proofA);
        assertEq(IWebWallet(w).isValidSignature(h, sig), MAGIC, "app A");
        (h, sig) = _typedSig(w, APP_PK, apps[1], proofB);
        assertEq(IWebWallet(w).isValidSignature(h, sig), MAGIC, "app B");
        (bytes32 h2, bytes memory sig2) = _typedSig(w2, APP_PK, apps[1], proofB);
        assertEq(IWebWallet(w2).isValidSignature(h2, sig2), MAGIC, "app B on the other wallet");

        (, bytes32[] memory proofZero) = _tree(listed, 2);
        (, bytes32[] memory proofOwn) = _tree(listed, 3);
        bytes[7] memory sigs;
        bytes32[7] memory hashes;
        (hashes[0], sigs[0]) = _typedSig(w, APP_PK, apps[0], proofB);
        (hashes[1], sigs[1]) = _typedSig(w, APP_PK, apps[2], proofA);
        (hashes[2], sigs[2]) = _typedSig(w, APP_PK, apps[2], new bytes32[](0));
        (hashes[3], sigs[3]) = _typedSig(w, MALLORY_PK, apps[0], proofA);
        hashes[4] = keccak256("a message");
        bytes32 bound = _belowQuorum(_wrapped(w, hashes[4]), 0, _key(APP_PK));
        sigs[4] = _sigs(_pks(APP_PK), bound);
        (hashes[5], sigs[5]) = _typedSig(w, APP_PK, 0, proofZero);
        hashes[6] = hashes[4];
        sigs[6] = _auth(_pks(APP_PK), bound, 0, new IWebWallet.CallProof[](0), proofOwn);
        string[7] memory why = [
            "another app's proof",
            "an unlisted app",
            "an unlisted app, no proof",
            "domainsRoot 0",
            "PersonalSign",
            "separator 0",
            "PersonalSign, own separator listed"
        ];
        for (uint256 i; i < sigs.length; ++i) {
            assertEq(IWebWallet(w).isValidSignature(hashes[i], sigs[i]), bytes4(0xffffffff), why[i]);
        }
        assertEq(IWebWallet(w2).isValidSignature(h, sig), bytes4(0xffffffff), "replayed on another wallet");
        (h, sig) = _typedSigBy(w, _pks(APP_PK, MALLORY_PK), apps[0], proofA);
        assertEq(IWebWallet(w).isValidSignature(h, sig), bytes4(0xffffffff), "two sessions below quorum");
    }

    /// An unlinked identity's session shows no allowance.
    function test_anUnlinkedSessionShowsNoAllowance() public {
        _link(w, GITHUB, BOB, "", _admin());
        _add(w, _identity(GITHUB, BOB), APP_PK, false, _daily());
        _handle(_opNow(APP_PK, _pay(0.1 ether)));
        _rootW(w, abi.encodeCall(IWebWallet.unlink, (_identity(GITHUB, BOB))));
        assertEq(IWebWallet(w).allowanceOf(_key(APP_PK), NATIVE_TOKEN).amount, 0, "a dead session's allowance");
    }

    /// The proof of a session commits its rules.
    function test_aProofCommitsTheRules() public {
        IWebWallet.Policy memory p = IWebWallet.Policy(0, 0, false, 0, _sorted(_daily()));
        _addByLogin(relayer, X, ALICE, w, _key(APP_PK), p);
        assertEq(IWebWallet(w).sessionOf(_key(APP_PK)).policyHash, _ph(p), "policyHash");
        assertEq(IWebWallet(w).allowanceOf(_key(APP_PK), NATIVE_TOKEN).amount, 1 ether, "allowance");
        bytes32 committed = _ph(p);
        bytes memory payload = _payload(X, ALICE, ADD, _txData(w, _key(MALLORY_PK), committed));
        p.rules.allowances[0].amount += 1;
        vm.expectRevert(abi.encodeWithSelector(IWalletRegistry.WrongPolicy.selector, _ph(p), committed));
        IWebWallet(w).addSessionByLogin(X, V1, payload, "", p);
    }
}

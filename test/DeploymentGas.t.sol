// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {SimpleAccountFactory} from "../src/SimpleAccountFactory.sol";
import {SimpleAccount_WOTS} from "../src/SimpleAccount_WOTS.sol";
import {SimpleAccount_ECDSA} from "../src/SimpleAccount_ECDSA.sol";
import {WotsCVerifier} from "../src/WotsCVerifier.sol";
import {IWotsCVerifier} from "../src/Interfaces/IWotsCVerifier.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {WotsSigner} from "./WotsCVerifier.t.sol";
import {EntryPointLib} from "kernel/sdk/TestBase/erc4337Util.sol";

/// @dev Measures deployment + first-userOp costs for SimpleAccount_WOTS and
///      SimpleAccount_ECDSA, plus subsequent-userOp costs for comparison.
contract DeploymentGasTest is Test {
    IEntryPoint entrypoint;
    SimpleAccountFactory factory;
    WotsCVerifier verifier;

    function setUp() public {
        entrypoint = IEntryPoint(EntryPointLib.deploy());
        verifier = new WotsCVerifier();
        factory = new SimpleAccountFactory(entrypoint, IWotsCVerifier(address(verifier)));
    }

    // =========================================================================
    // Direct factory.createAccount — isolates the account deploy cost
    // =========================================================================

    function test_gas_factoryCreateAccount_wots() public {
        address owner = makeAddr("wotsOwner");
        uint256 before = gasleft();
        factory.createAccount(owner, 0, 1);
        uint256 used = before - gasleft();
        console.log("factory.createAccount (WOTS) gas:", used);
    }

    function test_gas_factoryCreateAccount_ecdsa() public {
        address owner = makeAddr("ecdsaOwner");
        uint256 before = gasleft();
        factory.createAccount(owner, 0, 0);
        uint256 used = before - gasleft();
        console.log("factory.createAccount (ECDSA) gas:", used);
    }

    // =========================================================================
    // Full first-userOp via EntryPoint.handleOps (matches what users see on-chain)
    // =========================================================================

    function test_gas_firstUserOp_wots() public {
        WotsSigner.Key memory k = WotsSigner.derive(bytes32(uint256(0xC0FFEE)));
        address predicted = factory.getAddress(k.addr, 0, 1);
        vm.deal(predicted, 10 ether);

        // initCode = factory address || createAccount(owner, salt, mode)
        bytes memory initCode = abi.encodePacked(
            address(factory),
            abi.encodeWithSelector(factory.createAccount.selector, k.addr, uint256(0), uint8(1))
        );

        bytes memory callData = abi.encodePacked(
            abi.encodeWithSelector(SimpleAccount_WOTS.execute.selector, address(0), uint256(0), bytes("")),
            bytes20(makeAddr("nextMain"))
        );

        PackedUserOperation memory op = PackedUserOperation({
            sender: predicted,
            nonce: 0,
            initCode: initCode,
            callData: callData,
            accountGasLimits: bytes32(abi.encodePacked(uint128(3_000_000), uint128(2_000_000))),
            preVerificationGas: 100_000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: "",
            signature: ""
        });

        bytes32 userOpHash = entrypoint.getUserOpHash(op);
        op.signature = WotsSigner.sign(k, userOpHash, bytes32(uint256(0xDEAD)));

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;

        uint256 before = gasleft();
        entrypoint.handleOps(ops, payable(makeAddr("beneficiary")));
        uint256 used = before - gasleft();
        console.log("first userOp (WOTS, includes deploy) gas:", used);
    }

    function test_gas_subsequentUserOp_wots() public {
        WotsSigner.Key memory k = WotsSigner.derive(bytes32(uint256(0xC0FFEE)));
        address addr = factory.createAccount(k.addr, 0, 1);
        vm.deal(addr, 10 ether);

        bytes memory callData = abi.encodePacked(
            abi.encodeWithSelector(SimpleAccount_WOTS.execute.selector, address(0), uint256(0), bytes("")),
            bytes20(makeAddr("nextMain"))
        );

        PackedUserOperation memory op = PackedUserOperation({
            sender: addr,
            nonce: 0,
            initCode: "",
            callData: callData,
            accountGasLimits: bytes32(abi.encodePacked(uint128(2_000_000), uint128(2_000_000))),
            preVerificationGas: 100_000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: "",
            signature: ""
        });

        bytes32 userOpHash = entrypoint.getUserOpHash(op);
        op.signature = WotsSigner.sign(k, userOpHash, bytes32(uint256(0xDEAD)));

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;

        uint256 before = gasleft();
        entrypoint.handleOps(ops, payable(makeAddr("beneficiary")));
        uint256 used = before - gasleft();
        console.log("subsequent userOp (WOTS) gas:", used);
    }

    function test_gas_firstUserOp_ecdsa() public {
        uint256 ownerPk = 0xA11CE;
        address owner = vm.addr(ownerPk);
        address predicted = factory.getAddress(owner, 0, 0);
        vm.deal(predicted, 10 ether);

        bytes memory initCode = abi.encodePacked(
            address(factory),
            abi.encodeWithSelector(factory.createAccount.selector, owner, uint256(0), uint8(0))
        );

        bytes memory callData = abi.encodePacked(
            abi.encodeWithSelector(SimpleAccount_ECDSA.execute.selector, address(0), uint256(0), bytes("")),
            bytes20(makeAddr("nextMain"))
        );

        PackedUserOperation memory op = PackedUserOperation({
            sender: predicted,
            nonce: 0,
            initCode: initCode,
            callData: callData,
            accountGasLimits: bytes32(abi.encodePacked(uint128(2_000_000), uint128(1_000_000))),
            preVerificationGas: 100_000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: "",
            signature: ""
        });

        bytes32 userOpHash = entrypoint.getUserOpHash(op);
        bytes32 ethHash = MessageHashUtils.toEthSignedMessageHash(userOpHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPk, ethHash);
        op.signature = abi.encodePacked(r, s, v);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;

        uint256 before = gasleft();
        entrypoint.handleOps(ops, payable(makeAddr("beneficiary")));
        uint256 used = before - gasleft();
        console.log("first userOp (ECDSA, includes deploy) gas:", used);
    }

    function test_gas_subsequentUserOp_ecdsa() public {
        uint256 ownerPk = 0xA11CE;
        address owner = vm.addr(ownerPk);
        address addr = factory.createAccount(owner, 0, 0);
        vm.deal(addr, 10 ether);

        bytes memory callData = abi.encodePacked(
            abi.encodeWithSelector(SimpleAccount_ECDSA.execute.selector, address(0), uint256(0), bytes("")),
            bytes20(makeAddr("nextMain"))
        );

        PackedUserOperation memory op = PackedUserOperation({
            sender: addr,
            nonce: 0,
            initCode: "",
            callData: callData,
            accountGasLimits: bytes32(abi.encodePacked(uint128(1_000_000), uint128(1_000_000))),
            preVerificationGas: 100_000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: "",
            signature: ""
        });

        bytes32 userOpHash = entrypoint.getUserOpHash(op);
        bytes32 ethHash = MessageHashUtils.toEthSignedMessageHash(userOpHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPk, ethHash);
        op.signature = abi.encodePacked(r, s, v);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;

        uint256 before = gasleft();
        entrypoint.handleOps(ops, payable(makeAddr("beneficiary")));
        uint256 used = before - gasleft();
        console.log("subsequent userOp (ECDSA) gas:", used);
    }
}

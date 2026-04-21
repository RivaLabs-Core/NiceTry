// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";

// Real Kernel v3.1 pieces
import {Kernel} from "kernel/Kernel.sol";
import {KernelFactory} from "kernel/factory/KernelFactory.sol";
import {IValidator, IHook} from "kernel/interfaces/IERC7579Modules.sol";
import {ValidatorLib} from "kernel/utils/ValidationTypeLib.sol";
import {ValidationId} from "kernel/types/Types.sol";
import {EntryPointLib} from "kernel/sdk/TestBase/erc4337Util.sol";
import {IEntryPoint} from "kernel/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "kernel/interfaces/PackedUserOperation.sol";
import {ExecLib} from "kernel/utils/ExecLib.sol";
import {ExecMode} from "kernel/types/Types.sol";

// Our pieces
import {WotsCVerifier} from "../src/WotsCVerifier.sol";
import {IWotsCVerifier} from "../src/Interfaces/IWotsCVerifier.sol";
import {KernelRotatingWOTSValidator} from "../src/Module/KernelRotatingWOTSValidator.sol";

// Test-only signer from the existing WOTS verifier suite.
import {WotsSigner} from "./WotsCVerifier.t.sol";

/// @dev End-to-end: real EntryPoint v0.7, real Kernel v3.1 account, real
///      WotsCVerifier, real in-Solidity WOTS+C signer. Proves the full flow
///      of the WOTS+C Kernel validator, including that Kernel tolerates a
///      WOTS-sized (several-hundred-byte) signature in userOp.signature and
///      the 20-byte nextOwner tail on userOp.callData.
contract KernelWOTSIntegrationTest is Test {
    IEntryPoint entrypoint;
    KernelFactory factory;
    WotsCVerifier realVerifier;
    KernelRotatingWOTSValidator validator;
    Kernel account;

    WotsSigner.Key signerKey;

    function setUp() public {
        entrypoint = IEntryPoint(EntryPointLib.deploy());

        Kernel impl = new Kernel(entrypoint);
        factory = new KernelFactory(address(impl));

        realVerifier = new WotsCVerifier();
        validator = new KernelRotatingWOTSValidator(IWotsCVerifier(address(realVerifier)));

        // Derive a real WOTS+C key; its address is the initial owner.
        signerKey = WotsSigner.derive(bytes32(uint256(0xC0FFEE)));

        ValidationId rootValidator =
            ValidatorLib.validatorToIdentifier(IValidator(address(validator)));

        bytes memory initData = abi.encodeWithSelector(
            Kernel.initialize.selector,
            rootValidator,
            IHook(address(0)),
            abi.encode(signerKey.addr),
            bytes(""),
            new bytes[](0)
        );

        address accountAddr = factory.createAccount(initData, bytes32(0));
        account = Kernel(payable(accountAddr));

        vm.deal(address(account), 10 ether);
    }

    function test_install_ownerSetToWOTSAddress() public view {
        assertEq(validator.owners(address(account)), signerKey.addr);
    }

    function test_userOp_rotatesOwner() public {
        address nextOwner = makeAddr("nextWotsOwner");
        address target = makeAddr("target");

        PackedUserOperation memory op = _buildUserOp(target, 0, "", nextOwner);
        bytes32 userOpHash = entrypoint.getUserOpHash(op);
        op.signature = WotsSigner.sign(signerKey, userOpHash, bytes32(uint256(0xDEADBEEF)));

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        entrypoint.handleOps(ops, payable(makeAddr("beneficiary")));

        assertEq(validator.owners(address(account)), nextOwner);
    }

    function test_userOp_wrongKeyRejected() public {
        address nextOwner = makeAddr("nextWotsOwner");

        PackedUserOperation memory op = _buildUserOp(makeAddr("target"), 0, "", nextOwner);
        bytes32 userOpHash = entrypoint.getUserOpHash(op);

        // Sign with a different key — not the installed owner.
        WotsSigner.Key memory wrongKey = WotsSigner.derive(bytes32(uint256(0xBADBAD)));
        op.signature = WotsSigner.sign(wrongKey, userOpHash, bytes32(uint256(1)));

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;

        vm.expectRevert();
        entrypoint.handleOps(ops, payable(makeAddr("beneficiary")));

        assertEq(validator.owners(address(account)), signerKey.addr);
    }

    // --- helpers ---

    function _buildUserOp(
        address target,
        uint256 value,
        bytes memory callData,
        address nextOwner
    ) internal view returns (PackedUserOperation memory) {
        ExecMode execMode = ExecLib.encodeSimpleSingle();
        bytes memory executionCalldata = ExecLib.encodeSingle(target, value, callData);

        bytes memory fullCallData = abi.encodePacked(
            abi.encodeWithSelector(account.execute.selector, execMode, executionCalldata),
            bytes20(nextOwner)
        );

        return PackedUserOperation({
            sender: address(account),
            nonce: entrypoint.getNonce(address(account), 0),
            initCode: "",
            callData: fullCallData,
            accountGasLimits: bytes32(abi.encodePacked(uint128(2_000_000), uint128(2_000_000))),
            preVerificationGas: 100_000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: "",
            signature: ""
        });
    }
}

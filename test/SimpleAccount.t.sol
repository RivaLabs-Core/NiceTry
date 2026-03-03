// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/SimpleAccount.sol";
import "../src/SimpleAccountFactory.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

contract SimpleAccountTest is Test {
    SimpleAccountFactory factory;
    SimpleAccount account;
    IEntryPoint entryPoint;

    uint256 ownerPk0 = 0xA11CE;
    uint256 ownerPk1 = 0xB0B;
    uint256 ownerPk2 = 0xCAFE;
    uint256 ownerPk3 = 0xDEAD;

    address owner0;
    address owner1;
    address owner2;
    address owner3;

    address recipient = makeAddr("recipient");

    address constant ENTRYPOINT = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;

    function setUp() public {
        owner0 = vm.addr(ownerPk0);
        owner1 = vm.addr(ownerPk1);
        owner2 = vm.addr(ownerPk2);
        owner3 = vm.addr(ownerPk3);

        entryPoint = IEntryPoint(ENTRYPOINT);
        vm.etch(ENTRYPOINT, hex"00");

        factory = new SimpleAccountFactory(entryPoint);

        address accountAddr = factory.createAccount(owner0, 0);
        account = SimpleAccount(payable(accountAddr));

        vm.deal(address(account), 100 ether);
    }

    // =========================================================================
    // Factory Tests
    // =========================================================================

    function test_FactoryDeploysAccount() public view {
        assertEq(account.owner(), owner0);
        assertEq(address(account.entryPoint()), ENTRYPOINT);
    }

    function test_FactoryDeterministicAddress() public view {
        address predicted = factory.getAddress(owner0, 0);
        assertEq(predicted, address(account));
    }

    function test_FactoryDifferentSaltGivesDifferentAddress() public view {
        address addr0 = factory.getAddress(owner0, 0);
        address addr1 = factory.getAddress(owner0, 1);
        assertTrue(addr0 != addr1);
    }

    function test_FactoryDifferentOwnerGivesDifferentAddress() public {
        address addr1 = factory.getAddress(owner0, 0);
        address addr2 = factory.getAddress(makeAddr("other"), 0);
        assertTrue(addr1 != addr2);
    }

    function test_FactoryReturnsSameAddressIfAlreadyDeployed() public {
        address first = factory.createAccount(owner0, 0);
        address second = factory.createAccount(owner0, 0);
        assertEq(first, second);
    }

    function test_CannotReinitialize() public {
        vm.expectRevert("SimpleAccount: already initialized");
        account.initialize(makeAddr("attacker"));
    }

    // =========================================================================
    // Execute + Rotation Tests
    // =========================================================================

    function test_ExecuteSendsETHAndRotatesOwner() public {
        _executeWithRotation(recipient, 1 ether, "", owner1);

        assertEq(recipient.balance, 1 ether);
        assertEq(account.owner(), owner1);
    }

    function test_ExecuteRevertsIfNotEntryPoint() public {
        bytes memory callData = _buildExecuteCalldata(recipient, 1 ether, "", owner1);

        vm.prank(makeAddr("random"));
        (bool ok,) = address(account).call(callData);
        assertFalse(ok);
    }

    function test_ExecuteRevertsOnZeroNextOwner() public {
        bytes memory callData = _buildExecuteCalldata(recipient, 1 ether, "", address(0));

        vm.prank(ENTRYPOINT);
        (bool ok,) = address(account).call(callData);
        assertFalse(ok);
    }

    function test_ExecuteEmitsRotationEvent() public {
        bytes memory callData = _buildExecuteCalldata(recipient, 0, "", owner1);

        vm.prank(ENTRYPOINT);
        vm.expectEmit(true, true, false, false);
        emit SimpleAccount.OwnerRotated(owner0, owner1);
        (bool ok,) = address(account).call(callData);
        assertTrue(ok);
    }

    function test_ExecuteBatchAndRotate() public {
        address recipient2 = makeAddr("recipient2");

        address[] memory targets = new address[](2);
        targets[0] = recipient;
        targets[1] = recipient2;

        uint256[] memory values = new uint256[](2);
        values[0] = 1 ether;
        values[1] = 2 ether;

        bytes[] memory datas = new bytes[](2);
        datas[0] = "";
        datas[1] = "";

        _executeBatchWithRotation(targets, values, datas, owner1);

        assertEq(recipient.balance, 1 ether);
        assertEq(recipient2.balance, 2 ether);
        assertEq(account.owner(), owner1);
    }

    function test_ExecuteBatchRevertsOnLengthMismatch() public {
        address[] memory targets = new address[](2);
        uint256[] memory values = new uint256[](1);
        bytes[] memory datas = new bytes[](2);

        bytes memory callData = abi.encodePacked(
            abi.encodeWithSelector(account.executeBatch.selector, targets, values, datas),
            bytes20(owner1)
        );

        vm.prank(ENTRYPOINT);
        (bool ok,) = address(account).call(callData);
        assertFalse(ok);
    }

    // =========================================================================
    // Signature Validation Tests
    // =========================================================================

    function test_ValidateUserOpValidSignature() public {
        bytes32 userOpHash = keccak256("test userop");
        bytes memory signature = _sign(ownerPk0, userOpHash);
        PackedUserOperation memory userOp = _buildUserOp(signature, 0);

        vm.prank(ENTRYPOINT);
        uint256 validationData = account.validateUserOp(userOp, userOpHash, 0);

        assertEq(validationData, 0);
    }

    function test_ValidateUserOpInvalidSignature() public {
        bytes32 userOpHash = keccak256("test userop");
        bytes memory signature = _sign(0xBAD, userOpHash);
        PackedUserOperation memory userOp = _buildUserOp(signature, 0);

        vm.prank(ENTRYPOINT);
        uint256 validationData = account.validateUserOp(userOp, userOpHash, 0);

        assertEq(validationData, 1);
    }

    function test_ValidateUserOpPaysPrefund() public {
        bytes32 userOpHash = keccak256("test userop");
        bytes memory signature = _sign(ownerPk0, userOpHash);
        PackedUserOperation memory userOp = _buildUserOp(signature, 0);

        uint256 prefund = 0.1 ether;
        uint256 epBalBefore = ENTRYPOINT.balance;

        vm.prank(ENTRYPOINT);
        account.validateUserOp(userOp, userOpHash, prefund);

        assertEq(ENTRYPOINT.balance, epBalBefore + prefund);
    }

    function test_ValidateUserOpRevertsIfNotEntryPoint() public {
        PackedUserOperation memory userOp = _buildUserOp(hex"00", 0);

        vm.prank(makeAddr("random"));
        vm.expectRevert("SimpleAccount: not from EntryPoint");
        account.validateUserOp(userOp, keccak256("x"), 0);
    }

    // =========================================================================
    // Multi-Transaction Rotation Chain
    // =========================================================================

    /// @dev 3 sequential UserOps: owner0 -> owner1 -> owner2 -> owner3
    function test_MultiTxRotationChain() public {
        // --- TX 0: owner0 signs, rotates to owner1 ---
        bytes32 hash0 = keccak256("userop-0");
        bytes memory sig0 = _sign(ownerPk0, hash0);

        vm.prank(ENTRYPOINT);
        assertEq(account.validateUserOp(_buildUserOp(sig0, 0), hash0, 0), 0);

        _executeWithRotation(recipient, 1 ether, "", owner1);

        assertEq(account.owner(), owner1);
        assertEq(recipient.balance, 1 ether);

        // --- TX 1: owner1 signs, rotates to owner2 ---
        bytes32 hash1 = keccak256("userop-1");
        bytes memory sig1 = _sign(ownerPk1, hash1);

        vm.prank(ENTRYPOINT);
        assertEq(account.validateUserOp(_buildUserOp(sig1, 1), hash1, 0), 0);

        _executeWithRotation(recipient, 2 ether, "", owner2);

        assertEq(account.owner(), owner2);
        assertEq(recipient.balance, 3 ether);

        // --- TX 2: owner2 signs, rotates to owner3 ---
        bytes32 hash2 = keccak256("userop-2");
        bytes memory sig2 = _sign(ownerPk2, hash2);

        vm.prank(ENTRYPOINT);
        assertEq(account.validateUserOp(_buildUserOp(sig2, 2), hash2, 0), 0);

        _executeWithRotation(recipient, 3 ether, "", owner3);

        assertEq(account.owner(), owner3);
        assertEq(recipient.balance, 6 ether);
    }

    /// @dev After rotation, the old owner's signature must be rejected.
    function test_OldOwnerRejectedAfterRotation() public {
        _executeWithRotation(recipient, 0, "", owner1);
        assertEq(account.owner(), owner1);

        // owner0 tries to sign — should fail
        bytes32 userOpHash = keccak256("sneaky userop");
        bytes memory oldSig = _sign(ownerPk0, userOpHash);

        vm.prank(ENTRYPOINT);
        uint256 validationData = account.validateUserOp(
            _buildUserOp(oldSig, 1),
            userOpHash,
            0
        );

        assertEq(validationData, 1); // rejected
    }

    /// @dev Rotating to self (same owner) should work.
    function test_RotateToSelf() public {
        _executeWithRotation(recipient, 1 ether, "", owner0);
        assertEq(account.owner(), owner0);
    }

    // =========================================================================
    // Receive ETH
    // =========================================================================

    function test_ReceiveETH() public {
        uint256 balBefore = address(account).balance;
        vm.deal(makeAddr("sender"), 1 ether);
        vm.prank(makeAddr("sender"));
        (bool ok,) = address(account).call{value: 1 ether}("");
        assertTrue(ok);
        assertEq(address(account).balance, balBefore + 1 ether);
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    /// @dev Build execute calldata with nextOwner appended as last 20 bytes
    function _buildExecuteCalldata(
        address to,
        uint256 value,
        bytes memory data,
        address nextOwner
    ) internal view returns (bytes memory) {
        return abi.encodePacked(
            abi.encodeWithSelector(account.execute.selector, to, value, data),
            bytes20(nextOwner)
        );
    }

    /// @dev Call execute with nextOwner appended, as EntryPoint
    function _executeWithRotation(
        address to,
        uint256 value,
        bytes memory data,
        address nextOwner
    ) internal {
        bytes memory callData = _buildExecuteCalldata(to, value, data, nextOwner);

        vm.prank(ENTRYPOINT);
        (bool ok, bytes memory ret) = address(account).call(callData);
        require(ok, string(ret));
    }

    /// @dev Call executeBatch with nextOwner appended, as EntryPoint
    function _executeBatchWithRotation(
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory datas,
        address nextOwner
    ) internal {
        bytes memory callData = abi.encodePacked(
            abi.encodeWithSelector(account.executeBatch.selector, targets, values, datas),
            bytes20(nextOwner)
        );

        vm.prank(ENTRYPOINT);
        (bool ok, bytes memory ret) = address(account).call(callData);
        require(ok, string(ret));
    }

    function _sign(uint256 pk, bytes32 userOpHash) internal pure returns (bytes memory) {
        bytes32 ethHash = MessageHashUtils.toEthSignedMessageHash(userOpHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, ethHash);
        return abi.encodePacked(r, s, v);
    }

    function _buildUserOp(
        bytes memory signature,
        uint256 nonce
    ) internal view returns (PackedUserOperation memory) {
        return PackedUserOperation({
            sender: address(account),
            nonce: nonce,
            initCode: "",
            callData: "",
            accountGasLimits: bytes32(0),
            preVerificationGas: 0,
            gasFees: bytes32(0),
            paymasterAndData: "",
            signature: signature
        });
    }
}

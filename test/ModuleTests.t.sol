// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {RotatingECDSAValidator} from "../src/Module/RotatingECDSAValidator.sol";
import {MockNexusAccount} from "../src/Module/MockNexusAccount.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

contract RotatingECDSAValidatorTest is Test {
    RotatingECDSAValidator validator;
    MockNexusAccount accountA;
    MockNexusAccount accountB;

    uint256 key0 = 0xA11CE;
    uint256 key1 = 0xB0B;
    uint256 key2 = 0xCA110;

    address owner0;
    address owner1;
    address owner2;

    function setUp() public {
        validator = new RotatingECDSAValidator();
        accountA  = new MockNexusAccount(address(validator));
        accountB  = new MockNexusAccount(address(validator));

        owner0 = vm.addr(key0);
        owner1 = vm.addr(key1);
        owner2 = vm.addr(key2);

        accountA.installValidator(abi.encode(owner0));
    }

    // --- helpers ---

    function _op(address sender, bytes memory callData, bytes memory sig)
        internal pure returns (PackedUserOperation memory)
    {
        return PackedUserOperation({
            sender:             sender,
            nonce:              0,
            initCode:           "",
            callData:           callData,
            accountGasLimits:   bytes32(0),
            preVerificationGas: 0,
            gasFees:            bytes32(0),
            paymasterAndData:   "",
            signature:          sig
        });
    }

    function _sign(uint256 signerKey, bytes32 opHash)
        internal pure returns (bytes memory)
    {
        bytes32 ethHash = MessageHashUtils.toEthSignedMessageHash(opHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, ethHash);
        return abi.encodePacked(r, s, v);
    }

    /// @dev callData payload that ends with nextOwner as its last 20 bytes.
    function _cd(address nextOwner) internal pure returns (bytes memory) {
        return abi.encodePacked(bytes20(nextOwner));
    }

    // --- onInstall ---

    function test_onInstall_setsOwner() public view {
        assertEq(validator.owners(address(accountA)), owner0);
    }

    function test_onInstall_revertsIfAlreadyInstalled() public {
        vm.expectRevert("RotatingECDSA: already installed");
        accountA.installValidator(abi.encode(owner1));
    }

    function test_onInstall_revertsOnZeroOwner() public {
        vm.expectRevert("RotatingECDSA: zero owner");
        accountB.installValidator(abi.encode(address(0)));
    }

    // --- isInitialized ---

    function test_isInitialized_trueAfterInstall() public view {
        assertTrue(validator.isInitialized(address(accountA)));
    }

    function test_isInitialized_falseBeforeInstall() public view {
        assertFalse(validator.isInitialized(address(accountB)));
    }

    function test_isInitialized_falseAfterUninstall() public {
        accountA.uninstallValidator();
        assertFalse(validator.isInitialized(address(accountA)));
    }

    function test_nexusGuard_rejectsUninstalledValidator() public {
        bytes32 opHash = keccak256("op");
        vm.expectRevert("MockNexus: validator not installed");
        accountB.validateUserOp(_op(address(accountB), _cd(owner1), _sign(key0, opHash)), opHash);
    }

    // --- validateUserOp success ---

    function test_validateUserOp_returnsSuccess() public {
        bytes32 opHash = keccak256("op1");
        uint256 result = accountA.validateUserOp(
            _op(address(accountA), _cd(owner1), _sign(key0, opHash)), opHash
        );
        assertEq(result, 0);
    }

    function test_validateUserOp_rotatesOwner() public {
        bytes32 opHash = keccak256("op1");
        accountA.validateUserOp(_op(address(accountA), _cd(owner1), _sign(key0, opHash)), opHash);
        assertEq(validator.owners(address(accountA)), owner1);
    }

    function test_validateUserOp_emitsOwnerRotated() public {
        bytes32 opHash = keccak256("op1");
        vm.expectEmit(true, true, true, true);
        emit RotatingECDSAValidator.OwnerRotated(address(accountA), owner0, owner1);
        accountA.validateUserOp(_op(address(accountA), _cd(owner1), _sign(key0, opHash)), opHash);
    }

    function test_validateUserOp_chainRotation() public {
        bytes32 h1 = keccak256("op1");
        accountA.validateUserOp(_op(address(accountA), _cd(owner1), _sign(key0, h1)), h1);
        assertEq(validator.owners(address(accountA)), owner1);

        bytes32 h2 = keccak256("op2");
        accountA.validateUserOp(_op(address(accountA), _cd(owner2), _sign(key1, h2)), h2);
        assertEq(validator.owners(address(accountA)), owner2);

        bytes32 h3 = keccak256("op3");
        accountA.validateUserOp(_op(address(accountA), _cd(owner0), _sign(key2, h3)), h3);
        assertEq(validator.owners(address(accountA)), owner0);
    }

    // --- validateUserOp failure ---

    function test_validateUserOp_wrongSignerReturnsFailed() public {
        bytes32 opHash = keccak256("op1");
        uint256 result = accountA.validateUserOp(
            _op(address(accountA), _cd(owner1), _sign(0xDEAD, opHash)), opHash
        );
        assertEq(result, 1);
    }

    function test_validateUserOp_wrongSignerDoesNotRotate() public {
        bytes32 opHash = keccak256("op1");
        accountA.validateUserOp(_op(address(accountA), _cd(owner1), _sign(0xDEAD, opHash)), opHash);
        assertEq(validator.owners(address(accountA)), owner0);
    }

    function test_validateUserOp_burnedKeyFails() public {
        bytes32 h1 = keccak256("op1");
        accountA.validateUserOp(_op(address(accountA), _cd(owner1), _sign(key0, h1)), h1);

        bytes32 h2 = keccak256("op2");
        uint256 result = accountA.validateUserOp(
            _op(address(accountA), _cd(owner2), _sign(key0, h2)), h2
        );
        assertEq(result, 1);
        assertEq(validator.owners(address(accountA)), owner1);
    }

    function test_keyBurned_evenIfExecutionFails() public {
        bytes32 opHash = keccak256("op1");
        accountA.validateUserOp(_op(address(accountA), _cd(owner1), _sign(key0, opHash)), opHash);
        assertEq(validator.owners(address(accountA)), owner1);

        uint256 result = accountA.validateUserOp(
            _op(address(accountA), _cd(owner2), _sign(key0, keccak256("op2"))), keccak256("op2")
        );
        assertEq(result, 1);
    }

    // --- malformed callData / next owner ---

    function test_malformedCallData_tooShort() public {
        vm.expectRevert("RotatingECDSA: calldata too short");
        accountA.validateUserOp(
            _op(address(accountA), hex"aabb", _sign(key0, keccak256("op"))),
            keccak256("op")
        );
    }

    function test_malformedCallData_zeroNextOwner() public {
        bytes32 opHash = keccak256("op1");
        vm.expectRevert("RotatingECDSA: zero next owner");
        accountA.validateUserOp(
            _op(address(accountA), _cd(address(0)), _sign(key0, opHash)), opHash
        );
    }

    // --- multi-account isolation ---

    function test_isolation_rotationDoesNotAffectOtherAccount() public {
        accountB.installValidator(abi.encode(owner2));

        bytes32 h = keccak256("op1");
        accountA.validateUserOp(_op(address(accountA), _cd(owner1), _sign(key0, h)), h);

        assertEq(validator.owners(address(accountA)), owner1);
        assertEq(validator.owners(address(accountB)), owner2);
    }

    // --- onUninstall ---

    function test_onUninstall_clearsOwner() public {
        accountA.uninstallValidator();
        assertEq(validator.owners(address(accountA)), address(0));
    }

    function test_onUninstall_allowsReinstall() public {
        accountA.uninstallValidator();
        accountA.installValidator(abi.encode(owner2));
        assertEq(validator.owners(address(accountA)), owner2);
    }

    // --- ERC-1271 ---

    function test_isValidSignatureWithSender_alwaysInvalid() public view {
        assertEq(
            validator.isValidSignatureWithSender(address(0), bytes32(0), ""),
            bytes4(0xffffffff)
        );
    }

    // --- isModuleType ---

    function test_isModuleType_validatorTrue() public view {
        assertTrue(validator.isModuleType(1));
    }

    function test_isModuleType_othersFalse() public view {
        assertFalse(validator.isModuleType(2));
        assertFalse(validator.isModuleType(3));
        assertFalse(validator.isModuleType(4));
    }

    // --- fuzz ---

    function testFuzz_wrongSigner_alwaysFails(uint256 randomKey) public {
        vm.assume(randomKey != key0 && randomKey > 0);
        vm.assume(randomKey < 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141);

        bytes32 opHash = keccak256("fuzz");
        uint256 result = accountA.validateUserOp(
            _op(address(accountA), _cd(owner1), _sign(randomKey, opHash)), opHash
        );
        assertEq(result, 1);
        assertEq(validator.owners(address(accountA)), owner0);
    }

    function testFuzz_rotationLandsOnNextOwner(address nextOwner) public {
        vm.assume(nextOwner != address(0));
        bytes32 opHash = keccak256("fuzz");
        accountA.validateUserOp(_op(address(accountA), _cd(nextOwner), _sign(key0, opHash)), opHash);
        assertEq(validator.owners(address(accountA)), nextOwner);
    }
}
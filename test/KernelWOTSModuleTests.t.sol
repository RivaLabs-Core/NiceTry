// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {KernelRotatingWOTSValidator} from "../src/Module/KernelRotatingWOTSValidator.sol";
import {MockKernelAccount} from "../src/Module/MockKernelAccount.sol";
import {IWotsCVerifier} from "../src/Interfaces/IWotsCVerifier.sol";
import {WOTS_BLOB_LEN} from "../src/WotsCVerifier.sol";
import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";

/// @dev Toggleable mock verifier — same shape as the one in test/SimpleAccount_WOTS.t.sol.
contract MockWotsVerifier is IWotsCVerifier {
    bool public result = true;
    function setResult(bool r) external { result = r; }
    function verify(bytes calldata, bytes32, address) external view returns (bool) {
        return result;
    }
}

contract KernelRotatingWOTSValidatorTest is Test {
    KernelRotatingWOTSValidator validator;
    MockWotsVerifier verifier;
    MockKernelAccount accountA;
    MockKernelAccount accountB;

    address owner0 = makeAddr("wotsOwner0");
    address owner1 = makeAddr("wotsOwner1");
    address owner2 = makeAddr("wotsOwner2");

    function setUp() public {
        verifier = new MockWotsVerifier();
        validator = new KernelRotatingWOTSValidator(verifier);
        accountA = new MockKernelAccount(address(validator));
        accountB = new MockKernelAccount(address(validator));
        accountA.installValidator(abi.encode(owner0));
    }

    // --- helpers ---

    function _op(address sender, bytes memory callData, bytes memory sig)
        internal pure returns (PackedUserOperation memory)
    {
        return PackedUserOperation({
            sender: sender,
            nonce: 0,
            initCode: "",
            callData: callData,
            accountGasLimits: bytes32(0),
            preVerificationGas: 0,
            gasFees: bytes32(0),
            paymasterAndData: "",
            signature: sig
        });
    }

    function _cd(address nextOwner) internal pure returns (bytes memory) {
        return abi.encodePacked(bytes20(nextOwner));
    }

    function _blob() internal pure returns (bytes memory) {
        return new bytes(WOTS_BLOB_LEN);
    }

    // --- onInstall ---

    function test_onInstall_setsOwner() public view {
        assertEq(validator.owners(address(accountA)), owner0);
    }

    function test_onInstall_revertsIfAlreadyInstalled() public {
        vm.expectRevert("KernelRotatingWOTS: already installed");
        accountA.installValidator(abi.encode(owner1));
    }

    function test_onInstall_revertsOnZeroOwner() public {
        vm.expectRevert("KernelRotatingWOTS: zero owner");
        accountB.installValidator(abi.encode(address(0)));
    }

    function test_onInstall_acceptsValue() public {
        vm.deal(address(this), 1 ether);
        accountB.installValidator{value: 0.5 ether}(abi.encode(owner1));
        assertEq(validator.owners(address(accountB)), owner1);
    }

    // --- isInitialized / onUninstall ---

    function test_isInitialized_trueAfterInstall() public view {
        assertTrue(validator.isInitialized(address(accountA)));
    }

    function test_isInitialized_falseBeforeInstall() public view {
        assertFalse(validator.isInitialized(address(accountB)));
    }

    function test_onUninstall_clearsOwner() public {
        accountA.uninstallValidator();
        assertFalse(validator.isInitialized(address(accountA)));
    }

    function test_onUninstall_allowsReinstall() public {
        accountA.uninstallValidator();
        accountA.installValidator(abi.encode(owner2));
        assertEq(validator.owners(address(accountA)), owner2);
    }

    // --- module type ---

    function test_isModuleType_validatorTrue() public view {
        assertTrue(validator.isModuleType(1));
    }

    function test_isModuleType_othersFalse() public view {
        assertFalse(validator.isModuleType(2));
        assertFalse(validator.isModuleType(3));
        assertFalse(validator.isModuleType(4));
        assertFalse(validator.isModuleType(5)); // kernel: policy
        assertFalse(validator.isModuleType(6)); // kernel: signer
    }

    // --- validateUserOp success ---

    function test_validateUserOp_returnsSuccessAndRotates() public {
        verifier.setResult(true);

        uint256 result = accountA.validateUserOp(
            _op(address(accountA), _cd(owner1), _blob()),
            keccak256("op")
        );

        assertEq(result, 0);
        assertEq(validator.owners(address(accountA)), owner1);
    }

    function test_validateUserOp_emitsOwnerRotated() public {
        verifier.setResult(true);

        vm.expectEmit(true, true, true, true);
        emit KernelRotatingWOTSValidator.OwnerRotated(address(accountA), owner0, owner1);
        accountA.validateUserOp(_op(address(accountA), _cd(owner1), _blob()), keccak256("op"));
    }

    function test_validateUserOp_chainRotation() public {
        verifier.setResult(true);

        accountA.validateUserOp(_op(address(accountA), _cd(owner1), _blob()), keccak256("op1"));
        assertEq(validator.owners(address(accountA)), owner1);

        accountA.validateUserOp(_op(address(accountA), _cd(owner2), _blob()), keccak256("op2"));
        assertEq(validator.owners(address(accountA)), owner2);

        accountA.validateUserOp(_op(address(accountA), _cd(owner0), _blob()), keccak256("op3"));
        assertEq(validator.owners(address(accountA)), owner0);
    }

    function test_validateUserOp_acceptsValue() public {
        vm.deal(address(this), 1 ether);
        verifier.setResult(true);

        uint256 result = accountA.validateUserOp{value: 0.1 ether}(
            _op(address(accountA), _cd(owner1), _blob()),
            keccak256("op")
        );

        assertEq(result, 0);
        assertEq(validator.owners(address(accountA)), owner1);
    }

    // --- validateUserOp failure ---

    function test_validateUserOp_invalidSigReturnsFailedNoRotate() public {
        verifier.setResult(false);

        uint256 result = accountA.validateUserOp(
            _op(address(accountA), _cd(owner1), _blob()),
            keccak256("op")
        );

        assertEq(result, 1);
        assertEq(validator.owners(address(accountA)), owner0);
    }

    function test_validateUserOp_badSigLengthReturnsFailed() public {
        verifier.setResult(true);

        uint256 result = accountA.validateUserOp(
            _op(address(accountA), _cd(owner1), new bytes(WOTS_BLOB_LEN - 1)),
            keccak256("op")
        );

        assertEq(result, 1);
        assertEq(validator.owners(address(accountA)), owner0);
    }

    function test_validateUserOp_badCalldataLengthReturnsFailed() public {
        verifier.setResult(true);

        uint256 result = accountA.validateUserOp(
            _op(address(accountA), hex"aabb", _blob()),
            keccak256("op")
        );

        assertEq(result, 1);
        assertEq(validator.owners(address(accountA)), owner0);
    }

    function test_validateUserOp_zeroNextOwnerReturnsFailed() public {
        verifier.setResult(true);

        uint256 result = accountA.validateUserOp(
            _op(address(accountA), _cd(address(0)), _blob()),
            keccak256("op")
        );

        assertEq(result, 1);
        assertEq(validator.owners(address(accountA)), owner0);
    }

    function test_uninstalledValidatorRejected() public {
        bytes32 opHash = keccak256("op");
        vm.expectRevert("MockKernel: validator not installed");
        accountB.validateUserOp(_op(address(accountB), _cd(owner1), _blob()), opHash);
    }

    // --- multi-account isolation ---

    function test_isolation_rotationDoesNotAffectOtherAccount() public {
        accountB.installValidator(abi.encode(owner2));
        verifier.setResult(true);

        accountA.validateUserOp(_op(address(accountA), _cd(owner1), _blob()), keccak256("op"));

        assertEq(validator.owners(address(accountA)), owner1);
        assertEq(validator.owners(address(accountB)), owner2);
    }

    // --- ERC-1271 disabled ---

    function test_isValidSignatureWithSender_alwaysInvalid() public view {
        assertEq(
            validator.isValidSignatureWithSender(address(0), bytes32(0), ""),
            bytes4(0xffffffff)
        );
    }

    // --- verifier immutable ---

    function test_verifierImmutableSet() public view {
        assertEq(address(validator.VERIFIER()), address(verifier));
    }
}

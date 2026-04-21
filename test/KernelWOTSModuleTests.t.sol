// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {KernelRotatingWOTSValidator} from "../src/Module/KernelRotatingWOTSValidator.sol";
import {MockKernelAccount} from "../src/Module/MockKernelAccount.sol";
import {IWotsCVerifier} from "../src/Interfaces/IWotsCVerifier.sol";
import {WOTS_BLOB_LEN} from "../src/WotsCVerifier.sol";
import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";

/// @dev wrecover mock: test pre-sets the address to return.
contract MockWotsVerifier is IWotsCVerifier {
    address public recovered;
    function setRecovered(address a) external { recovered = a; }
    function wrecover(bytes calldata, bytes32) external view returns (address) {
        return recovered;
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

    address spare1 = makeAddr("spare1");
    address spare2 = makeAddr("spare2");

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

    // --- Install ---

    function test_install_setsOwner() public view {
        assertEq(validator.owners(address(accountA)), owner0);
    }

    function test_install_revertsIfAlreadyInstalled() public {
        vm.expectRevert("KernelRotatingWOTS: already installed");
        accountA.installValidator(abi.encode(owner1));
    }

    function test_install_revertsOnZeroOwner() public {
        vm.expectRevert("KernelRotatingWOTS: zero owner");
        accountB.installValidator(abi.encode(address(0)));
    }

    function test_install_acceptsValue() public {
        vm.deal(address(this), 1 ether);
        accountB.installValidator{value: 0.5 ether}(abi.encode(owner1));
        assertEq(validator.owners(address(accountB)), owner1);
    }

    // --- Module type ---

    function test_isModuleType_validatorOnly() public view {
        assertTrue(validator.isModuleType(1));
        assertFalse(validator.isModuleType(2));
        assertFalse(validator.isModuleType(5));
        assertFalse(validator.isModuleType(6));
    }

    // --- Uninstall ---

    function test_onUninstall_clearsOwner() public {
        accountA.uninstallValidator();
        assertFalse(validator.isInitialized(address(accountA)));
    }

    // --- Main-signer validation ---

    function test_mainSigned_rotatesOwner() public {
        verifier.setRecovered(owner0);
        uint256 r = accountA.validateUserOp(_op(address(accountA), _cd(owner1), _blob()), keccak256("op"));
        assertEq(r, 0);
        assertEq(validator.owners(address(accountA)), owner1);
    }

    function test_emitsOwnerRotated() public {
        verifier.setRecovered(owner0);
        vm.expectEmit(true, true, true, true);
        emit KernelRotatingWOTSValidator.OwnerRotated(address(accountA), owner0, owner1);
        accountA.validateUserOp(_op(address(accountA), _cd(owner1), _blob()), keccak256("op"));
    }

    function test_strangerRecoveredRejected() public {
        verifier.setRecovered(makeAddr("stranger"));
        uint256 r = accountA.validateUserOp(_op(address(accountA), _cd(owner1), _blob()), keccak256("op"));
        assertEq(r, 1);
        assertEq(validator.owners(address(accountA)), owner0);
    }

    function test_badBlobLenRejected() public {
        verifier.setRecovered(owner0);
        uint256 r = accountA.validateUserOp(
            _op(address(accountA), _cd(owner1), new bytes(WOTS_BLOB_LEN - 1)),
            keccak256("op")
        );
        assertEq(r, 1);
    }

    function test_zeroNextOwnerRejected() public {
        verifier.setRecovered(owner0);
        uint256 r = accountA.validateUserOp(_op(address(accountA), _cd(address(0)), _blob()), keccak256("op"));
        assertEq(r, 1);
    }

    // --- Spare-key pool ---

    function test_addAndRemoveSpare() public {
        vm.prank(address(accountA));
        validator.rotateSpareKey(address(0), spare1);
        assertEq(validator.spareKeys(address(accountA), spare1), 1);
        assertEq(validator.spareKeyCount(address(accountA)), 1);

        vm.prank(address(accountA));
        validator.rotateSpareKey(spare1, address(0));
        assertEq(validator.spareKeys(address(accountA), spare1), 2);
        assertEq(validator.spareKeyCount(address(accountA)), 0);
    }

    function test_tombstonedCannotBeReadded() public {
        vm.prank(address(accountA));
        validator.rotateSpareKey(address(0), spare1);
        vm.prank(address(accountA));
        validator.rotateSpareKey(spare1, address(0));

        vm.prank(address(accountA));
        vm.expectRevert("KernelRotatingWOTS: new already touched");
        validator.rotateSpareKey(address(0), spare1);
    }

    function test_spareRequiresInstalled() public {
        vm.prank(address(accountB));
        vm.expectRevert("KernelRotatingWOTS: not installed");
        validator.rotateSpareKey(address(0), spare1);
    }

    function test_ownerCannotBeSpare() public {
        vm.prank(address(accountA));
        vm.expectRevert("KernelRotatingWOTS: owner cannot be spare");
        validator.rotateSpareKey(address(0), owner0);
    }

    // --- Spare signing ---

    function test_spareSigned_authorizesAndTombstones() public {
        vm.prank(address(accountA));
        validator.rotateSpareKey(address(0), spare1);

        verifier.setRecovered(spare1);
        uint256 r = accountA.validateUserOp(_op(address(accountA), _cd(owner1), _blob()), keccak256("op"));

        assertEq(r, 0);
        assertEq(validator.owners(address(accountA)), owner1);
        assertEq(validator.spareKeys(address(accountA), spare1), 2);
        assertEq(validator.spareKeyCount(address(accountA)), 0);
    }

    function test_consumedSpareCannotSignAgain() public {
        vm.prank(address(accountA));
        validator.rotateSpareKey(address(0), spare1);

        verifier.setRecovered(spare1);
        accountA.validateUserOp(_op(address(accountA), _cd(owner1), _blob()), keccak256("op0"));

        verifier.setRecovered(spare1);
        uint256 r = accountA.validateUserOp(_op(address(accountA), _cd(owner2), _blob()), keccak256("op1"));
        assertEq(r, 1);
    }

    function test_isolation_sparesArePerAccount() public {
        accountB.installValidator(abi.encode(owner2));

        vm.prank(address(accountA));
        validator.rotateSpareKey(address(0), spare1);

        verifier.setRecovered(spare1);
        uint256 r = accountB.validateUserOp(_op(address(accountB), _cd(owner1), _blob()), keccak256("op"));
        assertEq(r, 1);

        assertEq(validator.spareKeys(address(accountA), spare1), 1);
    }

    // --- ERC-1271 disabled ---

    function test_isValidSignatureWithSender_alwaysInvalid() public view {
        assertEq(
            validator.isValidSignatureWithSender(address(0), bytes32(0), ""),
            bytes4(0xffffffff)
        );
    }

    function test_verifierImmutableSet() public view {
        assertEq(address(validator.VERIFIER()), address(verifier));
    }
}

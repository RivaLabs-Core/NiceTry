// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/SimpleAccount_WOTS.sol";
import "../src/SimpleAccountFactory.sol";
import {IWotsCVerifier} from "../src/Interfaces/IWotsCVerifier.sol";
import {WOTS_BLOB_LEN} from "../src/WotsCVerifier.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";

/// @dev Configurable mock. Test pre-sets the address wrecover() should return
///      to simulate "this key signed". Default is address(0) (= bad sig).
contract MockWotsVerifier is IWotsCVerifier {
    address public recovered;

    function setRecovered(address a) external { recovered = a; }

    function wrecover(bytes calldata, bytes32) external view returns (address) {
        return recovered;
    }
}

contract SimpleAccountWotsTest is Test {
    SimpleAccountFactory factory;
    SimpleAccount_WOTS account;
    MockWotsVerifier verifier;
    IEntryPoint entryPoint;

    address owner0 = makeAddr("wotsOwner0");
    address owner1 = makeAddr("wotsOwner1");
    address owner2 = makeAddr("wotsOwner2");
    address owner3 = makeAddr("wotsOwner3");

    address spare1 = makeAddr("spare1");
    address spare2 = makeAddr("spare2");

    address recipient = makeAddr("recipient");

    address constant ENTRYPOINT = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;

    function setUp() public {
        entryPoint = IEntryPoint(ENTRYPOINT);
        vm.etch(ENTRYPOINT, hex"00");

        verifier = new MockWotsVerifier();
        factory = new SimpleAccountFactory(entryPoint, verifier);

        address accountAddr = factory.createAccount(owner0, 0, 1);
        account = SimpleAccount_WOTS(payable(accountAddr));

        vm.deal(address(account), 100 ether);
    }

    // =========================================================================
    // Factory / init
    // =========================================================================

    function test_FactoryDeploysWotsAccount() public view {
        assertEq(account.owner(), owner0);
        assertEq(address(account.ENTRY_POINT()), ENTRYPOINT);
        assertEq(address(account.VERIFIER()), address(verifier));
    }

    function test_CannotReinitialize() public {
        vm.expectRevert("WotsAccount: already initialized");
        account.initialize(makeAddr("attacker"));
    }

    // =========================================================================
    // Main-signer validation + rotation
    // =========================================================================

    function test_mainSigned_rotatesOwner() public {
        verifier.setRecovered(owner0);

        bytes memory callData = _execCalldata(recipient, 0, "", owner1);
        PackedUserOperation memory op = _userOp(callData, _dummyBlob());

        vm.prank(ENTRYPOINT);
        uint256 r = account.validateUserOp(op, keccak256("op"), 0);

        assertEq(r, 0);
        assertEq(account.owner(), owner1);
    }

    function test_mainSigned_badRecoveredDoesNotRotate() public {
        verifier.setRecovered(address(0));

        bytes memory callData = _execCalldata(recipient, 0, "", owner1);
        PackedUserOperation memory op = _userOp(callData, _dummyBlob());

        vm.prank(ENTRYPOINT);
        uint256 r = account.validateUserOp(op, keccak256("op"), 0);

        assertEq(r, 1);
        assertEq(account.owner(), owner0);
    }

    function test_mainSigned_strangerRecoveredDoesNotRotate() public {
        verifier.setRecovered(makeAddr("stranger"));

        bytes memory callData = _execCalldata(recipient, 0, "", owner1);
        PackedUserOperation memory op = _userOp(callData, _dummyBlob());

        vm.prank(ENTRYPOINT);
        uint256 r = account.validateUserOp(op, keccak256("op"), 0);

        assertEq(r, 1);
        assertEq(account.owner(), owner0);
    }

    function test_validateRevertsOnBadSigLen() public {
        verifier.setRecovered(owner0);
        bytes memory callData = _execCalldata(recipient, 0, "", owner1);
        PackedUserOperation memory op = _userOp(callData, new bytes(WOTS_BLOB_LEN - 1));

        vm.prank(ENTRYPOINT);
        vm.expectRevert("WotsAccount: bad sig length");
        account.validateUserOp(op, keccak256("op"), 0);
    }

    function test_validateRevertsOnBadCalldataLen() public {
        verifier.setRecovered(owner0);
        PackedUserOperation memory op = _userOp(hex"aabbcc", _dummyBlob());

        vm.prank(ENTRYPOINT);
        vm.expectRevert("WotsAccount: missing next owner");
        account.validateUserOp(op, keccak256("op"), 0);
    }

    function test_validateRevertsOnZeroNextOwner() public {
        verifier.setRecovered(owner0);
        bytes memory callData = _execCalldata(recipient, 0, "", address(0));
        PackedUserOperation memory op = _userOp(callData, _dummyBlob());

        vm.prank(ENTRYPOINT);
        vm.expectRevert("WotsAccount: zero next owner");
        account.validateUserOp(op, keccak256("op"), 0);
    }

    function test_validateRevertsIfNotEntryPoint() public {
        bytes memory callData = _execCalldata(recipient, 0, "", owner1);
        PackedUserOperation memory op = _userOp(callData, _dummyBlob());

        vm.prank(makeAddr("random"));
        vm.expectRevert("WotsAccount: not from EntryPoint");
        account.validateUserOp(op, keccak256("op"), 0);
    }

    function test_validatePaysPrefund() public {
        verifier.setRecovered(owner0);
        bytes memory callData = _execCalldata(recipient, 0, "", owner1);
        PackedUserOperation memory op = _userOp(callData, _dummyBlob());

        uint256 before = ENTRYPOINT.balance;
        vm.prank(ENTRYPOINT);
        account.validateUserOp(op, keccak256("op"), 0.1 ether);

        assertEq(ENTRYPOINT.balance, before + 0.1 ether);
    }

    function test_multiTxMainRotationChain() public {
        verifier.setRecovered(owner0);
        _validateMain(owner0, owner1, keccak256("op0"));
        assertEq(account.owner(), owner1);

        verifier.setRecovered(owner1);
        _validateMain(owner1, owner2, keccak256("op1"));
        assertEq(account.owner(), owner2);

        verifier.setRecovered(owner2);
        _validateMain(owner2, owner3, keccak256("op2"));
        assertEq(account.owner(), owner3);
    }

    // =========================================================================
    // Spare-key pool management
    // =========================================================================

    function test_addSpareKey() public {
        vm.prank(ENTRYPOINT);
        account.rotateSpareKey(address(0), spare1);
        assertEq(account.spareKeys(spare1), 1);
        assertEq(account.spareKeyCount(), 1);
    }

    function test_removeSpareKey_tombstones() public {
        vm.prank(ENTRYPOINT);
        account.rotateSpareKey(address(0), spare1);

        vm.prank(ENTRYPOINT);
        account.rotateSpareKey(spare1, address(0));

        assertEq(account.spareKeys(spare1), 2); // tombstoned
        assertEq(account.spareKeyCount(), 0);
    }

    function test_replaceSpareKey_tombstonesOld() public {
        vm.prank(ENTRYPOINT);
        account.rotateSpareKey(address(0), spare1);

        vm.prank(ENTRYPOINT);
        account.rotateSpareKey(spare1, spare2);

        assertEq(account.spareKeys(spare1), 2);
        assertEq(account.spareKeys(spare2), 1);
        assertEq(account.spareKeyCount(), 1);
    }

    function test_tombstonedCannotBeReadded() public {
        vm.prank(ENTRYPOINT);
        account.rotateSpareKey(address(0), spare1);
        vm.prank(ENTRYPOINT);
        account.rotateSpareKey(spare1, address(0)); // tombstone

        vm.prank(ENTRYPOINT);
        vm.expectRevert("WotsAccount: new already touched");
        account.rotateSpareKey(address(0), spare1);
    }

    function test_bothZero_reverts() public {
        vm.prank(ENTRYPOINT);
        vm.expectRevert("WotsAccount: same address");
        account.rotateSpareKey(address(0), address(0));
    }

    function test_ownerCannotBeSpare() public {
        vm.prank(ENTRYPOINT);
        vm.expectRevert("WotsAccount: owner cannot be spare");
        account.rotateSpareKey(address(0), owner0);
    }

    function test_removeInactiveReverts() public {
        vm.prank(ENTRYPOINT);
        vm.expectRevert("WotsAccount: old not active");
        account.rotateSpareKey(makeAddr("ghost"), address(0));
    }

    function test_rotateSpareKey_onlyEntryPoint() public {
        vm.prank(makeAddr("random"));
        vm.expectRevert("WotsAccount: not from EntryPoint");
        account.rotateSpareKey(address(0), spare1);
    }

    // =========================================================================
    // Spare-key signing (unified path)
    // =========================================================================

    function test_spareSigned_authorizesAnyUserOpAndTombstones() public {
        // Register a spare key
        vm.prank(ENTRYPOINT);
        account.rotateSpareKey(address(0), spare1);

        // Spare signs an arbitrary execute userOp
        verifier.setRecovered(spare1);
        bytes memory callData = _execCalldata(recipient, 1 ether, "", owner1);
        PackedUserOperation memory op = _userOp(callData, _dummyBlob());

        vm.prank(ENTRYPOINT);
        uint256 r = account.validateUserOp(op, keccak256("op"), 0);

        assertEq(r, 0);
        assertEq(account.owner(), owner1);              // main rotated
        assertEq(account.spareKeys(spare1), 2);         // tombstoned
        assertEq(account.spareKeyCount(), 0);
    }

    function test_spareSigned_emitsConsumedEvent() public {
        vm.prank(ENTRYPOINT);
        account.rotateSpareKey(address(0), spare1);
        verifier.setRecovered(spare1);

        bytes memory callData = _execCalldata(recipient, 0, "", owner1);
        PackedUserOperation memory op = _userOp(callData, _dummyBlob());

        vm.prank(ENTRYPOINT);
        vm.expectEmit(true, false, false, false);
        emit SimpleAccount_WOTS.SpareKeyConsumed(spare1);
        account.validateUserOp(op, keccak256("op"), 0);
    }

    function test_consumedSpareCannotSignAgain() public {
        vm.prank(ENTRYPOINT);
        account.rotateSpareKey(address(0), spare1);

        verifier.setRecovered(spare1);
        _validateMain(spare1, owner1, keccak256("op0"));

        // Spare is now tombstoned. Trying to sign again returns FAILED.
        verifier.setRecovered(spare1);
        bytes memory callData = _execCalldata(recipient, 0, "", owner2);
        PackedUserOperation memory op = _userOp(callData, _dummyBlob());

        vm.prank(ENTRYPOINT);
        uint256 r = account.validateUserOp(op, keccak256("op1"), 0);
        assertEq(r, 1);
        assertEq(account.owner(), owner1); // unchanged (from op0 rotation)
    }

    function test_spareSigned_onlyConsumesThatSpare() public {
        vm.prank(ENTRYPOINT);
        account.rotateSpareKey(address(0), spare1);
        vm.prank(ENTRYPOINT);
        account.rotateSpareKey(address(0), spare2);

        verifier.setRecovered(spare1);
        _validateMain(spare1, owner1, keccak256("op"));

        assertEq(account.spareKeys(spare1), 2);
        assertEq(account.spareKeys(spare2), 1); // untouched
        assertEq(account.spareKeyCount(), 1);
    }

    // =========================================================================
    // Execute (no rotation in execute — it lives in validate)
    // =========================================================================

    function test_executeSendsETH() public {
        vm.prank(ENTRYPOINT);
        account.execute(recipient, 1 ether, "");
        assertEq(recipient.balance, 1 ether);
    }

    function test_executeDoesNotRotate() public {
        vm.prank(ENTRYPOINT);
        account.execute(recipient, 0, "");
        assertEq(account.owner(), owner0);
    }

    function test_executeBatch() public {
        address r2 = makeAddr("r2");
        address[] memory targets = new address[](2);
        targets[0] = recipient; targets[1] = r2;
        uint256[] memory values = new uint256[](2);
        values[0] = 1 ether; values[1] = 2 ether;
        bytes[] memory datas = new bytes[](2);

        vm.prank(ENTRYPOINT);
        account.executeBatch(targets, values, datas);
        assertEq(recipient.balance, 1 ether);
        assertEq(r2.balance, 2 ether);
    }

    function test_ReceiveETH() public {
        vm.deal(makeAddr("sender"), 1 ether);
        vm.prank(makeAddr("sender"));
        (bool ok,) = address(account).call{value: 1 ether}("");
        assertTrue(ok);
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    function _execCalldata(address to, uint256 value, bytes memory data, address nextOwner)
        internal view returns (bytes memory)
    {
        return abi.encodePacked(
            abi.encodeWithSelector(account.execute.selector, to, value, data),
            bytes20(nextOwner)
        );
    }

    function _dummyBlob() internal pure returns (bytes memory) {
        return new bytes(WOTS_BLOB_LEN);
    }

    function _userOp(bytes memory callData, bytes memory sig)
        internal view returns (PackedUserOperation memory)
    {
        return PackedUserOperation({
            sender: address(account),
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

    /// @dev Convenience: build + validate a main-signer userOp. Assumes verifier
    ///      is already configured to return the expected signer.
    function _validateMain(address /*signer*/, address nextOwner, bytes32 userOpHash) internal {
        bytes memory callData = _execCalldata(recipient, 0, "", nextOwner);
        PackedUserOperation memory op = _userOp(callData, _dummyBlob());

        vm.prank(ENTRYPOINT);
        uint256 r = account.validateUserOp(op, userOpHash, 0);
        assertEq(r, 0);
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/SimpleAccount_WOTS.sol";
import "../src/SimpleAccountFactory.sol";
import {IWotsCVerifier} from "../src/Interfaces/IWotsCVerifier.sol";
import {WOTS_BLOB_LEN} from "../src/WotsCVerifier.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";

/// @dev Configurable mock that returns a fixed verify() result so we can
///      exercise the account's logic without running real WOTS+C arithmetic.
contract MockWotsVerifier is IWotsCVerifier {
    bool public result = true;

    function setResult(bool r) external {
        result = r;
    }

    function verify(bytes calldata, bytes32, address) external view returns (bool) {
        return result;
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
    // Factory Tests
    // =========================================================================

    function test_FactoryDeploysWotsAccount() public view {
        assertEq(account.owner(), owner0);
        assertEq(address(account.ENTRY_POINT()), ENTRYPOINT);
        assertEq(address(account.VERIFIER()), address(verifier));
    }

    function test_FactoryDeterministicAddress() public view {
        address predicted = factory.getAddress(owner0, 0, 1);
        assertEq(predicted, address(account));
    }

    function test_FactoryEcdsaAndWotsDiffer() public view {
        address ecdsaAddr = factory.getAddress(owner0, 0, 0);
        address wotsAddr = factory.getAddress(owner0, 0, 1);
        assertTrue(ecdsaAddr != wotsAddr);
    }

    function test_FactoryInvalidModeReverts() public {
        vm.expectRevert("SimpleAccountFactory: invalid mode");
        factory.createAccount(owner0, 0, 2);
    }

    function test_FactoryGetAddressInvalidModeReverts() public {
        vm.expectRevert("SimpleAccountFactory: invalid mode");
        factory.getAddress(owner0, 0, 2);
    }

    function test_FactoryReturnsSameAddressIfAlreadyDeployed() public {
        address first = factory.createAccount(owner0, 0, 1);
        address second = factory.createAccount(owner0, 0, 1);
        assertEq(first, second);
    }

    function test_CannotReinitialize() public {
        vm.expectRevert("WotsAccount: already initialized");
        account.initialize(makeAddr("attacker"));
    }

    // =========================================================================
    // Validation + Rotation Tests
    // =========================================================================

    function test_ValidateUserOpValidRotatesOwner() public {
        verifier.setResult(true);

        bytes memory callData = _buildExecuteCalldata(recipient, 0, "", owner1);
        PackedUserOperation memory userOp = _buildUserOp(callData, _dummyBlob());

        vm.prank(ENTRYPOINT);
        uint256 validationData = account.validateUserOp(userOp, keccak256("op-0"), 0);

        assertEq(validationData, 0);
        assertEq(account.owner(), owner1);
    }

    function test_ValidateUserOpInvalidDoesNotRotate() public {
        verifier.setResult(false);

        bytes memory callData = _buildExecuteCalldata(recipient, 0, "", owner1);
        PackedUserOperation memory userOp = _buildUserOp(callData, _dummyBlob());

        vm.prank(ENTRYPOINT);
        uint256 validationData = account.validateUserOp(userOp, keccak256("op-0"), 0);

        assertEq(validationData, 1);
        assertEq(account.owner(), owner0); // unchanged
    }

    function test_ValidateUserOpRevertsOnBadSigLength() public {
        bytes memory shortSig = new bytes(WOTS_BLOB_LEN - 1);
        bytes memory callData = _buildExecuteCalldata(recipient, 0, "", owner1);
        PackedUserOperation memory userOp = _buildUserOp(callData, shortSig);

        vm.prank(ENTRYPOINT);
        vm.expectRevert("WotsAccount: bad sig length");
        account.validateUserOp(userOp, keccak256("op-0"), 0);
    }

    function test_ValidateUserOpRevertsOnBadCalldataLength() public {
        bytes memory callData = hex"aabbcc"; // < 24 bytes
        PackedUserOperation memory userOp = _buildUserOp(callData, _dummyBlob());

        vm.prank(ENTRYPOINT);
        vm.expectRevert("WotsAccount: missing next owner");
        account.validateUserOp(userOp, keccak256("op-0"), 0);
    }

    function test_ValidateUserOpRevertsIfNotEntryPoint() public {
        bytes memory callData = _buildExecuteCalldata(recipient, 0, "", owner1);
        PackedUserOperation memory userOp = _buildUserOp(callData, _dummyBlob());

        vm.prank(makeAddr("random"));
        vm.expectRevert("WotsAccount: not from EntryPoint");
        account.validateUserOp(userOp, keccak256("op-0"), 0);
    }

    function test_ValidateUserOpRevertsOnZeroNextOwner() public {
        verifier.setResult(true);

        bytes memory callData = _buildExecuteCalldata(recipient, 0, "", address(0));
        PackedUserOperation memory userOp = _buildUserOp(callData, _dummyBlob());

        vm.prank(ENTRYPOINT);
        vm.expectRevert("WotsAccount: zero next owner");
        account.validateUserOp(userOp, keccak256("op-0"), 0);
    }

    function test_ValidateUserOpPaysPrefund() public {
        verifier.setResult(true);

        bytes memory callData = _buildExecuteCalldata(recipient, 0, "", owner1);
        PackedUserOperation memory userOp = _buildUserOp(callData, _dummyBlob());

        uint256 prefund = 0.1 ether;
        uint256 epBalBefore = ENTRYPOINT.balance;

        vm.prank(ENTRYPOINT);
        account.validateUserOp(userOp, keccak256("op-0"), prefund);

        assertEq(ENTRYPOINT.balance, epBalBefore + prefund);
    }

    function test_ValidateUserOpEmitsRotation() public {
        verifier.setResult(true);

        bytes memory callData = _buildExecuteCalldata(recipient, 0, "", owner1);
        PackedUserOperation memory userOp = _buildUserOp(callData, _dummyBlob());

        vm.prank(ENTRYPOINT);
        vm.expectEmit(true, true, false, false);
        emit SimpleAccount_WOTS.OwnerRotated(owner0, owner1);
        account.validateUserOp(userOp, keccak256("op-0"), 0);
    }

    // =========================================================================
    // Execute Tests (no rotation here — WOTS rotates in validateUserOp)
    // =========================================================================

    function test_ExecuteSendsETH() public {
        vm.prank(ENTRYPOINT);
        account.execute(recipient, 1 ether, "");
        assertEq(recipient.balance, 1 ether);
    }

    function test_ExecuteDoesNotRotate() public {
        vm.prank(ENTRYPOINT);
        account.execute(recipient, 0, "");
        assertEq(account.owner(), owner0); // still the initial owner
    }

    function test_ExecuteRevertsIfNotEntryPoint() public {
        vm.prank(makeAddr("random"));
        vm.expectRevert("WotsAccount: not from EntryPoint");
        account.execute(recipient, 0, "");
    }

    function test_ExecuteBatch() public {
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

        vm.prank(ENTRYPOINT);
        account.executeBatch(targets, values, datas);

        assertEq(recipient.balance, 1 ether);
        assertEq(recipient2.balance, 2 ether);
    }

    function test_ExecuteBatchRevertsOnLengthMismatch() public {
        address[] memory targets = new address[](2);
        uint256[] memory values = new uint256[](1);
        bytes[] memory datas = new bytes[](2);

        vm.prank(ENTRYPOINT);
        vm.expectRevert("WotsAccount: length mismatch");
        account.executeBatch(targets, values, datas);
    }

    // =========================================================================
    // Multi-Transaction Rotation Chain
    // =========================================================================

    /// @dev 3 sequential UserOps: owner0 -> owner1 -> owner2 -> owner3
    function test_MultiTxRotationChain() public {
        verifier.setResult(true);

        // --- TX 0 ---
        _validateAndExpectRotation(owner1, keccak256("op-0"));
        assertEq(account.owner(), owner1);

        // --- TX 1 ---
        _validateAndExpectRotation(owner2, keccak256("op-1"));
        assertEq(account.owner(), owner2);

        // --- TX 2 ---
        _validateAndExpectRotation(owner3, keccak256("op-2"));
        assertEq(account.owner(), owner3);
    }

    /// @dev A failed validation (mock returns false) must not rotate or burn state.
    function test_FailedValidationKeepsOwner() public {
        verifier.setResult(false);

        bytes memory callData = _buildExecuteCalldata(recipient, 0, "", owner1);
        PackedUserOperation memory userOp = _buildUserOp(callData, _dummyBlob());

        vm.prank(ENTRYPOINT);
        uint256 validationData = account.validateUserOp(userOp, keccak256("bad"), 0);
        assertEq(validationData, 1);
        assertEq(account.owner(), owner0);

        // subsequent valid op with correct owner still works
        verifier.setResult(true);
        _validateAndExpectRotation(owner1, keccak256("op-next"));
        assertEq(account.owner(), owner1);
    }

    // =========================================================================
    // Backup signer management (main-signer triggered)
    // =========================================================================

    function test_addBackupSigner() public {
        address b = makeAddr("backup1");
        vm.prank(ENTRYPOINT);
        vm.expectEmit(true, false, false, false);
        emit SimpleAccount_WOTS.BackupSignerAdded(b);
        account.rotateBackupSigner(address(0), b);

        assertTrue(account.backupSigners(b));
        assertEq(account.backupSignerCount(), 1);
    }

    function test_removeBackupSigner() public {
        address b = makeAddr("backup1");
        vm.prank(ENTRYPOINT);
        account.rotateBackupSigner(address(0), b);

        vm.prank(ENTRYPOINT);
        vm.expectEmit(true, false, false, false);
        emit SimpleAccount_WOTS.BackupSignerRemoved(b);
        account.rotateBackupSigner(b, address(0));

        assertFalse(account.backupSigners(b));
        assertEq(account.backupSignerCount(), 0);
    }

    function test_replaceBackupSigner() public {
        address b1 = makeAddr("backup1");
        address b2 = makeAddr("backup2");

        vm.prank(ENTRYPOINT);
        account.rotateBackupSigner(address(0), b1);

        vm.prank(ENTRYPOINT);
        vm.expectEmit(true, true, false, false);
        emit SimpleAccount_WOTS.BackupSignerReplaced(b1, b2);
        account.rotateBackupSigner(b1, b2);

        assertFalse(account.backupSigners(b1));
        assertTrue(account.backupSigners(b2));
        assertEq(account.backupSignerCount(), 1); // count unchanged on replace
    }

    function test_rotateBackupSigner_bothZero_reverts() public {
        vm.prank(ENTRYPOINT);
        vm.expectRevert("WotsAccount: same backup address");
        account.rotateBackupSigner(address(0), address(0));
    }

    function test_rotateBackupSigner_sameAddress_reverts() public {
        address b = makeAddr("b");
        vm.prank(ENTRYPOINT);
        vm.expectRevert("WotsAccount: same backup address");
        account.rotateBackupSigner(b, b);
    }

    function test_rotateBackupSigner_oldNotRegistered_reverts() public {
        vm.prank(ENTRYPOINT);
        vm.expectRevert("WotsAccount: old not registered");
        account.rotateBackupSigner(makeAddr("ghost"), makeAddr("new"));
    }

    function test_rotateBackupSigner_newAlreadyRegistered_reverts() public {
        address b = makeAddr("b");
        vm.prank(ENTRYPOINT);
        account.rotateBackupSigner(address(0), b);

        vm.prank(ENTRYPOINT);
        vm.expectRevert("WotsAccount: new already registered");
        account.rotateBackupSigner(address(0), b);
    }

    function test_rotateBackupSigner_onlyEntryPoint() public {
        vm.prank(makeAddr("random"));
        vm.expectRevert("WotsAccount: not from EntryPoint");
        account.rotateBackupSigner(address(0), makeAddr("x"));
    }

    // =========================================================================
    // Backup-triggered main-signer recovery
    // =========================================================================

    /// @dev Register a backup, then craft a backup-signed userOp to rotate main.
    function test_backupRecovery_validFlow() public {
        address backup = makeAddr("backup");
        address newMain = makeAddr("newMain");

        // main registers the backup (normal main-signed flow)
        vm.prank(ENTRYPOINT);
        account.rotateBackupSigner(address(0), backup);

        // backup-signed userOp: callData = rotateMainSigner(backup) + bytes20(newMain)
        bytes memory callData = _buildRotateMainCalldata(backup, newMain);
        PackedUserOperation memory userOp = _buildUserOp(callData, _dummyBlob());

        verifier.setResult(true);

        // validateUserOp: succeeds and burns the backup
        vm.prank(ENTRYPOINT);
        uint256 validationData = account.validateUserOp(userOp, keccak256("recovery"), 0);

        assertEq(validationData, 0);
        assertFalse(account.backupSigners(backup)); // burned
        assertEq(account.backupSignerCount(), 0);
        assertEq(account.owner(), owner0);         // main unchanged yet — execute phase moves it

        // execute phase: EntryPoint calls rotateMainSigner(backup)
        vm.prank(ENTRYPOINT);
        vm.expectEmit(true, true, true, false);
        emit SimpleAccount_WOTS.MainSignerRecovered(backup, owner0, newMain);
        (bool ok,) = address(account).call(callData);
        assertTrue(ok);

        assertEq(account.owner(), newMain);
    }

    function test_backupRecovery_unauthorizedBackup_fails() public {
        address backup = makeAddr("backup"); // NOT registered
        bytes memory callData = _buildRotateMainCalldata(backup, makeAddr("newMain"));
        PackedUserOperation memory userOp = _buildUserOp(callData, _dummyBlob());

        verifier.setResult(true); // verifier would accept, but backup isn't registered

        vm.prank(ENTRYPOINT);
        uint256 validationData = account.validateUserOp(userOp, keccak256("recovery"), 0);
        assertEq(validationData, 1);
        assertEq(account.owner(), owner0); // no change
    }

    function test_backupRecovery_badSigFails_backupStillRegistered() public {
        address backup = makeAddr("backup");
        vm.prank(ENTRYPOINT);
        account.rotateBackupSigner(address(0), backup);

        bytes memory callData = _buildRotateMainCalldata(backup, makeAddr("newMain"));
        PackedUserOperation memory userOp = _buildUserOp(callData, _dummyBlob());

        verifier.setResult(false);

        vm.prank(ENTRYPOINT);
        uint256 validationData = account.validateUserOp(userOp, keccak256("recovery"), 0);
        assertEq(validationData, 1);
        assertTrue(account.backupSigners(backup)); // NOT burned on failed validation
        assertEq(account.backupSignerCount(), 1);
    }

    function test_backupRecovery_badCallDataLen_reverts() public {
        address backup = makeAddr("backup");
        vm.prank(ENTRYPOINT);
        account.rotateBackupSigner(address(0), backup);

        // Too short: just the selector + 20 bytes, missing the address arg in the middle.
        bytes memory callData = abi.encodePacked(
            this.rotateMainSigner_selector(),
            bytes20(makeAddr("next"))
        );
        PackedUserOperation memory userOp = _buildUserOp(callData, _dummyBlob());

        vm.prank(ENTRYPOINT);
        vm.expectRevert("WotsAccount: bad backup calldata");
        account.validateUserOp(userOp, keccak256("x"), 0);
    }

    function test_rotateMainSigner_onlyEntryPoint() public {
        vm.prank(makeAddr("random"));
        vm.expectRevert("WotsAccount: not from EntryPoint");
        account.rotateMainSigner(makeAddr("b"));
    }

    /// @dev Requirement 2: registering the current owner as a backup is blocked,
    ///      so main and backup roles stay disjoint.
    function test_rotateBackupSigner_cannotRegisterOwnerAsBackup() public {
        vm.prank(ENTRYPOINT);
        vm.expectRevert("WotsAccount: owner cannot be backup");
        account.rotateBackupSigner(address(0), owner0);
    }

    /// @dev Requirement 2: a main-signed userOp targeting rotateMainSigner is
    ///      rejected. It routes to the backup path which requires the claimed
    ///      backupAddr to be registered — and main cannot register itself
    ///      (see test above), so the backup path never accepts main's key.
    function test_mainCannotCallRotateMainSigner() public {
        verifier.setResult(true);

        // Main crafts a userOp with rotateMainSigner selector, claiming some
        // backup address. Sig is main's (mock returns true regardless).
        bytes memory callData = _buildRotateMainCalldata(owner0, makeAddr("targetMain"));
        PackedUserOperation memory userOp = _buildUserOp(callData, _dummyBlob());

        vm.prank(ENTRYPOINT);
        uint256 validationData = account.validateUserOp(userOp, keccak256("x"), 0);

        // Fails because owner0 is not registered as a backup (and can't be).
        assertEq(validationData, 1);
        assertEq(account.owner(), owner0);
    }

    function test_backupRecovery_burnsOnlyThatBackup() public {
        address b1 = makeAddr("b1");
        address b2 = makeAddr("b2");
        vm.prank(ENTRYPOINT);
        account.rotateBackupSigner(address(0), b1);
        vm.prank(ENTRYPOINT);
        account.rotateBackupSigner(address(0), b2);

        bytes memory callData = _buildRotateMainCalldata(b1, makeAddr("newMain"));
        PackedUserOperation memory userOp = _buildUserOp(callData, _dummyBlob());

        verifier.setResult(true);

        vm.prank(ENTRYPOINT);
        account.validateUserOp(userOp, keccak256("recovery"), 0);

        assertFalse(account.backupSigners(b1));
        assertTrue(account.backupSigners(b2));  // untouched
        assertEq(account.backupSignerCount(), 1);
    }

    /// @dev Main signer using main-path userOp still works normally while
    ///      backups are registered (no interference).
    function test_mainPath_unaffectedByBackups() public {
        vm.prank(ENTRYPOINT);
        account.rotateBackupSigner(address(0), makeAddr("b"));

        verifier.setResult(true);
        _validateAndExpectRotation(owner1, keccak256("op"));
        assertEq(account.owner(), owner1);
        assertEq(account.backupSignerCount(), 1); // unchanged
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

    /// @dev Build callData for the backup-triggered main rotation flow:
    ///      [selector(4)][abi.encode(backupAddr)(32)][nextOwner(20)]
    function _buildRotateMainCalldata(address backupAddr, address nextOwner)
        internal
        view
        returns (bytes memory)
    {
        return abi.encodePacked(
            abi.encodeWithSelector(account.rotateMainSigner.selector, backupAddr),
            bytes20(nextOwner)
        );
    }

    /// @dev Exposed so a test can grab the selector bytes without an account instance method.
    function rotateMainSigner_selector() public view returns (bytes4) {
        return account.rotateMainSigner.selector;
    }

    /// @dev WOTS_BLOB_LEN-byte dummy blob. Content irrelevant since the verifier is mocked.
    function _dummyBlob() internal pure returns (bytes memory blob) {
        blob = new bytes(WOTS_BLOB_LEN);
    }

    function _buildUserOp(
        bytes memory callData,
        bytes memory signature
    ) internal view returns (PackedUserOperation memory) {
        return PackedUserOperation({
            sender: address(account),
            nonce: 0,
            initCode: "",
            callData: callData,
            accountGasLimits: bytes32(0),
            preVerificationGas: 0,
            gasFees: bytes32(0),
            paymasterAndData: "",
            signature: signature
        });
    }

    function _validateAndExpectRotation(address nextOwner, bytes32 userOpHash) internal {
        bytes memory callData = _buildExecuteCalldata(recipient, 0, "", nextOwner);
        PackedUserOperation memory userOp = _buildUserOp(callData, _dummyBlob());

        vm.prank(ENTRYPOINT);
        uint256 validationData = account.validateUserOp(userOp, userOpHash, 0);
        assertEq(validationData, 0);
    }
}

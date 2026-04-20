// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IAccount} from "account-abstraction/interfaces/IAccount.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {IWotsCVerifier} from "./Interfaces/IWotsCVerifier.sol";
import {WOTS_BLOB_LEN} from "./WotsCVerifier.sol";

/// @title SimpleAccount_WOTS
/// @notice ERC-4337 smart account with WOTS+C post-quantum signature verification,
///         automatic main-signer rotation, and a pool of pre-committed backup
///         WOTS+C signers for recovery.
///
///         The "owner" is a WOTS+C address (derived from the WOTS public key),
///         not an ECDSA address. Each signature is one-time use — after every
///         validated UserOp, the owner rotates to the next WOTS+C address.
///
///         Two signer roles:
///           - main owner: signs any UserOp (execute, executeBatch, managing
///             backups, etc.). Rotates on every successful UserOp.
///           - backup signers: a pool of WOTS+C addresses registered by the
///             main. Each backup can sign exactly one UserOp, and that UserOp
///             MUST target `rotateMainSigner(address)` — nothing else. A
///             successful backup validation burns that backup in the mapping
///             (atomic with authorization, in validateUserOp) and the execute
///             phase moves `owner` to the new main in `rotateMainSigner`.
///
///         userOp.signature layout (both paths):
///           [WOTS_BLOB_LEN bytes WOTS+C blob]
///
///         userOp.callData layout:
///           main path:
///             [4 bytes selector][normal ABI-encoded params][20 bytes nextOwner]
///           backup path:
///             [4 bytes rotateMainSigner.selector][abi.encoded(backupAddr)(32)][20 bytes nextOwner]
///
///         nextOwner MUST live in callData (which userOpHash commits to), not
///         in signature — otherwise a relayer could rewrite it post-signing.
contract SimpleAccount_WOTS is IAccount {

    address public owner;
    IEntryPoint public immutable ENTRY_POINT;
    IWotsCVerifier public immutable VERIFIER;

    // Pool of pre-committed WOTS+C backup signers. A non-zero entry means the
    // address is authorized to sign exactly one main-signer rotation.
    mapping(address => bool) public backupSigners;
    uint256 public backupSignerCount;

    uint256 internal constant SIG_VALIDATION_SUCCESS = 0;
    uint256 internal constant SIG_VALIDATION_FAILED = 1;

    event WotsAccountInitialized(address indexed owner, address indexed verifier);
    event Executed(address indexed to, uint256 value, bytes data);
    event ExecutionFailed(string data);
    event OwnerRotated(address indexed previousOwner, address indexed newOwner);
    event BackupSignerAdded(address indexed backup);
    event BackupSignerRemoved(address indexed backup);
    event BackupSignerReplaced(address indexed oldBackup, address indexed newBackup);
    event MainSignerRecovered(address indexed fromBackup, address indexed previousMain, address indexed newMain);

    modifier onlyEntryPoint() {
        require(msg.sender == address(ENTRY_POINT), "WotsAccount: not from EntryPoint");
        _;
    }

    constructor(IEntryPoint _entryPoint, IWotsCVerifier _verifier) {
        ENTRY_POINT = _entryPoint;
        VERIFIER = _verifier;
    }

    /// @dev Called once by the factory after clone deployment
    function initialize(address _owner) external {
        require(owner == address(0), "WotsAccount: already initialized");
        require(_owner != address(0), "WotsAccount: zero owner");
        owner = _owner;
        emit WotsAccountInitialized(_owner, address(VERIFIER));
    }

    /// @inheritdoc IAccount
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external onlyEntryPoint returns (uint256 validationData) {
        require(userOp.signature.length == WOTS_BLOB_LEN, "WotsAccount: bad sig length");
        require(userOp.callData.length >= 24, "WotsAccount: missing next owner"); // 4 selector + 20 min

        address nextOwner = address(bytes20(userOp.callData[userOp.callData.length - 20:]));

        // Dispatch on the callData selector. If it targets rotateMainSigner,
        // the authorized signer is a backup; otherwise it's the main owner.
        bytes4 selector = bytes4(userOp.callData[0:4]);
        if (selector == this.rotateMainSigner.selector) {
            validationData = _validateBackupSignedUserOp(userOp, userOpHash);
        } else {
            validationData = _validateMainSignedUserOp(userOp, userOpHash, nextOwner);
        }

        if (missingAccountFunds > 0) {
            (bool ok,) = payable(msg.sender).call{value: missingAccountFunds}("");
            require(ok, "WotsAccount: prefund failed");
        }
    }

    /// @dev Main-signer path: verify blob against current `owner`, rotate on success.
    function _validateMainSignedUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        address nextOwner
    ) internal returns (uint256) {
        bool valid = VERIFIER.verify(userOp.signature, userOpHash, owner);
        if (!valid) return SIG_VALIDATION_FAILED;

        _rotateOwner(nextOwner);
        return SIG_VALIDATION_SUCCESS;
    }

    /// @dev Backup-signer path: verify blob against a registered backup and
    ///      burn that backup atomically with authorization. The main-signer
    ///      rotation is performed later in `rotateMainSigner` (execute phase).
    ///
    ///      callData layout: [selector(4)][abi.encode(backupAddr)(32)][nextOwner(20)]
    ///      The claimed `backupAddr` is committed to by userOpHash (it lives in
    ///      callData), so the WOTS+C signature authenticates the full tuple.
    function _validateBackupSignedUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) internal returns (uint256) {
        require(userOp.callData.length >= 56, "WotsAccount: bad backup calldata");
        address backupAddr = address(bytes20(userOp.callData[16:36]));

        if (!backupSigners[backupAddr]) return SIG_VALIDATION_FAILED;

        bool valid = VERIFIER.verify(userOp.signature, userOpHash, backupAddr);
        if (!valid) return SIG_VALIDATION_FAILED;

        // Burn the backup atomically with authorization (Option B). The main
        // owner will be updated in rotateMainSigner during the execute phase.
        delete backupSigners[backupAddr];
        unchecked { backupSignerCount--; }
        emit BackupSignerRemoved(backupAddr);

        return SIG_VALIDATION_SUCCESS;
    }

    function execute(address to, uint256 value, bytes calldata data) external onlyEntryPoint {
        (bool ok, bytes memory result) = to.call{value: value}(data);
        if (ok) {
            emit Executed(to, value, data);
        } else {
            emit ExecutionFailed(string(result));
        }
    }

    function executeBatch(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata datas
    ) external onlyEntryPoint {
        require(
            targets.length == values.length && values.length == datas.length,
            "WotsAccount: length mismatch"
        );
        bool ok;
        bytes memory result;
        for (uint256 i = 0; i < targets.length; i++) {
            (ok, result) = targets[i].call{value: values[i]}(datas[i]);
            if (!ok) break;
            emit Executed(targets[i], values[i], datas[i]);
        }
        if (!ok) {
            emit ExecutionFailed(string(result));
        }
    }

    function _rotateOwner(address nextOwner) internal {
        require(nextOwner != address(0), "WotsAccount: zero next owner");
        address previous = owner;
        owner = nextOwner;
        emit OwnerRotated(previous, nextOwner);
    }

    // =========================================================================
    // Backup-signer recovery
    // =========================================================================

    /// @notice Main-signer rotation triggered by a backup signer. Only reachable
    ///         via `validateUserOp`'s backup-signer path, which already verified
    ///         the WOTS+C signature against `backupAddr` and burned it.
    /// @dev    `backupAddr` is kept as a parameter purely for the event; the
    ///         actual authorization and burn happened in validation.
    ///
    ///         New main address is read from msg.data's last 20 bytes, matching
    ///         the `nextOwner` convention used everywhere else.
    function rotateMainSigner(address backupAddr) external onlyEntryPoint {
        address nextOwner;
        assembly {
            nextOwner := shr(96, calldataload(sub(calldatasize(), 20)))
        }
        require(nextOwner != address(0), "WotsAccount: zero next owner");

        address previous = owner;
        owner = nextOwner;
        emit OwnerRotated(previous, nextOwner);
        emit MainSignerRecovered(backupAddr, previous, nextOwner);
    }

    /// @notice Add, remove, or replace a backup signer. Called by the main
    ///         owner via a normal UserOp (validated through the main-signer
    ///         path, which already rotates `owner` in `validateUserOp`).
    ///
    ///           - oldBackup == 0, newBackup != 0: add `newBackup`
    ///           - oldBackup != 0, newBackup == 0: remove `oldBackup`
    ///           - oldBackup != 0, newBackup != 0: replace `oldBackup` with `newBackup`
    ///           - both zero: reverts (no-op, probably a caller bug)
    function rotateBackupSigner(address oldBackup, address newBackup) external onlyEntryPoint {
        require(oldBackup != newBackup, "WotsAccount: same backup address");
        // Main and backup roles must be disjoint: registering the current owner
        // as a backup would let main bypass the main-rotation path through
        // rotateMainSigner, defeating the intended separation.
        require(newBackup != owner, "WotsAccount: owner cannot be backup");

        if (oldBackup != address(0)) {
            require(backupSigners[oldBackup], "WotsAccount: old not registered");
            delete backupSigners[oldBackup];
        }

        if (newBackup != address(0)) {
            require(!backupSigners[newBackup], "WotsAccount: new already registered");
            backupSigners[newBackup] = true;
        }

        if (oldBackup == address(0)) {
            unchecked { backupSignerCount++; }
            emit BackupSignerAdded(newBackup);
        } else if (newBackup == address(0)) {
            unchecked { backupSignerCount--; }
            emit BackupSignerRemoved(oldBackup);
        } else {
            emit BackupSignerReplaced(oldBackup, newBackup);
        }
    }

    receive() external payable {}
}

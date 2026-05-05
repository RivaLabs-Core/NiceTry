// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {IKernelValidator} from "./IKernelValidator.sol";
import {IWotsCVerifier} from "../Interfaces/IWotsCVerifier.sol";
import {WOTS_BLOB_LEN} from "../Verifiers/WotsCVerifier.sol";

/// @title KernelRotatingWOTSValidator
/// @notice ZeroDev Kernel v3.1-compatible WOTS+C validator with automatic
///         main-signer rotation and a pool of pre-committed spare keys.
///
///         Authorization (unified):
///           - Recover signer via wrecover(sig, hash).
///           - If recovered == current owner, authorized (main path).
///           - Else if spare key is ACTIVE, authorized; tombstone the key.
///           - Else reject.
///           - On authorize: rotate owner to the last 20 bytes of callData.
///
///         userOp.signature = [WOTS_BLOB_LEN bytes WOTS+C blob]
///         userOp.callData  = [... any call ...][20 bytes nextOwner]
contract KernelRotatingWOTSValidator is IKernelValidator {

    uint256 internal constant MODULE_TYPE_VALIDATOR  = 1;
    uint256 internal constant SIG_VALIDATION_SUCCESS = 0;
    uint256 internal constant SIG_VALIDATION_FAILED  = 1;

    uint8 internal constant SPARE_NONE      = 0;
    uint8 internal constant SPARE_ACTIVE    = 1;
    uint8 internal constant SPARE_TOMBSTONE = 2;

    IWotsCVerifier public immutable VERIFIER;

    mapping(address account => address owner) public owners;
    // (account, sparekey) → SPARE_NONE | SPARE_ACTIVE | SPARE_TOMBSTONE
    mapping(address account => mapping(address key => uint8)) public spareKeys;
    mapping(address account => uint256) public spareKeyCount;

    event OwnerRotated(
        address indexed account,
        address indexed previousOwner,
        address indexed newOwner
    );
    event SpareKeyAdded(address indexed account, address indexed key);
    event SpareKeyRemoved(address indexed account, address indexed key);
    event SpareKeyReplaced(address indexed account, address indexed oldKey, address indexed newKey);
    event SpareKeyConsumed(address indexed account, address indexed key);

    constructor(IWotsCVerifier _verifier) {
        VERIFIER = _verifier;
    }

    // --- IModule ---

    function onInstall(bytes calldata data) external payable override {
        require(owners[msg.sender] == address(0), "KernelRotatingWOTS: already installed");
        address initialOwner = abi.decode(data, (address));
        require(initialOwner != address(0), "KernelRotatingWOTS: zero owner");
        owners[msg.sender] = initialOwner;
    }

    function onUninstall(bytes calldata) external payable override {
        delete owners[msg.sender];
        // spareKeys mapping per-account is left in place; if the validator is
        // reinstalled later, existing tombstones still block reuse.
    }

    function isModuleType(uint256 moduleTypeId) external pure override returns (bool) {
        return moduleTypeId == MODULE_TYPE_VALIDATOR;
    }

    function isInitialized(address smartAccount) external view override returns (bool) {
        return owners[smartAccount] != address(0);
    }

    // --- IValidator ---

    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) external payable override returns (uint256) {
        if (userOp.signature.length != WOTS_BLOB_LEN) return SIG_VALIDATION_FAILED;
        if (userOp.callData.length < 20) return SIG_VALIDATION_FAILED;

        address nextOwner = address(bytes20(userOp.callData[userOp.callData.length - 20:]));
        if (nextOwner == address(0)) return SIG_VALIDATION_FAILED;

        address recovered = VERIFIER.wrecover(userOp.signature, userOpHash);
        if (recovered == address(0)) return SIG_VALIDATION_FAILED;

        address currentOwner = owners[msg.sender];

        if (recovered != currentOwner) {
            if (spareKeys[msg.sender][recovered] != SPARE_ACTIVE) return SIG_VALIDATION_FAILED;
            spareKeys[msg.sender][recovered] = SPARE_TOMBSTONE;
            unchecked { spareKeyCount[msg.sender]--; }
            emit SpareKeyConsumed(msg.sender, recovered);
        }

        owners[msg.sender] = nextOwner;
        emit OwnerRotated(msg.sender, currentOwner, nextOwner);

        return SIG_VALIDATION_SUCCESS;
    }

    function isValidSignatureWithSender(
        address,
        bytes32,
        bytes calldata
    ) external pure override returns (bytes4) {
        return 0xffffffff;
    }

    // --- Spare-key pool management ---

    /// @notice Add / remove / replace a spare key for msg.sender (the account).
    ///         Semantics match SimpleAccount_WOTS.rotateSpareKey.
    function rotateSpareKey(address oldKey, address newKey) external {
        require(owners[msg.sender] != address(0), "KernelRotatingWOTS: not installed");
        require(oldKey != newKey, "KernelRotatingWOTS: same address");
        require(newKey != owners[msg.sender], "KernelRotatingWOTS: owner cannot be spare");

        if (oldKey != address(0)) {
            require(spareKeys[msg.sender][oldKey] == SPARE_ACTIVE, "KernelRotatingWOTS: old not active");
            spareKeys[msg.sender][oldKey] = SPARE_TOMBSTONE;
        }

        if (newKey != address(0)) {
            require(spareKeys[msg.sender][newKey] == SPARE_NONE, "KernelRotatingWOTS: new already touched");
            spareKeys[msg.sender][newKey] = SPARE_ACTIVE;
        }

        if (oldKey == address(0)) {
            unchecked { spareKeyCount[msg.sender]++; }
            emit SpareKeyAdded(msg.sender, newKey);
        } else if (newKey == address(0)) {
            unchecked { spareKeyCount[msg.sender]--; }
            emit SpareKeyRemoved(msg.sender, oldKey);
        } else {
            emit SpareKeyReplaced(msg.sender, oldKey, newKey);
        }
    }
}

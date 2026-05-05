// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {IKernelValidator} from "./IKernelValidator.sol";

/// @title KernelRotatingECDSAValidator
/// @notice ZeroDev Kernel v3.1-compatible ECDSA validator with automatic one-time-use
///         owner rotation on every validated UserOp.
///
///         Wire format (identical to the Nexus variant):
///         - userOp.signature  = 65-byte ECDSA signature over userOpHash
///         - userOp.callData   = [...account-specific calldata...][bytes20 nextOwner]
///
///         nextOwner MUST live in callData (which userOpHash commits to), not in
///         signature — otherwise a relayer could rewrite it post-signing.
///
///         The module owns per-account state: `owners[account]` tracks the current
///         signer. A single deployed module serves any number of Kernel accounts.
///
///         Kernel-specific notes:
///         - onInstall / onUninstall / validateUserOp are `payable` per Kernel's
///           IModule / IValidator interface. Nexus-style accounts that do not
///           attach value can still call them.
///         - Module type 1 (VALIDATOR). Kernel's extra types (policy=5, signer=6)
///           are for permission flows; a plain root validator only claims type 1.
///         - isValidSignatureWithSender returns 0xffffffff (ERC-1271 disabled),
///           consistent with the one-time-use threat model — persistent ERC-1271
///           signatures would defeat the OTS property.
contract KernelRotatingECDSAValidator is IKernelValidator {

    uint256 internal constant MODULE_TYPE_VALIDATOR = 1;
    uint256 internal constant SIG_VALIDATION_SUCCESS = 0;
    uint256 internal constant SIG_VALIDATION_FAILED  = 1;

    mapping(address account => address owner) public owners;

    event OwnerRotated(
        address indexed account,
        address indexed previousOwner,
        address indexed newOwner
    );

    // --- IModule ---

    function onInstall(bytes calldata data) external payable override {
        require(owners[msg.sender] == address(0), "KernelRotatingECDSA: already installed");
        address initialOwner = abi.decode(data, (address));
        require(initialOwner != address(0), "KernelRotatingECDSA: zero owner");
        owners[msg.sender] = initialOwner;
    }

    function onUninstall(bytes calldata) external payable override {
        delete owners[msg.sender];
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
        address nextOwner = _decodeNextOwner(userOp.callData);

        address signer = ECDSA.recover(
            MessageHashUtils.toEthSignedMessageHash(userOpHash),
            userOp.signature
        );

        if (signer != owners[msg.sender]) return SIG_VALIDATION_FAILED;

        address previous = owners[msg.sender];
        owners[msg.sender] = nextOwner;
        emit OwnerRotated(msg.sender, previous, nextOwner);

        return SIG_VALIDATION_SUCCESS;
    }

    function isValidSignatureWithSender(
        address,
        bytes32,
        bytes calldata
    ) external pure override returns (bytes4) {
        return 0xffffffff;
    }

    // --- internal ---

    function _decodeNextOwner(bytes calldata callData)
        internal
        pure
        returns (address nextOwner)
    {
        require(callData.length >= 20, "KernelRotatingECDSA: calldata too short");
        nextOwner = address(bytes20(callData[callData.length - 20:]));
        require(nextOwner != address(0), "KernelRotatingECDSA: zero next owner");
    }
}

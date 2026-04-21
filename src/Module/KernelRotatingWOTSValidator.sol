// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {IKernelValidator} from "./IKernelValidator.sol";
import {IWotsCVerifier} from "../Interfaces/IWotsCVerifier.sol";
import {WOTS_BLOB_LEN} from "../WotsCVerifier.sol";

/// @title KernelRotatingWOTSValidator
/// @notice ZeroDev Kernel v3.1-compatible WOTS+C validator with automatic
///         one-time-use owner rotation on every validated UserOp.
///
///         Mirrors KernelRotatingECDSAValidator but uses WOTS+C (post-quantum,
///         one-time) instead of ECDSA. The on-chain verification cost is
///         substantially higher than ecrecover; the benefit is OTS security
///         plus no reliance on ECDSA's algebraic assumptions.
///
///         Wire format:
///         - userOp.signature  = WOTS_BLOB_LEN-byte WOTS+C blob (see WotsCVerifier).
///         - userOp.callData   = [...account-specific calldata...][bytes20 nextOwner]
///
///         nextOwner MUST live in callData (which userOpHash commits to), not
///         in signature — otherwise a relayer could rewrite it post-signing.
///
///         Per-account storage: `owners[account]` tracks the current signer.
///         A single deployed module serves any number of Kernel accounts.
///
///         Kernel-specific notes:
///         - onInstall / onUninstall / validateUserOp marked payable per Kernel's
///           IModule / IValidator interface. Value is ignored; non-payable
///           callers remain compatible.
///         - Module type 1 (VALIDATOR). Kernel's extra types (policy=5, signer=6)
///           return false; this is a plain root validator, not a permission flow.
///         - isValidSignatureWithSender returns 0xffffffff (ERC-1271 disabled) —
///           persistent ERC-1271 signatures would undermine the OTS property.
contract KernelRotatingWOTSValidator is IKernelValidator {

    uint256 internal constant MODULE_TYPE_VALIDATOR = 1;
    uint256 internal constant SIG_VALIDATION_SUCCESS = 0;
    uint256 internal constant SIG_VALIDATION_FAILED  = 1;

    IWotsCVerifier public immutable VERIFIER;

    mapping(address account => address owner) public owners;

    event OwnerRotated(
        address indexed account,
        address indexed previousOwner,
        address indexed newOwner
    );

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

        bool valid = VERIFIER.verify(userOp.signature, userOpHash, owners[msg.sender]);
        if (!valid) return SIG_VALIDATION_FAILED;

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
}

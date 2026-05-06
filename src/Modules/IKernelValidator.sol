// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";

/// @dev Minimal ZeroDev Kernel v3.1 validator interface (subset of kernel-v3's
///      IValidator + IModule). Declared here as a shared surface so multiple
///      validator implementations and their mocks can target the same type
///      without duplicating the declaration. Kept in sync with
///      kernel-v3/src/interfaces/IERC7579Modules.sol.
interface IKernelValidator {
    // --- IModule ---
    function onInstall(bytes calldata data) external payable;
    function onUninstall(bytes calldata data) external payable;
    function isModuleType(uint256 moduleTypeId) external view returns (bool);
    function isInitialized(address smartAccount) external view returns (bool);

    // --- IValidator ---
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash)
        external payable returns (uint256);
    function isValidSignatureWithSender(address sender, bytes32 hash, bytes calldata data)
        external view returns (bytes4);
}

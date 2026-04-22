// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";

/// @title ERC-7579 module interfaces (generic, Nexus-compatible)
/// @notice Vendored from Biconomy Nexus v1.2.0:
///           contracts/interfaces/modules/IModule.sol
///           contracts/interfaces/modules/IValidator.sol
///         Nexus's interface is pure ERC-7579 — these are byte-compatible with
///         any ERC-7579 modular smart account. Kept here (rather than pulled
///         in from a dep) so the project has no transitive dependency on the
///         full Nexus source tree.

interface IModule {
    function onInstall(bytes calldata data) external;
    function onUninstall(bytes calldata data) external;
    function isModuleType(uint256 moduleTypeId) external view returns (bool);
    function isInitialized(address smartAccount) external view returns (bool);
}

interface IValidator is IModule {
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash)
        external returns (uint256);

    function isValidSignatureWithSender(address sender, bytes32 hash, bytes calldata data)
        external view returns (bytes4);
}

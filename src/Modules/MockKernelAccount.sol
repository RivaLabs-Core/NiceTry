// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {IKernelValidator} from "./IKernelValidator.sol";

/// @dev Minimal Kernel v3.1-style account mock. Exercises any IKernelValidator
///      with the same payable call pattern a real Kernel account would use.
contract MockKernelAccount {
    IKernelValidator public validator;

    constructor(address _validator) {
        validator = IKernelValidator(_validator);
    }

    function installValidator(bytes calldata initData) external payable {
        validator.onInstall{value: msg.value}(initData);
    }

    function uninstallValidator() external payable {
        validator.onUninstall{value: msg.value}("");
    }

    function validateUserOp(
        PackedUserOperation memory userOp,
        bytes32 userOpHash
    ) external payable returns (uint256) {
        require(
            validator.isInitialized(address(this)),
            "MockKernel: validator not installed"
        );
        return validator.validateUserOp{value: msg.value}(userOp, userOpHash);
    }

    function isValidSignature(bytes32 hash, bytes calldata sig)
        external
        view
        returns (bytes4)
    {
        return validator.isValidSignatureWithSender(address(this), hash, sig);
    }

    receive() external payable {}
}

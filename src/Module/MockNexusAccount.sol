// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IValidator} from "./IERC7579.sol";

contract MockNexusAccount {
    IValidator public validator;

    constructor(address _validator) {
        validator = IValidator(_validator);
    }

    function installValidator(bytes calldata initData) external {
        validator.onInstall(initData);
    }

    function uninstallValidator() external {
        validator.onUninstall("");
    }

    function validateUserOp(
        PackedUserOperation memory userOp,
        bytes32 userOpHash
    ) external returns (uint256) {
        require(
            validator.isInitialized(address(this)),
            "MockNexus: validator not installed"
        );
        return validator.validateUserOp(userOp, userOpHash);
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
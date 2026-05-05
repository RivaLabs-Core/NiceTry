// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {IModule, IValidator} from "./IERC7579.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/// @notice ERC-7579 validator implementing one-time-use ECDSA rotation. Conforms
///         to the canonical Biconomy Nexus IValidator/IModule interface (see
///         src/Module/IERC7579.sol for provenance).
contract RotatingECDSAValidator is IValidator {

    uint256 internal constant SIG_VALIDATION_SUCCESS = 0;
    uint256 internal constant SIG_VALIDATION_FAILED  = 1;
    uint256 internal constant MODULE_TYPE_VALIDATOR  = 1;

    mapping(address account => address owner) public owners;

    event OwnerRotated(
        address indexed account,
        address indexed previousOwner,
        address indexed newOwner
    );

    // --- IModule ---

    function onInstall(bytes calldata data) external override {
        require(owners[msg.sender] == address(0), "RotatingECDSA: already installed");
        address initialOwner = abi.decode(data, (address));
        require(initialOwner != address(0), "RotatingECDSA: zero owner");
        owners[msg.sender] = initialOwner;
    }

    function onUninstall(bytes calldata) external override {
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
    ) external override returns (uint256) {
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
        require(callData.length >= 20, "RotatingECDSA: calldata too short");
        nextOwner = address(bytes20(callData[callData.length - 20:]));
        require(nextOwner != address(0), "RotatingECDSA: zero next owner");
    }
}

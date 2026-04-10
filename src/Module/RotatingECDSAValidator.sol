// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {IERC7579Module, IERC7579Validator} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {ERC4337Utils} from "@openzeppelin/contracts/account/utils/draft-ERC4337Utils.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

contract RotatingECDSAValidator is IERC7579Module, IERC7579Validator {

    mapping(address account => address owner) public owners;

    event OwnerRotated(
        address indexed account,
        address indexed previousOwner,
        address indexed newOwner
    );

    // --- IERC7579Module ---

    function onInstall(bytes calldata data) public override {
        require(owners[msg.sender] == address(0), "RotatingECDSA: already installed");
        address initialOwner = abi.decode(data, (address));
        require(initialOwner != address(0), "RotatingECDSA: zero owner");
        owners[msg.sender] = initialOwner;
    }

    function onUninstall(bytes calldata) public override {
        delete owners[msg.sender];
    }

    function isModuleType(uint256 moduleTypeId) public pure override returns (bool) {
        return moduleTypeId == 1; // MODULE_TYPE_VALIDATOR
    }

    function isInitialized(address smartAccount) external view returns (bool) {
        return owners[smartAccount] != address(0);
    }

    // --- IERC7579Validator ---

    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) public override returns (uint256) {
        address nextOwner = _decodeNextOwner(userOp.callData);

        address signer = ECDSA.recover(
            MessageHashUtils.toEthSignedMessageHash(userOpHash),
            userOp.signature
        );

        if (signer != owners[msg.sender]) return ERC4337Utils.SIG_VALIDATION_FAILED;

        address previous = owners[msg.sender];
        owners[msg.sender] = nextOwner;
        emit OwnerRotated(msg.sender, previous, nextOwner);

        return ERC4337Utils.SIG_VALIDATION_SUCCESS;
    }

    function isValidSignatureWithSender(
        address,
        bytes32,
        bytes calldata
    ) public pure override returns (bytes4) {
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

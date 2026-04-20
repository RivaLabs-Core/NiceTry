// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IAccount} from "account-abstraction/interfaces/IAccount.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @title SimpleAccount
/// @notice Minimal ERC-4337 smart account with automatic owner rotation.
///
///         callData layout:
///         [4 bytes selector][normal ABI-encoded params][20 bytes nextOwner]
contract SimpleAccount_ECDSA is IAccount {
    address public owner;
    IEntryPoint public immutable entryPoint;

    uint256 internal constant SIG_VALIDATION_SUCCESS = 0;
    uint256 internal constant SIG_VALIDATION_FAILED = 1;

    event SimpleAccountInitialized(address indexed owner);
    event Executed(address indexed to, uint256 value, bytes data);
    event ExecutionFailed(string data);
    event OwnerRotated(address indexed previousOwner, address indexed newOwner);

    modifier onlyEntryPoint() {
        require(msg.sender == address(entryPoint), "SimpleAccount: not from EntryPoint");
        _;
    }

    constructor(IEntryPoint _entryPoint) {
        entryPoint = _entryPoint;
    }

    /// @dev Called once by the factory after clone deployment
    function initialize(address _owner) external {
        require(owner == address(0), "SimpleAccount: already initialized");
        require(_owner != address(0), "SimpleAccount: zero owner");
        owner = _owner;
        emit SimpleAccountInitialized(_owner);
    }

    /// @inheritdoc IAccount
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external onlyEntryPoint returns (uint256 validationData) {
        require(userOp.callData.length >= 24, "SimpleAccount: missing next owner"); // 4 selector + 20 minimum
        address nextOwner = address(bytes20(userOp.callData[userOp.callData.length - 20:]));

        bytes32 ethHash = MessageHashUtils.toEthSignedMessageHash(userOpHash);
        address signer = ECDSA.recover(ethHash, userOp.signature);

        bool valid = signer == owner;
        validationData = valid ? SIG_VALIDATION_SUCCESS : SIG_VALIDATION_FAILED;

        // Rotate owner to next address. Key is one-time use; a failed validation
        // reverts the whole userOp at the EntryPoint so this write only persists
        // on success. Recovery for burned keys on failed ops is handled separately.
        if (valid) {
            _rotateOwner(nextOwner);
        }

        if (missingAccountFunds > 0) {
            (bool ok,) = payable(msg.sender).call{value: missingAccountFunds}("");
            require(ok, "SimpleAccount: prefund failed");
        }
    }

    function execute(address to, uint256 value, bytes calldata data) external onlyEntryPoint {
        (bool ok, bytes memory result) = to.call{value: value}(data);
        if(ok){
            emit Executed(to, value, data);
        }
        else {
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
            "SimpleAccount: length mismatch"
        );
        bool ok;
        bytes memory result;
        for (uint256 i = 0; i < targets.length; i++) {
            (ok, result) = targets[i].call{value: values[i]}(datas[i]);
            if(!ok){
                break;
            }
            emit Executed(targets[i], values[i], datas[i]);
        }
        if(!ok){
            emit ExecutionFailed(string(result));
        }
    }

    function _rotateOwner(address nextOwner) internal {
        require(nextOwner != address(0), "SimpleAccount: zero next owner");
        address previous = owner;
        owner = nextOwner;
        emit OwnerRotated(previous, nextOwner);
    }

    receive() external payable {}
}

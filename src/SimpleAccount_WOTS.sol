// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IAccount} from "account-abstraction/interfaces/IAccount.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {IWotsCVerifier} from "./Interfaces/IWotsCVerifier.sol";

/// @title WotsAccount
/// @notice ERC-4337 smart account with WOTS+C post-quantum signature verification
///         and automatic owner rotation.
///
///         The "owner" is a WOTS+C address (derived from the WOTS public key),
///         not an ECDSA address. Each signature is one-time use — after every
///         validated UserOp, the owner rotates to the next WOTS+C address.
///
///         Signature layout in userOp.signature:
///         [468 bytes WOTS+C blob][20 bytes nextOwner]
///
///         The blob is verified against bytes32ToString(userOpHash) as the message.
contract SimpleAccount_WOTS is IAccount {

    address public owner;
    IEntryPoint public immutable ENTRY_POINT;
    IWotsCVerifier public immutable VERIFIER;

    uint256 internal constant SIG_VALIDATION_SUCCESS = 0;
    uint256 internal constant SIG_VALIDATION_FAILED = 1;
    uint256 internal constant WOTS_BLOB_LEN = 468;

    event WotsAccountInitialized(address indexed owner, address indexed verifier);
    event Executed(address indexed to, uint256 value, bytes data);
    event ExecutionFailed(string data);
    event OwnerRotated(address indexed previousOwner, address indexed newOwner);

    modifier onlyEntryPoint() {
        require(msg.sender == address(ENTRY_POINT), "WotsAccount: not from EntryPoint");
        _;
    }

    constructor(IEntryPoint _entryPoint, IWotsCVerifier _verifier) {
        ENTRY_POINT = _entryPoint;
        VERIFIER = _verifier;
    }

    /// @dev Called once by the factory after clone deployment
    function initialize(address _owner) external {
        require(owner == address(0), "WotsAccount: already initialized");
        require(_owner != address(0), "WotsAccount: zero owner");
        owner = _owner;
        emit WotsAccountInitialized(_owner, address(VERIFIER));
    }

    /// @inheritdoc IAccount
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external onlyEntryPoint returns (uint256 validationData) {
        // Extract WOTS+C blob (first 468 bytes) and nextOwner (last 20 bytes)
        require(userOp.signature.length >= WOTS_BLOB_LEN + 20, "WotsAccount: sig too short");

        bytes calldata blob = userOp.signature[0:WOTS_BLOB_LEN];
        address nextOwner = address(bytes20(userOp.signature[WOTS_BLOB_LEN:WOTS_BLOB_LEN + 20]));

        // Verify WOTS+C signature: blob + message must resolve to current owner
        bool valid = VERIFIER.verify(blob, userOpHash, owner);

        validationData = valid ? SIG_VALIDATION_SUCCESS : SIG_VALIDATION_FAILED;

        // Rotate owner to next WOTS+C address (even if validation fails,
        // the key is spent and must not be reused)
        if (valid) {
            _rotateOwner(nextOwner);
        }

        if (missingAccountFunds > 0) {
            (bool ok,) = payable(msg.sender).call{value: missingAccountFunds}("");
            require(ok, "WotsAccount: prefund failed");
        }
    }

    function execute(address to, uint256 value, bytes calldata data) external onlyEntryPoint {
        (bool ok, bytes memory result) = to.call{value: value}(data);
        if (ok) {
            emit Executed(to, value, data);
        } else {
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
            "WotsAccount: length mismatch"
        );
        bool ok;
        bytes memory result;
        for (uint256 i = 0; i < targets.length; i++) {
            (ok, result) = targets[i].call{value: values[i]}(datas[i]);
            if (!ok) break;
            emit Executed(targets[i], values[i], datas[i]);
        }
        if (!ok) {
            emit ExecutionFailed(string(result));
        }
    }

    function _rotateOwner(address nextOwner) internal {
        require(nextOwner != address(0), "WotsAccount: zero next owner");
        address previous = owner;
        owner = nextOwner;
        emit OwnerRotated(previous, nextOwner);
    }

    /// @dev Convert bytes32 to "0x..." hex string (66 chars)
    function _bytes32ToHexString(bytes32 data) internal pure returns (string memory) {
        bytes memory hexChars = "0123456789abcdef";
        bytes memory str = new bytes(66);
        str[0] = "0";
        str[1] = "x";
        for (uint256 i = 0; i < 32; i++) {
            str[2 + i * 2] = hexChars[uint8(data[i]) >> 4];
            str[3 + i * 2] = hexChars[uint8(data[i]) & 0x0f];
        }
        return string(str);
    }

    receive() external payable {}
}

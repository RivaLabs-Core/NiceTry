// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IAccount} from "account-abstraction/interfaces/IAccount.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {IWotsCVerifier} from "./Interfaces/IWotsCVerifier.sol";
import {WOTS_BLOB_LEN} from "./WotsCVerifier.sol";

/// @title SimpleAccount_WOTS
/// @notice ERC-4337 smart account with WOTS+C post-quantum signature verification
///         and automatic owner rotation.
///
///         The "owner" is a WOTS+C address (derived from the WOTS public key),
///         not an ECDSA address. Each signature is one-time use — after every
///         validated UserOp, the owner rotates to the next WOTS+C address.
///
///         userOp.signature layout:
///         [WOTS_BLOB_LEN bytes WOTS+C blob]
///
///         userOp.callData layout:
///         [4 bytes selector][normal ABI-encoded params][20 bytes nextOwner]
///
///         nextOwner MUST live in callData (which userOpHash commits to), not
///         in signature — otherwise a relayer could rewrite it post-signing.
contract SimpleAccount_WOTS is IAccount {

    address public owner;
    IEntryPoint public immutable ENTRY_POINT;
    IWotsCVerifier public immutable VERIFIER;

    uint256 internal constant SIG_VALIDATION_SUCCESS = 0;
    uint256 internal constant SIG_VALIDATION_FAILED = 1;

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
        // nextOwner is the last 20 bytes of callData (authenticated, since
        // userOpHash commits to callData). The WOTS+C blob is the full signature.
        require(userOp.signature.length == WOTS_BLOB_LEN, "WotsAccount: bad sig length");
        require(userOp.callData.length >= 24, "WotsAccount: missing next owner"); // 4 selector + 20 min

        address nextOwner = address(bytes20(userOp.callData[userOp.callData.length - 20:]));

        // Verify WOTS+C signature: blob + message must resolve to current owner
        bool valid = VERIFIER.verify(userOp.signature, userOpHash, owner);

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

    receive() external payable {}
}

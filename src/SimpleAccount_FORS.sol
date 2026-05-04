// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IAccount} from "account-abstraction/interfaces/IAccount.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {IForsVerifier} from "./Interfaces/IForsVerifier.sol";
import {FORS_SIG_LEN} from "./ForsVerifier.sol";

/// @title SimpleAccount_FORS
/// @notice ERC-4337 smart account using standalone FORS as the primary signer.
///
///         Owner is a 20-byte FORS address (derived from `(pkSeed, pkRoot)`).
///         Each successful UserOp rotates `owner` to the address packed in
///         the last 20 bytes of `userOp.callData`. Signers are expected to
///         use a fresh FORS keypair per signature; FORS' few-time-signature
///         property means the failure mode on accidental reuse is graceful
///         degradation rather than the immediate break that WOTS+C exhibits.
///
///         No spare-key pool and no SPHINCS+ recovery are wired in this
///         variant — kept minimal on purpose.
///
///         userOp.signature = [FORS_SIG_LEN bytes FORS blob]
///         userOp.callData  = [... any call ...][20 bytes nextOwner]
contract SimpleAccount_FORS is IAccount {

    address public owner;
    IEntryPoint public immutable ENTRY_POINT;
    IForsVerifier public immutable VERIFIER;

    uint256 internal constant SIG_VALIDATION_SUCCESS = 0;
    uint256 internal constant SIG_VALIDATION_FAILED  = 1;

    event ForsAccountInitialized(address indexed owner, address indexed verifier);
    event Executed(address indexed to, uint256 value, bytes data);
    event ExecutionFailed(string data);
    event OwnerRotated(address indexed previousOwner, address indexed newOwner);

    modifier onlyEntryPoint() {
        require(msg.sender == address(ENTRY_POINT), "ForsAccount: not from EntryPoint");
        _;
    }

    constructor(IEntryPoint _entryPoint, IForsVerifier _verifier) {
        ENTRY_POINT = _entryPoint;
        VERIFIER = _verifier;
        // Lock the implementation against direct initialize() — proxies have
        // their own zero-owner storage slot.
        owner = address(this);
    }

    /// @dev Called once by the factory after clone deployment.
    function initialize(address _owner) external {
        require(owner == address(0), "ForsAccount: already initialized");
        require(_owner != address(0), "ForsAccount: zero owner");
        owner = _owner;
        emit ForsAccountInitialized(_owner, address(VERIFIER));
    }

    /// @inheritdoc IAccount
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external onlyEntryPoint returns (uint256 validationData) {
        require(userOp.callData.length >= 24, "ForsAccount: missing next owner"); // 4 selector + 20

        if (userOp.signature.length != FORS_SIG_LEN) {
            validationData = SIG_VALIDATION_FAILED;
        } else {
            address nextOwner = address(bytes20(userOp.callData[userOp.callData.length - 20:]));
            address recovered = VERIFIER.recover(userOp.signature, userOpHash);

            if (recovered == address(0) || recovered != owner) {
                validationData = SIG_VALIDATION_FAILED;
            } else {
                _rotateOwner(nextOwner);
                validationData = SIG_VALIDATION_SUCCESS;
            }
        }

        if (missingAccountFunds > 0) {
            (bool ok,) = payable(msg.sender).call{value: missingAccountFunds}("");
            require(ok, "ForsAccount: prefund failed");
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
            "ForsAccount: length mismatch"
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
        require(nextOwner != address(0), "ForsAccount: zero next owner");
        address previous = owner;
        owner = nextOwner;
        emit OwnerRotated(previous, nextOwner);
    }

    receive() external payable {}
}

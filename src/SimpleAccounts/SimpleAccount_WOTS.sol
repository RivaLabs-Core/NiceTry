// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IAccount} from "account-abstraction/interfaces/IAccount.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {IWotsCVerifier} from "../Interfaces/IWotsCVerifier.sol";
import {WOTS_BLOB_LEN} from "../Verifiers/WotsCVerifier.sol";

/// @title SimpleAccount_WOTS
/// @notice ERC-4337 smart account with WOTS+C post-quantum signatures,
///         automatic main-signer rotation on every UserOp, and a pool of
///         pre-committed spare keys.
///
///         Signer roles:
///           - main owner: rotated on every successful UserOp via the last
///             20 bytes of userOp.callData.
///           - spare keys: pre-committed WOTS+C addresses registered by the
///             main owner. Each spare key can sign ONE UserOp (arbitrary
///             content). After use it is permanently tombstoned and can
///             never be re-registered. Main still rotates via the callData
///             tail when a spare key authorizes.
///
///         Authorization (unified, no selector dispatch):
///           1. Recover signer from WOTS+C blob via VERIFIER.wrecover(sig, hash).
///           2. If recovered == owner: authorized (main path).
///           3. Else if spareKeys[recovered] == ACTIVE: authorized, transition
///              to CONSUMED atomically.
///           4. Else: reject.
///           5. On authorized path, rotate main owner to callData's last 20 bytes.
///
///         userOp.signature = [WOTS_BLOB_LEN bytes WOTS+C blob]
///         userOp.callData  = [... any call ...][20 bytes nextOwner]
contract SimpleAccount_WOTS is IAccount {

    // Spare-key state machine. Once CONSUMED or TOMBSTONED, an address can
    // never be re-registered — protects against accidental reuse of a key
    // whose history has leaked.
    uint8 internal constant SPARE_NONE      = 0;
    uint8 internal constant SPARE_ACTIVE    = 1;
    uint8 internal constant SPARE_TOMBSTONE = 2;

    address public owner;
    IEntryPoint public immutable ENTRY_POINT;
    IWotsCVerifier public immutable VERIFIER;

    // Pre-committed WOTS+C addresses authorized to sign one UserOp each.
    // Value is one of SPARE_NONE / SPARE_ACTIVE / SPARE_TOMBSTONE.
    mapping(address => uint8) public spareKeys;
    uint256 public spareKeyCount;

    uint256 internal constant SIG_VALIDATION_SUCCESS = 0;
    uint256 internal constant SIG_VALIDATION_FAILED  = 1;

    event WotsAccountInitialized(address indexed owner, address indexed verifier);
    event Executed(address indexed to, uint256 value, bytes data);
    event ExecutionFailed(string data);
    event OwnerRotated(address indexed previousOwner, address indexed newOwner);
    event SpareKeyAdded(address indexed key);
    event SpareKeyRemoved(address indexed key);         // admin-initiated
    event SpareKeyReplaced(address indexed oldKey, address indexed newKey);
    event SpareKeyConsumed(address indexed key);        // used by signature

    modifier onlyEntryPoint() {
        require(msg.sender == address(ENTRY_POINT), "WotsAccount: not from EntryPoint");
        _;
    }

    constructor(IEntryPoint _entryPoint, IWotsCVerifier _verifier) {
        ENTRY_POINT = _entryPoint;
        VERIFIER = _verifier;
        // Lock the implementation itself against initialize().
        // Proxies delegatecall in and have their own (zero) owner slot.
        owner = address(this);
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
        require(userOp.signature.length == WOTS_BLOB_LEN, "WotsAccount: bad sig length");
        require(userOp.callData.length >= 24, "WotsAccount: missing next owner"); // 4 selector + 20 min

        address nextOwner = address(bytes20(userOp.callData[userOp.callData.length - 20:]));

        address recovered = VERIFIER.wrecover(userOp.signature, userOpHash);

        if (recovered == address(0)) {
            validationData = SIG_VALIDATION_FAILED;
        } else if (recovered == owner) {
            _rotateOwner(nextOwner);
            validationData = SIG_VALIDATION_SUCCESS;
        } else if (spareKeys[recovered] == SPARE_ACTIVE) {
            spareKeys[recovered] = SPARE_TOMBSTONE;
            unchecked { spareKeyCount--; }
            emit SpareKeyConsumed(recovered);
            _rotateOwner(nextOwner);
            validationData = SIG_VALIDATION_SUCCESS;
        } else {
            validationData = SIG_VALIDATION_FAILED;
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

    // =========================================================================
    // Spare-key pool management
    // =========================================================================

    /// @notice Add, remove, or replace a spare key.
    ///           - oldKey == 0, newKey != 0: add `newKey` (must be NONE)
    ///           - oldKey != 0, newKey == 0: tombstone `oldKey` (must be ACTIVE)
    ///           - oldKey != 0, newKey != 0: tombstone `oldKey`, add `newKey`
    ///           - both zero: reverts
    ///         Tombstoned and consumed addresses can never be re-added.
    function rotateSpareKey(address oldKey, address newKey) external onlyEntryPoint {
        require(oldKey != newKey, "WotsAccount: same address");
        require(newKey != owner, "WotsAccount: owner cannot be spare");

        if (oldKey != address(0)) {
            require(spareKeys[oldKey] == SPARE_ACTIVE, "WotsAccount: old not active");
            spareKeys[oldKey] = SPARE_TOMBSTONE;
        }

        if (newKey != address(0)) {
            require(spareKeys[newKey] == SPARE_NONE, "WotsAccount: new already touched");
            spareKeys[newKey] = SPARE_ACTIVE;
        }

        if (oldKey == address(0)) {
            unchecked { spareKeyCount++; }
            emit SpareKeyAdded(newKey);
        } else if (newKey == address(0)) {
            unchecked { spareKeyCount--; }
            emit SpareKeyRemoved(oldKey);
        } else {
            emit SpareKeyReplaced(oldKey, newKey);
        }
    }

    receive() external payable {}
}

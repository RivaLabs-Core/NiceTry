// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {SimpleAccount_ECDSA} from "./SimpleAccounts/SimpleAccount_ECDSA.sol";
import {SimpleAccount_WOTS} from "./SimpleAccounts/SimpleAccount_WOTS.sol";
import {SimpleAccount_FORS} from "./SimpleAccounts/SimpleAccount_FORS.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {IWotsCVerifier} from "./Interfaces/IWotsCVerifier.sol";
import {IForsVerifier} from "./Interfaces/IForsVerifier.sol";
import {LibClone} from "solady/utils/LibClone.sol";

/// @title SimpleAccountFactory
/// @notice Deploys per-user accounts as EIP-1167 minimal proxies pointing at
///         per-mode implementation contracts. Implementations are deployed
///         once in this factory's constructor.
///
///         Modes:
///           0 = ECDSA
///           1 = WOTS+C
///           2 = FORS (standalone, JARDIN-family)
contract SimpleAccountFactory {
    IEntryPoint public immutable ENTRY_POINT;
    IWotsCVerifier public immutable WOTS_VERIFIER;
    IForsVerifier public immutable FORS_VERIFIER;

    address public immutable ECDSA_IMPL;
    address public immutable WOTS_IMPL;
    address public immutable FORS_IMPL;

    event AccountCreated(address indexed account, address indexed owner, uint256 salt);

    constructor(
        IEntryPoint _entryPoint,
        IWotsCVerifier _wotsVerifier,
        IForsVerifier _forsVerifier
    ) {
        ENTRY_POINT = _entryPoint;
        WOTS_VERIFIER = _wotsVerifier;
        FORS_VERIFIER = _forsVerifier;
        ECDSA_IMPL = address(new SimpleAccount_ECDSA(_entryPoint));
        WOTS_IMPL  = address(new SimpleAccount_WOTS(_entryPoint, _wotsVerifier));
        FORS_IMPL  = address(new SimpleAccount_FORS(_entryPoint, _forsVerifier));
    }

    function createAccount(address owner, uint256 salt, uint8 mode) external returns (address accountAddr) {
        address impl = _implFor(mode);
        bytes32 fullSalt = _salt(owner, salt);

        address predicted = LibClone.predictDeterministicAddress(impl, fullSalt, address(this));
        if (predicted.code.length > 0) return predicted;

        accountAddr = LibClone.cloneDeterministic(impl, fullSalt);
        if (mode == 0) {
            SimpleAccount_ECDSA(payable(accountAddr)).initialize(owner);
        } else if (mode == 1) {
            SimpleAccount_WOTS(payable(accountAddr)).initialize(owner);
        } else if (mode == 2) {
            SimpleAccount_FORS(payable(accountAddr)).initialize(owner);
        } else {
            revert("SimpleAccountFactory: invalid mode");
        }

        emit AccountCreated(accountAddr, owner, salt);
    }

    function getAddress(address owner, uint256 salt, uint8 mode) public view returns (address) {
        address impl = _implFor(mode);
        return LibClone.predictDeterministicAddress(impl, _salt(owner, salt), address(this));
    }

    function _implFor(uint8 mode) internal view returns (address) {
        if (mode == 0) return ECDSA_IMPL;
        if (mode == 1) return WOTS_IMPL;
        if (mode == 2) return FORS_IMPL;
        revert("SimpleAccountFactory: invalid mode");
    }

    function _salt(address owner, uint256 salt) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(owner, salt));
    }
}

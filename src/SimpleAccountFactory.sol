// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {SimpleAccount_ECDSA} from "./SimpleAccount_ECDSA.sol";
import {SimpleAccount_WOTS} from "./SimpleAccount_WOTS.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {IWotsCVerifier} from "./Interfaces/IWotsCVerifier.sol";

contract SimpleAccountFactory {
    IEntryPoint public immutable ENTRY_POINT;
    IWotsCVerifier public immutable WOTS_VERIFIER;

    event AccountCreated(address indexed account, address indexed owner, uint256 salt);

    constructor(IEntryPoint _entryPoint, IWotsCVerifier _wotsVerifier) {
        ENTRY_POINT = _entryPoint;
        WOTS_VERIFIER = _wotsVerifier;
    }

    function createAccount(address owner, uint256 salt, uint8 mode) external returns (address) {
        address predicted = getAddress(owner, salt, mode);
        if (predicted.code.length > 0) return predicted;


        bytes32 fullSalt = _salt(owner, salt);
        address accountAddr;
        if(mode == 0){
            SimpleAccount_ECDSA account = new SimpleAccount_ECDSA{salt: fullSalt}(ENTRY_POINT);
            account.initialize(owner);
            accountAddr = address(account);
        } else if (mode == 1){
            SimpleAccount_WOTS account = new SimpleAccount_WOTS{salt: fullSalt}(ENTRY_POINT, WOTS_VERIFIER);
            account.initialize(owner);
            accountAddr = address(account);
        } else {
            revert("SimpleAccountFactory: invalid mode");
        }

        emit AccountCreated(accountAddr, owner, salt);
        return accountAddr;
    }

    function getAddress(address owner, uint256 salt, uint8 mode) public view returns (address) {
        bytes32 fullSalt = _salt(owner, salt);
        if(mode == 0){
            return address(uint160(uint256(keccak256(abi.encodePacked(
                bytes1(0xff),
                address(this),
                fullSalt,
                keccak256(abi.encodePacked(
                    type(SimpleAccount_ECDSA).creationCode,
                    abi.encode(ENTRY_POINT)
                ))
            )))));
        } else if (mode == 1) {
            return address(uint160(uint256(keccak256(abi.encodePacked(
                bytes1(0xff),
                address(this),
                fullSalt,
                keccak256(abi.encodePacked(
                    type(SimpleAccount_WOTS).creationCode,
                    abi.encode(ENTRY_POINT, WOTS_VERIFIER)
                ))
            )))));
        } else {
            revert("SimpleAccountFactory: invalid mode");
        }
    }

    function _salt(address owner, uint256 salt) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(owner, salt));
    }
}
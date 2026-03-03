// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {SimpleAccount} from "./SimpleAccount.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";

contract SimpleAccountFactory {
    IEntryPoint public immutable entryPoint;

    event AccountCreated(address indexed account, address indexed owner, uint256 salt);

    constructor(IEntryPoint _entryPoint) {
        entryPoint = _entryPoint;
    }

    function createAccount(address owner, uint256 salt) external returns (address) {
        address predicted = getAddress(owner, salt);
        if (predicted.code.length > 0) return predicted;

        bytes32 fullSalt = _salt(owner, salt);
        SimpleAccount account = new SimpleAccount{salt: fullSalt}(entryPoint);
        account.initialize(owner);

        emit AccountCreated(address(account), owner, salt);
        return address(account);
    }

    function getAddress(address owner, uint256 salt) public view returns (address) {
        bytes32 fullSalt = _salt(owner, salt);
        return address(uint160(uint256(keccak256(abi.encodePacked(
            bytes1(0xff),
            address(this),
            fullSalt,
            keccak256(abi.encodePacked(
                type(SimpleAccount).creationCode,
                abi.encode(entryPoint)
            ))
        )))));
    }

    function _salt(address owner, uint256 salt) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(owner, salt));
    }
}
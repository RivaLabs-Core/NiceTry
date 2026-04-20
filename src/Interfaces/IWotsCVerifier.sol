// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IWotsCVerifier {
    function verify(
        bytes calldata blob,
        bytes32 digest,
        address signer
    ) external view returns (bool);
}

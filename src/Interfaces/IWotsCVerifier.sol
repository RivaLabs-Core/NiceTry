// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IWotsCVerifier {
    /// @notice Recovers the WOTS+C signer address from a blob + digest,
    ///         analogous to `ecrecover`. Returns address(0) on any failure
    ///         (bad blob length, failed checksum, etc.).
    function wrecover(
        bytes calldata blob,
        bytes32 digest
    ) external view returns (address);
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IForsVerifier {
    /// @notice Verify a standalone FORS signature and recover the address
    ///         that signed it.
    /// @param sig    The FORS signature blob (length must equal SIG_LEN).
    ///               Layout: R(16) || pkSeed(16) || K × (sk(16) || auth(A·16)).
    /// @param digest The 32-byte message digest being verified.
    /// @return signer The 20-byte FORS address derived from (pkSeed, pkRoot),
    ///                or address(0) on any verification failure.
    function recover(
        bytes calldata sig,
        bytes32 digest
    ) external view returns (address signer);
}

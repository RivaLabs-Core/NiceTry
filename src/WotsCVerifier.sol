// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IWotsCVerifier} from "./Interfaces/IWotsCVerifier.sol";

/*
 * WOTS+C parameters.
 *
 * Declared at file scope so external consumers (e.g. the in-Solidity signer
 * in the test suite) can `import` them and stay in sync with the on-chain
 * verifier without duplication.
 *
 * To reconfigure, edit the three primary constants (WOTS_W_BITS, WOTS_N,
 * WOTS_L). Everything else is derived at compile time.
 *
 * Constraints:
 *   - WOTS_L * WOTS_W_BITS <= 256 (all digits fit in one keccak output word).
 *   - WOTS_N in 1..32 bytes. Changing N also requires updating any `bytes16`
 *     typing in signer / consumer code — Solidity's fixed-size byte type
 *     cannot be parameterized by a constant.
 */

// --- Primary parameters ---

uint256 constant WOTS_W_BITS = 5;    // log2(W); W = 32
uint256 constant WOTS_N      = 16;   // node size in bytes
uint256 constant WOTS_L      = 26;   // number of chains

// Optional override. Default: half of max sum = L*(W-1)/2 (minimizes search cost).
uint256 constant WOTS_TARGET_SUM = (WOTS_L * ((1 << WOTS_W_BITS) - 1)) / 2;

// --- Derived: Winternitz ---

uint256 constant WOTS_W      = 1 << WOTS_W_BITS;      // 32
uint256 constant WOTS_W_MAX  = WOTS_W - 1;            // max digit / terminal chain position
uint256 constant WOTS_W_MASK = WOTS_W - 1;            // bit mask for one digit

// --- Derived: blob layout ---

uint256 constant WOTS_R_LEN    = 32;
uint256 constant WOTS_CTR_LEN  = 4;
uint256 constant WOTS_SEED_LEN = WOTS_N;

uint256 constant WOTS_SIG_DATA = WOTS_L * WOTS_N;                               // chain-data region
uint256 constant WOTS_BLOB_LEN = WOTS_SIG_DATA + WOTS_R_LEN + WOTS_CTR_LEN + WOTS_SEED_LEN;

uint256 constant WOTS_R_OFFSET    = WOTS_SIG_DATA;
uint256 constant WOTS_CTR_OFFSET  = WOTS_SIG_DATA + WOTS_R_LEN;
uint256 constant WOTS_SEED_OFFSET = WOTS_SIG_DATA + WOTS_R_LEN + WOTS_CTR_LEN;

// --- Derived: bit ops ---

// Top-N bytes of a 32-byte word all 1s. For N=16:
//   0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000
uint256 constant WOTS_TOP_N_MASK = type(uint256).max << ((32 - WOTS_N) * 8);

// Shift for extracting digit 0 from the top of a 256-bit word.
uint256 constant WOTS_DIGIT_SHIFT_0 = 256 - WOTS_W_BITS;   // 251 for W_BITS=5

// --- Derived: scratch-memory regions used by the verifier's assembly ---

uint256 constant WOTS_CHAIN_MEM      = 0x100;              // step-hash buffer base
uint256 constant WOTS_CHAIN_I_OFF    = WOTS_N;             // offset of i_u32 within step buf
uint256 constant WOTS_CHAIN_CUR_OFF  = WOTS_N + 8;         // offset of cur (after seed||i||s)
uint256 constant WOTS_CHAIN_HASH_LEN = (WOTS_N * 2) + 8;   // seed(N) + i(4) + s(4) + cur(N)
uint256 constant WOTS_PK_MEM         = 0x200;              // pk-accumulator base

/**
 * WOTS+C Verifier. Algorithm and blob layout are fully determined by the
 * constants above.
 */
contract WotsCVerifier is IWotsCVerifier {

    // --- Public parameters (ABI-readable) ---
    //
    // Minimum an off-chain signer needs to reproduce a signature: W_BITS, N, L.
    // TARGET_SUM is exposed because the default (L*(W-1)/2) is technically
    // overridable in WotsParams. BLOB_LEN is exposed as a sanity-check
    // convenience — derivable from W_BITS/N/L but useful to assert against.

    uint256 public constant W_BITS     = WOTS_W_BITS;
    uint256 public constant N          = WOTS_N;
    uint256 public constant L          = WOTS_L;
    uint256 public constant TARGET_SUM = WOTS_TARGET_SUM;
    uint256 public constant BLOB_LEN   = WOTS_BLOB_LEN;

    /// @notice Recovers the WOTS+C signer address from a blob + digest.
    ///         Returns address(0) on bad blob length or failed checksum.
    function wrecover(
        bytes calldata blob,
        bytes32 digest
    ) external pure returns (address) {
        if (blob.length != WOTS_BLOB_LEN) return address(0);

        // Solidity inline assembly only accepts "direct number constants" —
        // literal numerics or references to them. Derived constants need to
        // be passed in via locals. With the optimizer on, these fold back.
        uint256 topMask = WOTS_TOP_N_MASK;
        uint256 sigData = WOTS_SIG_DATA;
        uint256 rOff    = WOTS_R_OFFSET;
        uint256 ctrOff  = WOTS_CTR_OFFSET;
        uint256 seedOff = WOTS_SEED_OFFSET;
        uint256 curOff  = WOTS_CHAIN_CUR_OFF;
        uint256 hashLen = WOTS_CHAIN_HASH_LEN;
        uint256 shift0  = WOTS_DIGIT_SHIFT_0;
        uint256 wMax    = WOTS_W_MAX;
        uint256 wMask   = WOTS_W_MASK;

        bytes32 r;
        bytes4 ctrBytes;
        bytes32 seedWord;
        assembly {
            r        := calldataload(add(blob.offset, rOff))
            ctrBytes := calldataload(add(blob.offset, ctrOff))
            // Load seed as the top-N bytes of a 32-byte word; mask to strip
            // any bytes past the blob's end that calldataload over-reads.
            seedWord := and(calldataload(add(blob.offset, seedOff)), topMask)
        }

        bytes32 h = keccak256(abi.encodePacked(r, ctrBytes, digest));

        // Checksum: sum of digits must equal TARGET_SUM.
        uint256 sum;
        for (uint256 i = 0; i < WOTS_L; i++) {
            uint256 digit = (uint256(h) >> (WOTS_DIGIT_SHIFT_0 - i * WOTS_W_BITS)) & WOTS_W_MASK;
            sum += digit;
        }
        if (sum != WOTS_TARGET_SUM) return address(0);

        bytes32 pkHash;
        assembly {
            for { let i := 0 } lt(i, WOTS_L) { i := add(i, 1) } {
                // cur = top-N bytes of the i-th N-byte chunk in the blob.
                let cur := and(
                    calldataload(add(blob.offset, mul(i, WOTS_N))),
                    topMask
                )

                let digit := and(shr(sub(shift0, mul(i, WOTS_W_BITS)), h), wMask)

                // Walk chain forward from position `digit` up to W_MAX.
                for { let s := digit } lt(s, wMax) { s := add(s, 1) } {
                    mstore(WOTS_CHAIN_MEM, seedWord)
                    mstore(add(WOTS_CHAIN_MEM, WOTS_CHAIN_I_OFF), or(shl(224, i), shl(192, s)))
                    mstore(add(WOTS_CHAIN_MEM, curOff), cur)
                    cur := and(keccak256(WOTS_CHAIN_MEM, hashLen), topMask)
                }

                mstore(add(WOTS_PK_MEM, mul(i, WOTS_N)), cur)
            }

            pkHash := keccak256(WOTS_PK_MEM, sigData)
        }

        return address(uint160(uint256(pkHash)));
    }
}

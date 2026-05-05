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
 *
 * Tweak discipline:
 *   - Each chain-step hash is keyed with a SPHINCS+ FIPS 205 ADRS structure
 *     (32 bytes; layer/tree/type/keypair/chain/hash) plus the public seed
 *     `pkSeed`. This matches the official SPHINCS+ tweak shape so this
 *     verifier composes cleanly with audit/spec tooling and could be
 *     dropped into a hypertree future without further reformatting.
 *   - The final pubkey-roots compression uses T_l with type=WOTS_PK,
 *     and the address is derived as keccak(pkSeed ‖ pkRoot)[12:32] —
 *     mirroring the FORS+C verifier in this repo.
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

// --- ADRS types (FIPS 205 §4.2) ---

uint256 constant WOTS_TYPE_HASH = 0;   // chain-step ADRS
uint256 constant WOTS_TYPE_PK   = 1;   // pubkey-compression ADRS

// --- Derived: scratch-memory regions used by the verifier's assembly ---
//
// Chain-step buffer (FIPS 205 tight packing — no zero padding):
//   [0..N)         : pkSeed                       (N bytes)
//   [N..N+32)      : ADRS                         (32 bytes)
//   [N+32..2N+32)  : cur                          (N bytes)
// Total hashed: 2N + 32 bytes.
//
// Pubkey-compression buffer (T_l input):
//   [0..N)                : pkSeed
//   [N..N+32)             : ADRS (type=WOTS_PK)
//   [N+32..N+32+L*N)      : pk_0 ‖ pk_1 ‖ … ‖ pk_{L-1}   (L*N bytes)
// Total hashed: N + 32 + L*N bytes.

uint256 constant WOTS_CHAIN_MEM       = 0x100;
uint256 constant WOTS_CHAIN_ADRS_OFF  = WOTS_N;                  // 16
uint256 constant WOTS_CHAIN_CUR_OFF   = WOTS_N + 32;             // 48
uint256 constant WOTS_CHAIN_HASH_LEN  = (WOTS_N * 2) + 32;       // 64

uint256 constant WOTS_PK_MEM          = 0x200;
uint256 constant WOTS_PK_ADRS_OFF     = WOTS_N;                  // 16
uint256 constant WOTS_PK_DATA_OFF     = WOTS_N + 32;             // 48
uint256 constant WOTS_PK_HASH_LEN     = WOTS_N + 32 + WOTS_L * WOTS_N; // 464 for N=16, L=26

/**
 * WOTS+C Verifier. Algorithm and blob layout are fully determined by the
 * constants above.
 *
 * Hashes used (all keccak256 truncated to N bytes where appropriate):
 *   - F_chain  = keccak(pkSeed ‖ ADRS ‖ cur)           -> N bytes  (chain step)
 *   - T_l      = keccak(pkSeed ‖ ADRS ‖ pk_0..pk_{L-1}) -> N bytes  (pubkey root)
 *   - Address  = keccak(pkSeed ‖ pkRoot)[12:32]         -> 20 bytes (account)
 */
contract WotsCVerifier is IWotsCVerifier {

    // --- Public parameters (ABI-readable) ---

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

        // Hoist parameter-derived values into locals — Solidity inline
        // assembly only accepts numeric literals or value-typed locals.
        uint256 topMask       = WOTS_TOP_N_MASK;
        uint256 rOff          = WOTS_R_OFFSET;
        uint256 ctrOff        = WOTS_CTR_OFFSET;
        uint256 seedOff       = WOTS_SEED_OFFSET;
        uint256 chainAdrsOff  = WOTS_CHAIN_ADRS_OFF;
        uint256 chainCurOff   = WOTS_CHAIN_CUR_OFF;
        uint256 chainHashLen  = WOTS_CHAIN_HASH_LEN;
        uint256 pkAdrsOff     = WOTS_PK_ADRS_OFF;
        uint256 pkDataOff     = WOTS_PK_DATA_OFF;
        uint256 pkHashLen     = WOTS_PK_HASH_LEN;
        uint256 wotsL         = WOTS_L;
        uint256 wotsN         = WOTS_N;
        uint256 wotsWBits     = WOTS_W_BITS;
        uint256 shift0        = WOTS_DIGIT_SHIFT_0;
        uint256 wMax          = WOTS_W_MAX;
        uint256 wMask         = WOTS_W_MASK;
        uint256 typePK        = WOTS_TYPE_PK;

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

        bytes32 pkRoot;
        assembly {
            for { let i := 0 } lt(i, wotsL) { i := add(i, 1) } {
                // cur = top-N bytes of the i-th N-byte chunk in the blob.
                let cur := and(
                    calldataload(add(blob.offset, mul(i, wotsN))),
                    topMask
                )

                let digit := and(shr(sub(shift0, mul(i, wotsWBits)), h), wMask)

                // Walk chain forward from position `digit` up to W_MAX.
                // Per-step: cur = F(pkSeed, ADRS, cur) where ADRS encodes
                // (layer=tree=kp=0, type=WOTS_HASH=0, chain=i, hash=s) per
                // FIPS 205 §4.2. As a 256-bit big-endian word that's
                //     adrs = (i << 32) | s
                // since i lives in ADRS bytes 24..27 and s in 28..31.
                for { let s := digit } lt(s, wMax) { s := add(s, 1) } {
                    let adrs := or(shl(32, i), s)
                    mstore(WOTS_CHAIN_MEM,                          seedWord)
                    mstore(add(WOTS_CHAIN_MEM, chainAdrsOff),       adrs)
                    mstore(add(WOTS_CHAIN_MEM, chainCurOff),        cur)
                    cur := and(keccak256(WOTS_CHAIN_MEM, chainHashLen), topMask)
                }

                // Stash pk_i tightly packed at WOTS_PK_MEM + pkDataOff + i*N.
                mstore(add(add(WOTS_PK_MEM, pkDataOff), mul(i, wotsN)), cur)
            }

            // ─── T_l: pkRoot = keccak(pkSeed ‖ ADRS_PK ‖ pk_0 ‖ … ‖ pk_{L-1}) ───
            // ADRS_PK encodes (type=WOTS_PK=1, all other fields 0).
            // Bytes 16..19 of ADRS hold "type" big-endian; placing 1 at byte 19
            // puts it at uint256 bit 96, hence `shl(96, typePK)`.
            mstore(WOTS_PK_MEM,                          seedWord)
            mstore(add(WOTS_PK_MEM, pkAdrsOff),          shl(96, typePK))
            pkRoot := and(keccak256(WOTS_PK_MEM, pkHashLen), topMask)
        }

        // ─── Address = keccak(pkSeed ‖ pkRoot)[12:32] ───
        // Tightly packed (no 16-byte zero padding between the fields).
        // Memory writes stay in scratch (offsets 0..47); FMP at 0x40 and
        // beyond is left untouched, so this assembly block is genuinely
        // memory-safe.
        bytes32 addrHash;
        assembly ("memory-safe") {
            mstore(0x00, seedWord)   // bytes 0..15: pkSeed, 16..31: zero
            mstore(0x10, pkRoot)     // bytes 16..31: pkRoot, 32..47: zero
            addrHash := keccak256(0x00, 0x20)
        }
        return address(uint160(uint256(addrHash)));
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IForsVerifier} from "./Interfaces/IForsVerifier.sol";

/*
 * Standalone FORS signature verifier (JARDIN-family Keccak variant).
 *
 * FORS-only post-quantum few-time signature scheme using the same hash
 * primitives, ADRS layout, and 16-byte hash truncation as the FORS sub-
 * component of our SLH-DSA-Keccak-128-24 SphincsVerifier. No XMSS
 * hypertree above — the public key is the FORS roots compression alone.
 *
 * Used as a primary signer (parallel to ECDSA / WOTS+C). Account-side
 * convention is to rotate the owner address on every signed UserOp,
 * matching WOTS+C semantics. Compared to WOTS+C the security degrades
 * gracefully on accidental key reuse instead of breaking immediately.
 *
 * Domain byte 0xFF..FD separates this scheme from spec SPHINCS+ and the
 * keccak-128-24 SLH-DSA family member.
 *
 * ─────────────────────────── Parameter tradeoff ────────────────────────
 *  All rows give ≥128-bit security at q=1 (intended single use per key).
 *  q=N security is the bound after N accidental reuses. "Tree work" is
 *  K·2^A keccak ops the signer must do per signature; it drives whether
 *  a Solidity round-trip test is feasible (<≈1M ops) or only a Python
 *  signer can produce vectors.
 *
 *   K  | A  | sig size | q=1 | q=2 | q=10 | q=100 | tree work | sol-signer?
 *   ---+----+----------+-----+-----+------+-------+-----------+-------------
 *    6 | 24 |  2,432 B | 128 | 122 | 108  |  88   |   100M    | no
 *    6 | 22 |  2,144 B | 116 | 110 |  92  |  64   |    25M    | no
 *    8 | 19 |  2,592 B | 128 | 120 | 102  |  78   |   4.2M    | borderline
 *   10 | 16 |  2,752 B | 128 | 118 |  95  |  65   |   655k    | slow (~10m)
 *   12 | 15 |  3,104 B | 132 | 119 |  89  |  53   |   393k    | slow (~5m)
 * ► 14 | 13 |  3,168 B | 128 | 114 |  80  |  ~40  |   115k    | yes (~1m)
 *   16 | 12 |  3,360 B | 128 | 112 |  70  |  ~28  |    65k    | yes (~30s)
 *   18 | 11 |  3,488 B | 126 | 110 |  60  |  ~16  |    37k    | yes (~15s)
 *
 *  Current selection: K=14, A=13. Trades ~30% larger signature for
 *  Solidity-feasible round-trip tests and graceful-but-bounded
 *  degradation on key reuse.
 *
 *  To revisit: change FORS_K and FORS_A below; assembly literals are
 *  also derived from these — see the inline comments in `recover()`.
 * ──────────────────────────────────────────────────────────────────────
 *
 * Estimated verification cost: ~55k gas.
 */

// --- Primary parameters ---

uint256 constant FORS_N = 16;     // hash truncation / node size
uint256 constant FORS_K = 14;     // FORS trees
uint256 constant FORS_A = 13;     // FORS tree height (2^A leaves per tree)

// --- Derived: signature layout ---

uint256 constant FORS_R_LEN         = 16;
uint256 constant FORS_PKSEED_LEN    = 16;
uint256 constant FORS_TREE_LEN      = 16 + FORS_A * 16;          // 224
uint256 constant FORS_SECTION_LEN   = FORS_K * FORS_TREE_LEN;    // 3,136
uint256 constant FORS_SIG_LEN       = FORS_R_LEN + FORS_PKSEED_LEN + FORS_SECTION_LEN; // 3,168

uint256 constant FORS_R_OFFSET       = 0;
uint256 constant FORS_PKSEED_OFFSET  = FORS_R_OFFSET + FORS_R_LEN;     // 16
uint256 constant FORS_SECTION_OFFSET = FORS_R_OFFSET + FORS_R_LEN + FORS_PKSEED_LEN; // 32

// --- Derived: bit ops ---

uint256 constant FORS_TOP_N_MASK = type(uint256).max << ((32 - FORS_N) * 8);

// Domain separation byte for Hmsg (32-byte big-endian, last byte = 0xFD).
uint256 constant FORS_DOM = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD;

// --- ADRS types (matches SPHINCS+ family) ---

uint256 constant FORS_TYPE_FORS_TREE  = 3;
uint256 constant FORS_TYPE_FORS_ROOTS = 4;

/// @title ForsVerifier
/// @notice Standalone FORS verifier in the JARDIN keccak family.
contract ForsVerifier is IForsVerifier {

    // --- Public parameters (ABI-readable) ---

    uint256 public constant N        = FORS_N;
    uint256 public constant K        = FORS_K;
    uint256 public constant A        = FORS_A;
    uint256 public constant SIG_LEN  = FORS_SIG_LEN;

    /// @inheritdoc IForsVerifier
    function recover(
        bytes calldata sig,
        bytes32 digest
    ) external pure override returns (address signer) {
        // Hoist computed constants into locals (Solidity inline assembly only
        // accepts direct number literals).
        uint256 SIG_LEN_      = FORS_SIG_LEN;
        uint256 N_MASK        = FORS_TOP_N_MASK;
        uint256 DOM           = FORS_DOM;
        uint256 SECTION_OFF   = FORS_SECTION_OFFSET;
        uint256 TREE_LEN_     = FORS_TREE_LEN;          // 16 + A·16
        uint256 ROOTS_HASH_LEN = (FORS_K + 2) * 32;     // seed + ADRS + K·32

        if (sig.length != SIG_LEN_) return address(0);

        assembly ("memory-safe") {
            // === Hard-coded literals corresponding to (K=14, A=13) ===
            // K = 14                        — outer loop bounds
            // A = 13                        — inner climb bound, mdT mask, shifts
            // A_MINUS_1 = 12                — globalY shift base
            // MD_BITS = 13                  — bits per md[t] in dVal
            // MD_MASK = 0x1FFF              — (1 << A) - 1 = 8191
            //
            // If you change FORS_K or FORS_A above, update the literals here
            // (and the table at the top of this file).

            let sigBase := sig.offset

            // R: top 16 B of the first 32-byte slot.
            // pkSeed: top 16 B of the next 32-byte slot.
            let R      := and(calldataload(sigBase),       N_MASK)
            let pkSeed := and(calldataload(add(sigBase, 16)), N_MASK)

            // ─── Hmsg = keccak(pkSeed ‖ R ‖ digest ‖ dom_FORS) = 128 B ───
            mstore(0x00, pkSeed)
            mstore(0x20, R)
            mstore(0x40, digest)
            mstore(0x60, DOM)
            let dVal := keccak256(0x00, 0x80)

            // md[t] = (dVal >> (A·t)) & ((1<<A) - 1)   for t = 0..K-1
            // (LSB-first; K · A bits used = 14 · 13 = 182 bits, fits in 256.)

            // From here on, pkSeed sits at 0x00 for every hash call.
            mstore(0x00, pkSeed)

            // ─── FORS tree verification ───
            //   ADRS base for FORS at this standalone keypair:
            //   type=3, layer=tree=kp=0
            let forsBase := shl(128, 3)

            for { let t := 0 } lt(t, 14) { t := add(t, 1) } {
                // mdT in 13 LSB; mask 0x1FFF
                let mdT     := and(shr(mul(13, t), dVal), 0x1FFF)
                let treeOff := add(SECTION_OFF, mul(t, TREE_LEN_))
                let sk      := and(calldataload(add(sigBase, treeOff)), N_MASK)

                // Leaf ADRS: cp=0, ha = (t << A) | mdT  = (t << 13) | mdT
                mstore(0x20, or(forsBase, or(shl(13, t), mdT)))
                mstore(0x40, sk)
                let node := and(keccak256(0x00, 0x60), N_MASK)

                // Climb A=13 auth-path levels.
                let authPtr := add(sigBase, add(treeOff, 16))
                let pathIdx := mdT
                for { let j := 0 } lt(j, 13) { j := add(j, 1) } {
                    let sibling   := and(calldataload(add(authPtr, shl(4, j))), N_MASK)
                    let parentIdx := shr(1, pathIdx)
                    // globalY = (t << (A-1-j)) | parentIdx = (t << (12-j)) | parentIdx
                    let globalY := or(shl(sub(12, j), t), parentIdx)
                    mstore(0x20, or(forsBase, or(shl(32, add(j, 1)), globalY)))
                    let s := shl(5, and(pathIdx, 1))
                    mstore(xor(0x40, s), node)
                    mstore(xor(0x60, s), sibling)
                    node := and(keccak256(0x00, 0x80), N_MASK)
                    pathIdx := parentIdx
                }
                // Stash root at 0x80 + t·0x20.
                mstore(add(0x80, shl(5, t)), node)
            }

            // ─── Compress K=14 FORS roots: T_l(seed, ADRS, roots) = (K+2)·32 = 512 B ───
            {
                let adrsRoots := shl(128, 4)   // type=FORS_ROOTS, kp=0
                mstore(0x20, adrsRoots)
                // Pack pattern: pack[t] at 0x40+t·32, source[t] at 0x80+t·32.
                // Safe because pack[t] overwrites source[t-2] (already consumed).
                for { let t := 0 } lt(t, 14) { t := add(t, 1) } {
                    mstore(add(0x40, shl(5, t)), mload(add(0x80, shl(5, t))))
                }
            }
            let pkRoot := and(keccak256(0x00, ROOTS_HASH_LEN), N_MASK)

            // ─── Address = keccak256(pad32(pkSeed) || pad32(pkRoot))[12:32] ───
            mstore(0x00, pkSeed)
            mstore(0x20, pkRoot)
            signer := and(keccak256(0x00, 0x40),
                0x000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
        }
    }
}

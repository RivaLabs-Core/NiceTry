// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IForsVerifier} from "../Interfaces/IForsVerifier.sol";

/*
 * Standalone FORS+C signature verifier (Keccak variant).
 *
 * FORS-only post-quantum few-time signature scheme using the same hash
 * primitives, ADRS layout, and 16-byte hash truncation as the FORS sub-
 * component of our SLH-DSA-Keccak-128-24 SphincsVerifier. No XMSS
 * hypertree above — the public key is the FORS roots compression alone.
 *
 * The +C variant (Hülsing–Kudinov–Ronen–Yogev, 2023; see also Kudinov–Nick
 * 2025-12-05 "Hash-based Signature Schemes for Bitcoin", §9.2) trims one
 * full FORS tree out of the signer's work and one full auth path out of
 * the signature, paid for by a per-signature grinding step:
 *
 *   - The signer iterates a 16-byte counter until the digest
 *         dVal = keccak(pkSeed ‖ R ‖ digest ‖ dom_FORS ‖ counter)
 *     has its highest A-bit field equal to zero (i.e. the K-th tree's
 *     index would be 0).
 *   - The K-th tree is then never computed, never opened, and never
 *     transmitted; the verifier just checks the zero-bit constraint and
 *     compresses K-1 real roots into pkRoot.
 *
 * Used as a primary signer (parallel to ECDSA / WOTS+C). Account-side
 * convention is to rotate the owner address on every signed UserOp,
 * matching WOTS+C semantics. Compared to WOTS+C the security degrades
 * gracefully on accidental key reuse instead of breaking immediately.
 *
 * Domain byte 0xFF..FD separates this scheme from spec SPHINCS+ and the
 * keccak-128-24 SLH-DSA family member.
 *
 * ─────────────────────────── Current selection: K=26, A=5 ─────────────
 *
 *  Signature size:  2,448 B
 *  Signer work:     ~2.4k keccak / signature
 *                   (≈ 2.4 ms on a laptop with hashlib-backed keccak;
 *                   ≈ 7 s on Ledger SE with software Keccak — usable!)
 *
 *  Security at q signatures (bits, classical):
 *      q=1: 128     q=2: 104     q=3: 89      q=4: 78      q=5: 70
 *
 *  q=1 is at the 128-bit NIST Level 1 ceiling (K·A = 130 just clears
 *  the hash-output cap). q-degradation is steep — reuse beyond q=2
 *  drops below Level 1. Justified by the rotation-per-UserOp model:
 *  the normal path is q=1, and the two-forest cache (see
 *  docs/fors-two-forest-cache.md) bounds the worst-case-reuse to a
 *  small budget (typically ≤ 2..3) for replacement / dropped-tx flows.
 *
 *  The signer-cost win over K=14, A=10 is ~17× (2^10 → 2^5 leaves per
 *  tree dominates), making this set viable on hardware wallets.
 *
 *  Full discussion of the scheme, parameter sweep, and rationale lives
 *  in docs/fors-parameters.md and docs/fors-two-forest-cache.md.
 *
 * ──────────────────────────────────────────────────────────────────────
 *
 * Estimated verification cost: ~40k gas.
 */

// --- Primary parameters ---

uint256 constant FORS_N = 16;     // hash truncation / node size
uint256 constant FORS_K = 26;     // FORS trees (paper-style; only K-1 are real under +C)
uint256 constant FORS_A = 5;      // FORS tree height (2^A leaves per tree)

// --- Derived: signature layout ---
//
// Layout (FORS+C):
//   [0      ..16   ) : R          (16 B, kept in top half of a 32-byte slot)
//   [16     ..32   ) : pkSeed     (16 B, ditto)
//   [32     ..2432 ) : (K-1)=25 trees, each (sk‖auth_path) of 16 + A·16 = 96 B
//   [2432   ..2448 ) : counter    (16 B, top half; bottom half is unused)
//
// The K-th tree's auth path is omitted entirely; the verifier knows
// mdT[K-1] = 0 from the grinding constraint and never opens that tree.

uint256 constant FORS_R_LEN         = 16;
uint256 constant FORS_PKSEED_LEN    = 16;
uint256 constant FORS_TREE_LEN      = 16 + FORS_A * 16;            // 176
uint256 constant FORS_SECTION_LEN   = (FORS_K - 1) * FORS_TREE_LEN;// 2,288
uint256 constant FORS_COUNTER_LEN   = 16;
uint256 constant FORS_SIG_LEN       =
    FORS_R_LEN + FORS_PKSEED_LEN + FORS_SECTION_LEN + FORS_COUNTER_LEN; // 2,336

uint256 constant FORS_R_OFFSET       = 0;
uint256 constant FORS_PKSEED_OFFSET  = FORS_R_OFFSET + FORS_R_LEN;     // 16
uint256 constant FORS_SECTION_OFFSET = FORS_PKSEED_OFFSET + FORS_PKSEED_LEN; // 32
uint256 constant FORS_COUNTER_OFFSET = FORS_SECTION_OFFSET + FORS_SECTION_LEN; // 2,320

// --- Derived: bit ops ---

uint256 constant FORS_TOP_N_MASK = type(uint256).max << ((32 - FORS_N) * 8);

// Domain separation byte for Hmsg (32-byte big-endian, last byte = 0xFD).
uint256 constant FORS_DOM = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD;

// --- ADRS types (matches SPHINCS+ family) ---

uint256 constant FORS_TYPE_FORS_TREE  = 3;
uint256 constant FORS_TYPE_FORS_ROOTS = 4;

/// @title ForsVerifier
/// @notice Standalone FORS+C verifier (Keccak primitive).
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
        // Hoist computed constants into locals — Solidity inline assembly
        // only accepts numeric literals or value-typed locals as operands.
        // Putting all parameter-derived values here means changing FORS_K
        // / FORS_A at the top of the file is enough to retune the verifier;
        // no assembly literal needs to be touched.
        uint256 SIG_LEN_       = FORS_SIG_LEN;
        uint256 N_MASK         = FORS_TOP_N_MASK;
        uint256 DOM            = FORS_DOM;
        uint256 SECTION_OFF    = FORS_SECTION_OFFSET;
        uint256 COUNTER_OFF    = FORS_COUNTER_OFFSET;
        uint256 TREE_LEN_      = FORS_TREE_LEN;             // 16 + A·16
        uint256 ROOTS_HASH_LEN = (FORS_K + 1) * 32;         // pkSeed + ADRS + (K-1)·N

        // Parameter-derived loop bounds and bit masks:
        uint256 KMINUS1   = FORS_K - 1;                      // outer tree-open loop bound
        uint256 A_        = FORS_A;                          // inner-loop bound, A·t shift, leaf-ADRS shift
        uint256 AMINUS1   = FORS_A - 1;                      // globalY shift base (A-1-j)
        uint256 MD_MASK   = (uint256(1) << FORS_A) - 1;      // mdT mask = (1<<A) - 1
        uint256 KMINUS1_A = (FORS_K - 1) * FORS_A;           // bit offset of the K-th mdT field in dVal

        if (sig.length != SIG_LEN_) return address(0);

        assembly ("memory-safe") {
            // Save FMP — the loops below trample 0x40 and 0x60 (Solidity's
            // FMP slot and zero slot) using them as keccak input scratch.
            // We restore both before falling through to Solidity's return.
            let fmpBackup := mload(0x40)

            let sigBase := sig.offset

            // R, pkSeed, counter: each is 16 B kept in the top half of a
            // 32-byte word, with the next 16 B masked off.
            let R       := and(calldataload(sigBase),                 N_MASK)
            let pkSeed  := and(calldataload(add(sigBase, 16)),        N_MASK)
            let counter := and(calldataload(add(sigBase, COUNTER_OFF)), N_MASK)

            // ─── Hmsg = keccak(pkSeed ‖ R ‖ digest ‖ dom_FORS ‖ counter) = 160 B ───
            mstore(0x00, pkSeed)
            mstore(0x20, R)
            mstore(0x40, digest)
            mstore(0x60, DOM)
            mstore(0x80, counter)
            let dVal := keccak256(0x00, 0xa0)

            // FORS+C grinding check: the K-th A-bit field of dVal (bits
            // (K-1)·A .. K·A-1) must be zero. If the signer didn't grind
            // to satisfy this, reject with address(0).
            if and(shr(KMINUS1_A, dVal), MD_MASK) {
                mstore(0x00, 0)
                return(0x00, 0x20)
            }

            // md[t] = (dVal >> (A·t)) & ((1<<A) - 1)   for t = 0..K-2
            // (LSB-first; (K-1) · A bits of dVal are consumed.)

            // From here on, pkSeed sits at 0x00 for every hash call.
            mstore(0x00, pkSeed)

            // ─── FORS tree verification (K-1 real trees) ───
            //   ADRS base for FORS at this standalone keypair:
            //   type=3, layer=tree=kp=0
            let forsBase := shl(128, 3)

            for { let t := 0 } lt(t, KMINUS1) { t := add(t, 1) } {
                // mdT = (dVal >> (A·t)) & MD_MASK
                let mdT     := and(shr(mul(A_, t), dVal), MD_MASK)
                let treeOff := add(SECTION_OFF, mul(t, TREE_LEN_))
                let sk      := and(calldataload(add(sigBase, treeOff)), N_MASK)

                // Leaf ADRS: cp=0, ha = (t << A) | mdT
                mstore(0x20, or(forsBase, or(shl(A_, t), mdT)))
                mstore(0x40, sk)
                let node := and(keccak256(0x00, 0x60), N_MASK)

                // Climb A auth-path levels.
                // authPtr pre-increments by 16 each iteration. The
                // sibling calldataload is inlined at its mstore use
                // site so the optimizer can fold it (a named local
                // would have to live across the ADRS construction
                // and pay stack-materialization gas).
                let authPtr := add(sigBase, add(treeOff, 16))
                let pathIdx := mdT
                for { let j := 0 } lt(j, A_) { j := add(j, 1) } {
                    let parentIdx := shr(1, pathIdx)
                    // globalY = (t << (A-1-j)) | parentIdx
                    let globalY := or(shl(sub(AMINUS1, j), t), parentIdx)
                    mstore(0x20, or(forsBase, or(shl(32, add(j, 1)), globalY)))
                    let s := shl(5, and(pathIdx, 1))
                    mstore(xor(0x40, s), node)
                    mstore(xor(0x60, s), and(calldataload(authPtr), N_MASK))
                    authPtr := add(authPtr, 16)
                    node := and(keccak256(0x00, 0x80), N_MASK)
                    pathIdx := parentIdx
                }
                // Stash root at 0x80 + t·0x20.
                mstore(add(0x80, shl(5, t)), node)
            }

            // ─── Compress K-1 FORS roots ───
            //   T(seed, ADRS_roots, root_0..root_{K-2}) over (K+1)·32 bytes
            {
                let adrsRoots := shl(128, 4)   // type=FORS_ROOTS, kp=0
                mstore(0x20, adrsRoots)
                // Pack pattern: pack[t] at 0x40+t·32, source[t] at 0x80+t·32.
                // Safe because pack[t] overwrites source[t-2] (already consumed).
                for { let t := 0 } lt(t, KMINUS1) { t := add(t, 1) } {
                    mstore(add(0x40, shl(5, t)), mload(add(0x80, shl(5, t))))
                }
            }
            let pkRoot := and(keccak256(0x00, ROOTS_HASH_LEN), N_MASK)

            // ─── Address = keccak256(pad32(pkSeed) || pad32(pkRoot))[12:32] ───
            mstore(0x00, pkSeed)
            mstore(0x20, pkRoot)
            signer := and(keccak256(0x00, 0x40),
                0x000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)

            // Restore FMP and zero slot for whatever follows in Solidity.
            mstore(0x40, fmpBackup)
            mstore(0x60, 0)
        }
    }
}

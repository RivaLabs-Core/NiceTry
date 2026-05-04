// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IForsVerifier} from "./Interfaces/IForsVerifier.sol";

/*
 * Standalone FORS signature verifier (JARDIN-family Keccak variant).
 *
 * FORS-only post-quantum few-time signature scheme using the same hash
 * primitives, ADRS layout, and parameter set as the FORS sub-component
 * of our SLH-DSA-Keccak-128-24 SphincsVerifier. No XMSS hypertree above —
 * the public key is the FORS roots compression alone.
 *
 * Used as a primary signer (parallel to ECDSA / WOTS+C). Account-side
 * convention is to rotate the owner address on every signed UserOp,
 * matching WOTS+C semantics. Compared to WOTS+C the security degrades
 * gracefully on accidental key reuse instead of breaking immediately.
 *
 * Parameters: n=16, k=6, a=24, hash truncated to 16 bytes.
 * Domain byte 0xFF..FD separates this scheme from spec SPHINCS+ and the
 * keccak-128-24 SLH-DSA family member.
 *
 * Signature size: 32 + 6 × (16 + 24·16) = 2,432 bytes.
 * Estimated verification cost: ~50k gas.
 */

// --- Primary parameters ---

uint256 constant FORS_N = 16;     // hash truncation / node size
uint256 constant FORS_K = 6;      // FORS trees
uint256 constant FORS_A = 24;     // FORS tree height (2^A leaves per tree)

// --- Derived: signature layout ---

uint256 constant FORS_R_LEN        = 16;
uint256 constant FORS_PKSEED_LEN   = 16;
uint256 constant FORS_TREE_LEN     = 16 + FORS_A * 16;          // 400
uint256 constant FORS_SECTION_LEN  = FORS_K * FORS_TREE_LEN;    // 2,400
uint256 constant FORS_SIG_LEN      = FORS_R_LEN + FORS_PKSEED_LEN + FORS_SECTION_LEN; // 2,432

uint256 constant FORS_R_OFFSET      = 0;
uint256 constant FORS_PKSEED_OFFSET = FORS_R_OFFSET + FORS_R_LEN;     // 16
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

        if (sig.length != SIG_LEN_) return address(0);

        assembly ("memory-safe") {
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

            // md[t] = (dVal >> 24·t) & 0xFFFFFF for t = 0..K-1
            // (LSB-first, 6 × 24 bits = 144 bits used)

            // From here on, pkSeed sits at 0x00 for every hash call.
            mstore(0x00, pkSeed)

            // ─── FORS tree verification ───
            //   ADRS base for FORS at this standalone keypair:
            //   type=3, layer=tree=kp=0
            let forsBase := shl(128, 3)

            for { let t := 0 } lt(t, 6) { t := add(t, 1) } {
                let mdT     := and(shr(mul(24, t), dVal), 0xFFFFFF)
                let treeOff := add(SECTION_OFF, mul(t, 400))
                let sk      := and(calldataload(add(sigBase, treeOff)), N_MASK)

                // Leaf ADRS: cp=0, ha = (t << a) | mdT
                mstore(0x20, or(forsBase, or(shl(24, t), mdT)))
                mstore(0x40, sk)
                let node := and(keccak256(0x00, 0x60), N_MASK)

                // Climb 24 auth-path levels.
                let authPtr := add(sigBase, add(treeOff, 16))
                let pathIdx := mdT
                for { let j := 0 } lt(j, 24) { j := add(j, 1) } {
                    let sibling   := and(calldataload(add(authPtr, shl(4, j))), N_MASK)
                    let parentIdx := shr(1, pathIdx)
                    let globalY := or(shl(sub(23, j), t), parentIdx)
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

            // ─── Compress 6 FORS roots: T_l(seed, ADRS, roots) = 256 B ───
            {
                let adrsRoots := shl(128, 4)   // type=FORS_ROOTS, kp=0
                mstore(0x20, adrsRoots)
                // Pack pattern: pack[t] at 0x40+t·32, source[t] at 0x80+t·32.
                // Safe because pack[t] overwrites source[t-2] (already consumed).
                for { let t := 0 } lt(t, 6) { t := add(t, 1) } {
                    mstore(add(0x40, shl(5, t)), mload(add(0x80, shl(5, t))))
                }
            }
            let pkRoot := and(keccak256(0x00, 0x100), N_MASK)

            // ─── Address = keccak256(pad32(pkSeed) || pad32(pkRoot))[12:32] ───
            mstore(0x00, pkSeed)
            mstore(0x20, pkRoot)
            signer := and(keccak256(0x00, 0x40),
                0x000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
        }
    }
}

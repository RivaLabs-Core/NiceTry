// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {
    ForsVerifier,
    FORS_K,
    FORS_A,
    FORS_SIG_LEN,
    FORS_R_OFFSET,
    FORS_PKSEED_OFFSET,
    FORS_SECTION_OFFSET,
    FORS_TREE_LEN,
    FORS_COUNTER_OFFSET,
    FORS_DOM
} from "../src/ForsVerifier.sol";

/// @dev Gas-measurement harness for the FORS+C verifier. We don't run a
///      Solidity-side signer (300k+ keccaks per signature is impractical
///      under via-ir); instead we craft a blob whose only "real" property
///      is that its grinding constraint is satisfied. The verifier still
///      walks the entire (K-1) tree-open path, so the measured gas matches
///      a real signature at the cost of an off-chain signer fixture.
contract ForsVerifierGasTest is Test {
    ForsVerifier verifier;

    function setUp() public {
        verifier = new ForsVerifier();
    }

    /// @dev Builds a 2336-byte blob with: random R, random pkSeed, random
    ///      tree contents, and a counter chosen so the bottom (K-1)·A bits
    ///      of dVal contain a zero in the K-th A-bit field. The verifier
    ///      will not find a sensible address in the result, but it will
    ///      execute the full tree-open path before producing one — which
    ///      is what we want to measure.
    function _craftGasBlob(bytes32 digest, bytes32 salt)
        internal
        pure
        returns (bytes memory blob)
    {
        bytes16 R      = bytes16(keccak256(abi.encode("R", salt)));
        bytes16 pkSeed = bytes16(keccak256(abi.encode("pkSeed", salt)));

        // Grind in assembly using FMP-rooted scratch — Solidity's
        // abi.encodePacked would allocate 160 fresh bytes per iteration and
        // blow up memory expansion gas quadratically over ~1024 attempts.
        // We don't bump FMP; subsequent Solidity allocations reuse this
        // region. Memory-safe.
        uint256 counterWord;
        {
            uint256 R_w      = uint256(uint128(R)) << 128;
            uint256 pkSeed_w = uint256(uint128(pkSeed)) << 128;
            uint256 dom      = FORS_DOM;
            uint256 maskBits = (uint256(1) << FORS_A) - 1;
            uint256 shiftBits = (FORS_K - 1) * FORS_A;
            uint256 maxIter  = uint256(1) << (FORS_A + 4); // 16× expected
            bool found;
            assembly ("memory-safe") {
                let scratch := mload(0x40)
                mstore(scratch,             pkSeed_w)
                mstore(add(scratch, 0x20),  R_w)
                mstore(add(scratch, 0x40),  digest)
                mstore(add(scratch, 0x60),  dom)
                for { let i := 0 } lt(i, maxIter) { i := add(i, 1) } {
                    let c := shl(128, i)
                    mstore(add(scratch, 0x80), c)
                    let dVal := keccak256(scratch, 0xa0)
                    if iszero(and(shr(shiftBits, dVal), maskBits)) {
                        counterWord := c
                        found := 1
                        break
                    }
                }
            }
            require(found, "could not grind counter");
        }
        bytes16 counter = bytes16(uint128(counterWord >> 128));

        blob = new bytes(FORS_SIG_LEN);
        // R at [0..16)
        for (uint256 i = 0; i < 16; i++) blob[i] = R[i];
        // pkSeed at [16..32)
        for (uint256 i = 0; i < 16; i++) blob[16 + i] = pkSeed[i];
        // Tree section: random fill — auth-path correctness is irrelevant
        // for gas; only the work the verifier performs matters.
        for (uint256 t = 0; t < FORS_K - 1; t++) {
            uint256 off = FORS_SECTION_OFFSET + t * FORS_TREE_LEN;
            bytes32 fill = keccak256(abi.encode("tree", salt, t));
            for (uint256 b = 0; b < FORS_TREE_LEN; b++) {
                blob[off + b] = fill[b % 32];
            }
        }
        // Counter at [COUNTER_OFFSET..COUNTER_OFFSET+16)
        for (uint256 i = 0; i < 16; i++) {
            blob[FORS_COUNTER_OFFSET + i] = counter[i];
        }
    }

    /// @dev Measures verification gas. Independent of whether the recovered
    ///      address is "valid" — the verifier does the same work either way.
    function test_gas_verify_oneShot() public view {
        bytes32 digest = keccak256("gas-one-shot");
        bytes memory blob = _craftGasBlob(digest, bytes32(uint256(0xFEED)));

        uint256 before = gasleft();
        verifier.recover(blob, digest);
        uint256 used = before - gasleft();

        console.log("ForsVerifier.recover one-shot gas:", used);
    }

    /// @dev Average across a few salts to smooth out call-frame noise.
    ///      FORS+C work is constant in K, A by construction (no per-leaf
    ///      branching), so the variance is tiny — but we report an avg
    ///      for symmetry with the WOTS+C suite.
    function test_gas_verify_average() public view {
        uint256 N = 5;
        uint256 totalGas;
        for (uint256 i = 0; i < N; i++) {
            bytes32 digest = keccak256(abi.encode("gas", i));
            bytes memory blob = _craftGasBlob(digest, bytes32(i));

            uint256 before = gasleft();
            verifier.recover(blob, digest);
            uint256 used = before - gasleft();

            totalGas += used;
        }
        console.log("ForsVerifier.recover avg gas (N=5):", totalGas / N);
    }

    /// @dev Sanity: bad-length blobs early-return cheaply.
    function test_gas_verify_badLength() public view {
        bytes memory blob = new bytes(FORS_SIG_LEN - 1);
        uint256 before = gasleft();
        verifier.recover(blob, keccak256("anything"));
        uint256 used = before - gasleft();
        console.log("ForsVerifier.recover bad-length gas:", used);
    }

}

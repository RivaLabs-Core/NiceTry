// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IWotsCVerifier} from "./Interfaces/IWotsCVerifier.sol";

/**
 * WOTS+C Verifier — w=32, n=16B, l=26, 130-bit security
 *
 * Blob (468B): chains(416B = 26×16B) + r(32B) + ctr(4B) + seed(16B)
 * Digits: 5-bit values (0..31), TARGET_SUM=403
 */
contract WotsCVerifier is IWotsCVerifier {

    uint16 constant TARGET_SUM = 403;
    uint8  constant L          = 26;
    uint16 constant BLOB_LEN   = 468;
    uint16 constant SIG_DATA   = 416;

    function verify(
        bytes calldata blob,
        bytes32 digest,
        address signer
    ) external pure returns (bool) {
        if (blob.length != BLOB_LEN) return false;

        bytes32 r;
        bytes4 ctrBytes;
        bytes16 seed;
        assembly {
            r        := calldataload(add(blob.offset, 416))
            ctrBytes := calldataload(add(blob.offset, 448))
            seed     := calldataload(add(blob.offset, 452))
        }

        bytes32 h = keccak256(abi.encodePacked(r, ctrBytes, digest));

        //Checksum check. If sum of blocks is not 403 verification fails.
        uint16 sum;
        for (uint8 i = 0; i < L; i++) {
            uint8 digit = uint8(uint256(h) >> (251 - uint16(i) * 5)) & 0x1F;
            sum += uint16(digit);
        }
        if (sum != TARGET_SUM) return false;

        bytes32 pkHash;
        assembly {
            let seedWord := seed
            let hVal := h

            for { let i := 0 } lt(i, 26) { i := add(i, 1) } {
                let cur := and(
                    calldataload(add(blob.offset, mul(i, 16))),
                    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000
                )

                let digit := and(shr(sub(251, mul(i, 5)), hVal), 0x1F)

                for { let s := digit } lt(s, 31) { s := add(s, 1) } {
                    mstore(0x100, seedWord)
                    mstore(0x110, or(shl(224, i), shl(192, s)))
                    mstore(0x118, cur)
                    cur := and(
                        keccak256(0x100, 40),
                        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000
                    )
                }

                mstore(add(0x200, mul(i, 16)), cur)
            }

            pkHash := keccak256(0x200, 416)
        }

        address derived = address(uint160(uint256(keccak256(abi.encodePacked(pkHash)))));
        return derived == signer;
    }
}

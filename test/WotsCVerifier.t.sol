// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/WotsCVerifier.sol";
import "../src/SimpleAccount_WOTS.sol";
import "../src/SimpleAccountFactory.sol";
import {IWotsCVerifier} from "../src/Interfaces/IWotsCVerifier.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";

/// @dev Test-only WOTS+C key derivation and signer, replicating the on-chain
///      WotsCVerifier algorithm exactly. Parameters: w=32, n=16B, l=26, target=403.
///
///      Not production code:
///      - Secret keys are derived from caller-supplied material via keccak (no PRF).
///      - Counter search is a plain loop; cap is ~MAX_CTR iterations.
library WotsSigner {
    uint16 constant TARGET_SUM = 403;
    uint8  constant L          = 26;
    uint32 constant MAX_CTR    = 1_000_000;

    struct Key {
        bytes16[26] sk;    // private chain starts
        bytes16     seed;  // public chain salt
        bytes16[26] pk;    // public chain ends (pos 31)
        address     addr;  // low 20 bytes of keccak256(pk[0]||..||pk[25])
    }

    /// @dev One chain hash step. Matches WotsCVerifier inline assembly bit-for-bit:
    ///      keccak256(seed(16) || i_u32(4) || s_u32(4) || cur_top16(16)) truncated to 16B.
    function chainStep(bytes16 seed, uint32 i, uint32 s, bytes16 cur)
        internal pure returns (bytes16)
    {
        return bytes16(keccak256(abi.encodePacked(seed, i, s, cur)));
    }

    /// @dev Derive a deterministic Key from `material`.
    function derive(bytes32 material) internal pure returns (Key memory k) {
        for (uint8 i = 0; i < L; i++) {
            k.sk[i] = bytes16(keccak256(abi.encodePacked(material, "sk", i)));
        }
        k.seed = bytes16(keccak256(abi.encodePacked(material, "seed")));

        // pk[i] = walk(sk[i]) for 31 hash iterations (s = 0..30)
        for (uint8 i = 0; i < L; i++) {
            bytes16 cur = k.sk[i];
            for (uint32 s = 0; s < 31; s++) {
                cur = chainStep(k.seed, uint32(i), s, cur);
            }
            k.pk[i] = cur;
        }

        // pkHash = keccak256(pk[0] || pk[1] || ... || pk[25]) — each 16 bytes, 416 total.
        bytes memory buf = new bytes(416);
        for (uint8 i = 0; i < L; i++) {
            bytes16 p = k.pk[i];
            for (uint b = 0; b < 16; b++) {
                buf[uint16(i) * 16 + b] = p[b];
            }
        }
        k.addr = address(uint160(uint256(keccak256(buf))));
    }

    /// @dev Produce a 468-byte blob that verifies against `k.addr` for `digest`.
    ///      Searches `ctr` until the digit checksum of keccak256(r || ctr || digest) == 403.
    function sign(Key memory k, bytes32 digest, bytes32 r)
        internal pure returns (bytes memory blob)
    {
        uint32 ctr;
        bytes32 h;
        bool found;
        for (ctr = 0; ctr < MAX_CTR; ctr++) {
            h = keccak256(abi.encodePacked(r, ctr, digest));
            uint256 sum;
            for (uint8 i = 0; i < L; i++) {
                sum += ((uint256(h) >> (251 - uint16(i) * 5)) & 0x1F);
            }
            if (sum == TARGET_SUM) {
                found = true;
                break;
            }
        }
        require(found, "WotsSigner: no ctr found");

        blob = new bytes(468);

        // chains[i] = walk(sk[i], digit[i] iterations)
        for (uint8 i = 0; i < L; i++) {
            uint8 digit = uint8(((uint256(h) >> (251 - uint16(i) * 5)) & 0x1F));
            bytes16 cur = k.sk[i];
            for (uint32 s = 0; s < digit; s++) {
                cur = chainStep(k.seed, uint32(i), s, cur);
            }
            for (uint b = 0; b < 16; b++) {
                blob[uint16(i) * 16 + b] = cur[b];
            }
        }

        // r at offset 416 (32 bytes)
        for (uint b = 0; b < 32; b++) {
            blob[416 + b] = r[b];
        }
        // ctr at offset 448 (4 bytes, big-endian)
        blob[448] = bytes1(uint8(ctr >> 24));
        blob[449] = bytes1(uint8(ctr >> 16));
        blob[450] = bytes1(uint8(ctr >> 8));
        blob[451] = bytes1(uint8(ctr));
        // seed at offset 452 (16 bytes)
        bytes16 seed = k.seed;
        for (uint b = 0; b < 16; b++) {
            blob[452 + b] = seed[b];
        }
    }
}

contract WotsCVerifierTest is Test {
    WotsCVerifier verifier;
    WotsSigner.Key k;

    function setUp() public {
        verifier = new WotsCVerifier();
        k = WotsSigner.derive(bytes32(uint256(0xC0FFEE)));
    }

    // =========================================================================
    // Core sign/verify round trip
    // =========================================================================

    function test_signAndVerify_happyPath() public {
        bytes32 digest = keccak256("hello world");
        bytes memory blob = WotsSigner.sign(k, digest, bytes32(uint256(0xABCD)));

        assertEq(blob.length, 468);
        assertTrue(verifier.verify(blob, digest, k.addr));
    }

    function test_verify_wrongSigner_fails() public {
        bytes32 digest = keccak256("hello world");
        bytes memory blob = WotsSigner.sign(k, digest, bytes32(uint256(0xABCD)));

        assertFalse(verifier.verify(blob, digest, makeAddr("notOwner")));
    }

    function test_verify_wrongDigest_fails() public {
        bytes32 digest = keccak256("hello world");
        bytes memory blob = WotsSigner.sign(k, digest, bytes32(uint256(0xABCD)));

        assertFalse(verifier.verify(blob, keccak256("different message"), k.addr));
    }

    function test_verify_tamperedBlob_fails() public {
        bytes32 digest = keccak256("hello world");
        bytes memory blob = WotsSigner.sign(k, digest, bytes32(uint256(0xABCD)));

        // Flip one bit in the chain portion
        blob[10] ^= bytes1(uint8(0x01));
        assertFalse(verifier.verify(blob, digest, k.addr));
    }

    function test_verify_wrongBlobLength_fails() public {
        bytes memory tooShort = new bytes(467);
        bytes memory tooLong = new bytes(469);
        assertFalse(verifier.verify(tooShort, bytes32(0), k.addr));
        assertFalse(verifier.verify(tooLong, bytes32(0), k.addr));
    }

    function test_verify_multipleSignaturesSameKey() public {
        // Same key can sign different messages (WOTS+ math doesn't prevent reuse;
        // one-time-use is enforced at the account layer, not the verifier).
        bytes32 d1 = keccak256("msg-1");
        bytes32 d2 = keccak256("msg-2");

        bytes memory b1 = WotsSigner.sign(k, d1, bytes32(uint256(1)));
        bytes memory b2 = WotsSigner.sign(k, d2, bytes32(uint256(2)));

        assertTrue(verifier.verify(b1, d1, k.addr));
        assertTrue(verifier.verify(b2, d2, k.addr));
    }

    function test_derive_deterministic() public pure {
        WotsSigner.Key memory a = WotsSigner.derive(bytes32(uint256(42)));
        WotsSigner.Key memory b = WotsSigner.derive(bytes32(uint256(42)));
        assertEq(a.addr, b.addr);
    }

    function test_derive_differentMaterialDifferentKey() public pure {
        WotsSigner.Key memory a = WotsSigner.derive(bytes32(uint256(1)));
        WotsSigner.Key memory b = WotsSigner.derive(bytes32(uint256(2)));
        assertTrue(a.addr != b.addr);
    }

    // =========================================================================
    // End-to-end: real WotsCVerifier + real SimpleAccount_WOTS + real signer
    // =========================================================================

    function test_endToEnd_accountValidatesAndRotates() public {
        address ENTRYPOINT = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;
        vm.etch(ENTRYPOINT, hex"00");

        // Deploy a real factory + account owned by our WOTS-derived address.
        SimpleAccountFactory factory = new SimpleAccountFactory(
            IEntryPoint(ENTRYPOINT),
            IWotsCVerifier(address(verifier))
        );
        address accountAddr = factory.createAccount(k.addr, 0, 1);
        SimpleAccount_WOTS account = SimpleAccount_WOTS(payable(accountAddr));

        address nextOwner = makeAddr("wotsNext");
        address recipient = makeAddr("recipient");

        // callData = execute(recipient, 0, "") || bytes20(nextOwner)
        bytes memory callData = abi.encodePacked(
            abi.encodeWithSelector(account.execute.selector, recipient, uint256(0), bytes("")),
            bytes20(nextOwner)
        );

        bytes32 userOpHash = keccak256("real-op");
        bytes memory sig = WotsSigner.sign(k, userOpHash, bytes32(uint256(0xDEADBEEF)));

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: accountAddr,
            nonce: 0,
            initCode: "",
            callData: callData,
            accountGasLimits: bytes32(0),
            preVerificationGas: 0,
            gasFees: bytes32(0),
            paymasterAndData: "",
            signature: sig
        });

        vm.prank(ENTRYPOINT);
        uint256 validationData = account.validateUserOp(userOp, userOpHash, 0);

        assertEq(validationData, 0);                 // signature accepted
        assertEq(account.owner(), nextOwner);        // rotation happened
    }

    function test_endToEnd_wrongKeyRejected() public {
        address ENTRYPOINT = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;
        vm.etch(ENTRYPOINT, hex"00");

        SimpleAccountFactory factory = new SimpleAccountFactory(
            IEntryPoint(ENTRYPOINT),
            IWotsCVerifier(address(verifier))
        );
        address accountAddr = factory.createAccount(k.addr, 0, 1);
        SimpleAccount_WOTS account = SimpleAccount_WOTS(payable(accountAddr));

        // Sign with a DIFFERENT key — verifier should reject.
        WotsSigner.Key memory other = WotsSigner.derive(bytes32(uint256(0xBADBAD)));

        bytes memory callData = abi.encodePacked(
            abi.encodeWithSelector(account.execute.selector, address(0), uint256(0), bytes("")),
            bytes20(makeAddr("next"))
        );
        bytes32 userOpHash = keccak256("real-op");
        bytes memory sig = WotsSigner.sign(other, userOpHash, bytes32(uint256(1)));

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: accountAddr,
            nonce: 0,
            initCode: "",
            callData: callData,
            accountGasLimits: bytes32(0),
            preVerificationGas: 0,
            gasFees: bytes32(0),
            paymasterAndData: "",
            signature: sig
        });

        vm.prank(ENTRYPOINT);
        uint256 validationData = account.validateUserOp(userOp, userOpHash, 0);

        assertEq(validationData, 1);            // rejected
        assertEq(account.owner(), k.addr);      // no rotation
    }
}

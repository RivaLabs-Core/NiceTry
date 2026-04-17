// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/SimpleAccount_WOTS.sol";
import "../src/SimpleAccountFactory.sol";
import {IWotsCVerifier} from "../src/Interfaces/IWotsCVerifier.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";

// Pull parameters from the verifier so the signer stays in sync automatically.
import {
    WotsCVerifier,
    WOTS_L,
    WOTS_N,
    WOTS_W_BITS,
    WOTS_W_MAX,
    WOTS_W_MASK,
    WOTS_TARGET_SUM,
    WOTS_BLOB_LEN,
    WOTS_SIG_DATA,
    WOTS_R_OFFSET,
    WOTS_CTR_OFFSET,
    WOTS_SEED_OFFSET,
    WOTS_DIGIT_SHIFT_0
} from "../src/WotsCVerifier.sol";

/// @dev Test-only WOTS+C key derivation and signer. Replicates the on-chain
///      WotsCVerifier algorithm using the same parameter set, imported from
///      src/WotsCVerifier.sol so changes propagate automatically.
///
///      NOTE: this signer's bytes16 typing assumes WOTS_N == 16. If you change
///      WOTS_N, you'll also need to adjust these types — Solidity's bytesN
///      can't be parameterized by a constant.
///
///      Not production code:
///      - Secret keys are derived from caller-supplied material via keccak (no PRF).
///      - Counter search is a plain loop; cap is ~MAX_CTR iterations.
library WotsSigner {
    uint32 constant MAX_CTR = 1_000_000;

    struct Key {
        bytes16[WOTS_L] sk;    // private chain starts
        bytes16         seed;  // public chain salt
        bytes16[WOTS_L] pk;    // public chain ends (pos W_MAX)
        address         addr;  // low 20 bytes of keccak256(pk[0]||..||pk[L-1])
    }

    /// @dev One chain hash step. Matches WotsCVerifier inline assembly bit-for-bit:
    ///      keccak256(seed(N) || i_u32(4) || s_u32(4) || cur_topN(N)) truncated to N bytes.
    function chainStep(bytes16 seed, uint32 i, uint32 s, bytes16 cur)
        internal pure returns (bytes16)
    {
        return bytes16(keccak256(abi.encodePacked(seed, i, s, cur)));
    }

    /// @dev Extract the i-th 5-bit (or W_BITS-bit) digit from a 256-bit word.
    function _digit(bytes32 h, uint256 i) private pure returns (uint256) {
        return (uint256(h) >> (WOTS_DIGIT_SHIFT_0 - i * WOTS_W_BITS)) & WOTS_W_MASK;
    }

    /// @dev Derive a deterministic Key from `material`.
    function derive(bytes32 material) internal pure returns (Key memory k) {
        for (uint256 i = 0; i < WOTS_L; i++) {
            k.sk[i] = bytes16(keccak256(abi.encodePacked(material, "sk", i)));
        }
        k.seed = bytes16(keccak256(abi.encodePacked(material, "seed")));

        // pk[i] = walk(sk[i]) for W_MAX hash iterations (s = 0..W_MAX-1)
        for (uint256 i = 0; i < WOTS_L; i++) {
            bytes16 cur = k.sk[i];
            for (uint32 s = 0; s < WOTS_W_MAX; s++) {
                cur = chainStep(k.seed, uint32(i), s, cur);
            }
            k.pk[i] = cur;
        }

        // pkHash = keccak256(pk[0] || ... || pk[L-1]) — each N bytes, SIG_DATA total.
        bytes memory buf = new bytes(WOTS_SIG_DATA);
        for (uint256 i = 0; i < WOTS_L; i++) {
            bytes16 p = k.pk[i];
            for (uint256 b = 0; b < WOTS_N; b++) {
                buf[i * WOTS_N + b] = p[b];
            }
        }
        k.addr = address(uint160(uint256(keccak256(buf))));
    }

    /// @dev Produce a BLOB_LEN-byte blob that verifies against `k.addr` for `digest`.
    ///      Searches `ctr` until the digit checksum of keccak256(r || ctr || digest) == TARGET_SUM.
    function sign(Key memory k, bytes32 digest, bytes32 r)
        internal pure returns (bytes memory blob)
    {
        uint32 ctr;
        bytes32 h;
        bool found;
        for (ctr = 0; ctr < MAX_CTR; ctr++) {
            h = keccak256(abi.encodePacked(r, ctr, digest));
            uint256 sum;
            for (uint256 i = 0; i < WOTS_L; i++) {
                sum += _digit(h, i);
            }
            if (sum == WOTS_TARGET_SUM) {
                found = true;
                break;
            }
        }
        require(found, "WotsSigner: no ctr found");

        blob = new bytes(WOTS_BLOB_LEN);

        // chains[i] = walk(sk[i], digit[i] iterations)
        for (uint256 i = 0; i < WOTS_L; i++) {
            uint32 digit = uint32(_digit(h, i));
            bytes16 cur = k.sk[i];
            for (uint32 s = 0; s < digit; s++) {
                cur = chainStep(k.seed, uint32(i), s, cur);
            }
            for (uint256 b = 0; b < WOTS_N; b++) {
                blob[i * WOTS_N + b] = cur[b];
            }
        }

        // r at R_OFFSET (32 bytes)
        for (uint256 b = 0; b < 32; b++) {
            blob[WOTS_R_OFFSET + b] = r[b];
        }
        // ctr at CTR_OFFSET (4 bytes, big-endian)
        blob[WOTS_CTR_OFFSET    ] = bytes1(uint8(ctr >> 24));
        blob[WOTS_CTR_OFFSET + 1] = bytes1(uint8(ctr >> 16));
        blob[WOTS_CTR_OFFSET + 2] = bytes1(uint8(ctr >> 8));
        blob[WOTS_CTR_OFFSET + 3] = bytes1(uint8(ctr));
        // seed at SEED_OFFSET (N bytes)
        bytes16 seed = k.seed;
        for (uint256 b = 0; b < WOTS_N; b++) {
            blob[WOTS_SEED_OFFSET + b] = seed[b];
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

        assertEq(blob.length, WOTS_BLOB_LEN);
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
    // Gas measurement
    // =========================================================================

    /// @dev Measures gas of the `verify` external call. Gas varies slightly with
    ///      the signature's digit values (chain-walk lengths = 31 - digit[i]).
    ///      Logs an average across several signatures for a stable figure.
    function test_gas_verify_average() public view {
        uint256 N = 5;
        uint256 totalGas;

        for (uint256 i = 0; i < N; i++) {
            bytes32 digest = keccak256(abi.encode("gas", i));
            bytes memory blob = WotsSigner.sign(k, digest, bytes32(i));

            uint256 before = gasleft();
            bool ok = verifier.verify(blob, digest, k.addr);
            uint256 used = before - gasleft();

            require(ok, "gas: verify returned false");
            totalGas += used;
        }

        uint256 avg = totalGas / N;
        console.log("WotsCVerifier.verify avg gas (N=5):", avg);
    }

    /// @dev Single-shot measurement for a deterministic signature (useful as a
    ///      regression guard if you want an upper bound). The checksum search
    ///      picks different ctr values in different runs, so the exact number
    ///      shifts; we just log it.
    function test_gas_verify_oneShot() public view {
        bytes32 digest = keccak256("gas-one-shot");
        bytes memory blob = WotsSigner.sign(k, digest, bytes32(uint256(0xFEED)));

        uint256 before = gasleft();
        bool ok = verifier.verify(blob, digest, k.addr);
        uint256 used = before - gasleft();

        require(ok, "gas: verify returned false");
        console.log("WotsCVerifier.verify one-shot gas:", used);
    }

    /// @dev End-to-end validateUserOp gas (verifier + account rotation + event).
    function test_gas_validateUserOp() public {
        address ENTRYPOINT = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;
        vm.etch(ENTRYPOINT, hex"00");

        SimpleAccountFactory factory = new SimpleAccountFactory(
            IEntryPoint(ENTRYPOINT),
            IWotsCVerifier(address(verifier))
        );
        address accountAddr = factory.createAccount(k.addr, 0, 1);
        SimpleAccount_WOTS account = SimpleAccount_WOTS(payable(accountAddr));

        bytes memory callData = abi.encodePacked(
            abi.encodeWithSelector(account.execute.selector, address(0), uint256(0), bytes("")),
            bytes20(makeAddr("next"))
        );
        bytes32 userOpHash = keccak256("gas-uop");
        bytes memory sig = WotsSigner.sign(k, userOpHash, bytes32(uint256(0x9999)));

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
        uint256 before = gasleft();
        uint256 validationData = account.validateUserOp(userOp, userOpHash, 0);
        uint256 used = before - gasleft();

        require(validationData == 0, "gas: validateUserOp failed");
        console.log("SimpleAccount_WOTS.validateUserOp gas:", used);
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

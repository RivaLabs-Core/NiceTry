# NiceTry

Reference Solidity implementation of the NiceTry ephemeral-key smart wallet design.

> [!NOTE]
> This repo contains contracts only. For the protocol specification see [NiceTry-Spec](https://github.com/RivaLabs-Core/ephemeral-keys). For a project overview, see [docs.nicetry.xyz](https://docs.nicetry.xyz/).

## What this repo contains

ERC-4337 smart accounts that rotate the authorizing key on every UserOp. Three
primary-signer schemes are supported, all sharing the same one-shot-rotation
discipline:

| Mode | Scheme | Signature | Verify gas |
|---|---|---|---|
| 0 | ECDSA (secp256k1) | 65 B | ~5k |
| 1 | WOTS+C | 468 B | ~73k |
| 2 | FORS+C | 2,448 B | ~52k |

Modes 1 and 2 are post-quantum: WOTS+C is a Winternitz one-time signature with
checksum, FORS+C is a Forest of Random Subsets few-time signature. Both use
the SPHINCS+ FIPS 205 ADRS layout.

A single factory (`SimpleAccountFactory`) deploys the right account variant
based on a `mode` parameter. ECDSA is the baseline; WOTS+C and FORS+C are the
post-quantum extensions of the same ephemeral-key idea.

For modular accounts (no rebuild required), three separate ERC-7579 validators
under `src/Modules/`:

- **`RotatingECDSAValidator`**: Biconomy Nexus / canonical ERC-7579.
- **`KernelRotatingECDSAValidator`**: ZeroDev Kernel v3.1.
- **`KernelRotatingWOTSValidator`**: ZeroDev Kernel v3.1, post-quantum.

Bundled vs. composable: pick the factory + a mode for a self-contained
deployment, pick a validator module to extend an existing modular account.

## Contract layout

```
src/
├── SimpleAccountFactory.sol             multi-mode CREATE2 factory
├── SimpleAccounts/
│   ├── SimpleAccount_ECDSA.sol          mode 0: ECDSA primary signer
│   ├── SimpleAccount_WOTS.sol           mode 1: WOTS+C primary signer
│   └── SimpleAccount_FORS.sol           mode 2: FORS+C primary signer
├── Verifiers/
│   ├── WotsCVerifier.sol                post-quantum verifier (mode 1)
│   └── ForsVerifier.sol                 post-quantum verifier (mode 2)
├── Interfaces/
│   ├── IWotsCVerifier.sol
│   └── IForsVerifier.sol
├── Modules/
│   ├── RotatingECDSAValidator.sol       ERC-7579 (Nexus-family)
│   ├── KernelRotatingECDSAValidator.sol ZeroDev Kernel v3.1
│   ├── KernelRotatingWOTSValidator.sol  ZeroDev Kernel v3.1, post-quantum
│   ├── IERC7579.sol  IKernelValidator.sol
│   └── MockKernelAccount.sol  MockNexusAccount.sol  (test mocks)
└── Utility/
    └── token.sol                        TestToken (dummy ERC20 for testing)
```

## Parameters

Parameters for the post-quantum schemes are still in a tuning phase. None of
the current choices are definitive, and we expect to revisit them as the
design and tooling mature.

**WOTS+C** (`src/Verifiers/WotsCVerifier.sol`): W=32 (5-bit Winternitz),
L=26 chains, N=16, target sum = L·(W−1)/2 = 403. Signature 468 bytes.

**FORS+C** (`src/Verifiers/ForsVerifier.sol`): K=26 trees, A=5 (32 leaves
each), N=16. Signature 2,448 bytes. q-degradation: q=1 = 128 bits (NIST
Level 1), q=2 = 104, q=5 = 70. Signer keygen ~2.4k keccak (interactive on
hardware wallets).

To retune either scheme, edit the primary parameters at the top of the
verifier file. All derived constants (signature layout, hash inputs, loop
bounds, masks) recompute automatically. See the relevant verifier file's
header comment for the trade-off table.

## Build and test

```bash
forge install
forge build
forge test
```

180 tests across 12 suites. Coverage includes:
- Round-trip cryptographic tests for both post-quantum verifiers using
  in-Solidity signer libraries (`test/{Wots,Fors}CVerifier.t.sol`).
- Account-side mock-based tests for all three signer modes.
- ZeroDev Kernel + Biconomy Nexus integration tests for the validator modules.
- Gas-measurement tests for verifiers and deployment costs.

## Deploy

A deploy script lives at `script/Deploy.s.sol`. Running it deploys two
verifiers (`WotsCVerifier`, `ForsVerifier`), three account implementations
(one per mode, deployed by the factory's constructor), and the factory
itself. The script targets the canonical ERC-4337 EntryPoint v0.7, which
lives at the same address on mainnet, Sepolia, and other rollups.

## Related repos

- [NiceTry-Spec](https://github.com/RivaLabs-Core/ephemeral-keys): protocol specification and design rationale
- [NiceTry-Wallet](https://github.com/RivaLabs-Core/NiceTry-Wallet): standalone wallet demo with local key management
- [NiceTry-Metamask](https://github.com/RivaLabs-Core/NiceTry-Metamask): MetaMask integration demo

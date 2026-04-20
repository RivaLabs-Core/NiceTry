# NiceTry

Reference Solidity implementation of the NiceTry ephemeral-key smart wallet design.

> [!NOTE]
> This repo contains contracts only. For the protocol specification see [NiceTry-Spec](https://github.com/RivaLabs-Core/ephemeral-keys). For a project overview, see [docs.nicetry.xyz](https://docs.nicetry.xyz/).

## What this repo contains

Two signing modes and a set of integrations.

**Signing modes**

- **ECDSA** — single-use ECDSA keypairs rotated on every transaction. Quantum-safe in the short term by eliminating long-term public key exposure. Works today on any EVM chain with no new precompiles.
- **WOTS+C** — Winternitz One-Time Signatures with checksum, verified onchain. Quantum-safe under standard hash assumptions. Larger signatures, higher gas, but post-quantum secure without relying on key rotation alone.

**Integrations**

- **`SimpleAccount_ECDSA` / `SimpleAccount_WOTS`** — standalone ERC-4337 smart accounts. Each user deploys their own instance. Validation, execution, and key rotation live in the same contract with no external dependencies beyond the EntryPoint.
- **`RotatingECDSAValidator`** — an ERC-7579 validator module. A single deployed module serves any number of ERC-7579 compliant accounts (Biconomy Nexus and equivalents), each with independent key state. Use this when you already have a modular account and want to add rotation without redeploying.

Bundled vs. composable: pick a `SimpleAccount` variant for a self-contained deployment, pick the validator module to extend an existing modular account.

## Contract layout

```
src/
├── SimpleAccount_ECDSA.sol       ERC-4337 account with ECDSA rotation
├── SimpleAccount_WOTS.sol        ERC-4337 account with WOTS+C signatures
├── SimpleAccountFactory.sol      CREATE2 factory for SimpleAccount variants
├── WotsCVerifier.sol             Onchain WOTS+C signature verifier
├── Interfaces/
│   └── IWotsCVerifier.sol        Verifier interface
└── Module/
    └── RotatingECDSAValidator.sol    ERC-7579 validator module for ECDSA rotation
```
## WOTS+C gas costs

Gas consumption of the onchain WOTS+C verifier across Winternitz parameter `W` (with corresponding chain length `L`). Measured on the reference implementation.

| W | L | NIST level | Signature size | `verify` avg | `validateUserOp` end-to-end |
|---:|---:|:---:|---:|---:|---:|
| 4 | 64 | 1 | 1,076 B | ~43K | ~49K |
| 8 | 44 | 1 | 756 B | ~43K | ~50K |
| 16 | 32 | 1 | 564 B | ~50K | ~57K |
| 32 | 26 | 1 | 468 B | ~71K | ~78K |
| 64 | 22 | 1 | 404 B | ~112K | ~118K |
| 128 | 20 | 1 | 372 B | ~194K | ~200K |
| 256 | 16 | 1 | 308 B | ~309K | ~315K |

Higher `W` reduces signature size but increases verification cost. `W=32` is a reasonable default balance; `W=4` or `W=8` minimize gas when signature size is not the binding constraint. When evaluating the implementation, factor in signing latency on constrained hardware signers: key generation and signing both require L hash chains of average length W/2, so signer compute scales approximately with W × L hash evaluations.

## Build and test

```bash
forge install
forge build
forge test
```

## Deploy

Deployment script at `script/Deploy.s.sol`. Network configuration in `foundry.toml`.

```bash
forge script script/Deploy.s.sol --rpc-url <rpc> --broadcast
```

## Deployed addresses

| Network | Contract | Address |
|---|---|---|
| Sepolia | `SimpleAccountFactory` | `0x338fbbde8bacf9576cc435fd7496128ccc534d81` |

## Related repos

- [NiceTry-Spec](https://github.com/RivaLabs-Core/ephemeral-keys) — protocol specification and design rationale
- [NiceTry-Wallet](https://github.com/RivaLabs-Core/NiceTry-Wallet) — standalone wallet demo with local key management
- [NiceTry-Metamask](https://github.com/RivaLabs-Core/NiceTry-Metamask) — MetaMask integration demo

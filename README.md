# NiceTry

Reference Solidity implementation of the NiceTry ephemeral-key smart wallet design.

> [!NOTE]
> This repo contains contracts only. For the protocol specification see [NiceTry-Spec](https://github.com/RivaLabs-Core/ephemeral-keys). For a project overview, see [docs.nicetry.xyz](https://docs.nicetry.xyz/).

## What this repo contains

Two Solidity implementations of the ECDSA ephemeral-key mode:

- **`SimpleAccount`** — a standalone ERC-4337 smart account with rotation baked into the account contract. Each user deploys their own instance. Validation, execution, and key rotation live in the same contract with no external dependencies beyond the EntryPoint.

- **`RotatingECDSAValidator`** — an ERC-7579 validator module. A single deployed module serves any number of ERC-7579 compliant accounts, each with independent key state. Use this when you already have a modular account and want to add rotation without redeploying.

Bundled vs. composable: pick `SimpleAccount` for a self-contained deployment, pick the validator module to extend an existing modular account.

## Contract layout

```
src/
├── SimpleAccount.sol          ERC-4337 account with rotation
├── SimpleAccountFactory.sol   CREATE2 factory for SimpleAccount
└── Module/
    └── RotatingECDSAValidator.sol   ERC-7579 validator module
```

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

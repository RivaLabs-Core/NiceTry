# Ephemeral Keys with WOTS+C and Multi-Wallet Support - Design Notes

## The problem

A WOTS+C wallet rotates signing keys after each use. If two wallets share the same seed and derivation path, they generate identical key sequences. Any independent advancement of the epoch counter on either wallet risks reusing the same one-time key, which breaks the scheme entirely.

## The solution

Each wallet needs a key stream that is unique, deterministic on that wallet, and non-reconstructible anywhere else. To do this, a wallet-unique salt can be added to the mnemonic, generating a unique key stream. This wallet salt must be unique per-wallet, that's the only hard requisite for this salt.

A user will have access to a set of signers, one for each wallet in his possession, each coming from a separate key stream. Each key is associated with an authorized signer on the smart contract wallet, making each wallet capable of signing transactions on the same smart contract wallet with their unique signer.

## How it works

From a single mnemonic, the design supports two derivation paths:

- **Mnemonic-only path.** Derives the recovery key directly from the mnemonic to be used with a post-quantum signature scheme (e.g. SPHINCS+). Accessible from any wallet, fully recoverable from the mnemonic alone. The recovery key has full signing authority over the wallet, but existing PQ signature schemes make verification very expensive. This path is intended for recovery scenarios only, including a compromised wallet, lost wallet, or key exhaustion.
- **Wallet-bound path.** Derives from mnemonic + wallet_salt. Produces a derivation path unique to this specific wallet, from which the WOTS+C ephemeral signers are generated. These are the keys used for day-to-day transaction signing. Signatures are orders of magnitude cheaper to verify. This path is not recoverable from the mnemonic alone: the salt must also be available.

## Components

- **Standard mnemonic.** Generated using a generic format (BIP-39 or equivalent). The root secret from which everything else derives.
- **Recovery key.** Derived from the mnemonic only. Post-quantum scheme (e.g. SPHINCS+). Full signing authority, but high verification cost makes it impractical for regular use.
- **Salt.** A value unique to each wallet that shares the same mnemonic. Must be persisted alongside the wallet (implementation is flexible, e.g. hash of a timestamp, as long as uniqueness is guaranteed). Loss of the salt means the WOTS+C signer tree cannot be re-derived, requiring recovery via the mnemonic-only path.
- **WOTS+C signers.** Ephemeral, single-use signers derived from the mnemonic plus the salt. The gas-efficient path for standard transaction signing. The smart contract accepts both WOTS+C and SPHINCS+ signatures, but economic incentive keeps users here.

From a UX perspective, the system explicitly selects which mode to enter (standard or recovery). The interaction pattern is similar to the passphrase-based hidden wallet on Ledger and Trezor, though the underlying model is different: both paths here operate on the same account, with the contract enforcing distinct key types rather than separate account sets.

## Onchain contract side

The contract doesn't need to know anything about the derivation scheme. Each wallet maps to a signer mapping element holding a commitment of the wallet's current signer's private key. When onboarding a new wallet, an existing authorized signer calls addSigner with the new wallet's first WOTS+C public key hash. This can be done either with an already authorized wallet or, for a simpler UX, with the signer associated with the stateless PQ recovery (derived from the mnemonic-only path) on the new wallet.

Once added, each wallet advances its own local index counter independently, and no index is stored onchain.

## Recovery

If a user loses access to his wallet, he can fully recover access to his funds by knowing the mnemonic.

In the case the lost wallet was the only authorized signer, the address associated with the stateless PQ recovery (derived from the mnemonic-only path) can be used to rotate the signer to a new wallet's first signer.

In case the lost wallet was one of many authorized signers, any of the other signers can sign a transaction to rotate the lost one, or removeSigner can be called to revoke signing rights to the lost wallet. A substitute can then be initialized later calling addSigner with any of the authorized signers.

Full backup requirements: the mnemonic.

## A potential mechanism for salt management: BIP39 passphrase as a wallet binding layer

BIP39 defines an optional passphrase that can be mixed into seed derivation alongside the mnemonic, producing a completely different derivation path with every different passphrase, enabling the same wallet to hold multiple derivation paths starting from the same mnemonic.

In this use case, rather than a user-typed passphrase, each wallet computes its own deterministically from a unique identifier.

This wallet-specific passphrase is fed into BIP39's PBKDF2 in place of a normal, user chosen, passphrase. Even with the same mnemonic on two separate wallets, with a different wallet-specific passphrase the derivation path is completely different, with no overlap in WOTS+C key streams and no cross-wallet coordination needed.

The wallet-specific passphrase does not need to be secret, since security still rests entirely on the mnemonic, the only requirement is that it be unique to the wallet. Mnemonic + wallet-specific passphrase identifier fully determines the key stream.

## References

- BIP39 spec: github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
- BIP32 spec: github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
- Ledger passphrase: support.ledger.com/article/115005214529-zd
- Trezor hidden wallet: trezor.io/learn/a/passphrases-and-hidden-wallets
# NiceTry FORS Verity Work

This directory contains the first Lean model for the NiceTry standalone FORS+C
verifier.

The initial boundary is intentionally narrow:

- model the typed FORS+C recovery algorithm from `docs/signing-spec.md`,
- prove deterministic structural facts about that model,
- keep cryptographic hash behavior opaque,
- fix the raw 2448-byte signature layout used by calldata parsing,
- compile guarded Verity kernels to Yul.

This does not yet prove the optimized Solidity verifier in
`src/Verifiers/ForsVerifier.sol`. The intended bridge is either:

1. deploy a future Verity-generated verifier artifact, or
2. prove equivalence between the optimized Solidity verifier and a clean
   reference implementation.

## Current Files

- `NiceTry/Fors/Types.lean`: constants and typed signature structures.
- `NiceTry/Fors/Hash.lean`: opaque hash/address primitives.
- `NiceTry/Fors/Model.lean`: typed recovery model and raw-signature parser.
- `NiceTry/Fors/TreeShape.lean`: executable one-tree shape model with
  arithmetic hash stand-ins.
- `NiceTry/Fors/TreeKeccak.lean`: one-tree model at the concrete EVM
  memory-transcript/opaque-Keccak boundary.
- `NiceTry/Fors/FullKeccak.lean`: typed full-verifier model covering Hmsg,
  forced-zero, 25 tree roots, roots compression, and address derivation.
- `NiceTry/Fors/RawKeccak.lean`: raw 2448-byte signature parser bridge into
  the full Keccak-boundary verifier model.
- `NiceTry/Fors/Spec.lean`: property definitions for the model.
- `NiceTry/Fors/Proofs/Basic.lean`: first structural proofs.
- `NiceTry/Fors/Proofs/TreeShape.lean`: path-order and ADRS arithmetic proofs
  for the one-tree shape model.
- `NiceTry/Fors/Proofs/TreeKeccak.lean`: memory-write and hash-range proofs
  for the one-tree Keccak transcript model.
- `NiceTry/Fors/Proofs/FullKeccak.lean`: structural proofs for the typed
  full-verifier transcript model.
- `NiceTry/Fors/Proofs/RawKeccak.lean`: raw parser offset and typed-bridge
  proofs for the full verifier model.
- `NiceTry/Fors/Verity/GuardKernel.lean`: first `verity_contract` layer for
  layout constants and the forced-zero guard.
- `NiceTry/Fors/Verity/TreeShapeKernel.lean`: one-tree Verity kernel for index
  extraction, ADRS arithmetic, sibling ordering, and the fixed A=5 climb.
- `NiceTry/Fors/Verity/TreeKeccakKernel.lean`: one-tree Verity kernel whose
  generated Yul uses the FORS leaf/node `mstore` + `keccak256` transcripts.
- `NiceTry/Fors/Verity/FullVerifierKernel.lean`: typed full-verifier Verity
  kernel over a 150-word opening array, plus an ABI-compatible
  `recover(bytes,bytes32)` parser entrypoint.
- `artifacts/fors-guard-kernel/ForsGuardKernel.yul`: generated Yul for that
  guard kernel.
- `artifacts/fors-tree-shape-kernel/ForsTreeShapeKernel.yul`: generated Yul
  for the one-tree shape kernel.
- `artifacts/fors-tree-keccak-kernel/ForsTreeKeccakKernel.yul`: generated Yul
  for the one-tree Keccak transcript kernel.
- `artifacts/fors-full-verifier-kernel/ForsFullVerifierKernel.yul`: generated
  Yul for the typed/raw full-verifier kernel, including
  `recover(bytes,bytes32)`.
- `artifacts/fors-full-verifier-kernel/ForsFullVerifierKernel.solc.json`: Solc
  artifact for the generated full-verifier Yul, used by the Forge parity test
  because Foundry does not compile this Yul artifact as part of the normal
  Solidity test build.
- `../test/VerityForsFullVerifier.t.sol`: concrete parity test that deploys the
  Solc artifact, runs `recover(bytes,bytes32)` on the Python-generated FORS
  vector, checks bad-length rejection, and pins the generated Yul source hash.

## Proof Boundary

The current Lean layer can prove facts such as:

- `K - 1 = 25`, `TREE_LEN = 96`, `SIG_LEN = 2448`,
- extracted FORS indices are always below `2^A`,
- non-`SIG_LEN` raw inputs are rejected,
- raw fields are read at the offsets from the signing spec,
- raw parser offsets cover `R`, `pkSeed`, `counter`, and all 150 FORS opening
  words up to the counter boundary,
- typed recovery can return an address only when the forced-zero condition holds,
- a signature whose openings reconstruct an expected `pkRoot` recovers
  `addr(pkSeed, pkRoot)`,
- when forced-zero holds, typed recovery returns the address derived from the
  modeled root compression.

It does not prove:

- Keccak security,
- FORS unforgeability,
- q-signature security bounds,
- equivalence to the existing inline assembly implementation,
- correctness of an off-chain signer.

## Build

```bash
lake update
lake build NiceTry
lake exe verity-compiler \
  --module NiceTry.Fors.Verity.GuardKernel \
  --output artifacts/fors-guard-kernel
lake exe verity-compiler \
  --module NiceTry.Fors.Verity.TreeShapeKernel \
  --output artifacts/fors-tree-shape-kernel
lake exe verity-compiler \
  --module NiceTry.Fors.Verity.TreeKeccakKernel \
  --output artifacts/fors-tree-keccak-kernel
lake exe verity-compiler \
  --module NiceTry.Fors.Verity.FullVerifierKernel \
  --output artifacts/fors-full-verifier-kernel
```

The concrete generated-artifact parity test is run from the repository root:

```bash
forge test --match-contract VerityForsFullVerifierTest -vvv
```

If the Yul is regenerated, refresh
`artifacts/fors-full-verifier-kernel/ForsFullVerifierKernel.solc.json` from a
Solc/Foundry compile of that Yul source and update the pinned source hash in
the Forge test. The current local Foundry nightly emits the Yul artifact JSON
successfully but then reports a Solar lint error on strict-Yul `object "Name"`
syntax.

On this Windows machine, `evmyul` required a local dependency-cache adjustment
to use LLVM clang instead of a hardcoded `cc` command and to omit the Unix-only
`-fPIC` flag. The tracked Lean/Yul sources do not depend on that cache patch,
but regenerating artifacts on Windows may need the same toolchain fix.

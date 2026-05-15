# Formally Checked FORS+C Recovery Kernel

This directory contains the Lean and Verity work for a standalone FORS+C
verifier.

The public claim is intentionally narrow:

- the typed model reconstructs the same FORS public root from `R`, `pkSeed`,
  `digest`, `counter`, and 25 explicit FORS openings;
- the raw-signature model fixes the 2448-byte calldata layout used by
  `recover(bytes,bytes32)`;
- non-2448-byte raw signatures are rejected;
- a signature can recover a non-zero signer only when the omitted FORS tree
  index is forced to zero;
- when a legitimate signature reconstructs an expected `pkRoot`, recovery
  returns the address derived from `pkSeed || pkRoot`;
- the generated Verity full-verifier Yul artifact has a concrete Foundry replay
  test against the Python-generated reference vector.

This is not a claim that the optimized Solidity verifier has been formally
proved equivalent to the Lean/Verity model. That equivalence is still outside
the current proof boundary.

## What Is Covered

This work covers the FORS+C recovery rule, not the whole production verifier.

Covered by Lean proofs:

- Constants and layout: `K = 26`, `RealTrees = 25`, `TREE_LEN = 96`,
  `OpeningWords = 150`, and `SIG_LEN = 2448`.
- Raw signature decoding: the model reads `R`, `pkSeed`, 25 opening sections,
  and `counter` from the fixed byte offsets used by `recover(bytes,bytes32)`.
- Length rejection: any raw signature whose length is not exactly `2448`
  decodes to `none` and cannot recover an address.
- FORS index bounds: each extracted FORS index is below `2^A`, with `A = 5`.
- Path shape: one-tree reconstruction uses the modeled leaf index, sibling
  ordering, tree height, tree scale, and ADRS arithmetic.
- Forced-zero guard: successful typed recovery requires the omitted-tree index
  derived from Hmsg to be zero.
- Legitimate-signature theorem: if the modeled signature reconstructs an
  expected `pkRoot`, then recovery returns the address derived from
  `pkSeed || pkRoot`.
- Raw-to-typed bridge: if a raw 2448-byte signature decodes to a typed
  signature satisfying the legitimacy predicate, raw recovery returns the same
  expected address.
- Transcript shape: the model records the intended memory inputs for Hmsg,
  leaf hashing, node hashing, roots compression, and address derivation at the
  opaque Keccak boundary.

Covered by generated Verity artifacts:

- A guard kernel for constants and forced-zero checking.
- A one-tree shape kernel for index extraction, path climb, and ADRS arithmetic.
- A one-tree Keccak-transcript kernel that emits Yul with the expected
  `mstore` and `keccak256` calls for leaf and node hashing.
- A full verifier kernel that emits Yul for typed recovery and for the
  ABI-compatible `recover(bytes,bytes32)` raw parser.

Covered by Foundry replay tests:

- The optimized Solidity verifier recovers the expected address for the
  Python-generated FORS+C vector.
- The generated Verity full-verifier Yul artifact, compiled to EVM bytecode,
  recovers the same expected address for the same vector.
- The generated Verity artifact returns `address(0)` for a bad-length
  signature.
- The replay test pins the Yul source hash so the compiled artifact cannot
  silently drift from the generated source.

## What Is Not Covered

This work does not prove cryptographic security.

Not covered:

- No proof of Keccak correctness, collision resistance, preimage resistance, or
  random-oracle behavior.
- No proof of FORS unforgeability.
- No proof of q-signature security bounds.
- No proof that the Python signer constructs all authentication paths
  correctly; it is only a reference implementation exercised by tests.
- No proof that the optimized inline-assembly Solidity verifier is equivalent
  to the Lean model or to the generated Verity Yul artifact.
- No proof that deployed production bytecode is byte-for-byte equivalent to the
  generated Verity artifact.
- No complete formal ABI refinement proof for `recover(bytes,bytes32)`;
  calldata parsing still has Verity `local_obligations`.
- No complete formal EVM memory refinement proof for the low-level Keccak
  transcript writes; those memory/Keccak boundaries still have
  `local_obligations`.
- No broad test-vector suite yet; the current concrete replay coverage uses
  one deterministic FORS+C vector.

The current result should therefore be read as: the FORS+C recovery algorithm
and raw signature layout have a Lean model, structural Lean proofs, generated
Verity Yul, and one concrete EVM replay check. It should not be read as: the
production Solidity verifier is fully formally verified.

## Branch Recap

The Verity branch now contains four layers of work.

1. A Lean model of the FORS+C verifier:
   - fixed constants for the deployed parameter set;
   - typed signature structures;
   - typed recovery;
   - raw 2448-byte signature decoding;
   - full Keccak-boundary recovery shape covering Hmsg, forced-zero checking,
     per-tree root reconstruction, roots compression, and address derivation.

2. Lean proofs over that model:
   - layout and parameter equalities such as `K - 1 = 25`, `TREE_LEN = 96`,
     and `SIG_LEN = 2448`;
   - FORS index bounds below `2^A`;
   - bad-length rejection for raw signatures;
   - raw parser offset facts for `R`, `pkSeed`, `counter`, and all 150 opening
     words;
   - path-order and ADRS arithmetic facts for one-tree reconstruction;
   - transcript-shape facts at the opaque Keccak boundary;
   - the main legitimacy theorem: if a typed or raw signature satisfies the
     modeled legitimacy predicate for an expected `pkRoot`, recovery returns
     `addr(pkSeed, pkRoot)`.

3. Verity contracts compiled to Yul:
   - a guard kernel for constants and the forced-zero rule;
   - a one-tree shape kernel;
   - a one-tree Keccak-transcript kernel;
   - a full verifier kernel with a typed opening-array entrypoint and an
     ABI-compatible `recover(bytes,bytes32)` entrypoint.

4. Concrete replay tests:
   - a Python reference signer now emits a deterministic FORS+C test vector;
   - the optimized Solidity verifier recovers the expected address from that
     vector;
   - the generated Verity full-verifier artifact is deployed in Foundry and
     recovers the same address from the same vector;
   - the Verity replay test also checks bad-length rejection and pins the Yul
     source hash used by the compiled artifact.

## Proof Boundary

The verified Lean surface is the FORS+C recovery model under an opaque hash
boundary.

Exact current guarantees:

- `recoverRaw?` rejects any raw signature whose length is not `2448`.
- `decodeRaw` reads the fields at the fixed byte offsets described by the
  signing specification.
- `recoverTyped?` can return an address only if the derived Hmsg value passes
  the forced-zero guard.
- If a typed signature satisfies `LegitSignatureFor sig digest pkRoot`, then
  typed recovery returns `addressFromRoot sig.pkSeed pkRoot`.
- If a raw signature satisfies `RawLegitSignatureFor raw digest pkRoot`, then
  raw recovery returns the same expected address after decoding.
- The full Keccak-boundary model writes the expected transcript shapes for
  Hmsg, leaf hashing, node hashing, roots compression, and address derivation.

Outside the proof boundary:

- Keccak security is not proved.
- FORS unforgeability is not proved.
- q-signature security bounds are not proved.
- The optimized inline-assembly Solidity verifier is not yet proved equivalent
  to the Lean/Verity model.
- The generated Verity Yul artifact is tested with a concrete vector, but the
  deployed production bytecode is not yet linked to a formal equivalence proof.
- The off-chain signer is tested as a reference implementation, not proved
  correct in Lean.
- Verity `local_obligations` remain around ABI parsing and low-level
  memory/Keccak transcript refinement.

## File Map

- `NiceTry/Fors/Types.lean`: constants and typed signature structures.
- `NiceTry/Fors/Hash.lean`: opaque hash and address primitives.
- `NiceTry/Fors/Model.lean`: typed recovery model and raw-signature parser.
- `NiceTry/Fors/TreeShape.lean`: executable one-tree shape model with
  arithmetic hash stand-ins.
- `NiceTry/Fors/TreeKeccak.lean`: one-tree model at the EVM memory-transcript
  and opaque-Keccak boundary.
- `NiceTry/Fors/FullKeccak.lean`: typed full-verifier model covering Hmsg,
  forced-zero checking, 25 tree roots, roots compression, and address
  derivation.
- `NiceTry/Fors/RawKeccak.lean`: raw 2448-byte signature parser bridge into the
  full Keccak-boundary verifier model.
- `NiceTry/Fors/Spec.lean`: property definitions, including
  `LegitSignatureFor` and `RawLegitSignatureFor`.
- `NiceTry/Fors/Proofs/Basic.lean`: first structural proofs.
- `NiceTry/Fors/Proofs/TreeShape.lean`: path-order and ADRS arithmetic proofs
  for the one-tree shape model.
- `NiceTry/Fors/Proofs/TreeKeccak.lean`: memory-write and hash-range proofs for
  the one-tree Keccak transcript model.
- `NiceTry/Fors/Proofs/FullKeccak.lean`: structural proofs for the typed
  full-verifier transcript model.
- `NiceTry/Fors/Proofs/RawKeccak.lean`: raw parser offset and typed-bridge
  proofs for the full verifier model.
- `NiceTry/Fors/Verity/GuardKernel.lean`: Verity contract for constants and the
  forced-zero guard.
- `NiceTry/Fors/Verity/TreeShapeKernel.lean`: one-tree Verity kernel for index
  extraction, ADRS arithmetic, sibling ordering, and the fixed A=5 climb.
- `NiceTry/Fors/Verity/TreeKeccakKernel.lean`: one-tree Verity kernel whose
  generated Yul uses the leaf/node `mstore` and `keccak256` transcripts.
- `NiceTry/Fors/Verity/FullVerifierKernel.lean`: full Verity verifier kernel,
  including the ABI-compatible `recover(bytes,bytes32)` parser entrypoint.
- `artifacts/fors-guard-kernel/ForsGuardKernel.yul`: generated Yul for the
  guard kernel.
- `artifacts/fors-tree-shape-kernel/ForsTreeShapeKernel.yul`: generated Yul for
  the one-tree shape kernel.
- `artifacts/fors-tree-keccak-kernel/ForsTreeKeccakKernel.yul`: generated Yul
  for the one-tree Keccak-transcript kernel.
- `artifacts/fors-full-verifier-kernel/ForsFullVerifierKernel.yul`: generated
  Yul for the full verifier kernel.
- `artifacts/fors-full-verifier-kernel/ForsFullVerifierKernel.solc.json`: Solc
  artifact for the generated full-verifier Yul, used by the Foundry replay
  test.
- `../test/VerityForsFullVerifier.t.sol`: concrete generated-artifact replay
  test.

## Main Properties

The core statements are:

- Bad raw lengths are rejected.
- Raw parsing uses the fixed FORS+C byte layout.
- The forced-zero guard is necessary for successful recovery.
- Typed legitimacy implies recovery of the expected address.
- Raw legitimacy implies recovery of the expected address after decoding.
- One-tree reconstruction uses the modeled sibling order and ADRS arithmetic.
- The full verifier model compresses exactly 25 reconstructed roots.
- Address derivation is modeled as the low 160 bits of the hash of
  `pkSeed || pkRoot`.

Implementation shape:

- The Lean model separates typed recovery from raw decoding.
- The Verity full kernel keeps the raw ABI parser thin and delegates checked
  recovery to contract-local helpers.
- The generated Yul artifact is compiled into a pinned Solc JSON artifact for
  Foundry replay.
- The concrete replay test uses the same reference vector as the optimized
  Solidity verifier test.

That gives an inspectable, replayable verification boundary: exact signature
layout, exact recovery rule, exact forced-zero guard, and a concrete generated
EVM artifact that agrees with the reference vector.

## Build

```bash
cd verity
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

On this Windows machine, `evmyul` required a local dependency-cache adjustment
to use LLVM clang instead of a hardcoded `cc` command and to omit the Unix-only
`-fPIC` flag. The tracked Lean and Yul sources do not depend on that cache
patch, but regenerating artifacts on Windows may need the same toolchain fix.

## EVM Replay Tests

The full-verifier Yul artifact is not just generated. It is deployed and
exercised directly in Foundry through a compiled Solc artifact.

```bash
# From the repository root
forge test --match-contract VerityForsFullVerifierTest -vvv
```

That test:

- reads `artifacts/fors-full-verifier-kernel/ForsFullVerifierKernel.solc.json`;
- deploys the generated full-verifier artifact;
- loads `test/vectors/fors-reference-0.json`;
- calls `recover(bytes,bytes32)`;
- checks that the recovered address equals the vector address;
- checks that a bad-length signature returns `address(0)`;
- checks that the generated Yul source still matches the pinned SHA-256 hash.

If the Yul is regenerated, refresh
`artifacts/fors-full-verifier-kernel/ForsFullVerifierKernel.solc.json` from a
Solc or Foundry compile of that Yul source and update the pinned source hash in
the Foundry test. The current local Foundry nightly emits the Yul artifact JSON
successfully but then reports a Solar lint error on strict-Yul `object "Name"`
syntax.

## Why This Split Is Useful

For this verifier, the practical split is:

1. Keep the optimized Solidity verifier as the production implementation.
2. Keep the Lean/Verity verifier as the formal recovery model and generated
   artifact.
3. Use concrete vectors to keep the Python signer, Solidity verifier, and
   generated Verity artifact aligned.
4. Add a separate equivalence step for optimized Solidity versus the clean
   model or generated artifact.

The useful guarantee today is not "the whole production verifier is formally
verified." The useful guarantee is sharper: the FORS+C recovery rule and raw
layout are modeled, partially proved in Lean, compiled through Verity to Yul,
and replay-tested on EVM bytecode against an independent reference vector.

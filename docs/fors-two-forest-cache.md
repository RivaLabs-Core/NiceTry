# Two-Forest FORS Cache

This note formalizes the local signer cache for the NiceTry FORS account model.
The smart account stores a single `owner` address, and every successful UserOp rotates that owner to the
`nextOwner` appended to `userOp.callData`.

Terminology: a "FORS forest" here means the full signer material for one FORS
public key: `skSeed`, `pkSeed`, all per-tree nodes needed to extract auth paths,
the compressed `pkRoot`, and the Ethereum-style owner address derived from that
public key.

## Goal

Keep signing interactive on constrained devices while preserving the simple
on-chain invariant:

```text
current FORS signer authorizes UserOp i
UserOp i calldata ends with nextOwner
account.validateUserOp verifies current owner, then owner = nextOwner
```

The signer should normally have two FORS forests ready:

```text
current: full forest for the signer that can authorize the next UserOp
next:    full forest whose address will be appended as nextOwner
```

After a signature is released, the device starts building `next + 1` in the
background so the user does not wait at the next confirmation screen.

## Cache Entries

Each cache entry should contain:

```text
index             monotonic local derivation index
skSeed            secret seed for this FORS signer
pkSeed            public seed carried in signatures
pkRoot            compressed FORS public key
ownerAddress      last20(keccak256(pkSeed || pkRoot))
treeNodes         cached tree nodes, enough to extract auth paths
state             READY | BURNED | PENDING_ONCHAIN | CONFIRMED | RETIRED
reuseCount        number of distinct messages signed with this signer
signedDigests     optional small log for exact rebroadcast detection
```

`treeNodes` can omit leaf secrets if they are derived on demand from `skSeed`.
This keeps the cache smaller and avoids persisting more secret material than
needed.

## Steady-State Pipeline

Let `S_i` be the current signer and `S_{i+1}` be the next signer.

Before signing UserOp `i`:

```text
chain owner        = address(S_i)
cache current      = S_i, full forest ready
cache next         = S_{i+1}, at least address ready, ideally full forest ready
calldata tail      = bytes20(address(S_{i+1}))
userOpHash         commits to that calldata tail
```

Signing UserOp `i`:

```text
1. Build callData = account call || bytes20(address(S_{i+1})).
2. Compute userOpHash.
3. Atomically burn S_i before releasing any signature bytes.
4. Produce the FORS signature from cached S_i tree nodes.
5. Return the signature to the host.
6. Mark S_i as PENDING_ONCHAIN.
7. Start building S_{i+2} in the background.
```

After UserOp `i` is confirmed on-chain:

```text
1. Mark S_i as RETIRED.
2. Promote S_{i+1} to current.
3. Promote S_{i+2} to next once its address and forest are ready.
```

The important ordering is that `address(S_{i+1})` must be known before signing
UserOp `i`, because `nextOwner` is part of the signed `userOpHash`. The full
forest for `S_{i+1}` only needs to be ready before UserOp `i+1`.

## Background Building

The device should start building `S_{i+2}` immediately after releasing the
signature for UserOp `i`. This work does not affect the current signature.

If the next confirmation screen appears before `S_{i+2}` is complete, the
device has two options:

```text
best UX:     wait until S_{i+2}.ownerAddress is available, then sign
best safety: wait until the full S_{i+2} forest is cached, then sign
```

The second option guarantees that after UserOp `i+1` lands, the wallet can sign
UserOp `i+2` without a cold keygen delay.

## Failure And Retry Semantics

Burn-before-sign means local state can temporarily move ahead of chain state.
If a signed UserOp is dropped, the chain still expects `S_i`, but the device has
already burned it.

Allowed responses:

```text
rebroadcast same UserOp:
  Safe. No new signature is produced and no additional FORS material is leaked.

replacement UserOp with same signer:
  Counts as a reuse of S_i. Permit only inside an explicit small reuse budget,
  for example maxReuseCount = 2 or 3.

recovery/spare path:
  Use if the reuse budget is exhausted or local state is ambiguous.
```

This is why choosing FORS over WOTS is valuable here. The normal path remains
one signature per key, but dropped transactions, bundler replacement, or a
specific burn-before-sign failure mode can be handled as bounded degradation
instead of catastrophic key loss.

## Memory Estimates

For `N = 16`, storing all public tree nodes for one full FORS forest costs:

```text
K * (2^(A + 1) - 1) * N bytes
```

Examples:

| Parameters | Nodes per forest | Two forests |
| ---------- | ---------------- | ----------- |
| K=26, A=5  | 26,208 B         | 52,416 B    |
| K=32, A=4  | 15,872 B         | 31,744 B    |

If a FORS+C variant omits one full tree, subtract one tree:

```text
(2^(A + 1) - 1) * N bytes
```

For `K=26, A=5`, that is `1,008 B`.

Caching leaf secrets adds:

```text
K * 2^A * N bytes
```

For `K=26, A=5`, that is `13,312 B` per forest. Prefer deriving leaf secrets
from `skSeed` during signing unless signing latency requires caching them too.

## Security Invariants

The implementation should enforce these invariants:

```text
1. Never release a signature before the current signer is atomically burned.
2. Never sign a new digest with a BURNED signer unless the user enters an
   explicit retry/replacement flow.
3. Never exceed the configured reuse budget for a signer.
4. Always derive nextOwner from public FORS key material:
   address = last20(keccak256(pkSeed || pkRoot)).
5. Always include nextOwner in callData before computing userOpHash.
6. Persist enough metadata to recover safely after power loss.
```

The cache is a UX optimization, not an on-chain trust assumption. The contract
only cares that the current owner verifies the UserOp and that the appended
`nextOwner` is nonzero.

## Suggested State Machine

```text
READY
  signer has address and forest cache available

BURNED
  device has committed to not using this signer for normal fresh signatures

PENDING_ONCHAIN
  signature was released, but inclusion is not confirmed yet

CONFIRMED
  chain owner has rotated away from this signer

RETIRED
  local cache may delete tree nodes and keep only audit metadata
```

Power-loss recovery should resume from persisted state. In ambiguous cases, the
device should prefer rebroadcasting an existing signature or entering the
bounded-reuse recovery flow rather than silently producing a fresh signature.

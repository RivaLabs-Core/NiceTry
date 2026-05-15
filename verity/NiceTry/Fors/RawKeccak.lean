import NiceTry.Fors.FullKeccak

namespace NiceTry.Fors

/-
Raw-signature parser bridge for the full Keccak-boundary verifier.

This layer connects the 2448-byte signature layout to the typed full verifier
model. It still treats `RawSig.read16` abstractly, but it fixes every byte
offset that the EVM parser must use.
-/

def RawOpeningFields : Nat := 6

def rawOpeningOffset (tree field : Nat) : Nat :=
  SectionOffset + tree * TreeLen + field * N

def rawOpeningAt (raw : RawSig) (tree field : Nat) : Nat :=
  raw.read16 (rawOpeningOffset tree field)

def rawOpenings (raw : RawSig) : Nat -> Nat :=
  fun idx => rawOpeningAt raw (idx / RawOpeningFields) (idx % RawOpeningFields)

def memoryRecoverRaw?
    (raw : RawSig)
    (digest : Nat) :
    Option Address :=
  if raw.len = SigLen then
    memoryRecoverTyped?
      (raw.read16 ROffset)
      (raw.read16 PkSeedOffset)
      digest
      (raw.read16 CounterOffset)
      (rawOpenings raw)
  else
    none

end NiceTry.Fors

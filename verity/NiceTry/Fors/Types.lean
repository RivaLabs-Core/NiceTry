namespace NiceTry.Fors

abbrev Word := Nat
abbrev Digest := Word
abbrev Hash16 := Nat
abbrev Counter := Word
abbrev Address := Nat

def N : Nat := 16
def K : Nat := 26
def A : Nat := 5
def RealTrees : Nat := K - 1

def RLen : Nat := 16
def PkSeedLen : Nat := 16
def TreeLen : Nat := 16 + A * 16
def SectionLen : Nat := RealTrees * TreeLen
def CounterLen : Nat := 16
def SigLen : Nat := RLen + PkSeedLen + SectionLen + CounterLen

def ROffset : Nat := 0
def PkSeedOffset : Nat := ROffset + RLen
def SectionOffset : Nat := PkSeedOffset + PkSeedLen
def CounterOffset : Nat := SectionOffset + SectionLen

abbrev TreeIndex := Fin RealTrees
abbrev AuthLevel := Fin A

def LastTree : TreeIndex := Fin.mk 24 (by decide)
def LastAuthLevel : AuthLevel := Fin.mk 4 (by decide)

inductive AdrsType where
  | forsTree
  | forsRoots
deriving DecidableEq, Repr

structure Adrs where
  adrsType : AdrsType
  tree : Nat := 0
  height : Nat := 0
  index : Nat := 0
deriving DecidableEq, Repr

structure TreeOpening where
  sk : Hash16
  auth : AuthLevel -> Hash16

structure TypedSig where
  r : Hash16
  pkSeed : Hash16
  openings : TreeIndex -> TreeOpening
  counter : Counter

/--
Raw signatures model the verifier-visible byte string. `read16 offset` returns
the 16-byte chunk starting at `offset`, interpreted as the top half of a
32-byte EVM word after masking. A later executable/parser layer can refine this
into concrete byte extraction; this layer fixes the offset discipline.
-/
structure RawSig where
  len : Nat
  read16 : Nat -> Hash16

end NiceTry.Fors

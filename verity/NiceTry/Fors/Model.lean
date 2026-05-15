import NiceTry.Fors.Hash

namespace NiceTry.Fors

def twoPow (n : Nat) : Nat := 2 ^ n

/-- LSB-first FORS index extraction: tree `t` consumes bits `[A*t, A*(t+1))`. -/
def indexAt (dVal : Word) (tree : Nat) : Nat :=
  (dVal / twoPow (A * tree)) % twoPow A

/-- The omitted K-th tree is represented by the index at position `K - 1`. -/
def omittedIndex (dVal : Word) : Nat :=
  indexAt dVal RealTrees

/-- FORS+C grinding condition: the omitted tree index must be zero. -/
def forcedZero (dVal : Word) : Bool :=
  omittedIndex dVal == 0

def leafAdrs (tree leafIdx : Nat) : Adrs :=
  { adrsType := .forsTree, tree := tree, height := 0, index := leafIdx }

def nodeAdrs (tree height parentIdx : Nat) : Adrs :=
  { adrsType := .forsTree, tree := tree, height := height, index := parentIdx }

def rootsAdrs : Adrs :=
  { adrsType := .forsRoots }

/--
One Merkle climb step. If the current path index is even, the current node is
the left child; otherwise the auth sibling is the left child.
-/
def climbLevel
    (pkSeed : Hash16)
    (tree height pathIdx : Nat)
    (node sibling : Hash16) :
    Hash16 :=
  let parentIdx := pathIdx / 2
  let adrs := nodeAdrs tree height parentIdx
  if pathIdx % 2 = 0 then
    nodeHash pkSeed adrs node sibling
  else
    nodeHash pkSeed adrs sibling node

/-- Fixed A=5 FORS tree reconstruction for one typed opening. -/
def reconstructTree
    (pkSeed : Hash16)
    (tree : TreeIndex)
    (leafIdx : Nat)
    (opening : TreeOpening) :
    Hash16 :=
  let leaf := leafHash pkSeed (leafAdrs tree.val leafIdx) opening.sk
  let node1 := climbLevel pkSeed tree.val 1 leafIdx leaf (opening.auth (Fin.mk 0 (by decide)))
  let idx1 := leafIdx / 2
  let node2 := climbLevel pkSeed tree.val 2 idx1 node1 (opening.auth (Fin.mk 1 (by decide)))
  let idx2 := idx1 / 2
  let node3 := climbLevel pkSeed tree.val 3 idx2 node2 (opening.auth (Fin.mk 2 (by decide)))
  let idx3 := idx2 / 2
  let node4 := climbLevel pkSeed tree.val 4 idx3 node3 (opening.auth (Fin.mk 3 (by decide)))
  let idx4 := idx3 / 2
  climbLevel pkSeed tree.val 5 idx4 node4 (opening.auth (Fin.mk 4 (by decide)))

def recoverRoot (sig : TypedSig) (dVal : Word) : Hash16 :=
  let roots : TreeIndex -> Hash16 :=
    fun tree =>
      reconstructTree sig.pkSeed tree (indexAt dVal tree.val) (sig.openings tree)
  compressRoots sig.pkSeed roots

def treeOffset (tree : TreeIndex) : Nat :=
  SectionOffset + tree.val * TreeLen

def authOffset (tree : TreeIndex) (level : AuthLevel) : Nat :=
  treeOffset tree + 16 + level.val * 16

def readHash16 (raw : RawSig) (offset : Nat) : Hash16 :=
  raw.read16 offset

def decodeOpening (raw : RawSig) (tree : TreeIndex) : TreeOpening :=
  { sk := readHash16 raw (treeOffset tree)
    auth := fun level => readHash16 raw (authOffset tree level) }

def decodeTyped (raw : RawSig) : TypedSig :=
  { r := readHash16 raw ROffset
    pkSeed := readHash16 raw PkSeedOffset
    openings := fun tree => decodeOpening raw tree
    counter := readHash16 raw CounterOffset }

/-- Raw decoder for the byte layout in `docs/signing-spec.md` section 4.2. -/
def decodeRaw (raw : RawSig) : Option TypedSig :=
  if raw.len = SigLen then
    some (decodeTyped raw)
  else
    none

/-- Typed FORS+C recovery model. Bad forced-zero grinding returns `none`. -/
def recoverTyped? (sig : TypedSig) (digest : Digest) : Option Address :=
  let dVal := hMsg sig.pkSeed sig.r digest sig.counter
  if forcedZero dVal then
    some (addressFromRoot sig.pkSeed (recoverRoot sig dVal))
  else
    none

def recoverRaw? (raw : RawSig) (digest : Digest) : Option Address :=
  if raw.len = SigLen then
    match decodeRaw raw with
    | some sig => recoverTyped? sig digest
    | none => none
  else
    none

end NiceTry.Fors

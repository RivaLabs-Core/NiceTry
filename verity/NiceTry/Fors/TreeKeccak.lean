import NiceTry.Fors.TreeShape

namespace NiceTry.Fors

/-
One-tree FORS model at the EVM Keccak-call boundary.

The Keccak result is still opaque, but the memory transcript is concrete:
which 32-byte words are written, where they are written, and which memory range
is hashed. This is the proof boundary needed before replacing the current
Solidity assembly with, or comparing it against, generated Verity/Yul.
-/

def ScratchBase : Nat := 0x380
def ScratchAdrsOffset : Nat := 0x3a0
def ScratchLeftOffset : Nat := 0x3c0
def ScratchRightOffset : Nat := 0x3e0
def LeafHashLen : Nat := 0x60
def NodeHashLen : Nat := 0x80
def NMaskWord : Nat := 2 ^ 256 - 2 ^ 128

structure MemoryWord where
  offset : Nat
  value : Nat
deriving DecidableEq, Repr

structure KeccakMemoryCall where
  offset : Nat
  size : Nat
  writes : List MemoryWord
deriving DecidableEq, Repr

opaque keccakHash16FromMemory : KeccakMemoryCall -> Hash16

def leafMemoryCall (pkSeed tree leafIdx sk : Nat) : KeccakMemoryCall :=
  { offset := ScratchBase
    size := LeafHashLen
    writes :=
      [ { offset := ScratchBase, value := pkSeed }
      , { offset := ScratchAdrsOffset, value := shapeLeafAdrsWord tree leafIdx }
      , { offset := ScratchLeftOffset, value := sk }
      ] }

def nodeMemoryCall
    (pkSeed tree height parentIdx left right : Nat) :
    KeccakMemoryCall :=
  { offset := ScratchBase
    size := NodeHashLen
    writes :=
      [ { offset := ScratchBase, value := pkSeed }
      , { offset := ScratchAdrsOffset, value := shapeNodeAdrsWord tree height parentIdx }
      , { offset := ScratchLeftOffset, value := left }
      , { offset := ScratchRightOffset, value := right }
      ] }

def memoryLeafHash (pkSeed tree leafIdx sk : Nat) : Hash16 :=
  keccakHash16FromMemory (leafMemoryCall pkSeed tree leafIdx sk)

def memoryNodeHash
    (pkSeed tree height parentIdx left right : Nat) :
    Hash16 :=
  keccakHash16FromMemory (nodeMemoryCall pkSeed tree height parentIdx left right)

def memoryClimbLevel
    (pkSeed tree height pathIdx node sibling : Nat) :
    Hash16 :=
  let parentIdx := pathIdx / 2
  if pathIdx % 2 = 0 then
    memoryNodeHash pkSeed tree height parentIdx node sibling
  else
    memoryNodeHash pkSeed tree height parentIdx sibling node

def memoryReconstructTree
    (pkSeed tree leafIdx sk auth0 auth1 auth2 auth3 auth4 : Nat) :
    Hash16 :=
  let leaf := memoryLeafHash pkSeed tree leafIdx sk
  let node1 := memoryClimbLevel pkSeed tree 1 leafIdx leaf auth0
  let idx1 := leafIdx / 2
  let node2 := memoryClimbLevel pkSeed tree 2 idx1 node1 auth1
  let idx2 := idx1 / 2
  let node3 := memoryClimbLevel pkSeed tree 3 idx2 node2 auth2
  let idx3 := idx2 / 2
  let node4 := memoryClimbLevel pkSeed tree 4 idx3 node3 auth3
  let idx4 := idx3 / 2
  memoryClimbLevel pkSeed tree 5 idx4 node4 auth4

def memoryTreeRootFromDVal
    (pkSeed dVal tree sk auth0 auth1 auth2 auth3 auth4 : Nat) :
    Hash16 :=
  memoryReconstructTree
    pkSeed tree (indexAt dVal tree) sk auth0 auth1 auth2 auth3 auth4

end NiceTry.Fors

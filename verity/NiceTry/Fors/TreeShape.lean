import NiceTry.Fors.Model

namespace NiceTry.Fors

/-
Executable tree-shape model for the first Verity FORS kernel.

This deliberately uses arithmetic stand-ins for the leaf/node compression
functions. The point of this layer is to fix the Merkle ordering, path index
updates, and ADRS word arithmetic before the exact Keccak memory semantics are
introduced.
-/

def ForsBaseWord : Nat := 3 * 2 ^ 128
def HeightWord (height : Nat) : Nat := height * 2 ^ 32

def shapeLeafAdrsWord (tree leafIdx : Nat) : Nat :=
  ForsBaseWord + tree * 32 + leafIdx

def shapeNodeAdrsWord (tree height parentIdx : Nat) : Nat :=
  ForsBaseWord + HeightWord height + tree * twoPow (A - height) + parentIdx

def shapeIndexAt (dVal tree : Nat) : Nat :=
  (dVal / twoPow (A * tree)) % twoPow A

def shapeLeafHash (pkSeed tree leafIdx sk : Nat) : Nat :=
  pkSeed + shapeLeafAdrsWord tree leafIdx + sk

def shapeNodeHash (pkSeed tree height parentIdx left right : Nat) : Nat :=
  pkSeed + shapeNodeAdrsWord tree height parentIdx + left * 131 + right * 257

def shapeClimbLevel
    (pkSeed tree height pathIdx node sibling : Nat) :
    Nat :=
  let parentIdx := pathIdx / 2
  if pathIdx % 2 = 0 then
    shapeNodeHash pkSeed tree height parentIdx node sibling
  else
    shapeNodeHash pkSeed tree height parentIdx sibling node

def shapeReconstructTree
    (pkSeed tree leafIdx sk auth0 auth1 auth2 auth3 auth4 : Nat) :
    Nat :=
  let leaf := shapeLeafHash pkSeed tree leafIdx sk
  let node1 := shapeClimbLevel pkSeed tree 1 leafIdx leaf auth0
  let idx1 := leafIdx / 2
  let node2 := shapeClimbLevel pkSeed tree 2 idx1 node1 auth1
  let idx2 := idx1 / 2
  let node3 := shapeClimbLevel pkSeed tree 3 idx2 node2 auth2
  let idx3 := idx2 / 2
  let node4 := shapeClimbLevel pkSeed tree 4 idx3 node3 auth3
  let idx4 := idx3 / 2
  shapeClimbLevel pkSeed tree 5 idx4 node4 auth4

def shapeTreeRootFromDVal
    (pkSeed dVal tree sk auth0 auth1 auth2 auth3 auth4 : Nat) :
    Nat :=
  shapeReconstructTree
    pkSeed tree (shapeIndexAt dVal tree) sk auth0 auth1 auth2 auth3 auth4

end NiceTry.Fors

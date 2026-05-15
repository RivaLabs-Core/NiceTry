import Contracts.Common
import Compiler.CheckContract

namespace NiceTry.Fors.Verity.TreeShapeKernel

open _root_.Contracts
open _root_.Verity hiding pure bind
open _root_.Verity.EVM.Uint256

/-
One-tree executable FORS kernel with arithmetic hash stand-ins.

This is not the final Keccak verifier. It is the next Verity boundary after
the guard kernel: tree index extraction, ADRS arithmetic, sibling ordering, and
the fixed A=5 auth-path climb.
-/
verity_contract ForsTreeShapeKernel where
  storage

  function forsBase () : Uint256 := do
    return shl 128 3

  function leafAdrs (tree : Uint256, leafIdx : Uint256) : Uint256 := do
    let base := shl 128 3
    return bitOr base (bitOr (shl 5 tree) leafIdx)

  function nodeAdrs
      (tree : Uint256, height : Uint256, treeScale : Uint256, parentIdx : Uint256) :
      Uint256 := do
    let base := shl 128 3
    let heightWord := shl 32 height
    let globalIdx := add (mul tree treeScale) parentIdx
    return bitOr base (bitOr heightWord globalIdx)

  function indexAt (dVal : Uint256, tree : Uint256) : Uint256 := do
    let bitOffset := mul 5 tree
    return bitAnd (shr bitOffset dVal) 31

  function leafHash
      (pkSeed : Uint256, tree : Uint256, leafIdx : Uint256, sk : Uint256) :
      Uint256 := do
    let adrs <- leafAdrs tree leafIdx
    return add (add pkSeed adrs) sk

  function nodeHash
      (pkSeed : Uint256, tree : Uint256, height : Uint256, treeScale : Uint256,
       parentIdx : Uint256, left : Uint256, right : Uint256) :
      Uint256 := do
    let adrs <- nodeAdrs tree height treeScale parentIdx
    return add (add pkSeed adrs) (add (mul left 131) (mul right 257))

  function climbLevel
      (pkSeed : Uint256, tree : Uint256, height : Uint256, treeScale : Uint256,
       pathIdx : Uint256, node : Uint256, sibling : Uint256) :
      Tuple [Uint256, Uint256] := do
    let parentIdx := div pathIdx 2
    if mod pathIdx 2 == 0 then
      let next <- nodeHash pkSeed tree height treeScale parentIdx node sibling
      return (next, parentIdx)
    else
      let next <- nodeHash pkSeed tree height treeScale parentIdx sibling node
      return (next, parentIdx)

  function allow_post_interaction_writes reconstructTree
      (pkSeed : Uint256, tree : Uint256, leafIdx : Uint256, sk : Uint256,
       auth0 : Uint256, auth1 : Uint256, auth2 : Uint256, auth3 : Uint256,
       auth4 : Uint256) :
      Uint256 := do
    let leaf <- leafHash pkSeed tree leafIdx sk
    let (node1, idx1) <- climbLevel pkSeed tree 1 16 leafIdx leaf auth0
    let (node2, idx2) <- climbLevel pkSeed tree 2 8 idx1 node1 auth1
    let (node3, idx3) <- climbLevel pkSeed tree 3 4 idx2 node2 auth2
    let (node4, idx4) <- climbLevel pkSeed tree 4 2 idx3 node3 auth3
    let (node5, idx5) <- climbLevel pkSeed tree 5 1 idx4 node4 auth4
    let _terminalIdx := idx5
    return node5

  function allow_post_interaction_writes treeRootFromDVal
      (pkSeed : Uint256, dVal : Uint256, tree : Uint256, sk : Uint256,
       auth0 : Uint256, auth1 : Uint256, auth2 : Uint256, auth3 : Uint256,
       auth4 : Uint256) :
      Uint256 := do
    let leafIdx <- indexAt dVal tree
    let root <- reconstructTree pkSeed tree leafIdx sk auth0 auth1 auth2 auth3 auth4
    return root

def spec := ForsTreeShapeKernel.spec

#check_contract ForsTreeShapeKernel

end NiceTry.Fors.Verity.TreeShapeKernel

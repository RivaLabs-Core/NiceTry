import Contracts.Common
import Compiler.CheckContract

namespace NiceTry.Fors.Verity.TreeKeccakKernel

open _root_.Contracts
open _root_.Verity hiding pure bind
open _root_.Verity.EVM.Uint256

/-
One-tree FORS kernel using the same memory transcript shape as the Solidity
assembly leaf/node hashes:

  leaf: keccak256(0x380, 0x60) over pkSeed, ADRS, sk
  node: keccak256(0x380, 0x80) over pkSeed, ADRS, left, right

The `local_obligations` mark the current Verity boundary honestly: the
generated Yul contains the real `mstore`/`keccak256` instructions, while the
Lean-side executable semantics for `keccak256` is still an abstract trust
boundary rather than a concrete cryptographic memory model.
-/
verity_contract ForsTreeKeccakKernel where
  storage

  function nMask () : Uint256 := do
    return 0xffffffffffffffffffffffffffffffff00000000000000000000000000000000

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
      (pkSeed : Uint256, tree : Uint256, leafIdx : Uint256, sk : Uint256)
      local_obligations [keccak_memory_refinement := assumed "Prove that the 0x380..0x3df memory writes are exactly the leaf transcript pkSeed||ADRS||sk and that masking keeps the top 16 bytes."]
      : Uint256 := do
    let adrs <- leafAdrs tree leafIdx
    unsafe "leaf hash uses explicit EVM memory transcript" do
      mstore 0x380 pkSeed
      mstore 0x3a0 adrs
      mstore 0x3c0 sk
    let digest := keccak256 0x380 0x60
    return bitAnd digest 0xffffffffffffffffffffffffffffffff00000000000000000000000000000000

  function nodeHash
      (pkSeed : Uint256, tree : Uint256, height : Uint256, treeScale : Uint256,
       parentIdx : Uint256, left : Uint256, right : Uint256)
      local_obligations [keccak_memory_refinement := assumed "Prove that the 0x380..0x3ff memory writes are exactly the node transcript pkSeed||ADRS||left||right and that masking keeps the top 16 bytes."]
      : Uint256 := do
    let adrs <- nodeAdrs tree height treeScale parentIdx
    unsafe "node hash uses explicit EVM memory transcript" do
      mstore 0x380 pkSeed
      mstore 0x3a0 adrs
      mstore 0x3c0 left
      mstore 0x3e0 right
    let digest := keccak256 0x380 0x80
    return bitAnd digest 0xffffffffffffffffffffffffffffffff00000000000000000000000000000000

  function allow_post_interaction_writes climbLevel
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

def spec := ForsTreeKeccakKernel.spec

#check_contract ForsTreeKeccakKernel

end NiceTry.Fors.Verity.TreeKeccakKernel

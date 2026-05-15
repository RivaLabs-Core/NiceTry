import Contracts.Common
import Compiler.CheckContract

namespace NiceTry.Fors.Verity.FullVerifierKernel

open _root_.Contracts hiding toUint256
open _root_.Verity hiding pure bind
open _root_.Verity.EVM.Uint256

/-
Full FORS+C verifier kernel.

It exposes both a typed helper over a 150-word opening array and an
ABI-compatible `recover(bytes,bytes32)` entrypoint that parses the 2448-byte
FORS+C signature layout directly from calldata.
-/
verity_contract ForsFullVerifierKernel where
  storage

  function nMask () : Uint256 := do
    return 0xffffffffffffffffffffffffffffffff00000000000000000000000000000000

  function lower160Mask () : Uint256 := do
    return 0x000000000000000000000000ffffffffffffffffffffffffffffffffffffffff

  function openingWords () : Uint256 := do
    return 150

  function rootsHashLen () : Uint256 := do
    return 864

  function sigLen () : Uint256 := do
    return 2448

  function sectionOffset () : Uint256 := do
    return 32

  function counterOffset () : Uint256 := do
    return 2432

  function treeLen () : Uint256 := do
    return 96

  function forcedZero (dVal : Uint256) : Bool := do
    let idx := bitAnd (shr 125 dVal) 31
    return idx == 0

  function hMsg
      (pkSeed : Uint256, r : Uint256, digest : Uint256, counter : Uint256)
      local_obligations [hmsg_keccak_memory_refinement := assumed "Prove that memory 0x00..0x9f is exactly pkSeed||R||digest||dom_FORS||counter before Hmsg keccak."]
      : Uint256 := do
    unsafe "Hmsg uses explicit EVM memory transcript" do
      mstore 0x00 pkSeed
      mstore 0x20 r
      mstore 0x40 digest
      mstore 0x60 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD
      mstore 0x80 counter
    return keccak256 0x00 0xa0

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

  function openingAt (openings : Array Uint256, tree : Uint256, field : Uint256) :
      Uint256 := do
    let idx := add (mul tree 6) field
    let value := arrayElement openings idx
    return bitAnd value 0xffffffffffffffffffffffffffffffff00000000000000000000000000000000

  function rawWord (sigData : Uint256, byteOffset : Uint256)
      local_obligations [raw_calldata_refinement := assumed "Prove that sigData points to the first byte of the ABI bytes payload and byteOffset is one of the FORS signature layout offsets."]
      : Uint256 := do
    let word := calldataload (add sigData byteOffset)
    return bitAnd word 0xffffffffffffffffffffffffffffffff00000000000000000000000000000000

  function allow_post_interaction_writes compressRoots (_pkSeed : Uint256)
      local_obligations [roots_keccak_memory_refinement := assumed "Prove that memory 0x00..0x35f is exactly pkSeed||ADRS_roots||root_0..root_24 before roots compression."]
      : Uint256 := do
    unsafe "roots compression uses explicit EVM memory transcript" do
      mstore 0x20 (shl 128 4)
    let digest := keccak256 0x00 0x360
    return bitAnd digest 0xffffffffffffffffffffffffffffffff00000000000000000000000000000000

  function addressFromRoot (pkSeed : Uint256, pkRoot : Uint256)
      local_obligations [address_keccak_memory_refinement := assumed "Prove that memory 0x00..0x3f is exactly pkSeed||pkRoot before address derivation."]
      : Uint256 := do
    unsafe "address derivation uses explicit EVM memory transcript" do
      mstore 0x00 pkSeed
      mstore 0x20 pkRoot
    let digest := keccak256 0x00 0x40
    return bitAnd digest 0x000000000000000000000000ffffffffffffffffffffffffffffffffffffffff

  function allow_post_interaction_writes recoverTyped
      (r : Uint256, pkSeed : Uint256, digest : Uint256, counter : Uint256,
       openings : Array Uint256)
      local_obligations [full_verifier_memory_refinement := assumed "Prove that the full typed verifier memory choreography preserves pkSeed, writes all 25 roots at 0x40+32*t, keeps scratch at 0x380+, and matches the FORS+C transcript spec."]
      : Uint256 := do
    if arrayLength openings == 150 then
      let maskedR := bitAnd r 0xffffffffffffffffffffffffffffffff00000000000000000000000000000000
      let maskedPkSeed := bitAnd pkSeed 0xffffffffffffffffffffffffffffffff00000000000000000000000000000000
      let maskedCounter := bitAnd counter 0xffffffffffffffffffffffffffffffff00000000000000000000000000000000
      let dVal <- hMsg maskedPkSeed maskedR digest maskedCounter
      let ok <- forcedZero dVal
      if ok then
        unsafe "initialize roots hash buffer with pkSeed" do
          mstore 0x00 maskedPkSeed
        forEach "t" 25 (do
          let leafIdx <- indexAt dVal t
          let sk <- openingAt openings t 0
          let auth0 <- openingAt openings t 1
          let auth1 <- openingAt openings t 2
          let auth2 <- openingAt openings t 3
          let auth3 <- openingAt openings t 4
          let auth4 <- openingAt openings t 5
          let root <- reconstructTree maskedPkSeed t leafIdx sk auth0 auth1 auth2 auth3 auth4
          let rootPtr := add 0x40 (mul t 0x20)
          unsafe "write recovered tree root into roots buffer" do
            mstore rootPtr root)
        let pkRoot <- compressRoots maskedPkSeed
        let signer <- addressFromRoot maskedPkSeed pkRoot
        return signer
      else
        return 0
    else
      return 0

  function allow_post_interaction_writes recover
      (_sig : Bytes, digest : Bytes32)
      local_obligations [raw_abi_parse_refinement := assumed "Prove that the hardcoded ABI reads match recover(bytes,bytes32): calldata[4] is the bytes offset, calldata[4+offset] is sig.length, and calldata[4+offset+32] is sig.data."]
      : Address := do
    let sigOffset := calldataload 4
    let sigLenOffset := add 4 sigOffset
    let sigLen := calldataload sigLenOffset
    if sigLen == 2448 then
      let sigData := add sigLenOffset 32
      let r <- rawWord sigData 0
      let pkSeed <- rawWord sigData 16
      let counter <- rawWord sigData 2432
      let digestWord := toUint256 digest
      let dVal <- hMsg pkSeed r digestWord counter
      let ok <- forcedZero dVal
      if ok then
        unsafe "initialize roots hash buffer with parsed pkSeed" do
          mstore 0x00 pkSeed
        forEach "t" 25 (do
          let leafIdx <- indexAt dVal t
          let treeBase := add 32 (mul t 96)
          let sk <- rawWord sigData treeBase
          let auth0 <- rawWord sigData (add treeBase 16)
          let auth1 <- rawWord sigData (add treeBase 32)
          let auth2 <- rawWord sigData (add treeBase 48)
          let auth3 <- rawWord sigData (add treeBase 64)
          let auth4 <- rawWord sigData (add treeBase 80)
          let root <- reconstructTree pkSeed t leafIdx sk auth0 auth1 auth2 auth3 auth4
          let rootPtr := add 0x40 (mul t 0x20)
          unsafe "write recovered raw tree root into roots buffer" do
            mstore rootPtr root)
        let pkRoot <- compressRoots pkSeed
        let signer <- addressFromRoot pkSeed pkRoot
        return wordToAddress signer
      else
        return zeroAddress
    else
      return zeroAddress

def spec := ForsFullVerifierKernel.spec

#check_contract ForsFullVerifierKernel

end NiceTry.Fors.Verity.FullVerifierKernel

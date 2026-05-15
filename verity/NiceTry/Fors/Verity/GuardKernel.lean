import Contracts.Common
import Compiler.CheckContract

namespace NiceTry.Fors.Verity.GuardKernel

open _root_.Contracts
open _root_.Verity hiding pure bind
open _root_.Verity.EVM.Uint256

/-
Small first Verity contract layer for the FORS+C verifier.

This is deliberately not the full verifier yet. It gives the project a
build-checked `verity_contract` target for the easiest executable boundary:
signature layout constants and the omitted-tree forced-zero guard.
-/
verity_contract ForsGuardKernel where
  storage

  function sigLen () : Uint256 := do
    return 2448

  function sectionOffset () : Uint256 := do
    return 32

  function counterOffset () : Uint256 := do
    return 2432

  function treeOffset (tree : Uint256) : Uint256 := do
    return add 32 (mul tree 96)

  function authOffset (tree : Uint256, level : Uint256) : Uint256 := do
    let base := add 32 (mul tree 96)
    return add (add base 16) (mul level 16)

  function omittedIndex (dVal : Uint256) : Uint256 := do
    return bitAnd (shr 125 dVal) 31

  function forcedZero (dVal : Uint256) : Bool := do
    let idx := bitAnd (shr 125 dVal) 31
    return idx == 0

def spec := ForsGuardKernel.spec

end NiceTry.Fors.Verity.GuardKernel

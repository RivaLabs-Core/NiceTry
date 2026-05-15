import NiceTry.Fors.TreeShape

namespace NiceTry.Fors

theorem shapeIndexAt_eq_indexAt (dVal tree : Nat) :
    shapeIndexAt dVal tree = indexAt dVal tree := by
  rfl

theorem shapeLeafAdrsWord_eq (tree leafIdx : Nat) :
    shapeLeafAdrsWord tree leafIdx = ForsBaseWord + tree * 32 + leafIdx := by
  rfl

theorem shapeNodeAdrsWord_level1 (tree parentIdx : Nat) :
    shapeNodeAdrsWord tree 1 parentIdx =
      ForsBaseWord + 2 ^ 32 + tree * 16 + parentIdx := by
  simp [shapeNodeAdrsWord, HeightWord, A, twoPow]

theorem shapeNodeAdrsWord_level2 (tree parentIdx : Nat) :
    shapeNodeAdrsWord tree 2 parentIdx =
      ForsBaseWord + 2 * 2 ^ 32 + tree * 8 + parentIdx := by
  simp [shapeNodeAdrsWord, HeightWord, A, twoPow]

theorem shapeNodeAdrsWord_level3 (tree parentIdx : Nat) :
    shapeNodeAdrsWord tree 3 parentIdx =
      ForsBaseWord + 3 * 2 ^ 32 + tree * 4 + parentIdx := by
  simp [shapeNodeAdrsWord, HeightWord, A, twoPow]

theorem shapeNodeAdrsWord_level4 (tree parentIdx : Nat) :
    shapeNodeAdrsWord tree 4 parentIdx =
      ForsBaseWord + 4 * 2 ^ 32 + tree * 2 + parentIdx := by
  simp [shapeNodeAdrsWord, HeightWord, A, twoPow]

theorem shapeNodeAdrsWord_level5 (tree parentIdx : Nat) :
    shapeNodeAdrsWord tree 5 parentIdx =
      ForsBaseWord + 5 * 2 ^ 32 + tree + parentIdx := by
  simp [shapeNodeAdrsWord, HeightWord, A, twoPow]

theorem shapeClimbLevel_even
    (pkSeed tree height pathIdx node sibling : Nat)
    (hEven : pathIdx % 2 = 0) :
    shapeClimbLevel pkSeed tree height pathIdx node sibling =
      shapeNodeHash pkSeed tree height (pathIdx / 2) node sibling := by
  simp [shapeClimbLevel, hEven]

theorem shapeClimbLevel_odd
    (pkSeed tree height pathIdx node sibling : Nat)
    (hOdd : pathIdx % 2 ≠ 0) :
    shapeClimbLevel pkSeed tree height pathIdx node sibling =
      shapeNodeHash pkSeed tree height (pathIdx / 2) sibling node := by
  simp [shapeClimbLevel, hOdd]

theorem shapeTreeRootFromDVal_eq
    (pkSeed dVal tree sk auth0 auth1 auth2 auth3 auth4 : Nat) :
    shapeTreeRootFromDVal pkSeed dVal tree sk auth0 auth1 auth2 auth3 auth4 =
      shapeReconstructTree
        pkSeed tree (indexAt dVal tree) sk auth0 auth1 auth2 auth3 auth4 := by
  rfl

end NiceTry.Fors

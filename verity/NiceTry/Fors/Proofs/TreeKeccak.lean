import NiceTry.Fors.TreeKeccak

namespace NiceTry.Fors

theorem leafMemoryCall_offset (pkSeed tree leafIdx sk : Nat) :
    (leafMemoryCall pkSeed tree leafIdx sk).offset = ScratchBase := by
  rfl

theorem leafMemoryCall_size (pkSeed tree leafIdx sk : Nat) :
    (leafMemoryCall pkSeed tree leafIdx sk).size = LeafHashLen := by
  rfl

theorem leafMemoryCall_writes (pkSeed tree leafIdx sk : Nat) :
    (leafMemoryCall pkSeed tree leafIdx sk).writes =
      [ { offset := ScratchBase, value := pkSeed }
      , { offset := ScratchAdrsOffset, value := shapeLeafAdrsWord tree leafIdx }
      , { offset := ScratchLeftOffset, value := sk }
      ] := by
  rfl

theorem nodeMemoryCall_offset
    (pkSeed tree height parentIdx left right : Nat) :
    (nodeMemoryCall pkSeed tree height parentIdx left right).offset =
      ScratchBase := by
  rfl

theorem nodeMemoryCall_size
    (pkSeed tree height parentIdx left right : Nat) :
    (nodeMemoryCall pkSeed tree height parentIdx left right).size =
      NodeHashLen := by
  rfl

theorem nodeMemoryCall_writes
    (pkSeed tree height parentIdx left right : Nat) :
    (nodeMemoryCall pkSeed tree height parentIdx left right).writes =
      [ { offset := ScratchBase, value := pkSeed }
      , { offset := ScratchAdrsOffset, value := shapeNodeAdrsWord tree height parentIdx }
      , { offset := ScratchLeftOffset, value := left }
      , { offset := ScratchRightOffset, value := right }
      ] := by
  rfl

theorem leafMemoryCall_hashes_96_bytes (pkSeed tree leafIdx sk : Nat) :
    (leafMemoryCall pkSeed tree leafIdx sk).offset = 0x380 ∧
      (leafMemoryCall pkSeed tree leafIdx sk).size = 0x60 := by
  constructor <;> rfl

theorem nodeMemoryCall_hashes_128_bytes
    (pkSeed tree height parentIdx left right : Nat) :
    (nodeMemoryCall pkSeed tree height parentIdx left right).offset = 0x380 ∧
      (nodeMemoryCall pkSeed tree height parentIdx left right).size = 0x80 := by
  constructor <;> rfl

theorem memoryClimbLevel_even
    (pkSeed tree height pathIdx node sibling : Nat)
    (hEven : pathIdx % 2 = 0) :
    memoryClimbLevel pkSeed tree height pathIdx node sibling =
      memoryNodeHash pkSeed tree height (pathIdx / 2) node sibling := by
  simp [memoryClimbLevel, hEven]

theorem memoryClimbLevel_odd
    (pkSeed tree height pathIdx node sibling : Nat)
    (hOdd : pathIdx % 2 ≠ 0) :
    memoryClimbLevel pkSeed tree height pathIdx node sibling =
      memoryNodeHash pkSeed tree height (pathIdx / 2) sibling node := by
  simp [memoryClimbLevel, hOdd]

theorem memoryTreeRootFromDVal_eq
    (pkSeed dVal tree sk auth0 auth1 auth2 auth3 auth4 : Nat) :
    memoryTreeRootFromDVal pkSeed dVal tree sk auth0 auth1 auth2 auth3 auth4 =
      memoryReconstructTree
        pkSeed tree (indexAt dVal tree) sk auth0 auth1 auth2 auth3 auth4 := by
  rfl

end NiceTry.Fors

import NiceTry.Fors.FullKeccak

namespace NiceTry.Fors

theorem openingWords_eq : OpeningWords = 150 := by
  simp [OpeningWords, RealTrees, K]

theorem rootsHashLen_eq : RootsHashLen = 864 := by
  simp [RootsHashLen, K]

theorem hMsgMemoryCall_shape (pkSeed r digest counter : Nat) :
    hMsgMemoryCall pkSeed r digest counter =
      { offset := 0
        size := 0xa0
        writes :=
          [ { offset := 0x00, value := pkSeed }
          , { offset := 0x20, value := r }
          , { offset := 0x40, value := digest }
          , { offset := 0x60, value := ForsDomainWord }
          , { offset := 0x80, value := counter }
          ] } := by
  rfl

theorem rootBufferWrites_length
    (pkSeed dVal : Nat)
    (openings : Nat -> Nat) :
    (rootBufferWrites pkSeed dVal openings).length = RealTrees := by
  simp [rootBufferWrites]

theorem rootBufferWrites_length_eq_25
    (pkSeed dVal : Nat)
    (openings : Nat -> Nat) :
    (rootBufferWrites pkSeed dVal openings).length = 25 := by
  simp [rootBufferWrites, RealTrees, K]

theorem first_rootBufferWrite_offset
    (pkSeed dVal : Nat)
    (openings : Nat -> Nat) :
    (rootBufferWrite pkSeed dVal openings 0).offset = 0x40 := by
  rfl

theorem last_rootBufferWrite_offset
    (pkSeed dVal : Nat)
    (openings : Nat -> Nat) :
    (rootBufferWrite pkSeed dVal openings 24).offset = 0x340 := by
  rfl

theorem rootsMemoryCall_prefix
    (pkSeed dVal : Nat)
    (openings : Nat -> Nat) :
    (rootsMemoryCall pkSeed dVal openings).offset = 0 ∧
      (rootsMemoryCall pkSeed dVal openings).size = RootsHashLen ∧
      (rootsMemoryCall pkSeed dVal openings).writes.take 2 =
        [ { offset := 0x00, value := pkSeed }
        , { offset := 0x20, value := ForsRootsAdrsWord }
        ] := by
  constructor
  · rfl
  constructor
  · rfl
  · rfl

theorem rootsMemoryCall_writes_length
    (pkSeed dVal : Nat)
    (openings : Nat -> Nat) :
    (rootsMemoryCall pkSeed dVal openings).writes.length = 27 := by
  simp [rootsMemoryCall, rootBufferWrites, RealTrees, K]

theorem addressMemoryCall_shape (pkSeed pkRoot : Nat) :
    addressMemoryCall pkSeed pkRoot =
      { offset := 0
        size := 0x40
        writes :=
          [ { offset := 0x00, value := pkSeed }
          , { offset := 0x20, value := pkRoot }
          ] } := by
  rfl

theorem memoryRecoverFromDVal_forcedZero_failure
    (pkSeed dVal : Nat)
    (openings : Nat -> Nat)
    (h : forcedZero dVal = false) :
    memoryRecoverFromDVal? pkSeed dVal openings = none := by
  simp [memoryRecoverFromDVal?, h]

theorem memoryRecoverFromDVal_forcedZero_success
    (pkSeed dVal : Nat)
    (openings : Nat -> Nat)
    (h : forcedZero dVal = true) :
    memoryRecoverFromDVal? pkSeed dVal openings =
      some (memoryAddressFromRoot pkSeed (memoryCompressRoots pkSeed dVal openings)) := by
  simp [memoryRecoverFromDVal?, h]

end NiceTry.Fors

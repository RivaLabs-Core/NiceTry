import NiceTry.Fors.RawKeccak

namespace NiceTry.Fors

theorem rawOpeningFields_eq : RawOpeningFields = 6 := by
  rfl

theorem rawOpeningOffset_eq (tree field : Nat) :
    rawOpeningOffset tree field = SectionOffset + tree * TreeLen + field * N := by
  rfl

theorem first_rawOpeningOffset_eq :
    rawOpeningOffset 0 0 = 32 := by
  simp [rawOpeningOffset, SectionOffset, PkSeedOffset, PkSeedLen, ROffset, RLen, TreeLen, N]

theorem second_tree_rawOpeningOffset_eq :
    rawOpeningOffset 1 0 = 128 := by
  simp [rawOpeningOffset, SectionOffset, PkSeedOffset, PkSeedLen, ROffset, RLen, TreeLen, A, N]

theorem first_tree_last_auth_rawOpeningOffset_eq :
    rawOpeningOffset 0 5 = 112 := by
  simp [rawOpeningOffset, SectionOffset, PkSeedOffset, PkSeedLen, ROffset, RLen, TreeLen, N]

theorem last_tree_rawOpeningOffset_eq :
    rawOpeningOffset 24 0 = 2336 := by
  simp [rawOpeningOffset, SectionOffset, PkSeedOffset, PkSeedLen, ROffset, RLen, TreeLen, A, N]

theorem last_tree_last_auth_rawOpeningOffset_eq :
    rawOpeningOffset 24 5 = 2416 := by
  simp [rawOpeningOffset, SectionOffset, PkSeedOffset, PkSeedLen, ROffset, RLen, TreeLen, A, N]

theorem raw_opening_region_ends_at_counter :
    rawOpeningOffset 24 5 + N = CounterOffset := by
  simp [rawOpeningOffset, SectionOffset, PkSeedOffset, PkSeedLen, ROffset, RLen,
    TreeLen, CounterOffset, SectionLen, RealTrees, K, A, N]

theorem rawOpenings_first (raw : RawSig) :
    rawOpenings raw 0 = raw.read16 32 := by
  simp [rawOpenings, rawOpeningAt, rawOpeningOffset, RawOpeningFields,
    SectionOffset, PkSeedOffset, PkSeedLen, ROffset, RLen, TreeLen, N]

theorem rawOpenings_last (raw : RawSig) :
    rawOpenings raw 149 = raw.read16 2416 := by
  simp [rawOpenings, rawOpeningAt, rawOpeningOffset, RawOpeningFields,
    SectionOffset, PkSeedOffset, PkSeedLen, ROffset, RLen, TreeLen, A, N]

theorem memoryRecoverRaw_bad_length
    (raw : RawSig)
    (digest : Nat)
    (h : Not (raw.len = SigLen)) :
    memoryRecoverRaw? raw digest = none := by
  simp [memoryRecoverRaw?, h]

theorem memoryRecoverRaw_good_length
    (raw : RawSig)
    (digest : Nat)
    (h : raw.len = SigLen) :
    memoryRecoverRaw? raw digest =
      memoryRecoverTyped?
        (raw.read16 ROffset)
        (raw.read16 PkSeedOffset)
        digest
        (raw.read16 CounterOffset)
        (rawOpenings raw) := by
  simp [memoryRecoverRaw?, h]

end NiceTry.Fors

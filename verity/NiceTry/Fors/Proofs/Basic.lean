import NiceTry.Fors.Spec

namespace NiceTry.Fors.Proofs.Basic

open NiceTry.Fors
open NiceTry.Fors.Spec

theorem realTrees_eq : RealTrees = 25 := by
  rfl

theorem treeLen_eq : TreeLen = 96 := by
  rfl

theorem sectionLen_eq : SectionLen = 2400 := by
  rfl

theorem sigLen_eq : SigLen = 2448 := by
  rfl

theorem counterOffset_eq : CounterOffset = 2432 := by
  rfl

theorem sectionOffset_eq : SectionOffset = 32 := by
  rfl

theorem counter_end_eq_sigLen : CounterOffset + CounterLen = SigLen := by
  rfl

theorem treeOffset_eq (tree : TreeIndex) :
    treeOffset tree = SectionOffset + tree.val * TreeLen := by
  rfl

theorem authOffset_eq (tree : TreeIndex) (level : AuthLevel) :
    authOffset tree level = treeOffset tree + 16 + level.val * 16 := by
  rfl

theorem first_tree_offset_eq :
    treeOffset (Fin.mk 0 (by decide) : TreeIndex) = 32 := by
  rfl

theorem last_tree_offset_eq :
    treeOffset LastTree = 2336 := by
  rfl

theorem last_auth_offset_eq :
    authOffset LastTree LastAuthLevel = 2416 := by
  rfl

theorem last_auth_end_eq_counterOffset :
    authOffset LastTree LastAuthLevel + 16 = CounterOffset := by
  rfl

theorem decodeTyped_opening_eq (raw : RawSig) (tree : TreeIndex) :
    (decodeTyped raw).openings tree = decodeOpening raw tree := by
  rfl

theorem indexAt_bound (dVal : Word) (tree : Nat) :
    indexAt dVal tree < twoPow A := by
  unfold indexAt
  have hpos : 0 < twoPow A := by
    unfold twoPow A
    decide
  exact Nat.mod_lt _ hpos

theorem omittedIndex_bound (dVal : Word) :
    omittedIndex dVal < twoPow A := by
  unfold omittedIndex
  exact indexAt_bound dVal RealTrees

theorem hMsg_uses_declared_transcript
    (pkSeed r : Hash16)
    (digest : Digest)
    (counter : Counter) :
    hMsg pkSeed r digest counter =
      keccakWord (hMsgTranscript pkSeed r digest counter) := by
  rfl

theorem leafHash_uses_declared_transcript
    (pkSeed sk : Hash16)
    (adrs : Adrs) :
    leafHash pkSeed adrs sk =
      keccakHash16 (leafTranscript pkSeed adrs sk) := by
  rfl

theorem nodeHash_uses_declared_transcript
    (pkSeed left right : Hash16)
    (adrs : Adrs) :
    nodeHash pkSeed adrs left right =
      keccakHash16 (nodeTranscript pkSeed adrs left right) := by
  rfl

theorem rootFields_length (roots : TreeIndex -> Hash16) :
    (rootFields roots).length = RealTrees := by
  rfl

theorem compressRoots_uses_declared_transcript
    (pkSeed : Hash16)
    (roots : TreeIndex -> Hash16) :
    compressRoots pkSeed roots =
      keccakHash16 (rootsTranscript pkSeed roots) := by
  rfl

theorem addressFromRoot_uses_declared_transcript
    (pkSeed pkRoot : Hash16) :
    addressFromRoot pkSeed pkRoot =
      keccakAddress (addressTranscript pkSeed pkRoot) := by
  rfl

theorem recoverRaw_bad_length (raw : RawSig) (digest : Digest)
    (h : Not (raw.len = SigLen)) :
    recoverRaw? raw digest = none := by
  simp [recoverRaw?, h]

theorem decodeRaw_bad_length (raw : RawSig)
    (h : Not (raw.len = SigLen)) :
    decodeRaw raw = none := by
  simp [decodeRaw, h]

theorem decodeRaw_good_length (raw : RawSig)
    (h : raw.len = SigLen) :
    decodeRaw raw = some (decodeTyped raw) := by
  simp [decodeRaw, h]

theorem decodeTyped_reads_header (raw : RawSig) :
    (decodeTyped raw).r = readHash16 raw ROffset /\
    (decodeTyped raw).pkSeed = readHash16 raw PkSeedOffset /\
    (decodeTyped raw).counter = readHash16 raw CounterOffset := by
  simp [decodeTyped]

theorem decodeOpening_reads_tree_fields (raw : RawSig) (tree : TreeIndex) :
    (decodeOpening raw tree).sk = readHash16 raw (treeOffset tree) /\
    (forall level : AuthLevel,
      (decodeOpening raw tree).auth level = readHash16 raw (authOffset tree level)) := by
  simp [decodeOpening]

theorem recoverRaw_decoded_matches_typed
    (raw : RawSig)
    (digest : Digest)
    (sig : TypedSig)
    (hlen : raw.len = SigLen)
    (hdecode : decodeRaw raw = some sig) :
    recoverRaw? raw digest = recoverTyped? sig digest := by
  simp [recoverRaw?, hlen, hdecode]

theorem recoverTyped_forcedZero_success
    (sig : TypedSig)
    (digest : Digest)
    (h : forcedZero (hMsg sig.pkSeed sig.r digest sig.counter) = true) :
    recoverTyped? sig digest =
      some (addressFromRoot sig.pkSeed
        (recoverRoot sig (hMsg sig.pkSeed sig.r digest sig.counter))) := by
  simp [recoverTyped?, h]

theorem legit_signature_recovers_expected_address
    (sig : TypedSig)
    (digest : Digest)
    (pkRoot : Hash16)
    (h : LegitSignatureFor sig digest pkRoot) :
    recoverTyped? sig digest =
      some (addressFromRoot sig.pkSeed pkRoot) := by
  unfold LegitSignatureFor at h
  cases h with
  | intro hzero hroot =>
      simp [recoverTyped?, hzero, hroot]

theorem legit_raw_signature_recovers_expected_address
    (raw : RawSig)
    (digest : Digest)
    (sig : TypedSig)
    (pkRoot : Hash16)
    (hlen : raw.len = SigLen)
    (hdecode : decodeRaw raw = some sig)
    (hlegit : LegitSignatureFor sig digest pkRoot) :
    recoverRaw? raw digest =
      some (addressFromRoot sig.pkSeed pkRoot) := by
  rw [recoverRaw_decoded_matches_typed raw digest sig hlen hdecode]
  exact legit_signature_recovers_expected_address sig digest pkRoot hlegit

theorem recoverTyped_forcedZero_failure
    (sig : TypedSig)
    (digest : Digest)
    (h : forcedZero (hMsg sig.pkSeed sig.r digest sig.counter) = false) :
    recoverTyped? sig digest = none := by
  simp [recoverTyped?, h]

theorem recoverTyped_some_implies_forcedZero
    (sig : TypedSig)
    (digest : Digest)
    (addr : Address)
    (h : recoverTyped? sig digest = some addr) :
    forcedZero (hMsg sig.pkSeed sig.r digest sig.counter) = true := by
  by_cases hz : forcedZero (hMsg sig.pkSeed sig.r digest sig.counter) = true
  · exact hz
  · have hf : forcedZero (hMsg sig.pkSeed sig.r digest sig.counter) = false := by
      cases hval : forcedZero (hMsg sig.pkSeed sig.r digest sig.counter) <;> simp_all
    have hn : recoverTyped? sig digest = none := recoverTyped_forcedZero_failure sig digest hf
    rw [hn] at h
    contradiction

theorem badLengthRejected_holds
    (raw : RawSig)
    (digest : Digest)
    (h : Not (raw.len = SigLen)) :
    BadLengthRejected raw (recoverRaw? raw digest) := by
  intro _
  exact recoverRaw_bad_length raw digest h

theorem forcedZeroRequired_holds
    (sig : TypedSig)
    (digest : Digest) :
    ForcedZeroRequired sig digest (recoverTyped? sig digest) := by
  intro hResult hSome
  cases hAddr : recoverTyped? sig digest with
  | none =>
      simp [hAddr] at hSome
  | some addr =>
      exact recoverTyped_some_implies_forcedZero sig digest addr hAddr

end NiceTry.Fors.Proofs.Basic

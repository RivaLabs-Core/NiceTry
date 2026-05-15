import NiceTry.Fors.Types

namespace NiceTry.Fors

/--
Hash output is still opaque at this layer, but the transcript shape is explicit.
This lets later proofs talk about the exact padding/ADRS/domain inputs without
claiming concrete Keccak values or cryptographic security.
-/
inductive TranscriptField where
  | pad16 : Hash16 -> TranscriptField
  | digest32 : Digest -> TranscriptField
  | adrs32 : Adrs -> TranscriptField
  | domainFors : TranscriptField
deriving DecidableEq, Repr

opaque keccakWord : List TranscriptField -> Word
opaque keccakHash16 : List TranscriptField -> Hash16
opaque keccakAddress : List TranscriptField -> Address

def hMsgTranscript
    (pkSeed : Hash16)
    (r : Hash16)
    (digest : Digest)
    (counter : Counter) :
    List TranscriptField :=
  [.pad16 pkSeed, .pad16 r, .digest32 digest, .domainFors, .pad16 counter]

def leafTranscript
    (pkSeed : Hash16)
    (adrs : Adrs)
    (sk : Hash16) :
    List TranscriptField :=
  [.pad16 pkSeed, .adrs32 adrs, .pad16 sk]

def nodeTranscript
    (pkSeed : Hash16)
    (adrs : Adrs)
    (left right : Hash16) :
    List TranscriptField :=
  [.pad16 pkSeed, .adrs32 adrs, .pad16 left, .pad16 right]

def rootFields (roots : TreeIndex -> Hash16) : List TranscriptField :=
  [
    .pad16 (roots (Fin.mk 0 (by decide))),
    .pad16 (roots (Fin.mk 1 (by decide))),
    .pad16 (roots (Fin.mk 2 (by decide))),
    .pad16 (roots (Fin.mk 3 (by decide))),
    .pad16 (roots (Fin.mk 4 (by decide))),
    .pad16 (roots (Fin.mk 5 (by decide))),
    .pad16 (roots (Fin.mk 6 (by decide))),
    .pad16 (roots (Fin.mk 7 (by decide))),
    .pad16 (roots (Fin.mk 8 (by decide))),
    .pad16 (roots (Fin.mk 9 (by decide))),
    .pad16 (roots (Fin.mk 10 (by decide))),
    .pad16 (roots (Fin.mk 11 (by decide))),
    .pad16 (roots (Fin.mk 12 (by decide))),
    .pad16 (roots (Fin.mk 13 (by decide))),
    .pad16 (roots (Fin.mk 14 (by decide))),
    .pad16 (roots (Fin.mk 15 (by decide))),
    .pad16 (roots (Fin.mk 16 (by decide))),
    .pad16 (roots (Fin.mk 17 (by decide))),
    .pad16 (roots (Fin.mk 18 (by decide))),
    .pad16 (roots (Fin.mk 19 (by decide))),
    .pad16 (roots (Fin.mk 20 (by decide))),
    .pad16 (roots (Fin.mk 21 (by decide))),
    .pad16 (roots (Fin.mk 22 (by decide))),
    .pad16 (roots (Fin.mk 23 (by decide))),
    .pad16 (roots (Fin.mk 24 (by decide)))
  ]

def rootsTranscript
    (pkSeed : Hash16)
    (roots : TreeIndex -> Hash16) :
    List TranscriptField :=
  [.pad16 pkSeed, .adrs32 { adrsType := .forsRoots }] ++ rootFields roots

def addressTranscript
    (pkSeed pkRoot : Hash16) :
    List TranscriptField :=
  [.pad16 pkSeed, .pad16 pkRoot]

def hMsg
    (pkSeed : Hash16)
    (r : Hash16)
    (digest : Digest)
    (counter : Counter) :
    Word :=
  keccakWord (hMsgTranscript pkSeed r digest counter)

def leafHash
    (pkSeed : Hash16)
    (adrs : Adrs)
    (sk : Hash16) :
    Hash16 :=
  keccakHash16 (leafTranscript pkSeed adrs sk)

def nodeHash
    (pkSeed : Hash16)
    (adrs : Adrs)
    (left right : Hash16) :
    Hash16 :=
  keccakHash16 (nodeTranscript pkSeed adrs left right)

def compressRoots
    (pkSeed : Hash16)
    (roots : TreeIndex -> Hash16) :
    Hash16 :=
  keccakHash16 (rootsTranscript pkSeed roots)

def addressFromRoot
    (pkSeed : Hash16)
    (pkRoot : Hash16) :
    Address :=
  keccakAddress (addressTranscript pkSeed pkRoot)

end NiceTry.Fors

import NiceTry.Fors.TreeKeccak

namespace NiceTry.Fors

/-
Typed full FORS+C verifier model at the EVM memory-transcript boundary.

The raw byte parser is intentionally still outside this layer. Inputs are the
typed verifier-visible words:

* `r`, `pkSeed`, and `counter` as 16-byte top-half words,
* `digest` as a full bytes32 word,
* 25 real FORS openings, each `(sk, auth0..auth4)`.

This layer adds the pieces that were not present in the one-tree kernel:
Hmsg, omitted-tree grinding check, 25 tree roots, roots compression, and final
address derivation.
-/

def OpeningWords : Nat := RealTrees * 6
def RootBufferStart : Nat := 0x40
def RootsAdrsOffset : Nat := 0x20
def RootsHashLen : Nat := (K + 1) * 32
def AddressHashLen : Nat := 0x40
def HMsgHashLen : Nat := 0xa0
def ForsDomainWord : Nat :=
  0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD
def ForsRootsAdrsWord : Nat := 4 * 2 ^ 128
def Lower160Mask : Nat := 2 ^ 160 - 1

opaque keccakWordFromMemory : KeccakMemoryCall -> Word
opaque keccakAddressFromMemory : KeccakMemoryCall -> Address

def hMsgMemoryCall (pkSeed r digest counter : Nat) : KeccakMemoryCall :=
  { offset := 0
    size := HMsgHashLen
    writes :=
      [ { offset := 0x00, value := pkSeed }
      , { offset := 0x20, value := r }
      , { offset := 0x40, value := digest }
      , { offset := 0x60, value := ForsDomainWord }
      , { offset := 0x80, value := counter }
      ] }

def memoryHMsg (pkSeed r digest counter : Nat) : Word :=
  keccakWordFromMemory (hMsgMemoryCall pkSeed r digest counter)

def openingWord (openings : Nat -> Nat) (tree field : Nat) : Nat :=
  openings (tree * 6 + field)

def openingSk (openings : Nat -> Nat) (tree : Nat) : Nat :=
  openingWord openings tree 0

def openingAuth (openings : Nat -> Nat) (tree level : Nat) : Nat :=
  openingWord openings tree (level + 1)

def rootBufferWrite
    (pkSeed dVal : Nat)
    (openings : Nat -> Nat)
    (tree : Nat) :
    MemoryWord :=
  { offset := RootBufferStart + tree * 32
    value :=
      memoryTreeRootFromDVal
        pkSeed dVal tree
        (openingSk openings tree)
        (openingAuth openings tree 0)
        (openingAuth openings tree 1)
        (openingAuth openings tree 2)
        (openingAuth openings tree 3)
        (openingAuth openings tree 4) }

def rootBufferWrites
    (pkSeed dVal : Nat)
    (openings : Nat -> Nat) :
    List MemoryWord :=
  (List.range RealTrees).map (rootBufferWrite pkSeed dVal openings)

def rootsMemoryCall
    (pkSeed dVal : Nat)
    (openings : Nat -> Nat) :
    KeccakMemoryCall :=
  { offset := 0
    size := RootsHashLen
    writes :=
      [ { offset := 0x00, value := pkSeed }
      , { offset := RootsAdrsOffset, value := ForsRootsAdrsWord }
      ] ++ rootBufferWrites pkSeed dVal openings }

def memoryCompressRoots
    (pkSeed dVal : Nat)
    (openings : Nat -> Nat) :
    Hash16 :=
  keccakHash16FromMemory (rootsMemoryCall pkSeed dVal openings)

def addressMemoryCall (pkSeed pkRoot : Nat) : KeccakMemoryCall :=
  { offset := 0
    size := AddressHashLen
    writes :=
      [ { offset := 0x00, value := pkSeed }
      , { offset := 0x20, value := pkRoot }
      ] }

def memoryAddressFromRoot (pkSeed pkRoot : Nat) : Address :=
  keccakAddressFromMemory (addressMemoryCall pkSeed pkRoot)

def memoryRecoverFromDVal?
    (pkSeed dVal : Nat)
    (openings : Nat -> Nat) :
    Option Address :=
  if forcedZero dVal then
    some (memoryAddressFromRoot pkSeed (memoryCompressRoots pkSeed dVal openings))
  else
    none

def memoryRecoverTyped?
    (r pkSeed digest counter : Nat)
    (openings : Nat -> Nat) :
    Option Address :=
  memoryRecoverFromDVal? pkSeed (memoryHMsg pkSeed r digest counter) openings

end NiceTry.Fors

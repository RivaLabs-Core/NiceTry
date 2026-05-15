import NiceTry.Fors.Model

namespace NiceTry.Fors.Spec

open NiceTry.Fors

def TypedRecoverSpec (sig : TypedSig) (digest : Digest) (result : Option Address) : Prop :=
  result = recoverTyped? sig digest

def RawRecoverSpec (raw : RawSig) (digest : Digest) (result : Option Address) : Prop :=
  result = recoverRaw? raw digest

def BadLengthRejected (raw : RawSig) (result : Option Address) : Prop :=
  Not (raw.len = SigLen) -> result = none

def ForcedZeroRequired (sig : TypedSig) (digest : Digest) (result : Option Address) : Prop :=
  result = recoverTyped? sig digest ->
    result.isSome = true ->
      forcedZero (hMsg sig.pkSeed sig.r digest sig.counter) = true

def ForcedZeroSuccessAddress (sig : TypedSig) (digest : Digest) (addr : Address) : Prop :=
  let dVal := hMsg sig.pkSeed sig.r digest sig.counter
  forcedZero dVal = true ->
    addr = addressFromRoot sig.pkSeed (recoverRoot sig dVal)

def LegitSignatureFor (sig : TypedSig) (digest : Digest) (pkRoot : Hash16) : Prop :=
  let dVal := hMsg sig.pkSeed sig.r digest sig.counter
  forcedZero dVal = true /\
    recoverRoot sig dVal = pkRoot

def RawLegitSignatureFor (raw : RawSig) (digest : Digest) (pkRoot : Hash16) : Prop :=
  Exists fun sig : TypedSig =>
    raw.len = SigLen /\
      decodeRaw raw = some sig /\
        LegitSignatureFor sig digest pkRoot

end NiceTry.Fors.Spec

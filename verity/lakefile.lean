import Lake
open Lake DSL

package NiceTryForsVerity where
  version := v!"0.1.0"

require verity from git
  "https://github.com/lfglabs-dev/verity.git"@"bd211c574f45cda31d66feab1bbc7e9d08dc5486"

lean_lib NiceTry where
  srcDir := "."
  roots := #[
    `NiceTry.Fors.Types,
    `NiceTry.Fors.Hash,
    `NiceTry.Fors.Model,
    `NiceTry.Fors.TreeShape,
    `NiceTry.Fors.TreeKeccak,
    `NiceTry.Fors.FullKeccak,
    `NiceTry.Fors.RawKeccak,
    `NiceTry.Fors.Spec,
    `NiceTry.Fors.Proofs.Basic,
    `NiceTry.Fors.Proofs.TreeShape,
    `NiceTry.Fors.Proofs.TreeKeccak,
    `NiceTry.Fors.Proofs.FullKeccak,
    `NiceTry.Fors.Proofs.RawKeccak,
    `NiceTry.Fors.Verity.GuardKernel,
    `NiceTry.Fors.Verity.TreeShapeKernel,
    `NiceTry.Fors.Verity.TreeKeccakKernel,
    `NiceTry.Fors.Verity.FullVerifierKernel
  ]

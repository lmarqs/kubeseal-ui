# Documentation

## Reference

- [CLI I/O contract](reference/cli-io-contract.md) — which stream carries what,
  the exit codes, when `ksui` prompts, and how its flags line up with kubeseal's.

## Decisions

Architecture decision records, one per decision, in the order they were made.

- [1. Seal in-process instead of shelling out to kubeseal](adr/0001-seal-in-process.md)
- [2. Dependency pins for sealed-secrets and the Charm stack](adr/0002-dependency-pins.md)
- [3. Package layout](adr/0003-package-layout.md)
- [4. Seal through NewSealedSecret rather than kubeseal.Seal](adr/0004-sealing-entry-point.md)

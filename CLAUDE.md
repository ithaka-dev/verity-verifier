# verity-verifier — agent instructions

**This repository implements decisions made in
[verity-foundation](https://github.com/ithaka-dev/verity-foundation/blob/main/../..). It does not make them.**

Before substantive work, read:
1. [`docs/Verity-spec.md`](https://github.com/ithaka-dev/verity-foundation/blob/main/docs/Verity-spec.md) — §7 holds the ten invariants
2. [`docs/decisions/`](https://github.com/ithaka-dev/verity-foundation/blob/main/docs/decisions) — the ADRs listed below bind this repo directly
3. [`plan.md`](https://github.com/ithaka-dev/verity-foundation/blob/main/plan.md) — where this repo's issues sit in the sequence

**If something here seems undecided, it probably isn't.** Search the ADRs before deciding it in a
pull request. If it is genuinely undecided, it belongs in an ADR upstream — not in code here.

## Binding decisions

[ADR 0006](https://github.com/ithaka-dev/verity-foundation/blob/main/docs/decisions/0006-appmanifest-version-record.md) ·
[ADR 0007](https://github.com/ithaka-dev/verity-foundation/blob/main/docs/decisions/0007-compose-must-pin-digests.md) ·
[ADR 0009](https://github.com/ithaka-dev/verity-foundation/blob/main/docs/decisions/0009-verification-model.md) ·
[ADR 0014](https://github.com/ithaka-dev/verity-foundation/blob/main/docs/decisions/0014-verifier-update-discipline.md)

## The verification sequence (ADR 0009)

1. Fetch the published `app-compose.json` via `composeURI`
2. `sha256(compose)` == the licensed `composeHash`
3. The compose pins the licensed `imageDigest` and contains **no tag references**
4. Verify the quote's DCAP signature chain up to Intel
5. `expected_mrconfigid = 0x01 ‖ licensed_composeHash ‖ 0x00 × 15` — **branch on the prefix byte, never assume `0x01`**
6. Compare `MRTD` and `RTMR0–2` against references for the expected OS image
7. **Do not compare `RTMR3`** — `mr-kms` varies per boot, so no reference exists

## Three rules that will be violated under deadline pressure

- **Never loosen a check to resolve a mismatch.** Rule 7 guarantees someone sees spurious failures. Relaxing the comparison until they pass converts this library into decoration while everything appears to keep working. Narrow *what* is compared to legitimately stable values; never weaken *how strictly*.
- **Never consume a provider's parsed `tcb_info`.** Parse the raw quote from the RA-TLS leaf certificate. The API is for dashboards; this library trusts Intel's signature, not Phala's rendering of it.
- **Never return a bare boolean.** Verdicts carry version, reference-data date, and which checks ran — that is what makes a loosened verifier detectable (ADR 0014).

## Test fixtures

Real TDX quotes, event logs and compose documents are committed at
[`records/experiments/artifacts/`](https://github.com/ithaka-dev/verity-foundation/blob/main/records/experiments/artifacts) — measured, not mocked. Use them.

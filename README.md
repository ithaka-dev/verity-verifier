# verity-verifier

> ## 🚧 Not functional — do not adopt
>
> This repository is **scaffolding**. It does not yet do the thing its description says it does.
> Nothing here is ready to depend on, build against, or copy.
>
> **This matters more here than elsewhere.** A verifier that does not yet verify is worse
> than no verifier: it returns answers that look authoritative and are not. Until this banner is
> gone, **no attestation result from this code means anything.** Do not wire it into anything that
> makes a trust decision.
>
> **Readiness is per-repo and will be announced by removing this banner** and tagging a release.
> Until then, treat anything here as subject to change without notice — including its public
> interface, its behaviour, and its existence.
>
> Sequence and current position: [`plan.md`](https://github.com/ithaka-dev/verity-foundation/blob/main/plan.md).

**The crown jewel.** Agent-side attestation verification: given an endpoint, its evidence, and a licensed version record, decide whether what is running is what was licensed — and refuse on mismatch.

**Language:** Rust (+ WASM and Node bindings)
**Phase:** 1a of the [implementation plan](https://github.com/ithaka-dev/verity-foundation/blob/main/plan.md)

---

## Read before contributing

Every constraint that makes Verity work lives in
**[verity-foundation](https://github.com/ithaka-dev/verity-foundation)** — the specification, the
architecture decisions, the invariants, and the measured facts they rest on. This repository holds
an implementation of decisions made there, not the decisions themselves.

- [Specification](https://github.com/ithaka-dev/verity-foundation/blob/main/docs/Verity-spec.md) — start here; §7 holds the invariants
- [Decisions (ADRs)](https://github.com/ithaka-dev/verity-foundation/tree/main/docs/decisions) — why things are the way they are
- [`CLAUDE.md`](CLAUDE.md) — what binds *this* repository specifically

**If a decision seems missing, it probably isn't — go and find it.** If it genuinely is missing,
it belongs in an ADR in `verity-foundation`, not in a pull request here.

## Boundary

Verification happens **here or nowhere**. If this step is skipped or weakened, the whole system degrades to "login plus a container spawn" (spec §4.5).

- Parses the **raw TDX quote** from the RA-TLS leaf certificate. **Never** a cloud provider's parsed `tcb_info` — that trusts the provider's rendering of the hardware's statement, where the raw quote trusts Intel's signature over the statement itself ([ADR 0009](https://github.com/ithaka-dev/verity-foundation/blob/main/docs/decisions/0009-verification-model.md)).
- A verdict is **never a bare boolean** — it carries the verifier version, reference-data date, and which checks actually ran ([ADR 0014](https://github.com/ithaka-dev/verity-foundation/blob/main/docs/decisions/0014-verifier-update-discipline.md)).
- **Never loosen a check to resolve a mismatch.** `mr-kms` varies per boot, so spurious mismatches are guaranteed; relaxing the comparison until they pass converts this library into decoration while everything appears to keep working.

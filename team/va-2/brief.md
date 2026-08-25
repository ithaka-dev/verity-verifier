# Brief — VA-2: the proof-carrying verdict type is publicly forgeable

**Repo:** `verity-verifier` @ `32307b1` · **Issue:** VA-2 (audit finding VV-02, Medium) ·
**Board:** `verity-foundation/audit-implementation-plan.md`

## The issue (two separable parts)

`Verdict::new`, `Verdict::record`, and `TrustworthyVerdict::check` are all public
(`crates/verity-verifier/src/verdict.rs:603,614,811`). Consequences:

1. **Fabrication.** A caller can `fold` `Outcome::Passed` over `Check::essential()` and get a verdict
   that returns `is_trustworthy() == true` and passes `TrustworthyVerdict::check` — with no evidence
   examined. Reproduced 2026-08-25.
2. **Contradiction.** `Verdict::outcome` returns the **first** recorded result for a check
   (`verdict.rs:648-653`, `.find(...)`). `is_trustworthy()` → `missing_essentials()` → `outcome()`, so
   appending a later `Failed` for an already-`Passed` essential leaves a verdict that is
   simultaneously `is_trustworthy() == true` **and** lists that failure in `failures()`. Reproduced
   2026-08-25.

## What is and isn't already contained

- **`VerifiedClient` is not affected.** Its constructor is private and cannot be built from a
  fabricated verdict — that containment holds and is not in scope to change.
- **Part 2 is an internal-coherence bug under any reading.** A value that is both "trustworthy" and
  "has a failure" is incoherent regardless of how anyone reads the type. **This must be fixed.** The
  existing test `tests/verdict_semantics.rs:129 recording_a_check_twice_keeps_the_first` documents
  first-wins as *"the behaviour that exists, not the behaviour that is desirable… if the semantics
  are ever made last-wins, or duplicates rejected outright, this test should change with it — it is
  here so that change is deliberate rather than accidental."* The door is explicitly held open.
- **Part 1 is a design/doc decision, not a clear bug.** `TrustworthyVerdict::check` is **deliberately
  public** (its doc: raw-`verify()` callers — auditors, pre-purchase — "get the same affordance
  without a TCP stack") and **deliberately ungated** ("so the WASM bindings can adopt it later without
  a feature"). The type already documents its guarantee narrowly: *"What it does not establish: that
  the evidence came from the connection you are using."* So it is honestly a **content-judgment**
  ("this verdict's transcript shows every essential passed"), with provenance living only in
  `connect_verified`/`VerifiedClient`. The audit's worry is that downstream consumers (telemetry,
  audit storage, offline tooling) read it as "real verification happened." The architect must decide
  and recommend which guarantee the type should carry, and whether/how to make forgery harder without
  breaking the two deliberate design choices above.

## The load-bearing constraint (measured 2026-08-25)

**The WASM crate assembles verdicts check-by-check across the crate boundary.**
`crates/verity-verifier-wasm/src/lib.rs` calls `Verdict::new()` and `.record(...)` ~30 times (lines
299–405) to build the compose-only verdict — a path that *deliberately* produces an **untrustworthy**
verdict (it records `TcbStatus`/`QuoteSignature` as `Skipped`, and its module doc states compose-only
"remains untrustworthy"). So:

- Making `Verdict::new`/`record` simply crate-private (the audit's "preferred" remedy) **breaks the
  wasm crate**. This is the audit's "if external custom assembly is a required feature" branch — and
  it is required, by a first-party consumer.
- Note the wasm assembler never needs to *forge trust* — it builds a transcript and never calls
  `TrustworthyVerdict::check` to claim trust. The fabrication risk is specifically about *minting a
  `TrustworthyVerdict`*, not about *assembling a `Verdict`*.

## Blast radius

- **Source:** `src/verdict.rs` (the surface); `src/verify.rs` and `src/connect/http.rs` build verdicts
  internally via `new`/`record`; `wasm/src/lib.rs` builds them cross-crate.
- **`TrustworthyVerdict::check` callers:** `src/connect/http.rs:190` (the real assembled path), plus
  tests (`trustworthy_verdict.rs`, `verified_transport.rs:759`).
- **Tests that construct verdicts by hand** (must keep working, or move to a sanctioned test-only
  constructor): `tests/verdict_semantics.rs` (many), `tests/trustworthy_verdict.rs`,
  `tests/reference_and_verdict.rs`, `tests/verified_transport.rs`, `tests/transcript_contract.rs`,
  and the wasm crate's own `#[cfg(test)]` at `wasm/src/lib.rs:706+`.

## Acceptance criteria

1. **Part 2 fixed and pinned.** A verdict cannot be simultaneously `is_trustworthy()` and carry a
   failure/indeterminate for an essential. Architect picks the mechanism — reject duplicate records,
   or make a later `Failed`/`Indeterminate` permanently dominate a prior `Passed` — with the reasoning
   for which. `recording_a_check_twice_keeps_the_first` is updated deliberately (its own doc says to).
   Consider whether the `Indeterminate` exclusion from `failures()` interacts (an essential
   `Indeterminate` already makes a verdict untrustworthy via `missing_essentials`, so coherence must
   hold for it too).
2. **Part 1 addressed with an explicit, defended decision.** Either (a) the guarantee is narrowed to
   a content-judgment and the docs/type made airtight about it (provenance is `VerifiedClient`'s job),
   and/or (b) minting a `TrustworthyVerdict` is made harder for a downstream forger (e.g. a witness
   only the crate's own check functions can produce; a sanctioned assembler) **without** making
   `Verdict` un-assemblable by the wasm crate and **without** removing the raw-`verify()` audit
   affordance. If the honest answer is (a), say so and make the contract unambiguous rather than
   adding ceremony that buys nothing. If the architect concludes the choice turns on a **product**
   question the team cannot settle from existing decisions, escalate it to the user with a
   recommendation — do not guess.
3. **WASM path still compiles and behaves identically** (still produces an untrustworthy compose-only
   verdict; no new feature required to build it).
4. **Regression tests, seen-to-fail.** Both reproductions from the audit (fabrication; contradiction)
   become permanent tests, each demonstrated **red on the current tree first** then green after —
   except any part whose fix is doc-only, which is stated as such.

## Discipline & constraints

- **Seen-to-fail first** (CLAUDE.md): every guarding test red on the current tree before green.
- **ADR 0019:** commit directly to `main`; review record in the commit message. **ADR 0018:** reviewer
  sign-off is the gate. **ADR 0026:** this cycle (architect → developer → blind reviewer).
- **Do not disturb VA-1 or ADR 0035:** the `Outcome` enum contract (`Passed | Failed | Skipped |
  Indeterminate { .. }`), the `AttestedTcb` provenance surface, and `is_trustworthy()`'s definition
  (`missing_essentials().is_empty()`) all just landed at `32307b1` — a change to dominance semantics
  touches `outcome()`/`missing_essentials()`, so verify it does not regress VA-1's tests or the
  disposition table.
- Toolchain: local clippy needs `-A clippy::chunks_exact_to_as_chunks` (pre-existing lint on untouched
  `binding.rs`/`quote.rs`), allow nothing else. `wasm32-unknown-unknown` can't build locally (no
  rustup) — CI-only; but the wasm crate *does* typecheck on host via `cargo check -p verity-verifier-wasm`.
- Team artifacts under `team/va-2/`; leave `team/`, `team/va-1/` intact.

## Assumption (flag if wrong)

- Fixing part 2 by changing duplicate/dominance semantics does not break a legitimate internal caller
  that *relies* on first-wins. The internal builders in `verify.rs`/`http.rs` record each check
  exactly once on a given path, so dominance should be inert for them — but the architect must confirm
  no path records an essential twice by design (e.g. an error branch that overwrites).

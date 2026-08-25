# Critique — VA-2: the proof-carrying verdict type is publicly forgeable

**Reviewer:** va2-developer · **Against:** `team/va-2/design.md` (va2-architect) · **Repo state:** `32307b1` clean

Method: read `verdict.rs`, `verify.rs`, `connect/http.rs`, `wasm/src/lib.rs` (both the assembler and its
`#[cfg(test)]` block), `tests/verdict_semantics.rs`, `tests/trustworthy_verdict.rs`. Then **empirically**
verified the seen-to-fail and inertness claims rather than taking them on the design doc's word: added
scratch tests, ran them, reverted; then applied the exact proposed `outcome()` body to `verdict.rs`, ran
`cargo test -p verity-verifier --all-features` and `cargo check -p verity-verifier-wasm`, and reverted
(`git status` confirms clean — only `team/va-2/` untracked). Transcripts below.

---

## Part 2 — non-pass-dominates

### AGREE, with one AMEND on the doc claim (not the mechanism)

**(a) Order-independent for the trust question — verified, not just read.** Applied the design's exact
`outcome()` body and ran the full suite with `--all-features`: 29/29 in `verdict_semantics.rs` except the
one test the design says must flip, 22/22 lib unit tests (`verify::tests`, `connect::http::tests`,
`connect::tls::tests`, `verdict::tcb_acceptance_tests`), 18/18 `verified_transport.rs`, 14/14
`verify_negative.rs`, 12/12 `reference_and_verdict.rs`, 5/5 `transcript_contract.rs`, 3/3
`tcb_enforcement.rs`. `cargo check -p verity-verifier-wasm` still succeeds. This is real confirmation of
AC 3 and of "does not regress VA-1/ADR 0035," not an inference from reading the diff.

**(b) Inert for every production and wasm path — confirmed by code, not just the assumption.** Read
`verify.rs` top to bottom: every `Check` is recorded exactly once per execution path — the
`VerifiedCompose::check` / `images::*` / `record_attestation` / `Quote::parse` branches are all mutually
exclusive `match` arms, none of which records the same `Check` twice on one path. `record_attestation`'s
three arms each record `QuoteSignature`+`TcbStatus` exactly once. Same structure in
`crates/verity-verifier-wasm/src/lib.rs`'s `compose_only_verdict` (lines 290–408): every `Check` recorded
once per branch. `connect/http.rs` never calls `Verdict::record` itself — it delegates entirely to
`verify::verify`. So the brief's assumption holds, confirmed rather than merely re-asserted.

**(c) Does not regress VA-1/ADR 0035 — confirmed empirically** (see the full-suite run above): the TCB
disposition table (`the_disposition_table_is_pinned_by_literal_not_by_rederivation`), the degraded-status
tests in `verify.rs`'s own `#[cfg(test)]`, and every MA-6 `Indeterminate`/disposition test all stayed
green under the change.

**(d) `failures()`/`results()`/`dispositions()`/`Display` iterate the raw vector, unaffected — confirmed
by code read**, and important to be precise about which method: `Verdict::dispositions()` (**plural**)
maps `self.results` directly and never calls `outcome()`, so it is genuinely untouched — it will still
list a `Disposition` **per raw record**, including for a duplicate. `Verdict::disposition()` (**singular**,
taking one `Check`) *does* call `self.outcome(check)`, and *should* — that's correct, it's how the
dominant reading of a single check's remedy stays coherent with `is_trustworthy()`. Worth stating this
distinction explicitly in review notes since the names are one letter apart and easy to conflate.

### A real, concrete hole — worth naming, not blocking

The brief asked directly: *"two different non-Passed records for one check — Failed then Skipped — which
wins, and does it matter?"* It does matter, and the design's own prose slightly overclaims:

```rust
if !matches!(o, Outcome::Passed) {
    return Some(o); // first non-pass dominates
}
```

This returns on the **first** non-pass encountered while walking `results` in insertion order — not
"last recorded," not any severity-ranked priority. So when a check has **two or more distinct non-pass
records** (e.g. `Indeterminate` recorded first, then `Skipped` recorded second — a shape the assumption
rules out for every real path, but that the public `record()` builder does not prevent), `outcome()`
returns whichever came first in the vector, and that choice flows into `disposition(check)`:
`Indeterminate{VerifierCannotJudge}` disposition is `UpdateVerifier`; `Skipped` on an essential
dispositions to `Refuse`. Swap the recording order and the caller-facing remedy advice changes, even
though `is_trustworthy()` stays `false` either way.

There's a sharper version of this too: if the two non-pass records are `Skipped` then `Failed`,
`outcome()` returns `Skipped`, but `failures()` (raw scan) *still* lists the `Failed` entry — so a
consumer reading `outcome(check)` and a consumer reading `failures()` can again disagree about what
happened to that check, on this specific double-non-pass shape. That's a narrower recurrence of the exact
incoherence pattern this fix exists to close, just confined to a case (two non-pass records for one
check) that this issue never asked to fix and no real path produces.

**Disposition:** not a blocker. The mechanism correctly and provably closes the literal audit finding
(`Passed` + a later non-pass), which is the only shape any real code path can produce, confirmed above.
I don't think the mechanism needs a severity-ranked tiebreak (`Failed > Indeterminate > Skipped`) for a
case that's unreachable in practice — that would be complexity bought for a scenario nothing can trigger.
**AMEND requested:** tighten the doc comment. "Order-independent for the trust question" is true and
should stay; "inert for every real path" is true and confirmed above. But drop or qualify the unqualified
"order-independent" framing at the top of the design doc's Decision section, and add one sentence to the
`outcome()` doc naming this residual case explicitly (something like: *"Among multiple non-pass records
for the same check — never produced by any builder in this crate today — the first encountered wins;
`failures()` still lists every `Failed` record regardless, so a hand-built verdict with two different
non-pass records for one check can still show `outcome()` and `failures()` disagreeing. No real path
constructs one."*). Cheap to add, and it's exactly the kind of claim a future reader will otherwise
over-trust.

**Rejected sub-options — agree with rejecting both, for the stated reasons.** Fallible/panicking
`record()` breaks ~30 wasm call sites and the fold-style test-building idiom for a landmine that helps
nothing (a forger calling `record()` directly controls their own panic, so it isn't even a defense).
Silent-drop-at-record-time keeps the vector coherent but **fails open** on exactly the shape this issue
is about — a later refusal recorded over an earlier pass would vanish rather than dominate. Correctly
rejected.

**`recording_a_check_twice_keeps_the_first` rewrite — confirmed, not just read.** Ran the suite with the
mechanism applied: this is the *only* test that flips (`left: Some(Failed("this is ignored")), right:
Some(Passed)` — i.e. `outcome()` now returns the non-pass). `results().len() == 2` and the `failures()`
non-empty assertion are unaffected by the change (neither is touched by `outcome()`), matching the
design's claim that those two assertions can stay as-is in the rewritten test.

---

## Part 1 — fabrication: AGREE with (a)-alone, one AMEND on doc content, no escalation needed

**On the core call.** I agree the real security boundary is `VerifiedClient`'s private constructor, that
it is untouched by this forgery, and that `TrustworthyVerdict` is honestly a content-judgment. Argument 4
is the one that actually settles it for me, and I want to restate why it's decisive rather than just
citing it: a witness scoped to "only the crate's own check functions can produce it" does **not** raise
the bar against a realistic forger, because the strictly easier and already-open route to a false
"witnessed, trustworthy" verdict is not touching `Verdict::record` at all — it's calling the real,
public `verify()` with `Evidence` the caller assembled (a recorded/replayed quote next to a certificate
the caller controls, or replayed collateral). `verify()` performs no I/O and, per its own module doc,
"trusts whatever it's handed." A witness minted on `verify()` success would happily mint one here too,
and it would look *more* trustworthy to a downstream consumer than a bare hand-assembled `Verdict`
precisely because it carries the witness. So the witness doesn't close the gap the audit is worried about
— it relabels a document that was already forgeable through the front door, and the relabelling reads as
reassurance. That's the "manufactures false confidence" failure named in the design, and I'd call it a
correct, not merely defensible, conclusion. I don't think this needs escalation to the user: it's
settled by an existing design fact (`verify()` is deliberately I/O-free and evidence-agnostic, and must
stay public per this same brief), not a new product tradeoff.

**AMEND — the doc block should name both forgery routes, not just one.** The proposed rustdoc says:

> A caller can hand-assemble a `Verdict` of all-`Passed` records and wrap it; the wrapper reports what
> the transcript says, and the transcript is only as honest as whoever built it.

That's route 1 (hand-built `Verdict`). It doesn't name route 2 (a real `verify()` call fed
caller-controlled/replayed `Evidence`), even though route 2 is the one that defeats the witness idea in
argument 4 and is, if anything, the more dangerous one — it produces output indistinguishable from a
genuine verification by every existing accessor. `verify()`'s own doc already says as much ("a caller who
supplies one obtained anywhere else gets a truthful verdict about a connection they are not using"), but
a downstream consumer who only ever sees a stored/serialized `TrustworthyVerdict` — telemetry, audit
storage, offline tooling, exactly the audience VA-2 is about — is not the audience reading `verify()`'s
doc. I'd add a third bullet under "What it does NOT prove":

```text
/// - That `verify()`, even if it produced this verdict, was given evidence tied to a connection
///   anyone currently holds. `verify()` performs no I/O and trusts whatever `Evidence` it is handed —
///   a caller can replay a recorded quote beside a certificate they control and get a truthful verdict
///   about a connection nobody is using. This is why a "was this witnessed by our own check code"
///   marker would not close this gap: the easier and equally undetectable forgery never touches
///   `Verdict::record` at all.
```

Doc-only, no code or API change, consistent with the design's own "airtight contract, no ceremony"
framing — this just makes the contract airtight against the specific argument the design itself uses to
reject (b), rather than leaving that argument implicit in `design.md` where a downstream reader will
never see it.

**T-D pin — agree.** Treating "no public path from `TrustworthyVerdict` to `VerifiedClient`" as a
doc-invariant next to the private constructor, rather than forcing a runtime test for a compile-time
property, is the right call — there is no way to write a meaningful `#[test]` for "no public
constructor exists" that isn't `assert!(true)` dressed up.

---

## Verdict summary

| Decision | Position |
|---|---|
| Part 2 mechanism (non-pass-dominates in `outcome()`) | **AGREE** — verified inert on every real path by actually applying it and running the full suite + wasm typecheck, not just reading the diff |
| Part 2 doc claim "order-independent" | **AMEND** — true for the trust question, not true for `outcome()`'s specific value when a check carries ≥2 distinct non-pass records (unreachable today); add one qualifying sentence |
| Rejected sub-options (fallible/panicking `record`, silent-drop) | **AGREE** with rejecting both |
| `recording_a_check_twice_keeps_the_first` rewrite | **AGREE** — confirmed it's the only test the change flips |
| Part 1 recommendation: (a)-alone, no witness | **AGREE** — argument 4 is correct and decisive, not just defensible; no user escalation needed |
| Part 1 doc deliverable | **AMEND** — add a bullet naming the `verify()`-with-replayed-evidence route explicitly, not just hand-assembly |
| T-A / T-B (seen-to-fail) | **CONFIRMED red-first empirically** (ran both against current tree) |
| T-C (order-independence, Failed/Passed swapped) | Not run directly, but follows immediately from the confirmed mechanism — low risk |
| T-D (characterization pin, doc-invariant not runtime test) | **AGREE** |

No objections that block moving to implementation. Two AMENDs, both doc text, both cheap, both concrete.

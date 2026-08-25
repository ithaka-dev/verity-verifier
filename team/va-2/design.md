# Design — VA-2: the proof-carrying verdict type is publicly forgeable

**Repo:** `verity-verifier` @ `32307b1` · **Issue:** VA-2 (audit VV-02, Medium) ·
**Cycle:** ADR 0026 rust-team (architect → developer → blind reviewer) · **Author:** va2-architect

---

## Decision, up front

- **Part 2 (contradiction) — a real bug, fixed by changing one accessor.** `Verdict::outcome()`
  stops returning the *first* recorded result and returns a **non-`Passed` record in preference to a
  `Passed` one** ("non-pass dominates"). This makes it structurally impossible for a verdict to be
  `is_trustworthy() == true` while an essential also carries a `Failed`/`Skipped`/`Indeterminate`
  record. It is **order-independent for the trust question** (any non-pass sinks it, whatever the
  order) and **inert for every real path**, because every production and wasm builder records each
  check exactly once. The one thing it does *not* fix an order for — which of two *different*
  non-pass records `outcome()` reports — is unreachable on any real path and never changes the trust
  answer.

- **Part 1 (fabrication) — recommendation (a) alone: narrow the guarantee and make the contract
  airtight. Do not add a witness/sanctioned assembler.** `TrustworthyVerdict` is, and should remain,
  a **content-judgment** — "this transcript shows every essential check ran and passed" — and nothing
  more. Provenance (that the evidence came from a live connection you are using) lives only in
  `VerifiedClient`, whose constructor is private and is *not in scope to change*. A witness that only
  the crate's own `verify()` could mint would not close the audit's worry; it would manufacture
  exactly the provenance confidence the type still cannot honestly carry (see §Part 1, argument 4),
  at real cost to the value type and to the wasm/test assembly story. **This is doc/contract-only.**
  I do **not** think this needs user escalation — the design intent is already consistent and points
  to (a) — but I flag the witness question as the one decision I was least sure about (§Least sure).

Neither part changes `Verdict::new`/`record` visibility, so the wasm crate's ~30 cross-crate
assembly calls and every hand-building test keep compiling unchanged (AC 3).

---

## Part 2 — contradiction (must fix)

### The bug, precisely

`Verdict` stores `results: Vec<(Check, Outcome)>`. Two accessors resolve that vector by *different*
strategies:

- `outcome()` (`verdict.rs:648`) uses `.find(...)` → **first** record for the check.
- `failures()` (`verdict.rs:663`) scans **all** records.

`is_trustworthy()` → `missing_essentials()` → `outcome()`, so appending a later `Failed` for an
already-`Passed` essential leaves the verdict simultaneously `is_trustworthy() == true` (first-wins
sees the `Passed`) **and** listing that failure in `failures()` (all-scan sees the `Failed`). The
same shape sinks ADR 0035 §2: a `Passed` then an essential `Indeterminate` reads as trustworthy under
first-wins, contradicting "an essential `Indeterminate` makes the verdict untrustworthy."

### Mechanism: non-pass dominates, applied in `outcome()`

Change the *single-value* resolver so a pass is reported for a check only if **nothing non-passing
was also recorded** for it. Everything derives from `outcome()` (`missing_essentials`,
`is_trustworthy`, `disposition(check)`), so fixing it there fixes the whole derived surface in one
place rather than patching `missing_essentials` alone and leaving `disposition(check)` still saying
`Satisfied` on a check that also carries a `Failed`.

```rust
/// The outcome of one check, if it was considered at all.
///
/// **Non-pass dominates.** A check recorded more than once reports a non-`Passed` record in
/// preference to a `Passed` one, so a later `Failed`/`Skipped`/`Indeterminate` can never be masked
/// by an earlier `Passed`. This is what keeps `is_trustworthy()` coherent with `failures()` and
/// with an essential `Indeterminate` (ADR 0035 §2): a verdict cannot read trustworthy while any
/// essential also carries a refusal or an unestablished outcome. Order-independent for the trust
/// question — any non-pass sinks it regardless of order — and inert for every single-record path,
/// which is every production and wasm builder. It is **not** order-independent for the specific
/// value reported when a check carries two or more *different* non-pass records (e.g.
/// `Indeterminate` then `Skipped` returns the first of the two); that case is unreachable on any
/// real path — every `Check` is recorded exactly once — and the trust answer is identical either way.
#[must_use]
pub fn outcome(&self, check: Check) -> Option<&Outcome> {
    let mut passed: Option<&Outcome> = None;
    for (c, o) in &self.results {
        if *c != check {
            continue;
        }
        if !matches!(o, Outcome::Passed) {
            return Some(o); // first non-pass dominates
        }
        passed.get_or_insert(o); // hold the pass only until a non-pass appears
    }
    passed
}
```

Notes bounding the change:

- `results()`, `failures()`, `dispositions()`, and `Display` all iterate the **raw** vector and are
  **unchanged** — the full transcript still shows every record (the existing test's "both are kept
  in the transcript" assertion still holds). Only the single-value resolver changes.
- "First non-pass" among multiple non-pass records is arbitrary but coherent; it never arises on a
  real path, so no production behaviour depends on which non-pass is chosen.
- Rejected sub-option — **reject duplicates via a fallible/​panicking `record`.** `record` is a
  `pub`, infallible, builder-style `self -> Self` called ~30× cross-crate by wasm. Making it return
  `Result` is a large blast-radius signature break on the crate's most-used constructor and wrecks
  the fold-style assembly; making it panic puts a downstream-triggerable landmine into a `pub`
  builder. Rejected.
- Rejected sub-option — **silently drop the duplicate at record time (keep-first).** Fixes the
  contradiction but fails **open**: an attempt to record a refusal *after* a pass is discarded, which
  is the exact footgun `recording_a_check_twice_keeps_the_first`'s own doc names ("a future branch
  that records a refusal over an earlier pass would have no effect"). Non-pass-dominates fails closed
  in that same scenario. Rejected.

### Does not regress VA-1 / ADR 0035

- `missing_essentials()` (`!outcome().is_some_and(Outcome::passed)`), `is_trustworthy()`
  (`missing_essentials().is_empty()`), the `Outcome` enum, and `AttestedTcb` are all **untouched**;
  they simply now read the dominant outcome. VA-1's disposition-table and TCB tests build
  single-record verdicts, so they are unaffected by construction.
- ADR 0035 §2 (essential `Indeterminate` ⇒ untrustworthy) is **strengthened**, not regressed: a
  `Passed`-then-`Indeterminate` essential now resolves to `Indeterminate` → untrustworthy, with
  `failures()` still (correctly) excluding it. Untrustworthy-with-no-listed-failure is the legitimate
  "unestablished" shape (`a_check_that_never_ran_appears_in_both`) — coherent, not contradictory.
- ADR 0035 §Consequences `Refusal::kind()` triage reads `missing_essentials`/per-check outcomes;
  it inherits the dominant outcome and stays coherent.

### Assumption to confirm (flagged, per brief)

No internal path records an essential **twice on the same path**. I read `verify.rs` (each check
recorded once; success/error branches mutually exclusive; `record_attestation` records
`QuoteSignature`+`TcbStatus` once per arm) and wasm `compose_only_verdict` (same) and found none.
**Developer must confirm** by running the whole suite green after the `outcome()` change — if any
path double-records by design, dominance would change its resolved outcome and that path needs
review. I believe none does.

---

## Part 1 — fabrication (design/doc decision, recommendation (a) alone)

### What is and isn't at risk

The reproduction — `Check::essential().fold(Verdict::new(), |v,c| v.record(c, Outcome::Passed))`
then `TrustworthyVerdict::check(...) == Ok` — is real: `new`/`record`/`check` are all public and
must stay so (`check` for raw-`verify()` auditors with no TCP stack; `new`/`record` ungated for the
wasm assembler). But note what it does **not** reach: `VerifiedClient`'s constructor is private and
cannot be built from a fabricated verdict. **The security boundary an agent relies on — "proceed
only against a connection I verified myself" — is held by `connect_verified`/`VerifiedClient`, which
the forgery cannot cross.** The brief confirms this containment is intact and out of scope to change.

So the forgery's only effect is on a **downstream consumer that reads a bare `TrustworthyVerdict` as
proof that real verification happened** (telemetry, audit storage, offline tooling). The type
already disclaims that: *"What it does not establish: that the evidence came from the connection you
are using."* It is honestly a **content-judgment**: "this transcript shows every essential passed."

### Why (a) — narrow + airtight — and not (b) — witness/sanctioned assembler

Four arguments, the fourth decisive:

1. **The guarantee is already correctly scoped and true.** "Every essential check ran and passed in
   this transcript" is a useful predicate. Composed with `VerifiedClient` (private ctor) it yields
   the provenance property; alone it does not, and says so.

2. **The real boundary is elsewhere and holds.** The thing that must be unforgeable — an *agent
   proceeding* — is gated by `VerifiedClient`, not by `TrustworthyVerdict`. Hardening the wrapper
   does not harden that boundary (it is already hard), and not hardening it does not weaken it.

3. **(b) has real cost.** A witness only `verify()` can mint means a private provenance marker on
   `Verdict` — a type that derives `PartialEq, Eq, Clone` and whose tests assert `returned ==
   verdict`. It splits `Verdict` into verify-produced vs hand-built tiers that ADR 0035's world does
   not have, and risks the wasm-assembly / hand-building-test story the whole issue is constrained
   to preserve.

4. **(b) does not even close the worry — it moves the misreading one step, and manufactures false
   confidence.** There are two routes to a forged `TrustworthyVerdict`, and a witness only blocks the
   first:
   - **Route 1 — hand-assembled `Verdict`.** `Verdict::new().record(…, Passed)…` then `check`,
     bypassing `verify()` entirely. A witness that `check` demanded, mintable only inside the crate's
     own check functions, would block this.
   - **Route 2 — replayed/caller-assembled `Evidence` into the real `verify()`.** `verify()` performs
     **no I/O** and trusts the `Evidence` it is handed, including the caller-supplied
     `peer_certificate`. A forger feeds it a recorded quote plus a matching certificate and gets a
     genuine, all-`Passed` verdict — carrying a *real* witness — about a connection they are not
     using. This is the very gap `connect_verified` exists to close and which `verify()`'s own doc
     calls out, and **no witness scoped to the crate's check functions can distinguish it from an
     honest verification**, because the checks really did run.

   So a witness proves "*our code ran the checks*," not "against genuine, live evidence," and route 2
   walks straight through it while looking exactly like success. It would let a downstream consumer
   believe provenance was established when it was not — precisely the false-confidence failure ADR
   0002 (fake spend limits) and ADR 0014 (a loosened verifier that still says "verified") teach this
   project to refuse. **Ceremony that buys nothing, and worse than nothing because it looks like it
   buys provenance.**

Therefore: keep `new`/`record`/`check` public and ungated; **make the contract airtight** instead.

### The (a) deliverable — doc/contract hardening (no behaviour change)

1. **Promote and sharpen `TrustworthyVerdict`'s "what it does not establish."** Turn the single
   sentence into an explicit, enumerated contract on the type and on `check`:

   ```text
   /// # What holding one proves — and only this
   ///
   /// That the `Verdict` it wraps records `Outcome::Passed` for every essential check
   /// (`Check::essential`). It is a judgment about a transcript, nothing more.
   ///
   /// # What it does NOT prove
   ///
   /// - That any check was actually performed against real evidence. A caller can hand-assemble a
   ///   `Verdict` of all-`Passed` records and wrap it; the wrapper reports what the transcript says,
   ///   and the transcript is only as honest as whoever built it.
   /// - That the evidence was genuine even when the transcript is genuine. `verify()` performs no
   ///   I/O and trusts the `Evidence` it is handed, including the `peer_certificate`; a caller who
   ///   feeds it a recorded quote plus a matching certificate gets a real, all-`Passed` verdict
   ///   about a connection they are not using. A `TrustworthyVerdict` minted from that verdict is
   ///   indistinguishable from one about a live endpoint.
   /// - That the evidence came from a live connection, or from any connection at all.
   /// - That the inputs were not chosen by the caller.
   ///
   /// The only thing that binds a verdict to a connection the caller actually made is
   /// [`crate::connect::connect_verified`] / [`crate::connect::VerifiedClient`], whose constructor
   /// is private for exactly this reason. Treat a bare `TrustworthyVerdict` from an untrusted source
   /// as an unverified claim; require a `VerifiedClient` where provenance matters.
   ```

2. **State the same on `check`'s doc** (it is the public mint) so anyone reading the entry point sees
   it: `check` judges a transcript; it does not authenticate the transcript's origin.

3. **No lockdown of construction, no test-only constructor.** Because `new`/`record` stay public
   (wasm needs them) and the fabrication is inherent-and-documented rather than prevented, tests keep
   hand-building through the public builder. No sanctioned assembler is introduced.

### Product-question check (per brief)

The choice is **settleable from existing design intent** and does not need user escalation: the type
already documents itself as a content-judgment, `VerifiedClient` already holds provenance behind a
private constructor, and the audit's concern is a downstream *reading* — a contract/doc matter. The
consistent reading is (a). I record the witness option as considered-and-rejected rather than
punting it upward. (See §Least sure for the one caveat I want a human eye on.)

---

## Test plan (seen-to-fail discipline)

Per CLAUDE.md: every guarding test must be **red on the current tree first**, then green. New tests
land in `crates/verity-verifier/tests/verdict_semantics.rs` unless noted.

### Part 2 — permanent regressions (behavioural; go red first)

- **T-A `a_later_failed_dominates_an_earlier_pass_for_the_same_essential`** — the audit
  reproduction. Build `Verdict::new().record(MrConfigId, Passed).record(MrConfigId,
  Failed("…"))`; assert **all three** cohere: `outcome(MrConfigId)` is `Failed`,
  `!is_trustworthy()`, and `failures()` non-empty for `MrConfigId`. **Seen-to-fail:** on the current
  tree `outcome()` returns `Passed` and `is_trustworthy()` is `true` while `failures()` lists the
  failure — the contradiction, red. Green after the `outcome()` change.
- **T-B `a_later_indeterminate_dominates_an_earlier_pass_for_an_essential`** — the ADR 0035
  interaction the brief calls out. `record(MrConfigId, Passed).record(MrConfigId,
  unestablished(VerifierCannotJudge, "…"))`; assert `!is_trustworthy()`, `outcome()` is
  `Indeterminate`, and `failures()` correctly **excludes** it (coherent untrustworthy-without-failure
  shape). **Seen-to-fail:** current tree reads trustworthy, red.
- **T-C order-independence** — assert `record(Failed).record(Passed)` and
  `record(Passed).record(Failed)` both yield `outcome() == Failed` and `!is_trustworthy()`. Pins that
  the fix is symmetric, not merely last-wins.
- **Update `recording_a_check_twice_keeps_the_first`** (`verdict_semantics.rs:129`) — its own doc
  invites this: rename to reflect non-pass-dominates, assert `outcome()` returns the **non-pass**
  record (not the first), keep the "both are kept in the transcript" `results().len() == 2` and
  `failures()` assertions (those are unchanged). This is the deliberate change the old test existed
  to force.

### Part 1 — doc-only, plus one containment pin (stated as such)

- **Doc-only:** the `TrustworthyVerdict`/`check` contract hardening changes no behaviour, so it has
  **no red-first test** — stated explicitly per AC 4. A `cargo test --doc` run keeps the doc examples
  compiling.
- **T-D `a_hand_fabricated_verdict_is_a_content_judgment_not_provenance` (characterization pin, not
  red-first).** Assert the *documented* behaviour so a future change that quietly alters it fails a
  test: a hand-built all-`Passed` verdict **does** produce `Ok(TrustworthyVerdict)` (this is
  by-design, not a hole), *and* — the load-bearing half — there is no public path from that wrapper
  to a `VerifiedClient`. The second half is a compile-time/type property (private constructor); I
  recommend asserting it as a **doc-invariant comment referencing the private ctor** rather than a
  runtime test, since "no public constructor exists" is enforced by the type system and the reviewer,
  not by a `#[test]`. Flag for the developer: if a lightweight runtime assertion of the boundary is
  feasible without widening any API, add it; otherwise the doc-invariant stands. Marked as a pin, not
  a seen-to-fail gate.

### Whole-suite gate

After both changes: `cargo test -p verity-verifier` and `cargo check -p verity-verifier-wasm` green
(wasm typechecks on host; `wasm32` is CI-only). Clippy with only the sanctioned
`-A clippy::chunks_exact_to_as_chunks` allow. This run is also where the Part 2 assumption (no
internal double-record) is confirmed — a red here would surface a path I missed.

---

## Blast radius summary

| Surface | Change | Risk |
|---|---|---|
| `Verdict::outcome()` | first-wins → non-pass-dominates | Inert for single-record paths (all of them); confirm via suite |
| `Verdict::new`/`record` | **none** (stay `pub`, ungated) | wasm + tests unaffected (AC 3) |
| `TrustworthyVerdict` / `check` docs | hardened contract, no behaviour change | doc-only |
| `recording_a_check_twice_keeps_the_first` | updated deliberately | its own doc sanctions it |
| VA-1 / ADR 0035 tests | none expected | verify green; §regression argument above |

---

## Least sure

**Whether to add a defence-in-depth witness anyway (Part 1 (b)).** I land firmly on **no** —
argument 4 (a witness proves "our code ran," not "against live evidence," and so manufactures
provenance confidence the type still cannot honestly carry) convinces me it is worse than the honest
content-judgment framing. But it is the one call where a reasonable person who weights
"downstream-consumer misuse" more heavily than I do could ask for the witness regardless of its
limits. If the user or the team wants belt-and-suspenders against downstream misreading despite the
false-confidence risk, that is the conversation to have — and my recommendation into it stays (a).
Everything else here I hold with high confidence.

---

## Decision log

Round 1 (design), critique (developer AGREE both parts, no OBJECT), round 2 amendments below.

1. **Part 2 mechanism = non-pass-dominates in `outcome()`.** Chosen over fallible/panicking `record`
   (blast radius on a `pub` builder wasm calls ~30×) and keep-first-drop (fails open). Developer
   applied it on a scratch tree: full suite + `cargo check -p verity-verifier-wasm` green, only
   `recording_a_check_twice_keeps_the_first` flips, and both seen-to-fail reproductions (T-A, T-B)
   confirmed genuinely red on the current tree. Part 2 assumption (no internal double-record)
   confirmed by the developer against `verify.rs` and wasm `lib.rs`. **Consensus.**

2. **Part 1 = (a) alone, doc/contract-only, no witness, no escalation.** Developer independently
   endorsed, sharpening argument 4: the decisive reason is route 2 (replayed `Evidence` into the real
   public `verify()`, which does no I/O and trusts what it is handed) — a witness scoped to the
   crate's own check functions cannot stop it, because the checks really run and the verdict is
   indistinguishable from genuine. **Consensus.**

3. **AMEND 1 (conceded, doc-text).** The round-1 "order-independent" claim was too broad: it holds
   for `is_trustworthy()` (any non-pass sinks it regardless of order) but not for the specific value
   `outcome()`/`disposition(check)` reports when a check carries two or more *different* non-pass
   records. Unreachable on any real path (every `Check` recorded once) and the trust answer is
   identical either way — but the `outcome()` doc and the up-front decision now name the residual case
   rather than let the broad claim stand.

4. **AMEND 2 (conceded, doc-text).** The Part 1 "what it does NOT prove" contract now names route 2
   explicitly (replayed `Evidence` into `verify()`), not only route 1 (hand-assembled `Verdict`).
   This is the route that actually defeats the witness idea, and the VA-2 audience
   (telemetry/audit-storage/offline tooling reading a bare `TrustworthyVerdict`) does not see
   `verify()`'s own doc where it was previously only implied. Argument 4 now enumerates both routes.

## Phase 3 implementation notes (developer)

Implemented exactly as designed with both amendments applied. One deliberate deviation from the
test plan's letter, recorded here as instructed:

- **T-D placed in `tests/trustworthy_verdict.rs`, not `tests/verdict_semantics.rs`.** The test plan
  says new tests land in `verdict_semantics.rs` "unless noted," and T-D wasn't explicitly noted
  otherwise — but T-D characterizes `TrustworthyVerdict::check` specifically, alongside every other
  test that exercises that constructor, in the file that already imports `TrustworthyVerdict` and
  already documents the containment property ("A test seam may build the plumbing; nothing may
  build the guarantee" — same file, same posture). Landing it in `verdict_semantics.rs`, which is
  about `Verdict`'s own accessors, would have separated it from its natural neighbors for no
  benefit. No behavioural difference; purely a file-organization call.

No other deviation. `outcome()`'s mechanism, both parts of the doc contract, T-A/T-B/T-C, and the
`recording_a_check_twice_keeps_the_first` rewrite all match the design as amended. Full gate
results and seen-to-fail transcripts are in the developer's report to the facilitator.

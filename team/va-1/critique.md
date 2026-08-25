# VA-1 critique — developer judgement on the architect's design

**Reviewer:** va1-developer (rust-developer) · **Design under review:** `team/va-1/design.md`
**Repo state read:** `verity-verifier` @ `163e667`, plus `attest.rs`, `verify.rs`, `verdict.rs`,
`connect.rs`, `connect/http.rs`, `lib.rs`, the wasm crate's `compose_only_verdict`, and every test/example
in the brief's blast radius.

Verdict up front: the shape is right and almost all of it is directly implementable as specified.
Two concrete gaps would stop a straight transcription from compiling or from actually delivering the
"no wildcard" discipline the design claims — both AMEND, neither OBJECT, both fixed in one or two
lines. Negative (b)'s composition argument holds, for reasons stronger than "no fixture exists" —
see below.

---

## Per-decision verdict

### 1. Delete `TcbPolicy`; enforce `UpToDate`-only inside `verify_quote` via private `is_tcb_acceptable`

**AGREE.** Confirmed against the actual code: `TcbPolicy::default()`/`up_to_date_only()` already
accepts exactly `["UpToDate"]` (`attest.rs:107-120`), so folding `Attested::is_up_to_date()`
(`attest.rs:57-61`) onto the new private `is_tcb_acceptable` is a same-module call with no visibility
issue and no behaviour change. The blast radius in §5 matches what I found by grep independently —
every `TcbPolicy` reference in `src/`, `tests/`, and `examples/` is accounted for, nothing missed.

### 2. Record the real status as verdict-level `AttestedTcb`, not on `Outcome`

**AGREE**, and the rejected-alternatives reasoning is correct, not just plausible. I checked the two
claims that matter most:

- `Outcome::Passed` really is matched as a bare unit variant in the places the design cites —
  `passed()` (`verdict.rs:253-255`), `label()` (`verdict.rs:275-282`), and `transcript_line`
  (`verdict.rs:459-466`, which explicitly renders `Passed` as "nothing to explain"). Putting a
  detail string on `Passed` would touch all three, and `transcript_line` is a **shell contract**
  (`closed-loop/04`, `06` grep it) — that's a correctly identified, real cost, not a hypothetical one.
- The `Verdict` field addition is inert for every existing equality/kind assertion I could find:
  `Verdict::new()`/`Default` both init the new field the same way, so
  `verified_transport.rs`'s `Verdict::new() → GuaranteeViolated` pin is untouched, and every
  `Display` assertion in `verdict_semantics.rs` uses `.contains(...)`, not exact-string equality
  (`verdict_semantics.rs:373-401`), so the new "platform TCB:" line cannot break them. I checked for
  exact-`Debug`/exact-`Display` assertions crate-wide and found none on `Verdict`.

### 3. Two extracted seams (`is_tcb_acceptable`, `record_attestation`) plus a renamed/extended CI job

**AMEND — two implementability gaps, both mechanical, neither structural:**

**(a) `AttestedTcb` has no way to be constructed from `attest.rs`.** §1's `AttestedTcb` (design.md
lines 59-71) declares `status`/`advisory_ids` as plain (private) struct fields with no `pub(crate)`
constructor — only the three accessor methods are public. §3's `record_attestation`
(design.md lines 168, 177) needs `AttestedTcb::from(&attested)` and `AttestedTcb::from_error(&e)`,
and §4 requires those conversions to live in `attest.rs` so the ungated `verdict` module never
depends on the gated `attest` one. `Attested`'s fields (`attest.rs:37-38`) are private too, but that
side is fine — `From<&Attested>`/`from_error` are defined in the *same* module as `Attested`, so
same-module private access works. It's the far side, `AttestedTcb`, that has no legal way in from
`attest.rs`: struct fields (unlike enum-variant fields) aren't implicitly visible to the crate just
because the type is `pub`. Concretely this needs one addition to §1's snippet:

```rust
impl AttestedTcb {
    pub(crate) fn new(status: String, advisory_ids: Vec<String>) -> Self {
        Self { status, advisory_ids }
    }
}
```

Small, doesn't touch the public surface, doesn't need `#[must_use]` since nothing discards it in the
one call site. I'd also suggest keeping it `pub(crate)` rather than public — nothing outside the
crate should ever fabricate an `AttestedTcb`, which is exactly the "no seam that could manufacture
provenance" discipline the module doc's collateral-source section already argues for elsewhere.

**(b) `record_attestation`'s error match is not actually wildcard-free, contrary to what §3 claims.**
The snippet (design.md lines 162-188) is:

```rust
match result {
    Ok(attested) => { /* ... */ }
    Err(e @ attest::AttestError::TcbUnacceptable { .. }) => { /* ... */ }
    Err(e) => { /* ... */ }
}
```

§3 says this is "matched exhaustively and without a wildcard in-crate ... the same discipline
`Outcome::label` and `Refusal::kind` use" — but it isn't. `Outcome::label` (`verdict.rs:275-282`) and
`weight()` (`verdict.rs:355-366`) name every variant explicitly; `Err(e)` here is a catch-all binding
over every *other* `AttestError` variant, functionally identical to `_`. Today that's harmless —
`AttestError` has exactly two variants, so `Err(e)` can only mean `SignatureInvalid` — but it means a
future variant added to this `#[non_exhaustive]` enum (by this crate, since it's defined here) falls
into the "signature didn't verify" bucket silently instead of forcing a decision at this match, which
is precisely the failure mode the design says it's avoiding. One-line fix, matching the file's own
established idiom:

```rust
Err(e @ attest::AttestError::SignatureInvalid { .. }) => { /* unchanged */ }
```

I'd flag this even though it's currently a no-op change, because it's the difference between the
claim in the design doc being true and being aspirational — and this crate's whole discipline
(`Outcome::label`, `weight`, `Refusal::kind`, all cited by name in this very design) is built on that
distinction actually holding.

Neither gap changes the shape of the design. Both are one-liners a developer would hit within the
first compile attempt, not blockers.

### 4. CI job rename + grep

**AGREE.** Checked the regex (`\bTcbPolicy\b|fn +accepting|fn +accepts`) against what survives the
change: `is_tcb_acceptable` and `Attested::is_up_to_date` don't match (neither contains `accepting`
or `accepts` as a substring after `fn `), so no false positive against the code the design itself
introduces. No false negative I could find either — `accepting`/`accepts` as free functions were the
only two spellings of the widening mechanism.

---

## Negative (b) — the architect's own least-certain point

**Position: the composition is sufficient, and for a stronger reason than "no fixture exists."**

The reachability claim is correct and I verified it against the actual mechanism, not just the
architect's assertion: `attest::verify_quote` calls `dcap_qvl::verify::verify`, which validates a
signature chain against Intel's compiled-in production root (per the module doc, `attest.rs:1-24`,
and `connect.rs:145-148`'s parallel argument about `CollateralSource`). Producing `Ok(Attested{status:
degraded})` or `Err(TcbUnacceptable{..})` therefore requires a **genuinely Intel-signed** quote over a
platform in a degraded state, verified against collateral that hasn't expired — not something a
committed fixture can be, ever, regardless of how cleverly it's constructed. This is the same
constraint `connect.rs`'s module doc already states outright ("no local end-to-end success path") and
for the identical reason. So the "true assembled-API test" the facilitator asks whether to demand
literally cannot exist offline. Demanding one anyway would only motivate exactly the kind of seam the
module doc forbids by name — a "trust this quote" flag, fake collateral, a policy that skips
signature verification — which is a strictly worse outcome than not having the test.

Given that, is composition of `is_tcb_acceptable` ∘ `record_attestation` ∘ a wiring check actually
equivalent to the unreachable test, or just the best available consolation prize? I think it's
genuinely equivalent, for a reason the design doesn't quite spell out but that I checked holds: once
`record_attestation` is extracted as the crate's **only** mapping from an `attest::Result` to
`Verdict` fields, and `verify()`'s body calls it exactly once with `attest::verify_quote`'s literal
return value (no intermediate transformation — I read the surrounding code in `verify.rs:170-176` and
confirmed there's nothing between the call and the match today that the extraction would need to
preserve or lose), then there is no code path by which "what `record_attestation` does when handed a
genuine-signature-degraded-TCB result" and "what `verify()` does on that same input" could diverge.
It isn't two things being tested and hoped to agree; after the extraction it's structurally one thing.
That's stronger than a dynamic "wiring test" — it's the same move the codebase already made for
`transcript_line` (pulled out of `examples/verify-attestation.rs`) and `compose_only_verdict` (pulled
out of the wasm boundary), both cited in the design, and both precedents for exactly this pattern:
logic welded to an untestable boundary is untested; logic extracted to a plain function is testable
regardless of the boundary.

One precision request for the implementation, not a design objection: I'd want the "public `verify()`
wiring test" the design promises in §6 to actually be, and be documented as, the *offline-reachable
arm* strengthened with the new assertion — i.e. extend `garbage_quote_fails_signature_and_mrconfigid`
and `skipped_essentials_are_not_trustworthy` (both real, both already exercise `verify()` end to end
through a genuine `SignatureInvalid` today) to additionally assert `attested_tcb().is_none()`. That
*is* a true assembled-API test, just of the one arm that's reachable — and I confirmed by reading
`verify_negative.rs` in full that neither test currently makes any TCB-related assertion, so adding
one is additive, not a rewrite. I'd rather the commit message say plainly "the assembled-API test
covers the reachable arm; the unreachable arm is covered by composition, and here is why that's the
same guarantee" than have `record_attestation`'s in-module tests silently stand in for something the
brief's acceptance criteria imply should be end-to-end. That's a documentation instruction, not a
design change.

**No OBJECT.** There is no borrow-checker fight, no trait-indirection problem, no async boundary, and
no missing error path here — the constraint is physical (an Intel signature cannot be fabricated
offline), the design names it honestly, and the substitute is sound by construction once the
extraction is done correctly.

---

## Seen-to-fail and test-intent preservation

**Seen-to-fail reproducibility:** I can confirm the *shape* is right but not yet the *transcripts* —
`is_tcb_acceptable` and `record_attestation` don't exist on the current tree, so their red-then-green
demonstrations are necessarily a Phase 4 activity (write the function, write the test, break it per
the design's own prescribed mutation, capture red, revert, capture green). I did not write code in
this phase per the facilitator's instruction. What I did verify now, so it doesn't need re-discovery
at Phase 4: the CI grep's regex has no false positive against the code this change introduces (checked
above), and the two existing "seen-to-fail" claims about *removal* — a reintroduced `pub fn accepting`
tripping the CI grep, and the arity test in `tests/tcb_enforcement.rs` failing to compile if a `tcb`
param returns — are both true by construction of the proposed grep and of Rust's arity checking, not
things that need a live run to believe.

**Test-intent preservation, specifically `verify_negative.rs`:** I read the whole file. Every test
there goes through the `run!` macro, which always passes `&TcbPolicy::default()` — the strict policy
— and **no test in this file ever constructs a `TcbPolicy::accepting(...)` or exercises a widened
policy**. The brief's framing ("verify_negative.rs asserting a degraded status is refused") describes
what the file establishes in aggregate — that only a genuine `UpToDate` signature can pass — not a
specific widened-policy test that needs special handling. So dropping the trailing
`&TcbPolicy::default()` from the `run!` macro (`verify_negative.rs:71-93`) is a pure transcription
edit with no intent to preserve beyond "still compiles, still uses the strict rule" — which is now
true unconditionally rather than by default-argument choice. The `TcbPolicy`-specific behavioural
tests that *do* need rewriting (widening, case-insensitivity, the degraded-status sweep) all live in
`tests/attest.rs`, not `verify_negative.rs`, exactly where the design's §5/§6 send them.

---

## Summary for the architect

Ship the design as specified with two additions: a `pub(crate) fn new` on `AttestedTcb` so the
`attest.rs`-side conversions actually compile, and naming `SignatureInvalid` explicitly rather than
`Err(e)` in `record_attestation`'s match so the "no wildcard" claim is literally true rather than
true-by-coincidence-of-two-variants. Negative (b)'s composition strategy is correct and I'd defend it
to the reviewer on the grounds above, not merely accept it as the least-bad option. No OBJECT anywhere
in the design.

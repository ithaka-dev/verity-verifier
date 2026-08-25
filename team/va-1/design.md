# VA-1 design — remove caller-configurable TCB acceptance, enforce ADR 0014

**Issue:** VA-1 (audit VV-01, High) · **Repo:** `verity-verifier` @ `163e667`
**Author:** va1-architect (rust-architect) · **Status:** for developer consensus

## Recommendation, up front

Three moves, and they are separable:

1. **Delete `TcbPolicy` entirely.** No public route — `verify`, `verify_quote`, `ConnectRequest`,
   `ConnectRequest::new` — takes a TCB acceptance argument. UpToDate-only is enforced *structurally*
   inside `verify_quote`, which continues to return `Err(TcbUnacceptable)` for anything else.
2. **Record the real Intel status as verdict-level provenance, not on the `Outcome`.** Add
   `AttestedTcb { status, advisory_ids }` to the ungated `verdict` module and a
   `Verdict::attested_tcb() -> Option<&AttestedTcb>` accessor, populated whenever a signature
   verified (on a *passing* `UpToDate` and on a failing degraded status alike). **The `Outcome`
   enum is not touched** — `Passed | Failed | Skipped | Indeterminate { .. }` survives byte-for-byte,
   so `is_trustworthy()`, the disposition table, `label()`, `transcript_line`, and the WASM
   projection are all unchanged.
3. **Extract two small seams so the enforcement and the wiring are testable offline** — a private
   `is_tcb_acceptable(&str) -> bool` in `attest`, and a `record_attestation(...)` mapping in
   `verify` — then rename/extend the CI job to assert the knob cannot come back.

Both assumptions the brief flagged **hold** (details in §7). No new `Outcome` variant; no ADR 0035
change; no ADR 0014 supersession — this *implements* ADR 0014 decision 2, it does not amend it.

The one decision I was least certain about is where the genuine-signature-plus-degraded-TCB path can
honestly be tested (§6, negative b): it is **offline-unreachable by construction**, and the design
covers it by composition rather than by manufacturing a fake-collateral seam. That reasoning is
spelled out so the developer can push back.

---

## 1. Public API surface — what changes

### Removed (breaking, accepted at v0.0.0 — matches the brief's "deliberate breaking change")

| Symbol | File | Was |
|---|---|---|
| `attest::TcbPolicy` (struct, `Default`, `up_to_date_only`, `accepting`, `accepts`) | `attest.rs:97-147` | the knob |
| `policy: &TcbPolicy` on `attest::verify_quote` | `attest.rs:159-164` | arity 4 |
| `tcb: &TcbPolicy` on `verify::verify` | `verify.rs:125-130` | arity 4 |
| `pub tcb: &'a TcbPolicy` field on `connect::ConnectRequest` | `connect.rs:112` | public field |
| `tcb` param on `connect::ConnectRequest::new` | `connect.rs:122-135` | arity 4 |

`verify_quote`, `verify`, and `ConnectRequest::new` each drop their last parameter and become arity 3.

### New public surface

In `verdict` (**ungated**, alongside `Verdict` — this is the load-bearing placement decision, see §3):

```rust
/// Intel's TCB statement about the platform a verdict is about.
///
/// Verdict-level provenance, like `verifier_version` and `reference_data_date` — *not* a check
/// outcome. It is present whenever a signature verified, on a passing `UpToDate` as well as on a
/// refused degraded status, so a reader can always see which status was judged and any advisories
/// Intel published. It is descriptive: `is_trustworthy()` never reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AttestedTcb {
    status: String,
    advisory_ids: Vec<String>,
}

impl AttestedTcb {
    /// Construct from a verified quote's status. `pub(crate)` on purpose: this type is *read* by
    /// external callers off a `Verdict`, never built by them — the only constructor is the one
    /// `record_attestation` uses to map an `attest::Attested`/`AttestError` across the module
    /// boundary (the `verdict` module stays ungated, so it cannot name `attest` types itself). Keeping
    /// the constructor crate-internal preserves "a verdict's TCB statement comes from the verifier,
    /// not from a caller", the same posture as the deleted knob's removal.
    #[must_use]
    pub(crate) fn new(status: String, advisory_ids: Vec<String>) -> Self {
        Self { status, advisory_ids }
    }
    #[must_use] pub fn status(&self) -> &str { &self.status }
    #[must_use] pub fn advisory_ids(&self) -> &[String] { &self.advisory_ids }
    /// Whether Intel considers this platform up to date. The property the verifier enforces.
    #[must_use] pub fn is_up_to_date(&self) -> bool { self.status.eq_ignore_ascii_case("UpToDate") }
}

impl Verdict {
    /// Intel's TCB statement, when a signature verified. `None` when it did not, or when this
    /// construction cannot verify one (the WASM `compose_only_verdict` path).
    #[must_use] pub fn attested_tcb(&self) -> Option<&AttestedTcb> { self.tcb.as_ref() }

    /// Record the attested TCB statement. Builder-style, like `record`.
    #[must_use] pub fn record_attested_tcb(mut self, tcb: AttestedTcb) -> Self {
        self.tcb = Some(tcb);
        self
    }
}
```

`Verdict` gains one private field:

```rust
pub struct Verdict {
    verifier_version: &'static str,
    reference_data_date: &'static str,
    results: Vec<(Check, Outcome)>,
    tcb: Option<AttestedTcb>,   // new; None on every path that verified no signature
}
```

`#[derive(Debug, Clone, PartialEq, Eq)]` still holds (`AttestedTcb` is `Eq`). `Verdict::new()` /
`Default` initialise `tcb: None`, so `Verdict::default() == Verdict::new()` and the
`verified_transport.rs` pin of `Verdict::new() → GuaranteeViolated` are both unaffected.

`Check::TcbStatus` stays. It remains an essential check recording `Passed | Failed | Skipped` exactly
as today. The **structured status rides beside it**, not inside it.

---

## 2. Where enforcement moves — `attest.rs`

`verify_quote` keeps refusing degraded platforms; it just stops taking a policy. The acceptance test
becomes a private, non-configurable free function so it is unit-testable without a public knob:

```rust
/// The one enforced rule: only `UpToDate` is acceptable. Private and takes no configuration —
/// ADR 0014 decision 2 makes this mandatory and not a caller's choice. This is the heir to the
/// deleted `TcbPolicy::accepts`, minus the ability to widen it.
fn is_tcb_acceptable(status: &str) -> bool {
    status.eq_ignore_ascii_case("UpToDate")
}

pub fn verify_quote(
    raw_quote: &[u8],
    collateral: &Collateral,
    now_secs: u64,
) -> Result<Attested, AttestError> {
    let report = qvl_verify(raw_quote, collateral, now_secs)
        .map_err(|e| AttestError::SignatureInvalid { detail: format!("{e:?}") })?;

    let status = report.status.clone();
    let advisory_ids = report.advisory_ids.clone();

    if !is_tcb_acceptable(&status) {
        return Err(AttestError::TcbUnacceptable { status, advisory_ids });
    }
    Ok(Attested { tcb_status: status, advisory_ids })
}
```

`Attested` and `AttestError` are otherwise unchanged; `Attested::is_up_to_date()` stays and now
shares its rule with `is_tcb_acceptable` (fold one onto the other to keep a single definition —
`Attested::is_up_to_date()` can call `is_tcb_acceptable(&self.tcb_status)`).

**Why enforcement stays inside `verify_quote` and does not move up into `verify()`.** The tempting
refactor — have `verify_quote` return `Ok(Attested)` for any verified signature and let `verify()`
judge the status — would make a *public* `verify_quote` hand back an `Attested` for a `Revoked`
platform, trusting its caller to check `is_up_to_date()`. That is caller-configurable acceptance
wearing a different hat, and a direct `verify_quote` caller (which is public API, exercised by
`tests/attest.rs`) is exactly the caller ADR 0014 refuses to trust. Enforcement is structural at the
lowest layer that has the status. Rejected.

---

## 3. The key decision — recording the real status without breaking the `Outcome` contract

**Chosen: a verdict-level field (`AttestedTcb`), option B in the brief's framing.**

The status and advisory IDs are attached to the `Verdict`, in the same category as `verifier_version`
and `reference_data_date` — provenance about the thing being judged — and read through
`Verdict::attested_tcb()`. `verify()` populates it inside a small extracted seam:

```rust
// verify.rs — the arms currently inlined at verify.rs:171-199, extracted so they are testable and
// so the AttestedTcb population lives in one place.
fn record_attestation(
    verdict: Verdict,
    result: Result<attest::Attested, attest::AttestError>,
) -> Verdict {
    match result {
        Ok(attested) => {
            let tcb = AttestedTcb::from(&attested); // status is "UpToDate" here, by construction
            verdict
                .record(Check::QuoteSignature, Outcome::Passed)
                .record(Check::TcbStatus, Outcome::Passed)
                .record_attested_tcb(tcb)
        }
        Err(e @ attest::AttestError::TcbUnacceptable { .. }) => {
            // Signature verified; platform is out of date. Keep "genuine but stale" distinguishable
            // from "not genuine" — and surface the real status structurally as well as in the string.
            let tcb = AttestedTcb::from_error(&e); // reads status + advisory_ids off the error
            verdict
                .record(Check::QuoteSignature, Outcome::Passed)
                .record(Check::TcbStatus, Outcome::Failed(e.to_string()))
                .record_attested_tcb(tcb)
        }
        Err(e @ attest::AttestError::SignatureInvalid { .. }) => verdict
            .record(Check::QuoteSignature, Outcome::Failed(e.to_string()))
            .record(Check::TcbStatus, Outcome::Skipped("signature did not verify".to_owned())),
        // no AttestedTcb: nothing was attested
    }
}
```

**The `SignatureInvalid` arm is named, not left as `Err(e)`.** `AttestError` is the crate's own
`#[non_exhaustive]` enum, and `#[non_exhaustive]` only forces a wildcard on *external* crates — in
this crate the two variants can be matched by name, so a future `AttestError` variant becomes a
compile error here rather than falling silently into a catch-all with the wrong outcome. That is the
discipline `Outcome::label` and `weight()` actually use; an `Err(e)` catch-all only *looks* like it
and is harmless today purely because `AttestError` has two variants. (Conceded from the Phase-2
critique — the original skeleton's `Err(e)` was a functional wildcard the surrounding prose
misdescribed.) The conversions `From<&Attested>` / a `from_error(&AttestError)` helper live on the
gated (`attest`) side and call `AttestedTcb::new`, so the ungated `verdict` module never names an
`attest` type.

`verify()` then reads:

```rust
verdict = record_attestation(
    verdict,
    attest::verify_quote(evidence.raw_quote, evidence.collateral, evidence.now_secs),
);
```

### Why the field, and not the alternatives

**Rejected — detail on `Outcome::Passed`** (making it `Passed(String)` or `Passed { detail }`).
This is the only way to put the status *on the outcome*, and it breaks ADR 0035 at the root.
`Outcome::Passed` is a unit variant that `passed()` matches with `matches!(self, Self::Passed)`,
that `label()`/`transcript_line`/`Display`/`to_js` all render as "nothing to explain", and that
dozens of tests assert as `Some(&Outcome::Passed)`. Every one of those is a breaking ripple, and the
change contradicts the codebase's stated rule that *a pass has nothing to explain* (`transcript_line`,
`Display`). The four-word transcript vocabulary ADR 0035 §6 fixes as a shell contract would gain a
parenthetical on `passed`, which `closed-loop/04` and `06` grep. Not worth it, and not safe.

**Rejected — a new `Outcome` variant.** Explicitly an ADR 0035 escalation, and unnecessary: the
status is not a fifth disposition of a check, it is a fact about the platform. Assumption (2) holds.

**Rejected — encode it into a `Skipped`/`Failed` detail string only.** The failing path already
carries the status in the `Failed` detail (`e.to_string()`), but a *passing* `TcbStatus` has no
string to carry it, which is the whole gap the brief names. A structured field serves both paths and
is machine-readable (`status()` / `advisory_ids()`) rather than prose a caller must parse — the same
principle ADR 0035 decision 3 used to make `Unestablished` typed rather than a string.

**Why ungated placement in `verdict`.** `Verdict` is constructed by the WASM `compose_only_verdict`
path, which has no collateral and no `attest` feature. The field must therefore be defined without
the `attest` feature, so `AttestedTcb` lives in `verdict` (like `Check`, `Outcome`, `Disposition`).
The WASM path simply leaves it `None` — consistent with its `TcbStatus: Skipped`, and the drift guard
in the wasm crate keeps the two surfaces honest.

### Rendering (human `Display` only — not a shell contract)

`Verdict`'s `Display` gains one provenance line when `tcb` is `Some`, adjacent to the version/date
header and **outside** the per-check loop:

```
verity-verifier 0.0.0 (reference data 2026-08-14)
  platform TCB: UpToDate
  pass          compose_hash
  ...
```

On a refusal it shows e.g. `platform TCB: OutOfDate (advisories: INTEL-SA-00615)`. This does **not**
touch `transcript_line` or the per-check column layout that `closed-loop/04` and `06` grep — those
still emit `^  tcb_status +passed` / `+FAILED` exactly as before. The new line is anchored on
`platform TCB:`, which collides with none of the greps. `tests/transcript_contract.rs` and the
`verdict_semantics` `Display` tests must be extended to pin the new line, not to change the old ones.

The `verify-attestation.rs` example runner keeps printing `transcript_line` per check (the shell
contract) and may additionally print the `Display` block; it must not replace the per-check lines.

---

## 4. Error model, async, unsafe, feature-gating

- **Error model — unchanged.** `thiserror` typed errors throughout (`AttestError`, `CollateralError`,
  `Refusal`, `TransportError`), `#[non_exhaustive]`, no `anyhow`, no `Box<dyn Error>`. `AttestError`
  keeps `SignatureInvalid` / `TcbUnacceptable` — the "genuine but stale" vs "not genuine" split is
  load-bearing and stays.
- **Async — N/A, and deliberately so.** `verify`/`verify_quote` remain pure and I/O-free; no runtime
  is introduced. The `connect` feature's socket work is untouched. `ConnectOptions::now_secs()` and
  the `CollateralSource` timeout discipline are out of scope (brief).
- **Unsafe — none.** No `unsafe` is added or touched. Posture unchanged.
- **Feature-gating — unchanged, additivity preserved.** `attest`/`verify`/`connect` stay gated;
  `verdict` stays ungated and now also owns `AttestedTcb`. The `From<&Attested>` conversion sits on
  the gated side. No feature toggles behaviour; the field is present in the type on every target and
  merely unpopulated where no signature is verified. The wasm build (`--no-default-features`, no
  `attest`) still compiles: `AttestedTcb` needs only `std`.

---

## 5. Call sites to update (mechanical, same change)

Dropping one argument each. The brief's blast radius, confirmed:

- **Source:** `verify.rs` (verify signature + the discard at :180-181 → `record_attestation`),
  `attest.rs` (verify_quote signature, delete `TcbPolicy`), `connect.rs` (drop `tcb` field + `new`
  param + the `use ...TcbPolicy`), `connect/http.rs` (`OwnedRequest.tcb` field at :70, `from_borrowed`
  at :80, the `verify()` call at :170-184 drops its `tcb` arg, and `real_connector` test helper at
  :871 drops `tcb:`), `lib.rs` doc example (drop `use ...TcbPolicy` at :73 and the
  `&TcbPolicy::default()` arg at :96).
- **`verify()` call sites (tests/examples):** `tests/channel_binding.rs` (×4, drop the `&TcbPolicy::default()`
  line each), `tests/verify_negative.rs` (the `run!` macro at :90), `tests/reference_and_verdict.rs`
  (:203), `examples/verify-attestation.rs` (:200-210 + the `use` at :48).
- **`ConnectRequest::new` call sites:** `tests/verified_transport.rs` (×4 — the `let tcb = TcbPolicy::default();`
  at :302/:324/:756/:775 and the `new(...)` calls), `examples/connect-verified.rs` (:57 `use`, :162
  `let tcb`).
- **`tests/attest.rs`:** the four `verify_quote(..., &TcbPolicy::default())` calls drop the last arg;
  the `TcbPolicy` unit tests (`default_policy_accepts_only_up_to_date`, `looser_policy_requires_naming_the_statuses`,
  `the_default_policy_refuses_every_degraded_status`, `an_unrecognised_status_is_refused`,
  `accepting_widens_only_what_it_names`, `status_comparison_is_case_insensitive`,
  `an_empty_policy_accepts_nothing`) are **rewritten** onto `is_tcb_acceptable` (see §6). Their intent
  — every degraded/unknown status refused, case-insensitive — is preserved and strengthened, not
  dropped.
- **WASM:** untouched by the knob (it never constructed a `TcbPolicy`). Optional parity change in §6.
- **README.md / any prose** referencing `TcbPolicy`: update or delete. Mechanical.

Every dropped argument is a transcription edit; the *test intents* are preserved per the brief.

---

## 6. Test plan — seen-to-fail, and the two required negatives

Discipline: each guard is demonstrated **red on the current tree first** (by making the described
break), then green after the fix. Capture the red transcripts (ADR 0019 → into the commit message).

### Enforcement (`is_tcb_acceptable`) — in-module `#[cfg(test)]` in `attest.rs`

Private, so it is tested from an in-`src` module (precedent: `channel.rs`, `connect/http.rs` tests).
Direct heir of the deleted T-01 tests:

- `only_up_to_date_is_acceptable`: `is_tcb_acceptable` is `true` for `UpToDate` and every case
  variant (`uptodate`, `UPTODATE`, `uPtOdAtE`); `false` for `OutOfDate`,
  `OutOfDateConfigurationNeeded`, `SWHardeningNeeded`, `ConfigurationNeeded`,
  `ConfigurationAndSWHardeningNeeded`, `Revoked`, `""`, `"Fine"`, `"UpToDateish"`, `"🙂"`.
- **Seen-to-fail:** widen it to `|| status.eq_ignore_ascii_case("Revoked")` → the `Revoked` row goes
  red. Capture, revert.

### Wiring + provenance (`record_attestation`) — in-module `#[cfg(test)]` in `verify.rs`

This is the **assembled-verdict** coverage for negative (b) that is reachable offline. It runs the
*exact* production mapping over constructed `attest` results (a test-only `Attested`/`AttestError` is
constructible: `AttestError` variants are public; `Attested` needs a `pub(crate)` or
`#[cfg(test)]` constructor — add a `pub(crate) fn` behind the `attest` feature):

- `a_degraded_status_fails_tcb_and_sinks_the_verdict`: parametrised over every degraded/revoked
  status, `record_attestation(Verdict::new(), Err(TcbUnacceptable{status, advisories}))` yields
  `TcbStatus: Failed`, `QuoteSignature: Passed`, `!is_trustworthy()`, `attested_tcb().status() ==
  status`, and the advisories surfaced. **Seen-to-fail:** revert the `TcbUnacceptable` arm to record
  `TcbStatus: Passed` (the original VV-01 bug) → `is_trustworthy()` returns `true`, red.
- `a_passing_verdict_shows_which_status_passed`: `record_attestation(.., Ok(Attested{status:"UpToDate",
  advisories}))` yields `TcbStatus: Passed` **and** `attested_tcb()` is `Some` with `status ==
  "UpToDate"` and the advisories. **Seen-to-fail:** drop `.record_attested_tcb(tcb)` on the `Ok` arm
  → `attested_tcb()` is `None`, red. This is the acceptance-criterion-3 guard: the status is legible
  *on success*.
- `a_bad_signature_records_no_attested_tcb`: `Err(SignatureInvalid)` → `QuoteSignature: Failed`,
  `TcbStatus: Skipped`, `attested_tcb()` is `None`.

### Assembled public `verify()` — `tests/verify_negative.rs` / `tests/attest.rs`

The reachable-offline integration assertions (signature fails first with placeholder collateral):

- **The wiring test is concretely `tests/verify_negative.rs`'s existing `garbage_quote_fails_signature_and_mrconfigid`
  and `skipped_essentials_are_not_trustworthy`, strengthened with an `attested_tcb().is_none()`
  assertion** (framing confirmed with the developer — neither makes any TCB assertion today, so this
  is purely additive, and it is a genuine assembled-API test of the reachable arm: these drive the
  public `verify()`, whose only TCB mapping is now `record_attestation`, so the assertion pins that
  `verify()` records no phantom `AttestedTcb` when the signature failed). **Seen-to-fail:** have the
  `SignatureInvalid` arm populate an `AttestedTcb` → both go red.
- **Honest limit, stated for the reviewer:** the *genuine-signature-plus-degraded-TCB* verdict cannot
  be produced through the public `verify()` offline — it needs a live Intel signature over a degraded
  platform, which no committed fixture can be (collateral is platform-and-time-specific and expires).
  This is the same class of honesty as `connect.rs`'s "there is no local end-to-end success path".
  Negative (b) is therefore closed by **composition**: `is_tcb_acceptable` (every degraded status
  refused) ∘ `record_attestation` (a `TcbUnacceptable` becomes `TcbStatus: Failed` and sinks the
  verdict, run over every status through the real mapping) ∘ the public-`verify()` wiring test that
  the mapping is what `verify()` calls. **Do not** add a fake-collateral or "trust this quote" seam to
  force the path — that is the attacker-reachable seam the module doc forbids.

### Negative (a) — no public route accepts an arbitrary status name

Two layers, neither relying on trybuild (rejected: `.stderr` snapshots are toolchain-fragile across
the pinned 1.97.1 / local 1.98 split the brief calls out, and would rot):

- **CI grep (load-bearing), in the renamed job (§ below):** fail if `TcbPolicy`, `fn accepting`, or
  `fn accepts` reappears in `crates/*/src` or `crates/*/examples`. **Seen-to-fail:** add a
  `pub fn accepting` shim → job red.
- **Arity is a compile-time guard, made explicit:** a `tests/tcb_enforcement.rs` test that calls
  `verify(&licensed, &evidence, None)` and `ConnectRequest::new(ep, lic, doc)` at the *new* arity,
  with a comment stating it exists to stop a policy parameter returning. Re-adding a `tcb` param
  breaks compilation of this file (and the rest of the suite). It is the "API test … if a knob were
  reintroduced" acceptance #1 asks for.

### WASM (optional parity, recommended)

`to_js` / `JsVerdict` may gain an `attestedTcb: Option<{status, advisoryIds}>` field for surface
parity, always `null` on the current `compose_only_verdict` path (no collateral). Small, and keeps the
JS verdict a faithful projection of the Rust one. The existing `Outcome` wildcard `_ => "unknown"`
stays exactly as is — **no new `Outcome` variant means no wasm match change**, which is itself
evidence assumption (2) holds. If the developer judges the parity field scope creep, defer it; it is
not required by acceptance.

---

## 7. CI job — rename and extend (`.github/workflows/ci.yml`, `no-dangerous-attestation` ~:162)

Keep both existing assertions (the `danger-allow-tcb-override` feature grep and the
`dangerous_verify_with_tcb_override` call grep — the brief requires they stay). Add the knob grep and
rename the job so the name matches what it now proves:

```yaml
  no-dangerous-attestation:
    name: TCB enforcement is mandatory — not overridable, not caller-configurable
    # ... existing two steps unchanged ...
      - name: no caller-configurable TCB policy
        run: |
          if grep -rnE '\bTcbPolicy\b|fn +accepting|fn +accepts' \
              crates/*/src crates/*/examples 2>/dev/null; then
            echo "::error::a caller-configurable TCB status policy was reintroduced; VA-1 / ADR 0014 decision 2 forbid it"
            exit 1
          fi
```

`is_tcb_acceptable` and `Attested::is_up_to_date` do not match the pattern; `accepting`/`accepts` do.
The grep is toolchain-robust and mirrors the job's existing grep-based style. **Seen-to-fail:** it
must be watched to go red against a reintroduced `pub fn accepting` before it is trusted (CLAUDE.md:
a gate is only trustworthy once seen to fail).

---

## 8. Assumptions — both hold

**(1) Enforced policy is exactly `UpToDate`. HOLDS.** The current default (`up_to_date_only`) already
accepts only `UpToDate`, and the whole existing suite asserts every other Intel status — including
`SWHardeningNeeded` and `ConfigurationNeeded` — is refused by default. VA-1 makes that behaviour
non-configurable; it does not tighten or loosen it. ADR 0014 decision 3's "warn on merely old" is
about *verifier/reference-data age and OS-image revocation*, a different axis from TCB status; it does
not carve out a SWHardeningNeeded tolerance. The operator decision recorded in the brief (2026-08-25,
"no named degraded statuses are wanted; UpToDate only") is explicit and current. No escalation.
A future desire to tolerate, say, `SWHardeningNeeded` on real dStack platforms would be a deliberate
ADR-superseding decision with its own record — not this issue, and not a silent widening.

**(2) Recording the real status needs no new `Outcome` variant. HOLDS.** Option B (verdict-level
`AttestedTcb`) records status + advisories with the `Outcome` enum untouched. `is_trustworthy()`, the
disposition table, `label()`, `transcript_line`, the WASM projection, and the four-word transcript
vocabulary are all unchanged. No ADR 0035 escalation.

---

## 9. Summary of the shape

`TcbPolicy` and every parameter carrying it are deleted; `verify_quote` enforces `UpToDate`-only
through a private `is_tcb_acceptable`, so no public route can widen acceptance. The real Intel status
and advisory IDs become verdict-level provenance via a new ungated `AttestedTcb` read through
`Verdict::attested_tcb()`, populated on both the passing and the refused path — leaving the ADR 0035
`Outcome` contract and `is_trustworthy()`/disposition machinery completely untouched. Two seams
(`is_tcb_acceptable`, `record_attestation`) make enforcement and wiring testable offline; a renamed CI
job plus an arity test keep the knob from returning. The one place genuine testing hits a wall — a
live signature over a degraded platform — is covered by composition and documented rather than faked.

---

## 10. Decision log

- **D1.** Remove `TcbPolicy` outright; enforce `UpToDate`-only structurally inside `verify_quote` via
  a private `is_tcb_acceptable`. Enforcement stays at the lowest layer that has the status, so a
  direct `verify_quote` caller cannot obtain an `Attested` for a degraded platform.
- **D2.** Record the real status as verdict-level `AttestedTcb` provenance, not on `Outcome`. Rejected
  detail-on-`Passed` (breaks ADR 0035's four-word shell contract) and a new `Outcome` variant
  (unnecessary; would escalate ADR 0035). `AttestedTcb` lives in the ungated `verdict` module so the
  WASM path compiles with it `None`.
- **D3 (AMEND a, conceded — Phase 2).** `AttestedTcb`'s fields are private and it needs a constructor
  for `record_attestation` to build one across the module boundary. Added `pub(crate) AttestedTcb::new`
  — crate-internal because external callers only *read* the type off a `Verdict`. The §1 skeleton
  would not have compiled without it.
- **D4 (AMEND b, conceded — Phase 2).** `record_attestation`'s error match named the `SignatureInvalid`
  arm explicitly (`Err(e @ AttestError::SignatureInvalid { .. })`) instead of an `Err(e)` catch-all.
  The catch-all was a functional wildcard the surrounding prose wrongly called exhaustive; the named
  arm makes a future `AttestError` variant a compile error here, matching how `Outcome::label`/`weight`
  actually enforce the discipline.
- **D5 (framing, confirmed — Phase 2).** The assembled-API wiring test for negative (b) is concretely
  `verify_negative.rs`'s `garbage_quote_fails_signature_and_mrconfigid` and
  `skipped_essentials_are_not_trustworthy`, strengthened with `attested_tcb().is_none()`. Additive;
  neither asserts anything about TCB today.
- **D6.** Negative (b)'s genuine-signature-plus-degraded-TCB verdict is offline-unreachable by
  construction; closed by composition (enforcement ∘ mapping ∘ wiring), documented rather than faked.
  Developer concurs.
- **D7 (implementation deviation).** `AttestedTcb` is built directly inside `verify::record_attestation`
  via `Attested`'s existing public accessors (`tcb_status()`, `advisory_ids()`) and the public fields
  on `AttestError::TcbUnacceptable`, rather than through a `From<&Attested>` impl / `from_error`
  helper defined in `attest.rs` as §3's skeleton sketched. The skeleton's helper would have needed an
  `AttestError::attested_tcb(&self)` method with an `unreachable!()` arm for the non-`TcbUnacceptable`
  case, since `record_attestation` already narrows to that variant before calling it — a panic path
  this crate's discipline (no `unwrap`/`panic` in production without justification) argues against
  when a panic-free alternative exists. `verify.rs` is itself gated behind `attest` (same as
  `attest.rs`), so it can perform the conversion directly with no encapsulation cost; `verdict.rs`
  still never names an `attest` type. Behaviour is identical; only which module holds the four-line
  mapping changed.
- **D8 (implementation fix).** `AttestedTcb::new` is `#[cfg(feature = "attest")]`, not unconditionally
  `pub(crate)` as §1's skeleton showed. Without it, `cargo build --no-default-features` (the wasm CI
  leg) reported `new` as dead code — and this repo's CI runs with `RUSTFLAGS: -D warnings`, so a
  warning there is a build failure. Nothing can construct an `AttestedTcb` without a signature to
  attest in the first place, so gating the constructor removes a real unreachable capability rather
  than hiding one; `Verdict::attested_tcb()` and the accessors stay available on every target,
  correctly returning `None` where nothing was attested.
- **D9 (implementation fix).** Three doc comments explaining the deletion (`attest.rs` ×2,
  `verdict.rs` ×1) referenced the removed type by its literal name, `TcbPolicy`. The new CI grep in §7
  is `\bTcbPolicy\b|fn +accepting|fn +accepts`, which — as first written — matched its own explanatory
  prose and would have failed the job it exists to keep green. Reworded to describe the type
  ("the deleted caller-configurable policy type") rather than name it; verified the grep clean
  afterward. No other historical reference to the old name exists in `crates/*/src` or
  `crates/*/examples`.
- **D10.** WASM parity (`attestedTcb` on `JsVerdict`) deferred, per §6's explicit permission — scope
  creep beyond acceptance, and the existing `_ => "unknown"` `Outcome` wildcard already stands as
  evidence assumption (2) holds without it.

### Phase 4 — fresh-reviewer findings, addressed

- **D11 (MUST FIX, finding 1).** The CI grep's own `if grep ... crates/*/src crates/*/examples
  2>/dev/null; then` failed open: under bash, an unmatched glob is passed through as a literal path,
  `grep` reports "No such file or directory" and exits 2, and `if grep ...; then` treats exit 2
  identically to "no match" — a guard that disarms itself if `examples/` is ever removed. Reproduced
  under bash with a real reintroduced knob and a real missing `examples/` directory: grep printed the
  violation to stdout and still exited 2, so the step would have reported success. Fixed by grepping
  `crates/` directly (matching the two sibling steps' own shape, which already do this and don't have
  the bug) with `--include='*.rs' --exclude-dir=tests`, dropping the glob paths entirely.
  `--exclude-dir=tests` is load-bearing, not incidental: `tests/attest.rs` and
  `tests/tcb_enforcement.rs` legitimately name the deleted type in doc comments explaining its
  removal, and without the exclusion the fixed grep would fail on its own test suite.
- **D12 (SHOULD FIX, finding 2).** `is_tcb_acceptable` (the enforcement rule) and
  `AttestedTcb::is_up_to_date` (the read-back) were two independent `eq_ignore_ascii_case("UpToDate")`
  spellings with nothing tying them together. Unified: the predicate now lives once, as
  `pub(crate) fn is_tcb_acceptable` in the ungated `verdict` module (not `attest`, so `attest`
  — already gated and already depending on `verdict` for `AttestedTcb` — can depend on it without
  `verdict` ever depending back on `attest`). `attest.rs`'s own copy and its in-module test were
  deleted; the test moved to `verdict.rs` as `tcb_acceptance_tests::only_up_to_date_is_acceptable`.
  Also added an explicit `!tcb.is_up_to_date()` assertion to the degraded-status test in `verify.rs`,
  so the read-back path is pinned directly rather than only the enforcement path.
- **D13 (SHOULD FIX, finding 3).** `a_degraded_status_fails_tcb_and_sinks_the_verdict`'s
  `!is_trustworthy()` assertion was vacuous — seeded from `Verdict::new()`, the verdict has only two
  checks recorded, so it reads untrustworthy regardless of what `record_attestation` does. Fixed by
  seeding every other essential check as `Passed` first (`every_other_essential_passing()`), so the
  assertion now demonstrates the degraded TCB status alone sinking an otherwise-trustworthy verdict.
  Reworded the assertion message to match.
- **D14 (nit, finding 4, taken).** `Verdict::record_attested_tcb` narrowed from `pub` to `pub(crate)`.
  Unlike `Verdict::record` (which stays `pub` because `Check`/`Outcome` are fully public and the wasm
  crate calls `record` cross-crate), `AttestedTcb` has no public constructor at all — only
  `AttestedTcb::new`, itself `pub(crate)` — so no external caller could ever pass a meaningful
  argument to `record_attested_tcb` regardless. Narrowing costs nothing real and matches the "a
  verdict's TCB statement comes from the verifier, not a caller" posture.
- **D15 (nit, finding 6, taken).** `#[non_exhaustive]` removed from `AttestedTcb`: both fields are
  private with no public constructor but `AttestedTcb::new`, so the attribute added nothing —
  contrast `connect::CollateralUnavailable`, which needs it because it has a public field.
- **D16 (implementation fix, caught by D12/D14's own gates).** Both `is_tcb_acceptable` (moved to
  `verdict.rs`, D12) and `record_attested_tcb` (narrowed to `pub(crate)`, D14) needed
  `#[cfg(feature = "attest")]` — without it, `cargo build --no-default-features` reported each as
  dead code, which is a hard failure under this repo's `RUSTFLAGS: -D warnings`. Same shape as D8;
  caught the same way, by actually running that build rather than by inspection. `is_tcb_acceptable`
  itself did *not* need the gate (only `record_attested_tcb` and `AttestedTcb::new` construct/consume
  attested data; `is_tcb_acceptable` is a pure predicate `AttestedTcb::is_up_to_date` calls
  unconditionally on every target) — verified by building `--no-default-features` clean before adding
  any gate, then adding it only where the build actually complained.
- **Process note.** Mid-review, a `git checkout -- crates/verity-verifier/src/attest.rs` intended to
  discard a temporary seen-to-fail shim instead reverted the entire file to its pre-VA-1 state,
  discarding all of Phase 3's uncommitted work on it. Caught immediately by `git status` showing the
  file no longer modified; reconstructed from the file content already captured earlier in the same
  session's transcript (attest.rs had been read and edited repeatedly, so its final Phase-3 shape was
  fully known) and verified byte-for-byte behaviourally equivalent by re-running every gate — `cargo
  test --all-features` returned the identical 297/297 pass count and `git diff --stat` showed 122
  changed lines against a pre-incident 123, a one-line difference from `Write` vs `Edit` tool
  whitespace rather than any content loss. No `git checkout`, `restore`, or `clean` was used again for
  the remainder of this work; every subsequent temporary edit was reverted with a matching `Edit` call
  instead.

## 11. Seen-to-fail evidence (Phase 3)

Every guard below was demonstrated red on the tree with the fix in place, by deliberately reproducing
the exact defect the guard exists to catch, then reverted and confirmed green. Full transcripts are in
the implementation commit message; summarised here:

| Guard | Break applied | Result |
|---|---|---|
| `attest::tests::only_up_to_date_is_acceptable` (moved to `verdict::tcb_acceptance_tests` in Phase 4, D12 — see below) | Widened `is_tcb_acceptable` to also accept `"Revoked"` | `assertion failed: !is_tcb_acceptable("Revoked")`, red → reverted, green |
| `verify::tests::a_degraded_status_fails_tcb_and_sinks_the_verdict` | Reverted the `TcbUnacceptable` arm of `record_attestation` to record `TcbStatus: Passed` (the original VV-01 bug) | `OutOfDate: a degraded TCB must reach a refusal, not a pass`, red → reverted, green |
| `verify::tests::a_passing_verdict_shows_which_status_passed` | Dropped `.record_attested_tcb(tcb)` on the `Ok` arm | `the status must be legible on a pass, not only on a refusal`, red → reverted, green |
| `verify_negative.rs::garbage_quote_fails_signature_and_mrconfigid` + `::skipped_essentials_are_not_trustworthy` (the D5 wiring test) | Made the `SignatureInvalid` arm of `record_attestation` populate a bogus `AttestedTcb` | Both tests failed on the new `attested_tcb().is_none()` assertion, red → reverted, green |
| CI grep (`no caller-configurable TCB policy`) | Added a throwaway `pub fn accepting() {}` to `attest.rs` | grep matched (job would fail), red → shim removed, grep clean |
| `tests/tcb_enforcement.rs` (arity guard) | Added a fourth parameter to `attest::verify_quote` | Whole crate failed to compile (`E0061`, argument #4 missing at the `verify()` call site), red → reverted, green |

Every gate above is a guard that has now been seen to fail, per this repo's CLAUDE.md discipline.

### Phase 4 seen-to-fail evidence (review findings)

| Guard | Break applied | Result |
|---|---|---|
| CI grep, **normal case** (D11) | Reintroduced `pub fn accepting() {}` in `attest.rs`, `examples/` present | New grep (`crates/ --include='*.rs' --exclude-dir=tests`) matched the knob and printed it; step would correctly fail |
| CI grep, **old fail-open reproduction** (D11) | Same knob, with `examples/` temporarily moved away, run under the **old** glob-based command (`crates/*/src crates/*/examples`) via real `bash` (not the interactive shell's grep wrapper) | `grep: crates/*/examples: No such file or directory` printed the violation to stdout but exited **2**; `if grep ...; then` was false — the old step would have silently passed with the knob present. Bug reproduced exactly as flagged. |
| CI grep, **new fix under the same missing-path case** (D11) | Same knob, same missing `examples/`, run under the **new** command (`crates/` directly, no globs) | Correctly matched and printed the knob; step would correctly fail even with `examples/` absent — the fail-open scenario is closed |
| CI grep, **clean tree** (D11) | Shim removed, `examples/` restored | No match; step correctly passes |
| `verdict::tcb_acceptance_tests::only_up_to_date_is_acceptable` + `verify::tests::a_degraded_status_fails_tcb_and_sinks_the_verdict`'s new `is_up_to_date()` assertion (D12) | Widened the now-unified `is_tcb_acceptable` in `verdict.rs` to also accept `"Revoked"` | Both went red simultaneously — `Revoked must be refused` in the former, `AttestedTcb::is_up_to_date must agree with the refusal above` in the latter — confirming the read-back path is actually exercised by the shared predicate, not just the enforcement path. Reverted, both green. |
| `verify::tests::a_degraded_status_fails_tcb_and_sinks_the_verdict`, **re-verified against its new (D13) seeded shape** | Reproduced the VV-01 bug again (`TcbStatus: Passed` on `TcbUnacceptable`) against the test as rewritten for D13 (seeded with every other essential `Passed`) | `OutOfDate: a degraded TCB must reach a refusal, not a pass`, red → reverted, green — confirms the seeding change didn't accidentally weaken what the test catches |

All `--no-default-features`, `connect`-alone, `cargo fmt --all --check`, `cargo clippy --all-targets
--all-features -- -D warnings` (only the pre-existing `chunks_exact_to_as_chunks` allow), `cargo doc
--no-deps --all-features`, and `cargo test --all-features` (297/297) gates were re-run clean after
every fix in this section, including after the accidental-revert recovery above.

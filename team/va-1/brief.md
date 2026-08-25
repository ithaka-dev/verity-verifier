# Brief — VA-1: remove caller-configurable TCB acceptance, enforce ADR 0014

**Repo:** `verity-verifier` @ `163e667` · **Issue:** VA-1 (audit finding VV-01, High) ·
**Board:** `verity-foundation/audit-implementation-plan.md`

## The issue

`TcbPolicy::accepting([...])` accepts arbitrary status strings, is exposed on the public
`ConnectRequest::tcb`, and flows into `verify()`. On the accepting path `verify()` records **both**
`QuoteSignature: Passed` **and** `TcbStatus: Passed` and **discards** the real status
(`verify.rs:180-181` — `.record(Check::TcbStatus, Outcome::Passed)` then `let _ = attested;`). A
caller passing `accepting(["Revoked"])` against a revoked platform therefore gets a trustworthy
verdict whose provenance shows `TcbStatus: Passed`, hiding both the actual Intel status and that the
policy was widened.

This violates **ADR 0014 rule 2** (TCB enforcement is mandatory and **not configurable** — no
option, no override, no strict mode) and **rule 1** (a verdict carries provenance so loosening is
detectable — here the loosening is invisible on the exact surface built to expose it).

**Operator decision (2026-08-25): enforce ADR 0014, do NOT supersede it.** No named degraded
statuses are wanted. The knob goes away; the single project decision (UpToDate only) is enforced
inside the verifier; and the real status becomes legible in every verdict, including on success.

## Acceptance criteria

1. **No public route accepts an arbitrary TCB status name.** `TcbPolicy` (and any equivalent knob) is
   gone from `verify`, `ConnectRequest`, and the connection APIs. Enforced by a test — ideally one
   that would fail to compile, or an API test, if a knob were reintroduced.
2. **UpToDate-only is enforced inside the verifier**, not chosen by the caller. `verify_quote` (or its
   successor) refuses any non-`UpToDate` status structurally.
3. **The real Intel TCB status and advisory IDs appear in every verdict, including on success.** The
   `Attested` struct already exposes `tcb_status()` / `advisory_ids()` (`attest.rs:44,53`) — today
   discarded at `verify.rs:181`. On a passing `TcbStatus` the verdict must let a reader see *which*
   status passed (`UpToDate`) and any advisories. **Must not break the ADR 0035 `Outcome` contract**
   (`Passed | Failed | Skipped | Indeterminate { .. }`) — architect decides the representation
   (e.g. detail carried on `Outcome::Passed`? a verdict-level field? — your call, but it must be
   legible in a *passing* verdict, and it must not weaken `is_trustworthy()` / the disposition table).
4. **The CI job stops overclaiming.** `.github/workflows/*.yml` job "TCB enforcement is not
   overridable" (~line 163) today asserts only that `dcap-qvl`'s `danger-allow-tcb-override` feature
   and `dangerous_verify_with_tcb_override` function are absent. Keep those. Add an assertion that no
   public API accepts arbitrary TCB status names (API/compile-fail test invoked here, or a grep for a
   reintroduced knob), and rename it so the name matches what it proves.

## Discipline (CLAUDE.md — non-negotiable)

- **Seen-to-fail first.** Every guarding test must be demonstrated red on the current tree, then green
  after the fix. Two required negatives: (a) no public route accepts an arbitrary status name;
  (b) every degraded/revoked status stays untrustworthy through the **complete assembled API**
  (not just a `verify_quote` unit call). Capture the red evidence.
- **ADR 0019:** PRs are paused — commit directly to `main`; the review record goes in the commit
  message.
- **ADR 0018:** reviewer sign-off is the gate.
- Keep `danger-allow-tcb-override` banned (existing CI assertions stay).

## Blast radius (measured 2026-08-25)

`TcbPolicy` referenced in 4 source files + 5 test files + 2 examples:

- **Source:** `src/attest.rs` (defn `TcbPolicy`, `up_to_date_only`, `accepting`, `accepts`;
  `verify_quote` takes `&TcbPolicy`), `src/verify.rs` (`verify()` takes `tcb: &TcbPolicy`, the
  discard at :180-181), `src/connect.rs` (`ConnectRequest::tcb` field + `new(...)` param;
  `connect_verified` at :292), `src/connect/http.rs:170` (calls `verify::verify`), `src/lib.rs`
  (re-export / doc).
- **`verify()` call sites** all in tests/examples: `channel_binding.rs` (×4), `verify_negative.rs`,
  `reference_and_verdict.rs`, `examples/verify-attestation.rs`, and internally `connect/http.rs:170`.
- **`ConnectRequest::new` call sites:** `verified_transport.rs` (×4), `examples/connect-verified.rs`.
- **WASM is untouched by the knob:** `verity-verifier-wasm` records `(TcbStatus, Skipped)` because it
  cannot do signature verification (`wasm/src/lib.rs:405`) and never constructs a `TcbPolicy`. The
  change must keep that path compiling and its semantics unchanged.

Every removed-param call site (tests + examples) must be updated in the same change — a dropped
`tcb` argument is a mechanical edit, but the *tests' intent* (e.g. `verify_negative.rs` asserting a
degraded status is refused) must be preserved and, where relevant, strengthened to go through the
assembled API per acceptance (b).

## Constraints

- MSRV / toolchain: `rust-toolchain.toml` pins 1.97.1; local machine has Homebrew rust 1.98 + **no
  rustup**. Local clippy needs `-A clippy::chunks_exact_to_as_chunks` (pre-existing lint on untouched
  `binding.rs`/`quote.rs`) — **allow nothing else**. `wasm32-unknown-unknown` cannot be built locally;
  that path verifies only in CI.
- Public-API stability: this is the crown-jewel third-party surface. Removing `TcbPolicy` is a
  deliberate breaking change to an unreleased (`0.0.0`) crate — acceptable, but the `#[non_exhaustive]`
  and doc discipline of the surrounding code must be matched.
- Do not touch unrelated code. The `danger_verification_time` seam and `CollateralSource` timeout
  discipline are out of scope (they are separate, correct mitigations).
- Team artifacts for this issue live in `team/va-1/` (the top-level `team/{brief,design,critique}.md`
  are MA-6's landed record — do not touch them).

## Assumptions (flag if wrong)

- The enforced policy is exactly `UpToDate` (the current `up_to_date_only` set). No `SWHardeningNeeded`
  / `ConfigurationNeeded` tolerance. If the architect finds a documented reason UpToDate-only is too
  strict for real dStack platforms, that is a design escalation to the user, not a silent widening.
- Recording the real status does not require a new `Outcome` variant; it fits on the existing surface.
  If the architect concludes a variant is unavoidable, that touches ADR 0035 and escalates to the user.

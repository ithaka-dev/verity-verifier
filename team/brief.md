# MA-6 (parts 1 and 2) — `Outcome::Indeterminate` and a typed per-check disposition

**Repo:** `verity-verifier`
**Issue source:** `verity-foundation/audit-implementation-plan.md`, MA-6, from the 2026-08-09
system-design review
**Facilitator:** this session, 2026-08-22
**Round budget:** 2 fix-loop rounds. Exceeding it stops the work and puts the position to the user.

## The issue, in one paragraph

`Outcome` has three variants: `Passed`, `Failed(String)`, `Skipped(String)`. There is no way to say
*"I attempted this check and could not establish an answer."* Stale references and collateral or
gateway outages therefore surface as `Failed`, which is indistinguishable from an attack. That is the
loosening pressure ADR 0009 rule 3 resists: refusals that are actually infrastructure faults train
whoever operates the agent to relax the check. MA-6 adds the fourth outcome and a **typed**
instruction per `(Check, Outcome)` so callers branch on an enum rather than on prose.

## Scope

**In scope — parts 1 and 2:**

1. `Outcome::Indeterminate { reason }` — attempted, could not establish. Distinct from `Failed`
   (violated) and `Skipped` (not attempted). **Do not overload `Skipped`** — it is ADR 0014's
   regression signal and F-09's alert is built on it.
2. A `disposition()` accessor per `(Check, Outcome)` returning
   `Refuse | RetryRetrieval | UpdateVerifier | UpdateReference | ProceedNonEssential`.

**Explicitly out of scope — part 3.** MA-6 also asks for boot-measurement references published as a
signed, versioned artifact keyed on `os_image_hash`. That is distribution and signing infrastructure,
not a verdict-surface change, and it is a separate issue. **Its blocking precondition is now
satisfied** — see measured facts below.

**Do not promote `Check::BootMeasurements` to `essential()` in this change.** MA-6 gates that on the
signed feed existing, which it does not.

## Acceptance criteria

- `Outcome` has four variants.
- `Indeterminate` **never contributes to `unrun_essentials()`**.
- Each `(Check, Outcome)` maps to exactly one disposition; the mapping is exhaustive.
- A missing boot reference yields `Indeterminate` → `UpdateReference`, not `Failed` or `Skipped`.
- A gateway/collateral retrieval failure yields `Indeterminate` → `RetryRetrieval`, not a mismatch.

## Measured facts

Gathered by the facilitator on **2026-08-22** by reading the tree at `e69fe86`-era HEAD
(`verity-verifier` HEAD `3342449`). **Re-verify rather than trust these** — one of them is the kind of
claim that has been wrong before in this project.

1. **`Outcome` is at `crates/verity-verifier/src/verdict.rs:124`**, `#[non_exhaustive]`, three
   variants.
2. **In-crate matches are deliberately exhaustive with no wildcard** — `label()` (~`:163`),
   `transcript_line()` (`:206`), `Verdict`'s `Display` (`:424`). The doc comment on `label()` states
   this is intentional: `#[non_exhaustive]` binds other crates only, so inside this crate a new
   variant is a **compile error**, forcing an explicit choice. Adding `Indeterminate` should break
   these three, and that is the design working.
3. **The WASM crate already has wildcards for exactly this**:
   `crates/verity-verifier-wasm/src/lib.rs:98-107` renders `_ => "unknown"` and
   `_ => Some("outcome variant unknown to these bindings; upgrade them")`. So the WASM surface will
   **compile without change and silently render `Indeterminate` as "unknown"**. Safe-by-design, but
   it means the JS surface needs deliberate work in this change or it under-reports.
4. **`label()` is a shell contract.** `verity-foundation/closed-loop/04-refuses-on-mismatch.sh` and
   `06-refuses-relayed-endpoint.sh` grep `passed` / `skipped` / `FAILED` out of the runner's stdout.
   A fourth word becomes a **cross-repo contract**; `tests/transcript_contract.rs` pins the format.
5. **`unrun_essentials()` (`:290`) filters on `self.outcome(*c).is_none()`** — "no outcome recorded
   at all". A recorded `Indeterminate` is therefore excluded **already**, with no code change. The
   acceptance criterion is satisfied by construction — but it is satisfied *incidentally*, so it
   needs a test pinning it or the next refactor loses it silently.
6. **`missing_essentials()` (`:304`) filters `!passed`.** An essential check that is `Indeterminate`
   therefore makes the verdict untrustworthy. That is believed correct — we could not establish an
   essential property, so we must not claim trust — but **state the position explicitly**; it is the
   single most consequential semantic decision in this change.
7. **`Check::essential()` (`:102`) excludes `BootMeasurements`** deliberately, and includes
   `ChannelBound` and `TcbStatus`. Do not change this list.
8. **`verify()` (`verify.rs:104`) does not fetch anything.** It takes `evidence.compose_document`
   already retrieved. So the "gateway down" case **does not arise inside `verify()`** — it arises in
   `compose.rs` (`FetchError`, `:113`; `Source`, `:155`) and in `connect.rs`'s `Refusal` (`:569`).
   **This is a genuine scoping question the design must answer:** can callers construct an
   `Indeterminate` outcome, or is it only produced internally? The gateway criterion may be
   unreachable without a public path.
9. **`verify.rs:199` currently records** `Skipped("no OS image reference supplied")` for
   `BootMeasurements`. This is the site MA-6 says must become `Indeterminate`.
10. **The boot reference is now n=2 and node-independent.** Measured 2026-08-22 on prod9 (node 18)
    against the 2026-08-08 prod5 capture: `MRTD`, `RTMR0`, `RTMR1`, `RTMR2` all identical; `RTMR3`
    differs as it must. Record:
    `verity-foundation/records/experiments/2026-08-22-boot-reference-is-node-independent.md`,
    commit `d33cd34`. This retires part 3's *capture* precondition, not part 3.

## Constraints

- **Public-API stability:** `Outcome` is `#[non_exhaustive]`, so adding a variant is not a breaking
  change for downstream crates. `disposition()` is new public surface — MA-6's gate is reviewer
  sign-off precisely because this is third-party-facing.
- **ADR 0014:** a verdict must stay legible about *which checks ran*. Do not let `Indeterminate`
  blur the `Failed` / never-ran distinction that F-09's alert depends on.
- **Never a bare boolean.** `is_trustworthy()` stays derived, not offered directly.
- **Agents must branch on the enum, never on prose.** `reason` strings are for humans; a caller
  matching on string content is the failure this change exists to prevent.
- MSRV / toolchain: as configured in the workspace — do not change it.

## Assumption flagged

The facilitator assumes an essential check returning `Indeterminate` must make the verdict
**untrustworthy** (fact 6). If the architect believes otherwise, that forks the design and comes back
before Phase 2, not after.

## Measured facts, addendum (2026-08-22, after first dispatch)

11. **`channel_bound`'s no-certificate case must stay `Skipped`.** `verify.rs:70` records
    `PeerCertificate::NotConnected => Skipped(...)`, and
    `verity-foundation/closed-loop/04-refuses-on-mismatch.sh:236` asserts `^  channel_bound +skipped`
    on its control run — the gate whose stated purpose is catching a verifier that silently stopped
    performing channel binding. Sweeping every `Skipped` into `Indeterminate` costs us the CR-1
    regression gate.
12. **The crate already defines `Skipped`.** `verify.rs:217-219`: *"`Skipped` in this crate means
    'considered and declined for a legitimate reason', and an unparseable quote is not one."* The
    existing boundary is legitimate-configuration-gap vs. evidence-is-unusable; `Indeterminate` is a
    third category between them and the design must place it in that same vocabulary. Note the same
    path records `BootMeasurements` as `Skipped("quote could not be parsed")`, which under the new
    taxonomy is probably wrong.
13. **`04:221` is guarded.** The `^  boot_measurements +passed` assertion only runs when a boot
    reference is supplied, so converting the *no-reference* case — the conversion MA-6 asks for — does
    not break it. `04:207`'s loop covers only compose_hash, images_pinned, licensed_image_present,
    quote_signature, tcb_status, mr_config_id.

## Corrections to this brief (2026-08-22, by the architect at Phase 1)

**These supersede the facts above. The facilitator wrote both errors; the architect caught them by
reading the code, and the facilitator re-verified both before accepting.**

- **Fact 2 was wrong, not merely incomplete.** It claimed in-crate matches on `Outcome` are
  exhaustive with no wildcard, so the compiler forces a decision at every site. **False.**
  `Verdict::failures()` (`verdict.rs:275-277`) has `_ => None`, and `Outcome::passed()` (`:139`) is a
  `matches!`. Two of five sites absorb a new variant **in silence** — and `failures()` is the
  accessor a caller reaches for when rendering what went wrong. The silent behaviour is what we
  happen to want, which is a coincidence, not a property, and must be pinned by test.

  The error's shape is worth naming: the facilitator read `label()`'s doc comment, which *does* argue
  for wildcard-free matching, and generalised it across the crate without checking the other sites —
  while `failures()`'s wildcard was inside text it had already displayed. A correct observation
  generalised past its subject, which is the failure mode
  `records/experiments/2026-08-17-correction-the-skills-are-tracked-by-yadm.md` names.

- **Fact 4 predicted a cross-repo break that does not exist.** No grep on `boot_measurements skipped`
  exists in `04` or `06`. Changing `verify.rs:201-204` breaks no gate. It falsifies a comment
  (`04:149`) and an operator message (`04:174`), and exposes that the no-reference branch asserts
  **nothing** — so the new word would ship unexercised by the only end-to-end gate over it. Fact 4's
  general claim — that a fourth transcript word is a cross-repo contract — stands.

- **Fact 9's line number is `:201-204`, not `:199`.**

- **Fact 8 is correct and understated.** `ConnectRequest.compose_document` is also a `Vec<u8>`
  (`connect.rs:102`), so the gateway case sits outside `connect_verified()` too, not just `verify()`.

Facts 1, 3, 5, 6, 7, 10, 11, 12, 13 verified as written.

## Corrections to facts 11 and 12 (2026-08-22, architect; facilitator re-verified)

- **Fact 11 overstated the risk.** `04:236` is real, but it is the **second** line of defence, not
  the first. `tests/channel_binding.rs:311-340`
  (`a_verdict_without_a_connection_is_not_trustworthy_and_says_so`) drives `verify()` with
  `PeerCertificate::NotConnected` and matches `Some(Outcome::Skipped(why))`, asserting the reason
  text as well. Sweeping that site into `Indeterminate` turns `cargo test` red in seconds, long
  before anyone spends a CVM. **Do not weaken that test to accommodate the new variant** — its three
  assertions (considered / did not pass / did not vanish) are the CR-1 regression signal itself.

- **Fact 12 is worse than reported, in a useful way.** The comment at `verify.rs:218-221` says an
  unparseable quote is not a legitimate reason to skip — and **three lines above it,
  `BootMeasurements` is skipped for an unparseable quote** (`:217`). The comment's subject is
  `ChannelBound`, so nothing is buggy; but the definition it states cannot be the crate's definition,
  because the crate contradicts it one statement earlier in the same expression chain.

  This is the strongest argument in the change for publishing a **rule** rather than just a variant:
  under the binary vocabulary there was no way to describe that line except by contradicting the
  definition sitting beside it. Under §2's rule (moot **or** declined) the existing behaviour is
  correct and the *comment* is the defect. **The comment must be rewritten in this change** — leaving
  it ships a definition MA-6 has just superseded, inside the file that violates it.

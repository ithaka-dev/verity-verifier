# MA-6 parts 1 and 2 — developer critique

**Role:** developer (ADR 0026 Rust team cycle)
**Date:** 2026-08-22
**Status:** Phase 2 critique, for consensus before implementation
**Design under review:** `team/design.md` (as of the §3.8 insertion and T-14/T-15)

---

## 0. Method, and what was actually executed

I built a working prototype of the design in a scratch copy of the tree
(`/private/tmp/claude-501/.../scratchpad/vv`, `rsync` of HEAD minus `target` and `.git`) and
compiled, linted and tested it. **The real repo was not touched** — `git status --porcelain` in
`verity-verifier` shows only the pre-existing untracked `team/`.

Prototype contents: `Outcome::Indeterminate { cause: Unestablished, detail: String }`,
`Unestablished`, `Disposition` + `name()`, private `Weight`/`weight()`, free `disposition()`,
`Verdict::disposition`/`dispositions`, `Check::ALL`/`index()`, and the `verify.rs:201-204`
conversion.

Commands and results:

| Command | Result |
|---|---|
| `cargo build --all-features` (baseline) | clean, 23.9s |
| `cargo build --all-features` (prototype, before fixing breaks) | **exactly 3 errors**, all `E0004` |
| `cargo clippy --all-features --lib -p verity-verifier -- -D warnings` | **clean** |
| `cargo test --all-features` | **20 binaries, 0 failures** |

Everything below marked *measured* is from that prototype, not from reading.

---

## 1. The headline measurement — the core conversion breaks nothing

**MA-6's named site changes behaviour and not one test notices.**

After converting `verify.rs:201-204` from `Skipped("no OS image reference supplied")` to
`Indeterminate { ReferenceUnavailable, … }`, the entire suite stayed green. I then checked why —
`grep -rn 'BootMeasurements' crates/*/tests`:

- `verdict_semantics.rs:258` (`an_absent_boot_reference_does_not_make_a_verdict_untrustworthy`)
  constructs the outcome **by hand** and never calls `verify()`.
- `reference_and_verdict.rs:139` only asserts `!essential().contains(&BootMeasurements)`.
- Nothing else touches it.

So **no Rust test and no shell gate exercises the no-boot-reference path through `verify()`
today.** The architect's fact-4 correction establishes the shell side ships unexercised; the Rust
side is unexercised too. Consequence for §5: **T-9 must drive `verify()`.** If it constructs the
outcome by hand it reproduces exactly the hole it exists to close.

---

## 2. Verdicts

| § | Verdict |
|---|---|
| §2 rule + eight-row table | **AMEND** — not total, and two contradictory discriminators decide rows 6 and 7 |
| §3.1 essential `Indeterminate` ⇒ untrustworthy | **AGREE** — measured, holds with no code change |
| §3.2 gateway criterion unreachable | **AMEND** — true for the gateway, false for collateral (`connect.rs:341`) |
| §3.3 typed `cause` | **AGREE** — compiles; or-pattern joins; `label()` stays `const fn` |
| §3.4 free `disposition()`, `Weight`, `ALL` | **AGREE**; **OBJECT** to `Check::index()` |
| §3.5 the sixth variant `Satisfied` | **AGREE** on the variant; T-7's invariant is unstatable; `Refuse`-on-trustworthy is undocumented |
| §3.6 fix the WASM surface here | **AGREE** on the conclusion; reason 3's mechanism is factually wrong; drop the `377/381` conversion |
| §3.8 the two immovable `Skipped` sites | **AGREE** on both sites; **AMEND** the comment rewrite — see §7 |
| §3.9 what is deliberately not changed | **AGREE** |
| §3.10 the fourth word `indeterminate` | **AGREE** on the word; `Display` has no column for it — decide in the design |
| §5 test plan | **AMEND** — three gaps |
| §6.1 the closed-loop assertion | **AMEND** — the branch it goes in is unreachable by default |
| **§2 propagation rule** (new) | **AGREE** — measured; T-16's negative reproduced both ways |
| **§4 step 3c `compose_unavailable`** (new) | **OBJECT** — it re-creates the critical page under F-09. See §14 |
| **§6a the alert split** (new) | **AMEND** — the decision is right; two specified changes are defective. See §14, §15 |
| **§6b the MR-CONFIG-ID arm** (new) | **AGREE** — and I verified the boundary argument against `binding.rs` |
| **§9 the four ADR dimensions** (new) | **AGREE** — checked against the skill; one addition |

---

## 3. §2 — the semantic rule and the eight-row table → **AMEND**

**Verification of totality: the table is not total, and the rule is not one rule.**

### 3a. A missing site

`grep -n 'Outcome::Skipped' crates/verity-verifier-wasm/src/lib.rs crates/verity-verifier/src/verify.rs`
gives nine production recording sites. The table covers eight.
**`verity-verifier-wasm/src/lib.rs:317-318`** records `ImagesPinned` / `LicensedImagePresent` as
`Skipped` after a compose mismatch and appears in no row. Semantically it is row 1's twin, so
nothing moves — but the table claims completeness and is one site short.

### 3b. The rule is two rules, and they disagree

The stated discriminator is **"is there a named remedy."** Applied honestly:

| Site | Missing input | Remedy | Table says |
|---|---|---|---|
| wasm `lib.rs:346` `ChannelBound` | `leafCertDer` | supply the certificate | **`Skipped`** |
| wasm `lib.rs:377,381` `QuoteSignature`/`TcbStatus` | Intel collateral | "use the Rust API" | **`Indeterminate`** |

Both are "the caller did not pass an input; passing it would establish the check." The rule cannot
separate them, so §3.8 separates them with a *second*, unstated rule — *did the caller decline* —
and that second rule points the other way for row 6: `lib.rs:359-371`'s own comment calls the
collateral omission **"a legitimate, structural omission"**, which is precisely "the caller
declined."

The clause "in this verdict" does not rescue it. Every remedy in `Unestablished` produces a
*different* verdict on a later attempt — retry, re-reference, re-verify. None of them changes *this*
one. The clause does no discriminating work.

### 3c. The `Failed` clause is violated by an existing site

§2 also defines `Failed` — *"the property was evaluated and does **not hold**"* — and the table lists
only `Skipped` sites, so this clause is never checked against the code. It is false at
**`verify.rs:222`**: `ChannelBound` is `Failed` on an unparseable quote, and the property was never
evaluated (`ChannelBinding::check` is not called on that path). §3.8 concedes this: *"Under §2's rule
it is a category stretch."* That matters because `verify.rs:218-221` — the comment this change must
rewrite — annotates that exact line. See §7.

### 3d. Concrete alternative — one discriminator per pair, total over all nine sites

> - **`Failed`** — the check reached a **refusal**. Same inputs, same refusal.
> - **`Skipped`** — the check did not run and there is nothing to tell the operator to do: a prior
>   refusal made it moot, or its absence is the normal, expected condition of this call.
> - **`Indeterminate`** — the check did not conclude, and there is an action **this caller can take
>   in this environment** that would let it conclude.

Checked against every `Failed` site (`verify.rs:63, 120, 132, 139, 168, 172, 186, 197, 216, 222`) and
every `Skipped` site (`verify.rs:70, 145-146, 175, 201-204, 217`; wasm `317-318, 346, 377, 381`).
Every one is a first-class instance. Under it:

- `verify.rs:222` stops being an exception — an unparseable quote presented as an endpoint's
  attestation *is* a refusal, which is what the existing comment's surviving conclusion already says.
- Boot-reference → `Indeterminate` (obtaining a reference is a real, recommended act). MA-6's
  acceptance criterion is met.
- wasm `346` → `Skipped`, and **wasm `377/381` → `Skipped` too**: a browser caller cannot obtain
  Intel collateral, and "use the Rust API" is a different program, not an action on this call. This
  is the same argument §3.6 makes when rejecting the "upgrade them" string.
- It independently explains §3.5's `(BootMeasurements, Failed) → Refuse` asymmetry, which currently
  needs its own paragraph of justification: if `Failed` means *the check refused*, `Refuse` is the
  mechanical reading, not a strictness choice requiring defence.

---

## 4. §3.1 → **AGREE**

Measured on the prototype with essential `TcbStatus` set to `Indeterminate`:

```
TRUSTWORTHY_essential_indet=false
UNRUN=[]      MISSING=[TcbStatus]      FAILURES=[]
```

Facts 5 and 6 hold with zero code change, exactly as claimed, and exactly as *incidentally* as
claimed. The position is right and T-1/T-2/T-3 are the correct response.

---

## 5. §3.2 — the gateway criterion → **AMEND. Half of it is reachable, in this crate, today.**

The **gateway** half is correct and I verified the mechanism: `verify.rs:34` and `connect.rs:102`
both take `compose_document: Vec<u8>`, and `compose::Source` (`compose.rs:155`) is a public trait
embedders implement. Rejecting the `Evidence`-widening is right, for the three reasons given.

But the brief's criterion says "**gateway/collateral** retrieval failure." The **collateral** half is
inside this crate, on a live path:

- **`connect.rs:341`** — `let collateral = Arc::new(collateral.collateral_for(&raw_quote)?);` — a
  retrieval that fails inside `connect_verified`, producing `Refusal::CollateralUnavailable`.
- **`verified_transport.rs:696-710`** already drives the sibling `NotReached` case against a real
  closed TCP port, for free, in CI, asserting `RefusalKind::CouldNotEstablish`.

So `Refusal::disposition()` (§3.7) makes *"a retrieval outage dispositions to `RetryRetrieval` and is
provably never a mismatch"* **true on an executed code path, with an existing free test one line from
covering it.** §3.2 should say that rather than "no end-to-end demonstration exists."

**Considered and rejected — the more ambitious version.** Emitting a partial `Verdict` at
`connect.rs:341` with `QuoteSignature`/`TcbStatus` indeterminate would make `unrun_essentials()`
non-empty for five checks that were never reached — which is F-09's *"the verifier silently stopped
checking"* signal. That would poison the alert. Verdict-less refusal plus `Refusal::disposition()` is
the right shape.

**Direct consequence: §3.7 / step 5 is not the cuttable step.** See §11 Q1.

---

## 6. §3.3, §3.4, §3.5, §3.6, §3.9, §3.10

### §3.3 typed `cause` → **AGREE**

The argument is sound (same `Check`, different remedies) and it is free at implementation cost.
Measured: the struct variant joins the tuple variants in `transcript_line`'s or-pattern —

```rust
Outcome::Failed(why)
| Outcome::Skipped(why)
| Outcome::Indeterminate { detail: why, .. } => format!("{label} ({why})"),
```

— and `label()` stays `pub const fn` with a struct-variant arm. Both compile. The existing
`Clone`/`PartialEq`/`Eq` derives carry over with nothing downstream touched.

### §3.4 free `disposition()`, private `Weight`, `Check::ALL` → **AGREE**, except `index()` → **OBJECT**

The free function is right; `Weight` is right; rejecting `essential().contains()` is right (it
fail-opens on a new variant). Measured: written as a match on `Outcome` with a nested match on
`weight(check)` in the `Skipped` arm only, `clippy --all-targets -- -D warnings` is **clean** — no
`match_same_arms` under `pedantic`, which was my concern given `ci.yml:32`.

**`Check::index()` should not ship.** It has no consumer. It exists only so T-6 can test that `ALL`
is ordered and duplicate-free — a property nothing depends on, guarding a list whose staleness the
design itself says *"weakens test coverage, not the mapping."* That is new public API on a
third-party-facing crate, added to satisfy a test of a test. Drop `index()` and T-6; keep `ALL`.

Note also that `verdict_semantics.rs:395-410` already hand-enumerates all eight checks as literals.
If `ALL` lands, **that test must not be refactored onto it** — its whole point is that the strings are
literals a rename has to confront.

### §3.5 `Satisfied` → **AGREE on the variant. Two problems in the same section.**

`Satisfied` is right and the three rejected alternatives are correctly rejected.

**Problem 1 — T-7's invariant is not statable as written.**

> `disposition(c, o) ∈ { Satisfied, ProceedNonEssential }` ⟹ a verdict whose only non-passing
> essential is `(c, o)` is trustworthy.

If the disposition is `Satisfied`, `o` is `Passed`, so there is no non-passing essential — vacuous.
If it is `ProceedNonEssential`, `(c, o)` is `(BootMeasurements, Skipped)`, which is not essential —
the antecedent is ill-typed. The property you want, checkable over all 48 pairs:

> For every `c` in `Check::essential()` and every `o` where `!o.passed()`:
> `disposition(c, o) ∉ { Satisfied, ProceedNonEssential }`.

*No disposition ever advises proceeding on a non-passing essential.* One loop, and its negative is
the one already named (map `(Essential, Skipped)` → `ProceedNonEssential`).

**Problem 2 — `Refuse` on a trustworthy verdict, undocumented.** `(BootMeasurements, Failed)` →
`Refuse` while `is_trustworthy()` stays `true` — pinned today by `verdict_semantics.rs:270-281`. So
`Verdict::dispositions()` can hand a caller a `Refuse` on a verdict `TrustworthyVerdict::check`
accepts. §3.4 rejected `overall_disposition()` because a single actionable value competes with
`TrustworthyVerdict`; shipping `dispositions()` with a `Refuse` the trust boolean contradicts hands
every caller the ingredients to build that competing rule, and *"any `Refuse` ⇒ do not proceed"* is
the obvious thing they will write. The mapping is defensible. **`Disposition::Refuse`'s doc comment
must state that it can appear on a trustworthy verdict, and that dispositions never override
`TrustworthyVerdict` in either direction.**

### §3.6 fix the WASM surface here → **AGREE on the conclusion; reason 3 is wrong; drop `377/381`**

**Reason 3 is factually wrong.** `tests/transcript_contract.rs:196-206`
(`the_labels_match_the_words_the_javascript_bindings_report`) does not reach the WASM crate at all.
It lives in `crates/verity-verifier/tests/`, which does not depend on `verity-verifier-wasm`; it
asserts `Outcome::label()` against three hardcoded literals with a *comment* describing `to_js`. **It
would pass if `to_js` were deleted.** It is not a gate that passes because of the wildcard — it is a
gate structurally incapable of observing the other surface. So adding an `Indeterminate` arm to
`to_js` does not make this test guard anything.

**The repair that follows:** the drift guard must live where both surfaces are in scope — the WASM
crate, which depends on the core. A test asserting, for all four variants,
`to_js(...).outcome == Outcome::label().to_lowercase()` is what would actually go red on drift.
`to_js` is natively testable (`lib.rs:650` calls it directly and runs on host), so this costs nothing.

**Reasons 1 and 2 stand, and I reproduced T-12's negative.** With the variant added and `to_js`
untouched:

```
OUTCOME="unknown" DETAIL=Some("outcome variant unknown to these bindings; upgrade them")
assertion `left == right` failed
  left: "unknown"   right: "indeterminate"
```

Exactly as §3.6 predicts. That transcript belongs in the commit message.

**Drop the `377/381` conversion from this change.** §3.6 argues "upgrade them" is unacceptable
because the bindings derive their version from the core, so no upgrade exists. `UpdateVerifier`'s
wire name would tell a browser caller `update_verifier` about a limitation no update fixes — the same
false remedy, in the typed field this change exists to make trustworthy. Under §3d those two sites
are `Skipped`. If you keep the conversion instead, the wire name must not say "update", which is a
third vocabulary deviation and, in my judgement, worse value than leaving the sites alone.

### §3.9 what is deliberately not changed → **AGREE**

`Check::essential()` untouched, `unrun_essentials`/`missing_essentials` untouched,
`Evidence`/`ConnectRequest` untouched. All correct, and §3.1's measurement confirms the two filters
need no change.

### §3.10 the fourth word → **AGREE on the word. `Verdict`'s `Display` has no column for it.**

Transcript rendering measured, byte for byte as predicted:

```
[  boot_measurements      indeterminate (no OS image reference supplied)]
```

six spaces, and `matches_grep(line, "boot_measurements", "indeterminate")` returns true.

But `Display for Verdict` (`verdict.rs:424-428`) uses a **fixed 8-column prefix**: `"  pass    "`,
`"  FAIL    "`, `"  skipped "`. `indeterminate` is 13 characters. §4 step 1 says only "a fourth line
form" and leaves the choice open. It is not free:

- A shorter token → the transcript word and the `Display` word disagree, breaking §3.10's own
  *"the word an operator greps should be the word in the type."*
- Widen every line to 14 → `verdict_semantics.rs:354-368`
  (`display_renders_pass_fail_and_skip_as_three_distinct_things`) goes red on
  `contains("pass    compose_hash")`, as does `transcript_contract.rs:182`.

Pick one in the design, not at the keyboard. My preference: widen `Display`, take the two test
updates, keep one word.

---

## 7. §3.8 — the two immovable sites → **AGREE on both. AMEND the comment rewrite.**

### The `ChannelBound` site: agreed, and the guard verified by running it

I converted `verify.rs:70` `NotConnected` to `Indeterminate` and ran the suite:

```
test a_verdict_without_a_connection_is_not_trustworthy_and_says_so ... FAILED
test result: FAILED. 12 passed; 1 failed
```

One test, that test, seconds. Fact 11's correction is right: `channel_binding.rs:311-340` catches the
sweep long before `04` ever runs.

### The comment rewrite is the part that needs amending

The framing is *"under §2's rule the behaviour is correct and the comment is the defect."* That holds
for `BootMeasurements` at `:217`. It does **not** hold for the statement the comment is actually
about. Per §3c, `ChannelBound` at `verify.rs:222` violates §2's `Failed` clause, and §3.8 concedes it
as *"a category stretch."*

So as designed, the rewrite replaces a comment whose stated definition its own expression chain
violates **with a comment whose stated definition its own line violates**, and disclaims the
violation in the same breath — at the crate's only written definition of the vocabulary, in a change
whose thesis is that the vocabulary must be stated as a rule. A reader who takes the rule seriously
will read the disclaimer as special pleading and eventually "fix" the line, which is the outcome T-15
exists to prevent.

**Use §3d's `Failed` clause** — *the check reached a refusal* — and the comment states a rule it
obeys, with its surviving conclusion unchanged.

---

## 8. §5 — test plan → **AMEND. Strongest plan I have reviewed here; three gaps.**

The "produce the negative first" discipline is correctly applied to T-1, T-2, T-4, T-5, T-7, T-9,
T-10, T-12, T-14.

**Gap 1 — T-3's negative is not "the wildcard is already there."** *"Assert first, note it passed on
arrival"* is exactly the pattern
`records/experiments/2026-08-15-a-taxonomy-of-gates-that-do-not-guard.md` warns about: a check
written at the moment its author is convinced the property holds. **The negative is free and I ran
it.** Changing `verdict.rs:275-277` to

```rust
Outcome::Failed(why) | Outcome::Indeterminate { detail: why, .. } => Some((*c, why.as_str())),
```

gives:

```
thread 't3_indeterminate_is_not_a_failure' panicked:
was [(BootMeasurements, "no OS image reference supplied")]
```

**Three** negatives cost nothing, not two.

**Gap 2 — T-8 is the only row with `n/a`, and the design names it the likeliest defect.** The
negative exists: flip one arm of `disposition()` and confirm **exactly one** row goes red. Two red ⇒
the literals were derived rather than written. None red ⇒ the table is `f(x) == f(x)`. That check *is*
the point of T-8 and belongs in the plan.

**Gap 3 — T-11 is in the wrong file.** `tests/compose_fetch.rs:12` is `#![cfg(feature = "fetch")]`,
and its module header says the tests **skip when no IPFS daemon is reachable**; CI runs it as a
separate job with a service container (`ci.yml:115`). `From<&FetchError> for Unestablished` is a pure
mapping and `FetchError` is ungated (`compose.rs:113`). Putting the acceptance-criterion test behind
a feature flag *and* a live daemon means it does not run on `cargo test`. Move it to
`verdict_semantics.rs` or a new ungated `dispositions.rs`.

**T-9 must drive `verify()`** — see §1.

### T-14 → **AGREE**, with one measured caveat

**It is not a general guard on that `verify()` call.** `channel_binding.rs:311-340` drives `verify()`
with `boot: None` — so it traverses MA-6's own conversion site — and asserts **nothing** about
`BootMeasurements`. That is precisely why it survived my `verify.rs:201-204` conversion while the
suite stayed green. T-14 must not be read as covering the boot path, and **T-9 cannot be folded into
it.**

**Name the shape of the weakening you are forbidding.** "Do not weaken" is a good instruction a
future reader will satisfy the wrong way. The specific weakening is replacing
`Some(Outcome::Skipped(why))` with a wildcard that extracts a detail string from any variant — which
keeps all three axis assertions green while destroying what the match arm is doing. Put that in the
test's doc comment, not only in the design.

Extending it with `disposition(ChannelBound, Skipped) == Refuse` overlaps T-4, but it pins the pair
*through `verify()`* rather than through the table, so it earns its place.

### T-15 → **AGREE**, and it is nearly free — the fixture already exists

`verify_negative.rs:184-196` (`garbage_quote_fails_signature_and_mrconfigid`) already reaches that
state with `vec![0u8; 700]`. I printed the outcomes:

```
BOOT=Some(Skipped("quote could not be parsed: unsupported quote version 0"))
CHAN=Some(Failed("quote could not be parsed: unsupported quote version 0"))
```

Both checks are already recorded and the file asserts neither.
`grep -rn 'quote could not be parsed' crates/` returns one production line and no test. So the
asymmetry §3.8 preserves is **currently pinned by nothing at all** — the design's *"rests on a comment
whose premise this change deletes"* is exactly right. Prefer a sibling test over extending the
existing one, so `garbage_quote_fails_signature_and_mrconfigid` keeps a name that describes what it
asserts.

---

## 9. §6.1 — the closed-loop assertion is a gate that will never run

§6.1 proposes adding `grep -qE "^  boot_measurements +indeterminate"` to `04`'s **no-reference
branch**. Read `04-refuses-on-mismatch.sh:158-172`:

```sh
image="${DSTACK_IMAGE:-dstack-0.5.9}"
boot_ref="${BOOT_REFERENCE:-}"
if [ -z "$boot_ref" ]; then
  candidate="$here/fixtures/boot-reference-dstack-$(echo "$image" | sed 's/^dstack-//').json"
```

and `closed-loop/fixtures/` contains `boot-reference-dstack-0.5.9.json`, whose `os_image` matches the
default. **On a default run the reference always resolves, so the no-reference branch is dead code
and the new grep never executes.** `BOOT_REFERENCE=""` falls straight through the `-z` test back to
auto-resolution; there is no sentinel to force it.

The design flags this assertion as *"will not be seen to pass until someone runs it."* It is worse:
as specified it cannot be run at all. Either add a sentinel (`BOOT_REFERENCE=none` short-circuiting
resolution) in the same `verity-foundation` change, or drop the assertion and rely on T-10. Adding it
as-is ships decoration into the file whose job is to not be decoration.

**On the approved `alerts.yaml` split:** I assume nothing about its shape. One consequence for the
design regardless of shape — the disposition name strings become a **PromQL label value**, which
makes §11 Q2's answer more load-bearing, not less. `alerts.yaml:24` already matches
`outcome="refused"` and `observability/conventions.md:73,90` are snake_case throughout.

---

## 10. What I falsified or established by running it

| Claim | Source | Result |
|---|---|---|
| Adding the variant breaks exactly the three wildcard-free sites | §1 fact 2 (corrected) | **Confirmed** — 3 × `E0004`, `label()`, `transcript_line()`, `Display` |
| `failures()` and `passed()` absorb it silently | §1 fact 2 correction | **Confirmed** — and the T-3 negative is free, transcript in §8 |
| WASM compiles unchanged and renders `"unknown"` | fact 3 / §3.6 | **Confirmed** — transcript in §6 |
| No closed-loop grep breaks | fact 4 correction | **Confirmed** — `04:207,221,236,302,310`; `06:178,214` |
| `unrun_essentials` excludes a recorded `Indeterminate` | fact 5 | **Confirmed** — `UNRUN=[]` |
| An essential `Indeterminate` sinks the verdict with no code change | fact 6 / §3.1 | **Confirmed** — `TRUSTWORTHY_essential_indet=false` |
| The `ChannelBound` sweep is caught in `cargo test` | fact 11 correction | **Confirmed** — 1 test red in seconds |
| Transcript line is six spaces, greppable | §3.10 | **Confirmed** byte for byte |
| `transcript_line`'s or-pattern joins a struct variant; `label()` stays `const` | §4 step 1 | **Confirmed** — compiles |
| The disposition table survives `clippy pedantic -D warnings` | implied by §3.4 | **Confirmed** — clean, no `match_same_arms` |
| **`transcript_contract.rs`'s JS-drift test observes the WASM surface** | §3.6 reason 3 | **FALSIFIED** — it does not depend on that crate; it would pass if `to_js` were deleted |
| **The conversion is covered by existing Rust tests** | implied throughout | **FALSIFIED** — 20 binaries green through the change; nothing drives that path |
| **§6.1's new grep will be exercised by `04`** | §6.1 | **FALSIFIED** — the branch is unreachable by default |
| **T-15's state is untested** | §5 T-15 | **Confirmed, with the fixture located** — transcript in §8 |

---

## 11. §8 — the three open questions

### Q1. Step 5 (`connect.rs`) — **IN, and it is the wrong thing to cut**

Per §5 above, `Refusal::disposition()` is the only place in this change where a retrieval outage →
`RetryRetrieval` becomes true on a code path that executes, and `verified_transport.rs:696-710`
already drives a real `NotReached` refusal for free. Cut it and
`impl From<&FetchError> for Unestablished` becomes a mapping nothing in the repo calls, and the
change ships with zero executed evidence for one of its two acceptance criteria. If the budget forces
a cut, cut **the `kind()` refinement only** and keep `Refusal::disposition()`.

On the `kind()` refinement: losing `const` is real and unavoidable — `missing_essentials()`
allocates, `outcome()` uses an iterator, and a `Vec` cannot be indexed in a `const fn`. All sixteen
call sites (`grep -rn '\.kind()'`) are value contexts, so nothing breaks. Two things the design
missed:

- The proposed rule (*`GuaranteeViolated` if any essential `Failed` or was `Skipped`;
  `CouldNotEstablish` when the only non-passing essentials are `Indeterminate`*) **does not cover
  essentials that never ran** — and `verified_transport.rs:592-596` asserts exactly that case,
  `Refusal::NotTrustworthy { verdict: Verdict::new() }` → `GuaranteeViolated`. Write the never-ran arm
  explicitly.
- `closed-loop/08:619` greps only `endpoint_unusable`, so no shell gate is at risk.

### Q2. `Disposition::name()` string form — **snake_case, not kebab**

Code evidence, three places:

- `connect.rs:723-725` — `RefusalKind::name()` → `"guarantee_violated"`, `"could_not_establish"`,
  `"endpoint_unusable"`, documented as *"a stable identifier, suitable for telemetry and for a shell
  harness to grep."*
- `verdict.rs:64-71` — `Check::name()` → `"compose_hash"`, `"licensed_image_present"`.
- `verity-foundation/observability/conventions.md:73,90` — `needs_holder_action`,
  `compose_hash_mismatch`, `mrconfigid_mismatch`.

Kebab would make `Disposition` the only non-snake_case identifier vocabulary in a two-repo telemetry
contract. The camelCase-JSON-keys argument does not survive contact with `RefusalKind`, which already
ships snake_case values through the same JSON surface. Use `satisfied`, `refuse`, `retry_retrieval`,
`update_verifier`, `update_reference`, `proceed_non_essential`. The now-approved `alerts.yaml` split
makes these PromQL label values, which strengthens the case.

### Q3. `Check::ALL` — **public, yes; drop `index()`**

`Check` is `#[non_exhaustive]` (`verdict.rs:29`), so a downstream caller genuinely cannot enumerate
the checks without it — a real consumer, not a test convenience. Document it as hand-maintained with
the guard living in `weight()`, as proposed. `index()` has no consumer at all; see §6.

---

## 12. Design smells found, flagged not fixed

- **`verify::Evidence` is not `#[non_exhaustive]`** (`verify.rs:25-26`) while `connect::ConnectRequest`
  is (`connect.rs:90-92`), for reasons stated in `connect.rs` that apply equally to both. The
  architect found this; I confirm it and agree it is a separate issue.
- **`Refusal::verdict()`** (`connect.rs:681-683`) has a `_ => None` wildcard — the same silent-absorb
  shape as `failures()`, one type over. Not in MA-6's path, but it is the second instance of a pattern
  the design correctly calls a coincidence rather than a property.

---

## 13. Position

Nothing here is a borrow-checker, trait-indirection or async problem. **The design is mechanically
implementable as specified** — I built it and it compiles, lints and tests clean. The disagreements
are about which claims are demonstrated, which vocabulary the crate already speaks, and one section
(§2 / §3.8) whose rule contradicts itself at the line it is about to annotate.

Consensus reachable on: §3d's three-way rule replacing §2's; `index()` and T-6 dropped; T-3's free
negative produced; T-8 given a negative; T-11 moved out of `compose_fetch.rs`; T-9 driving `verify()`;
snake_case names; step 5 kept; `Display`'s fourth line form decided in the design; the WASM drift
guard relocated to the crate that can see both surfaces; and either a `BOOT_REFERENCE` sentinel in
`04` or no assertion there.

---

# Round 2 — after loading `rust-developer` explicitly, and after §2/§6a/§6b/§9 landed

## 13. The skill question, answered honestly

I loaded `rust-developer` with the Skill tool. My persona text asserted it was already loaded; that
assertion was not evidence, and the team lead was right to make me check.

**Its conventions changed nothing in the critique.** I re-checked the design against each one and the
design is compliant:

- *Error handling* — `Unestablished` / `Disposition` are classifications, not errors; §9 states this
  and is right. `From<&FetchError>` (rather than `From<FetchError>`) is the correct choice because
  `FetchError` is not `Clone` (`compose.rs:111`).
- *API & storage isolation* ("keep serde derives off domain types; define wire DTOs at the
  boundary") — the design already complies: `Disposition` carries no serde, and the WASM surface
  projects through `Disposition::name()` into `JsCheck`, which is the boundary DTO. Worth stating as
  a standing constraint: a future "just `#[derive(Serialize)]` on `Disposition`" shortcut would
  violate it.
- *Testing / proptest* — the skill says proptest where there are formal invariants. Here the domain
  is finite (8 × 6 = 48), so exhaustive enumeration strictly dominates proptest. No change; recorded
  as a considered negative.
- *Unsafe, async, feature additivity* — nothing to add beyond what §9 already says.

**What did change is the verification baseline.** The skill names six CI gates. I had run two of
them. I have now run all six against the prototype:

| Gate | Result |
|---|---|
| `cargo fmt --all --check` | clean |
| `cargo clippy --all-targets --all-features -- -D warnings` | clean |
| `cargo build --workspace --all-targets` | clean |
| `cargo test --all-features` | 23 × `test result: ok`, 0 failures |
| `cargo doc --no-deps --all-features` | clean — **including the intra-doc links the design specifies**, `[`disposition`]`, `[`TrustworthyVerdict`]`, and `[`Verdict::dispositions`]` resolved from the feature-gated `connect.rs` |
| `cargo audit` | not run — no lockfile change in this design, so out of its blast radius |

Two findings from the gates I had skipped, both small and both real:

1. **`--all-targets` applies `missing_docs` to integration-test crates.** Every existing file in
   `tests/` carries a `//!` header. My recommended new `dispositions.rs` (§8, gap 3) **must** have
   one or CI goes red on a file the design does not mention creating.
2. **`Refusal::disposition()` costs nothing at the doc layer.** I implemented §3.7's signature
   verbatim, with its doc comment verbatim, and `cargo doc` is clean — so the cross-module link from
   the feature-gated module resolves. That removes one unknown from keeping step 5 in.

So: the gap in my instructions was **not** harmless for my role — it was harmless for my *judgements*
and not for my *evidence*. Three of the six commands I was supposed to have run, I had not.

---

## 14. §4 step 3c and §6a — **OBJECT**. The split moves the critical page rather than removing it.

This is the one finding in this round that changes the outcome of the change.

### The measurement

I implemented §4 step 3c's `compose_unavailable(cause, detail) -> Verdict` exactly as specified and
measured what it produces:

```
RECORDED             = ["compose_hash", "images_pinned", "licensed_image_present"]
UNRUN                = ["quote_signature", "tcb_status", "mr_config_id", "channel_bound"]
MISSING              = [all seven essentials]
TRUST                = false
REFUSE_DISPOSITIONS  = []
PRE_FIX images_pinned -> Refuse
NO_COUNTER_INCREMENT = ["quote_signature", "tcb_status", "mr_config_id",
                        "boot_measurements", "channel_bound"]
```

**The good news first, and it is real: `REFUSE_DISPOSITIONS = []`.** §6a's coupling fix works.
Without propagation, `disposition(ImagesPinned, Skipped)` is `Refuse` (last line above) and the
critical page fires; with it, nothing dispositions to `refuse`. **T-16's negative is genuine, is
free, and I reproduced it in both directions.** §2's propagation rule → **AGREE**.

### The objection

`compose_unavailable` is a **whole verdict** — §4 step 3c says it is what a caller records *instead
of* calling `verify()`, and §6a reasons about it incrementing `verity_verify_total{outcome="refused"}`.
It records three checks. **Five checks get no counter increment at all.**

Now read F-09's actual expression (`alerts.yaml:75-82`):

```promql
(  sum by (check) (increase(verity_verify_check_total[1h])) == 0  )
and on(check) (
   sum by (check) (increase(verity_verify_check_total[24h] offset 1h)) > 0 )
```

It fires when a check's series goes **quiet for an hour** having been active in the preceding 24. A
sustained gateway outage does exactly that, for five checks at once. `VerifierStoppedChecking`,
`severity: critical`, five times — with a runbook that says *"treat every acceptance since the
transition as unverified."*

**§6a's "F-09 is unaffected" is right about label addition and silent about series disappearance.**
It verified that `sum by (check)` discards a new `disposition` label — true, and I confirm it. It did
not check what happens when a verification stops emitting five of the eight series. That is the same
defect class §6a itself caught one layer down (*"the split would have shipped and done nothing"*),
recurring one layer up: **as specified, the split does not remove the critical page for an IPFS
outage, it renames it.**

There is a library-side witness for the same defect, independent of Prometheus: `UNRUN` is four
essentials, and `verdict.rs:282-288` defines `unrun_essentials()` as *"the failure mode §4.5 cannot
otherwise see… a check that silently stopped running."* A routine gateway outage now trips the
crate's own regression predicate. ADR 0014's vocabulary has no way to say *"we never got far enough
to attempt this"*, and `compose_unavailable` needs exactly that.

### The concrete alternative

Two parts, and the second is the load-bearing one.

**(a) Library — make the partial verdict say it is partial.** `compose_unavailable`'s doc must state
that the returned verdict is **incomplete by construction**, that `unrun_essentials()` on it means
"never reached", not "regressed", and that an emitter must not treat it as a full verification for
`verity.verify.checks`. That is a doc obligation, not a type change; the alternative — recording the
five quote-side checks as something — would need a seventh disposition for "not attempted", which
collides with `unrun_essentials()` and is worse.

**(b) `verity-foundation` — condition F-09 on its own stated premise.** F-09's description already
says *"Verifications are still being reported as accepted, but this comparison is no longer among the
checks they performed."* The expression does not encode "still being reported as accepted". Add one
conjunct:

```promql
and on() ( sum(increase(verity_verify_total{outcome="accepted"}[1h])) > 0 )
```

This closes the outage false positive without weakening the regression signal by one bit — a verifier
that quietly stopped checking **still returns `accepted`**, which is F-09's entire premise. It is a
`verity-foundation` change that §6a currently says is not needed, and it must join §6a's list.

Until (b) lands, **shipping §6a makes the operator experience worse than not splitting**: today one
critical fires for an outage; after the split, five do, under an alert whose runbook instructs the
operator to distrust every prior acceptance.

---

## 15. §6a — the rest → **AMEND**

The core decision is right and I want to say so plainly: rejecting a third `outcome` value, rejecting
a `disposition` label on the per-verification counter, and putting `disposition` on
`verity_verify_check_total{check, disposition}` is the correct answer, for the reasons given. The
48-series bound is right. `NoVerificationsObserved` and `VerifierAcceptedDegradedTcb` are genuinely
unaffected — I checked both selectors (`alerts.yaml:47-49`, `:105`).

Three defects in the specified changes:

**1. Re-keying F-08 breaks its own annotations.** §6a re-points F-08 at
`verity_verify_check_total{disposition="refuse"}`, a counter it documents as carrying exactly
`{check, disposition}`. F-08's annotations interpolate **`{{ $labels.refusal }}` twice** —
`alerts.yaml:31-32` (`reason {{ $labels.refusal }}`) and `:41-43` (*"First questions: is `refusal` a
mismatch or an unsupported format?"*). `refusal` is a label on `verity_verify_total`, not on the
check counter. After the re-key the summary renders `reason ` with nothing after it, and the
description's first diagnostic question cannot be answered from the alert. §6a says only *"the
description needs one added paragraph."*

Repair: interpolate `{{ $labels.check }}`, which **is** on the new counter and is strictly more useful
(*"the `mr_config_id` comparison refused"*), and re-point the "First questions" paragraph at the span
attribute `verity.verify.dispositions` rather than at a label that no longer exists on this series.

**2. `for: 0m` on a per-series F-08 changes its cardinality.** The new expression has no `sum`, so it
is per-series: one firing alert **per check**. A verdict with three refusing checks pages three times
where it paged once. Probably desirable — but it is a behaviour change §6a does not name, and
`for: 0m` means no debounce. Either state it as intended or wrap in `sum()`.

**3. The `unless` window imprecision is recorded, and the record is slightly wrong in the safe
direction.** §6a says a real violation plus an outage in the same window suppresses the warning and
fires only the critical. Correct. Worth adding: the reverse is *also* possible across a rule
boundary — an outage spanning two 5m windows with a violation in only one fires the warning in the
other, which is the harmless direction and should be said so nobody "fixes" it later.

Two things §6a gets right that I want on the record because they are easy to lose:

- The `UnsupportedMrConfigIdVersion` witness (`alerts.yaml:118-129`) is real, and the double-page is
  real: that event matches **both** `refusal="mrconfigid_unsupported"` and `outcome="refused"`, so
  `warning` and `critical` fire together today. Confirmed by reading both expressions.
- The refusal to write a dangling `runbook:` key is correct and matches this repo's rules.

---

## 16. §6b — the MR-CONFIG-ID arm → **AGREE**

I verified the premise: `MrConfigIdError` (`binding.rs:255-276`) already separates `UnknownVersion`
and `UnsupportedVersion` from `Mismatch`, with the doc comment quoted, and `verify.rs:186` collapses
all arms into `Outcome::Failed`. It is a four-line match, as claimed.

The `UnknownVersion`-stays-`Failed` boundary is right and the argument is right. The load-bearing
fact is `binding.rs:206-207`: an all-zero prefix is an **unpopulated field**, and it lands in
`UnknownVersion`. Dispositioning that to `UpdateVerifier` would tell an operator to upgrade in
response to evidence nobody can account for. T-17 asserting the all-zero case **by value** is the
right shape.

One addition: §6b says *"no closed-loop gate breaks — `04` and `06` grep `mr_config_id +passed` and
never `FAILED`."* I confirm the greps (`04:207-212`, `04:310`, `06:178`) — but `04:310`
(`grep -qE '^  mr_config_id +passed'`) is inside the *tampered* step, and its stated purpose is to
prove the refusal is **targeted** rather than a verifier falling over. Step 3b does not affect that
path (a tampered compose does not change the MR-CONFIG-ID prefix), so the conclusion holds — worth
naming the reason, because "we never grep FAILED" is a weaker argument than the one available.

Cuttable, agreed, and it should be the **first** cut before step 5. Step 5 carries an acceptance
criterion (§5 of this document); 6b carries a double-page retirement.

---

## 17. §9 — the four ADR dimensions → **AGREE**, one addition

Checked against the freshly-loaded skill. Public surface, error type (none), async (none), unsafe
(none) are all correctly stated, and the feature-gating direction — vocabulary in the ungated
`verdict`, `Refusal::disposition()` additive on top — is right and matches the skill's additivity
rule. `Weight`/`weight()` staying private is correct for the stated reason.

**Addition:** the table lists `verify::compose_unavailable` as new `pub`. Per §14, that item needs its
partial-verdict contract in the ADR too, not only in the rustdoc — it is the one new public item
whose *misuse* is silent and whose failure mode is a five-fold critical page. It is also the only new
item that is **feature-gated by accident**: `verify` is behind the `attest` feature
(`lib.rs:155-156`), so an embedder building `default-features = false` for wasm32 — the exact
embedder most likely to be implementing `compose::Source` by hand — **cannot reach
`compose_unavailable` at all.** It performs no I/O and needs nothing from `attest`. Either move it to
`verdict.rs` beside `disposition()`, or state in the ADR that the propagation rule is unreachable on
the wasm build and each embedder there invents their own — which is what step 3c exists to prevent.

---

## 18. Verification summary for round 2

Everything below was executed, not read.

| Claim | Result |
|---|---|
| §2's propagation rule removes every `refuse` disposition for a retrieval outage | **Confirmed** — `REFUSE_DISPOSITIONS = []` |
| T-16's negative is real and free | **Confirmed** — `disposition(ImagesPinned, Skipped) == Refuse` pre-fix |
| §6a's split removes the critical page for an IPFS outage | **FALSIFIED** — five checks lose their counter series; F-09 fires `critical` five times |
| `compose_unavailable` leaves the verdict legible under ADR 0014 | **FALSIFIED** — `unrun_essentials()` returns four essentials, which `verdict.rs:282-288` defines as the regression signal |
| §3.7's `Refusal::disposition()` is clean at the doc layer | **Confirmed** — implemented verbatim; `cargo doc --no-deps --all-features` clean |
| The whole design passes the skill's six-gate baseline | **Confirmed** — fmt, clippy `--all-targets`, build, test (23 ok / 0 failed), doc all clean |
| F-08's annotations survive the re-key | **FALSIFIED** — `{{ $labels.refusal }}` is not on `verity_verify_check_total` |

---

# Round 2, item 2 — the revised third clause. **No, not as worded.**

Two changes make it yes, and both are cheap. The distinction the architect reaches for is sound in
principle; the sentence it wrote does not implement it, and the citation offered for it does not
support it.

## The citation does not say what it is cited for

The architect's evidence that a wasm signature limit is permanent is `lib.rs:14-33`. That passage is
headed **"There is no `connect_verified` here, and there cannot be"**, and every line of it is about
peer certificates and raw TLS: *"a browser cannot open a raw TLS connection, and `fetch()` does not
expose the peer certificate at all."* It says nothing about signature verification or Intel
collateral.

The code's actual stated reason the WASM crate cannot verify signatures is one file over —
`crates/verity-verifier/Cargo.toml:16-20`:

> Intel DCAP signature verification… separable, because **it pulls in `ring`, which does not build
> for `wasm32-unknown-unknown`.** Consumers doing only the compose-side checks (the WASM bindings,
> for one) opt out and keep the target buildable.

That is a **dependency build-target gap** — precisely the class of thing a later version fixes. So on
the code, the wasm *signature* limit is more version-shaped than the architect claims, not less. The
genuinely permanent limit in that crate is `ChannelBound`, and both rules already keep it `Skipped`.

Read literally, then, the proposed `VerifierCannotJudge` doc — *"a later version of this verifier
would"* — **admits wasm `377/381` straight back in.** A later version plausibly would, if `ring`
ships a wasm32 backend or `dcap-qvl` swaps backend. That is the conversion the architect just
withdrew.

## The formulation contains two rules, and they disagree

- The **enumerated remedy** — *"run a verifier version that supports this construction"* — is an
  **action test**. It excludes wasm `377/381`: whoever operates a browser page cannot make `ring`
  build for wasm32; they can only reach a different artifact.
- The **doc string** — *"a later version of this verifier would"* — is a **capability
  counterfactual**. It admits wasm `377/381`, per above.

Whichever goes in the rustdoc is the one the next reader applies, and the doc string is the one that
will be read at the call site.

There is also a structural cost. My clause excluded the wasm sites **by the clause**. The revision
excludes them only by a closed list of three remedies; the general sentence admits them. Add a
fourth `Unestablished` cause later and the general sentence governs. The rule stops being
self-applying, which is what made it worth having over the design's original two-discriminator
version.

## The two changes that make it yes

**1. Keep the action test, drop the counterfactual, and bind it to the call:**

> **`Indeterminate`** — the check did not conclude, and **a named action available to whoever
> operates this caller would let *this same call* conclude it on a later attempt**: retrieve the
> document again, supply a reference, or run a verifier version that supports this construction.

`VerifierCannotJudge` documented as *"this build cannot compute the reference; a build that can
exists or can be made, and running it is an action available here"* — **not** "a later version
would."

*"This same call"* is the load-bearing phrase, and it does the work the version/build-target
distinction was reaching for without depending on a prediction about `ring`:

| Site | Same call, later attempt? | Result |
|---|---|---|
| `verify.rs:201-204` boot `None` | `verify()` with `boot: Some(&reference)` — same function, same build | **`Indeterminate`** ✓ |
| `verify.rs:186` `UnsupportedVersion` (§6b) | `check_mrconfigid` on the same evidence in an updated build | **`Indeterminate`** ✓ |
| compose retrieval failure (propagation) | one successful fetch and the same `verify()` concludes all three | **`Indeterminate`** ✓ |
| wasm `377/381` | `verify_compose_only` has no collateral parameter and this build has no signature verifier; **no later `verify_compose_only` call concludes it.** Reaching the Rust API is a different call. | **`Skipped`** ✓ |

**2. Carve `ChannelBound` explicitly, citing the argument the crate already wrote.** Both the
architect's clause and mine put wasm `lib.rs:346` in `Indeterminate` on a literal reading — passing
`leafCertDer` to the same call does conclude it — while the design and
`lib.rs:508-524` keep it `Skipped`. That residual is **already in the design**; it is not created by
either wording, and it is out of MA-6's scope to change. The honest handling is a named exception
with a citation rather than a silent one, and the citation exists — `verdict.rs:92-96`:

> There is no configuration in which its absence is legitimate **and** the verdict is about an
> endpoint, so "the caller had no reference for this" **never applies**.

That was written before MA-6 and it covers both `verify.rs:70` and wasm `346`. State it as the one
carve-out, in the ADR, with that reference. A rule plus one cited exception is honest; a rule bent
until it has no exceptions is the thing this project's records keep catching.

## Sweep, as requested — all ten `Failed` and all nine `Skipped`

Under `Failed` = *the check reached a refusal*; `Skipped` = *moot, or the exception above*;
`Indeterminate` = *the clause in change 1*.

**`Failed` (10):** `verify.rs:63` (binding refused), `:120`, `:132`, `:139`, `:168`, `:172`, `:186`
(`Mismatch` and `UnknownVersion`), `:197`, `:216`, `:222`. Every one is a refusal; `:222` is a
first-class instance rather than a "category stretch", which is what lets the `verify.rs:218-221`
comment state a rule it obeys.

**`Skipped` (9):** `verify.rs:145`, `:146`, `:175`, `:217`, wasm `:317`, `:318` — moot, a prior check
refused. wasm `:377`, `:381` — no later same call concludes them. `verify.rs:70` and wasm `:346` —
`ChannelBound`, per the carve-out.

**New `Indeterminate` (3):** `verify.rs:201-204`; `verify.rs:186`'s `UnsupportedVersion` arm; the
three compose-side checks under propagation.

Total, with one cited exception. §6b survives; wasm `377/381` stays out.

## Answer

**No as worded — yes with those two changes.** The version-versus-build-target instinct is right; it
just cannot rest on `lib.rs:14-33`, which is about a different check, or on a counterfactual about
`ring`. Bind it to *this same call* and the same boundary falls out of the clause itself, with no
prediction about a third-party crate's roadmap in it.

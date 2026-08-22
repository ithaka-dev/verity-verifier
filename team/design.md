# MA-6 parts 1 and 2 — design

**Role:** architect (ADR 0026 Rust team cycle)
**Date:** 2026-08-22
**Status:** draft, for developer consensus before Phase 2
**Scope:** `Outcome::Indeterminate` and a typed per-`(Check, Outcome)` disposition. Part 3 (signed
reference feed) stays out. `Check::essential()` is not touched.

---

## 0. The decision, up front

Six decisions, each argued in §3:

1. **Yes** — an essential check returning `Indeterminate` makes the verdict untrustworthy. No fork.
2. **The gateway acceptance criterion is not reachable inside `verify()` and must not be made
   reachable.** Neither `verify()` nor `connect_verified()` retrieves the compose document. What
   ships here is the vocabulary and the typed mapping the *fetch* layer needs; the end-to-end
   version is MI-5's, which the audit plan already assigns it. Stated plainly rather than
   simulated.
3. **`Indeterminate` carries a typed cause, not only prose.** `Indeterminate { cause: Unestablished,
   detail: String }`. Without this, `disposition()` would have to infer the remedy from the `Check`
   alone — and the same check has different remedies — or from the string, which the brief forbids.
   This is a deliberate deviation from the brief's `Indeterminate { reason }`.
4. **`disposition()` is a free function in `verdict.rs`**, `fn disposition(check: Check, outcome:
   &Outcome) -> Disposition`, exactly mirroring `transcript_line`. It matches `Check` exhaustively
   with **no wildcard**, so a future `Check` variant is a compile error.
5. **`Disposition` gets a sixth variant, `Satisfied`.** MA-6's five names enumerate *remedies*; a
   passing check has no remedy, and forcing it into `ProceedNonEssential` would make an essential
   pass indistinguishable from an advisory skip. Deviation from the brief, argued in §3.5.
6. **The fourth transcript word is `indeterminate`**, lower case. `unknown` is unavailable — the
   WASM bindings already use it for "variant these bindings do not recognise". **The WASM surface is
   fixed in this change, not deferred.**
7. **The alert split keeps `verity.verify.outcome` binary** and puts `disposition` on the *existing
   per-check* counter — neither of the two options put to me (§6a). Specifying it exposed a defect
   in this design: **`Indeterminate` must propagate to dependent checks, or the split fails on the
   exact case it was approved for.** That is a library change, it is right on its own terms, and it
   is now §2's propagation rule.

### Round 1 decision log

The developer prototyped this design in a scratch tree and executed its claims. **Every AMEND and
the single OBJECT is accepted.** What moved:

| # | Change | Source |
|---|---|---|
| 1 | **§2's rule replaced** by the developer's three-way rule, with the `Indeterminate` clause sharpened to distinguish a *version* limit from a *build-target* limit. Mine was two rules that disagreed, and its `Failed` clause was false at `verify.rs:222`. | critique §3d |
| 2 | Ninth recording site added — wasm `lib.rs:317-318`. The table claimed completeness at eight. | §3a |
| 3 | **The wasm `377/381` conversion withdrawn.** `update_verifier` would be the same false remedy as the "upgrade them" string I rejected it for. | §6 |
| 4 | **§3.6 reason 3 falsified.** `transcript_contract.rs` cannot see the WASM crate at all; the drift guard moves there. I asserted a mechanism I had not run. | §6 |
| 5 | **§3.2 corrected** — the *collateral* half of the criterion is reachable and executed (`connect.rs:341`). Step 5 is therefore not the cuttable step. | §5, §11 Q1 |
| 6 | **`Check::index()` and T-6 dropped.** OBJECT sustained. | §6 |
| 7 | **T-7's invariant restated** — mine was vacuous on one arm, ill-typed on the other. | §3.5 |
| 8 | `Disposition::Refuse` must document that it can appear on a **trustworthy** verdict; T-18 added. | §3.5 |
| 9 | **`Display` widens to 14 columns** — decided here rather than at the keyboard. | §3.10 |
| 10 | T-3 and T-8 given real negatives; T-9 must drive `verify()`; T-11 moved out of the feature-gated, daemon-dependent file. | §8 |
| 11 | **§6.1's closed-loop grep withdrawn** — its branch is unreachable by default. | §9 |
| 12 | snake_case, `ALL` public, step 5 in, `kind()`'s never-ran arm written explicitly. | §11 |

**Round 1 addendum — §6a/§6b/§9.** The developer's second pass found more, including the worst
defect in the document:

| # | Change | Source |
|---|---|---|
| 13 | **F-09 needs a premise guard.** My "F-09 is unaffected" checked *label addition* and never *series disappearance*: a sustained outage silences the quote-side checks and pages `critical` per check. The alert's own description states the premise its expression omits. **Same defect class I caught one layer down, recurring one layer up.** | round 2, OBJECT |
| 14 | **Step 3c withdrawn entirely.** I specified a `Verdict` for a document never retrieved, then three sections later endorsed rejecting exactly that shape at `connect.rs:341`. `unrun_essentials()` on it trips the crate's own regression predicate. Replaced by `Unestablished::disposition()` and a verdict-less refusal. | round 2, §9 + OBJECT |
| 15 | Re-keying F-08 breaks `{{ $labels.refusal }}` twice; use `{{ $labels.check }}`. Per-check firing named and kept deliberately. `unless` imprecision documented in both directions. | round 2 |
| 16 | §6b's "no gate breaks" argued from **reachability** (`04:310` is the tampered step; tampering does not change the prefix byte) instead of from absence. | round 2 |
| 17 | **Cut order reversed: 6b before step 5.** Step 5 carries an acceptance criterion; 6b carries a double-page retirement. | round 2 |
| 18 | **My §2 sharpening withdrawn.** I cited `lib.rs:14-33` for a claim it does not support; the real reason (`crates/verity-verifier/Cargo.toml:16-19`, `ring` lacks `wasm32`) is a *dependency* gap, which makes the wasm limit **more** version-shaped, so my doc string readmitted the sites I had withdrawn. Replaced by the developer's **"this same call"** clause, which turns on the function's signature rather than on a forecast. | round 3 |
| 19 | **`ChannelBound` carved as one cited exception**, using `verdict.rs:92-96`, written before MA-6 and covering `verify.rs:70` and wasm `346` together. A rule plus a cited exception, not a rule bent until it has none. | round 3 |
| 20 | **`design.md:1066` corrected** — it still asserted "F-09 is unaffected" after the F-09 entry below it had been rewritten. Fixed in one place and left false in another, in a document feeding an immutable ADR. | round 3 |
| 21 | **§6a re-framed: it specifies a contract, it does not repair a live pager.** Re-measured — the metric names appear in no source file in any repo, and the verifier has no telemetry dependency. Every rule in §6a is **unexercised by construction** until MA-5 lands an emitter, and by this project's standard none of these alerts has ever been seen to do anything. | round 3 |

Nothing in §§3.1, 3.3, 3.7, 3.9 moved. **Five of the seventeen are cases where I asserted something
I had not executed** — 4, 5, 11, 13 and 14 — the same class of error as the facilitator facts I
corrected in §1, committed by me, and twice in the section I wrote *after* being told the project's
history with exactly that failure.

---

Three **corrections to the supplied facts**, all in §1: fact 2 is incomplete in a way that matters,
fact 4 predicts a break that does not exist, and fact 12 turns out to be contradicted by the line
three above the comment that states it — which is the best argument in the change for publishing a
*rule* (§2) rather than just a variant.

---

## 1. The measured facts, re-verified

Read against `verity-verifier` working tree, 2026-08-22.

| # | Verdict | Notes |
|---|---|---|
| 1 | ✅ | `Outcome` at `verdict.rs:124`, `#[non_exhaustive]` at `:123`, three variants. |
| 2 | ⚠️ **incomplete — see below** | |
| 3 | ✅ exact | `verity-verifier-wasm/src/lib.rs:98-107`, both wildcards as quoted. |
| 4 | ⚠️ **the specific break named does not exist** — see below | |
| 5 | ✅ | `unrun_essentials()` `:290-296` filters `self.outcome(*c).is_none()`. |
| 6 | ✅ | `missing_essentials()` `:304-310` filters `!…is_some_and(Outcome::passed)`. I agree with the semantics — §3.1. |
| 7 | ✅ | `essential()` `:102-112`: seven checks, `BootMeasurements` excluded, `ChannelBound` and `TcbStatus` present. |
| 8 | ✅ **and understated** — see below | |
| 9 | ✅ modulo line number | The site is `verify.rs:201-204`, not `:199`. String is `"no OS image reference supplied"`. |
| 10 | ✅ | `records/experiments/2026-08-22-boot-reference-is-node-independent.md` exists and says what is claimed: four registers identical across prod5/prod9, `RTMR3` differs as the control. Same region, same node runtime — the record says so itself. |
| 11 | ✅ both halves, **with one correction that lowers the risk** — see below | `verify.rs:70`, `04:236` as quoted. |
| 12 | ✅ **and it exposes a contradiction three lines wide** — see below | `verify.rs:217-222`. |

### Fact 11: right, and already guarded in Rust — not only in shell

Both halves verified: `verify.rs:70` records `Skipped("no connection was made: …")` for
`PeerCertificate::NotConnected`, and `04:236` asserts `^  channel_bound +skipped` with a comment
saying the assertion exists so a verifier that silently stopped binding cannot sail through.

The design already keeps this site on `Skipped` (§2), and §3.10's word choice does not touch it. But
the correction is worth having: **the sweep would not first be caught by a gate that costs money.**
`tests/channel_binding.rs:311-340`
(`a_verdict_without_a_connection_is_not_trustworthy_and_says_so`) drives `verify()` with
`PeerCertificate::NotConnected` and matches `Some(Outcome::Skipped(why))` on `Check::ChannelBound`,
asserting the reason text as well. Converting that site turns it red in `cargo test`, in seconds,
before anyone deploys a CVM. So the shell gate is the second line of defence here, not the first —
which is the right shape, and worth knowing before anyone treats `04` as the only thing standing
between us and a CR-1 regression.

Still stated as an explicit decision in §2, because the facilitator's read of the temptation is
correct: the natural move when adding a fourth variant is to sweep every `Skipped` into it.

### Fact 12: the crate's written definition is contradicted by the line above the comment stating it

Verified verbatim at `verify.rs:218-221`. What the fact does not say is that the statement is
already false about its own neighbour:

```rust
.record(Check::MrConfigId, Outcome::Failed(why.clone()))
.record(Check::BootMeasurements, Outcome::Skipped(why.clone()))   // <- :217
// `Failed`, not `Skipped`, and for the same reason `MrConfigId` is: the evidence
// itself is unusable. `Skipped` in this crate means "considered and declined for a
// legitimate reason", and an unparseable quote is not one — reporting it as a skip
// would read as an ordinary configuration gap.
.record(Check::ChannelBound, Outcome::Failed(why));
```

The comment declares that an unparseable quote is not a legitimate reason to skip. **Three lines
above it, `BootMeasurements` is skipped for an unparseable quote.** The comment is about
`ChannelBound`, so nothing is *wrong* in the sense of a bug — but the definition it states cannot
be the crate's definition, because the crate does not follow it one statement earlier.

This is not a nit. It is the reason MA-6 must publish a rule rather than a variant: with the
existing binary vocabulary there was no way to describe that line except by contradicting the
definition beside it. §2's three-way rule is written to make every existing site expressible,
including this one, and §3.8 resolves it.

### Fact 2 is incomplete, and the omission is the interesting one

The brief names three in-crate matches on `Outcome` that are wildcard-free and will therefore break
when a variant is added: `label()`, `transcript_line()`, `Verdict`'s `Display`. All three verified.

**There is a fourth, and it has a wildcard.** `Verdict::failures()`, `verdict.rs:275-277`:

```rust
.filter_map(|(c, o)| match o {
    Outcome::Failed(why) => Some((*c, why.as_str())),
    _ => None,
})
```

Adding `Indeterminate` will **not** break this. It will silently classify every `Indeterminate` as
"not a failure". That happens to be the semantics we want — but it is acquired by accident, in the
accessor a caller reaches for when rendering *what went wrong*, and nothing forces the choice. Same
shape at `Outcome::passed()` (`:139`), which uses `matches!` and will silently answer `false`.

So the brief's mental model — "the compiler forces a decision at every in-crate site" — is not true
of this change. Two of the five sites absorb the new variant in silence. Both need a test (§5, T-2
and T-3), because "we happened to want what the wildcard did" is not a property, it is a
coincidence, and the next refactor is not bound by it.

### Fact 4: the cross-repo break it predicts does not exist

`label()` **is** a shell contract; that part is right. But the specific consequence — that changing
`verify.rs:201` from `Skipped` to `Indeterminate` breaks a closed-loop gate — is false.
`04-refuses-on-mismatch.sh` greps:

- `^  <name> +passed` for the six non-channel essentials (`:206-212`)
- `^  boot_measurements +passed`, **only inside `if [ -n "$boot_ref" ]`** (`:220-231`)
- `^  channel_bound +skipped` (`:236`)
- `^  compose_hash +FAILED` and `^  mr_config_id +passed` at step 4 (`:302`, `:310`)

There is no assertion anywhere on `boot_measurements skipped`. `06-refuses-relayed-endpoint.sh` does
not mention `boot_measurements` at all. So **no existing grep changes meaning.**

What does break is prose that will become false, and one absent assertion:

- `04:149` — "every run reported `boot_measurements skipped`" becomes wrong.
- `04:174` — the operator message "Check 8 will be skipped" becomes wrong.
- `tests/transcript_contract.rs` header claims its transcription of the grep patterns is **meant to
  be complete**. A fourth word not listed there is the drift that file exists to catch.
- The no-reference branch of `04` asserts *nothing*, so the new word ships unexercised by the only
  end-to-end gate over it. §6 adds the assertion.

### Fact 8 is correct, and stronger than stated

`verify()` (`verify.rs:104`) takes `evidence.compose_document: Vec<u8>` — already retrieved.
**`connect_verified()` is the same**: `ConnectRequest.compose_document: Vec<u8>` at
`connect.rs:102`, with a doc comment that already says a hostile source "can withhold the document"
and treats that as the caller's problem. Retrieval is `compose::Source`, a **public trait most
embedders implement themselves**.

So a downed gateway does not arise inside *either* entry point, and the compose fetch is frequently
not even in this crate. That drives §3.2.

### Two design smells found, out of scope

`verify::Evidence` is **not** `#[non_exhaustive]` (`verify.rs:25-26`) while `connect::ConnectRequest`
**is** (`connect.rs:90-92`), for stated reasons that apply equally to both. Not touched here — flagged
for a separate issue.

`Refusal::verdict()` (`connect.rs:681-683`) has a `_ => None` wildcard — the same silent-absorb shape
as `failures()`, one type over (found by the developer). Not in MA-6's path, and it is the second
instance of a pattern this design calls a coincidence rather than a property.

---

## 2. The semantic line these three words draw

The whole change rests on one rule. Everything else is bookkeeping.

> - **`Failed`** — the check **reached a refusal**. Same inputs, same refusal.
> - **`Skipped`** — the check did not run and **there is nothing to tell the operator to do**: a
>   prior refusal made it moot, or its absence is the normal, expected condition of this call, or
>   **this build structurally cannot perform it**.
> - **`Indeterminate`** — the check did not conclude, and a named action available to whoever
>   operates this caller would let **this same call** conclude it on a later attempt: retrieve the
>   document again, supply a reference, or run a verifier version that supports this construction.
>
> **One cited exception: `ChannelBound` is never `Indeterminate`.** On a literal reading the clause
> would admit wasm `lib.rs:346` — passing `leafCertDer` to the same call does conclude it — and the
> crate already ruled that out, before MA-6, at `verdict.rs:92-96`: *"There is no configuration in
> which its absence is legitimate **and** the verdict is about an endpoint, so 'the caller had no
> reference for this' **never applies**."* That covers `verify.rs:70` and wasm `346` together.

**This is the developer's rule from critique §3d, adopted, with one clause sharpened.** My original
— *`Failed` = evaluated and does not hold; `Skipped` = nothing the caller can do; `Indeterminate` =
a named remedy exists* — was wrong in three ways the developer demonstrated and I concede in full:

1. **It was two rules.** "Is there a named remedy" cannot separate wasm `lib.rs:346` (supply
   `leafCertDer`) from wasm `377/381` (obtain collateral); both are "the caller did not pass an
   input." I separated them with a second, unstated discriminator — *did the caller decline* — which
   points the **opposite** way from how I applied it: `lib.rs:359-371` calls the collateral omission
   *"a legitimate, structural omission"*, and the certificate is the one a Node caller can actually
   supply. I had the pair backwards under my own rule.
2. **"In this verdict" did no work.** Every remedy in `Unestablished` produces a different verdict on
   a later attempt and none changes this one.
3. **The `Failed` clause was false at `verify.rs:222`** — `ChannelBound` is `Failed` on an
   unparseable quote and `ChannelBinding::check` is never called there. §3.8 conceded it as "a
   category stretch", which is the tell.

The replacement is better on all three, and it **removes a paragraph rather than adding one**: §3.5's
`(BootMeasurements, Failed) → Refuse` needed its own defence as a strictness choice, and under
"`Failed` = the check reached a refusal" it is the mechanical reading.

**Round 2: my sharpening was wrong, and the clause above is the developer's replacement for it.**

I proposed distinguishing a **version limit** from a **build-target limit**, and citing
`lib.rs:14-33` for the claim that no version of the wasm bindings will ever verify a signature. That
citation does not support it: `lib.rs:14-33` is headed *"There is no `connect_verified` here, and
there cannot be"* and is entirely about peer certificates and raw TLS. **It says nothing about
signature verification or Intel collateral.** The code's actual reason is one file over, at
`crates/verity-verifier/Cargo.toml:16-19`: DCAP verification is *"separable, because it pulls in
`ring`, which does not build for wasm32-unknown-unknown."*

That is a **dependency build-target gap** — precisely the class a later version can close. So on the
code, the wasm signature limit is *more* version-shaped than I claimed, and my proposed doc string
**"a later version of this verifier would"** readmits wasm `377/381`, the conversion I had just
withdrawn. If `ring` ever ships a `wasm32` backend, my counterfactual becomes true.

The structural objection is the one that settles it: my formulation held **two rules that disagree**
— an *action test* in the enumerated remedies, which excludes the wasm sites, and a *capability
counterfactual* in the doc string, which admits them. The doc string is what gets read at the call
site, and a fourth `Unestablished` cause would be governed by the general sentence. It stopped being
self-applying, which was the whole reason to prefer a rule over a list.

**The adopted clause binds the remedy to the call, and rests on no prediction.** Applied to the four
cases:

| Site | Would a later attempt of **this same call** conclude it? | |
|---|---|---|
| boot reference `None` | `verify(…, boot: Some(&r), …)` — same function, same build | **Indeterminate** |
| `MrConfigIdError::UnsupportedVersion` | same evidence, same call, updated build | **Indeterminate** — §6b survives |
| compose retrieval failure | one fetch, then the same `verify()` concludes all three | **Indeterminate** |
| wasm `QuoteSignature` / `TcbStatus` | **no.** `verify_compose_only` has no collateral parameter and no signature verifier, so *no* later call of it concludes them; reaching the Rust API is a **different call** | **Skipped** |

The wasm row now turns on the **shape of the function's signature** — a fact about the API — rather
than on a forecast about a dependency's target support. That is checkable today and stays true
whatever `ring` does.

The rule is total over **all nine** production recording sites — the developer counted nine where I
claimed eight; wasm `lib.rs:317-318` was missing and is row 1's twin:

| Site | Today | Under the rule | Why |
|---|---|---|---|
| `verify.rs:145-146` `ImagesPinned` / `LicensedImagePresent` after a compose mismatch | `Skipped` | **unchanged** | Moot: a prior check refused. |
| **wasm `lib.rs:317-318`, the same pair after a compose mismatch** | `Skipped` | **unchanged** | Row 1's twin. Missing from this table until the developer counted the sites. |
| `verify.rs:175` `TcbStatus` after signature failure | `Skipped` | **unchanged** | Moot. |
| **`verify.rs:70` `ChannelBound` on `NotConnected`** | `Skipped` | **unchanged — and this one is load-bearing** | The caller declined; an offline audit is a legitimate choice. §3.8. |
| `verify.rs:217` `BootMeasurements` after an unparseable quote | `Skipped` | **unchanged, with the justification rewritten** | Moot: `MrConfigId` already `Failed`. §3.8. |
| **`verify.rs:201-204` `BootMeasurements`, no reference supplied** | `Skipped` | **`Indeterminate { ReferenceUnavailable }`** | A remedy exists: obtain a reference. This is MA-6's named site. |
| wasm `lib.rs:377,381` `QuoteSignature` / `TcbStatus` | `Skipped("… use the Rust API")` | **unchanged — conversion withdrawn** | This build can never do it. §3.6. |
| `verify.rs:222` `ChannelBound` on an unparseable quote | `Failed` | **unchanged, and no longer an exception** | It reached a refusal. Under my original rule this was "a category stretch"; under the adopted one it is a first-class instance. |
| wasm `lib.rs:346` `ChannelBound`, no certificate | `Skipped` | **unchanged** | The caller declined. |
| retrieval failure (caller-side, `compose::Source`) | not representable | **`Indeterminate { RetrievalFailed }`** | §3.2. |
| **dependents of an unestablished check** | not representable | **`Indeterminate`, same cause** | The propagation rule below. Without it the §6a alert split fails on the case it exists for. |
| dependents of a **`Failed`** check | `Skipped` | **unchanged** | Moot: the answer is already no. |

**The propagation rule**, which falls out of the three definitions and is not an extra convention:

> **`Indeterminate` propagates to dependent checks; `Failed` does not.** A dependent of a `Failed`
> check is `Skipped` — moot, the answer is already no. A dependent of an `Indeterminate` check is
> `Indeterminate` **with the same cause** — equally unestablished, and the *same remedy* establishes
> all of them at once.

Recording a dependent of an unestablished check as `Skipped` asserts that a prior check refused when
none did. That was wrong before §6a's alert made it visible; the alert is what surfaced it, not what
motivates it.

> **Status: a written rule with no implementation site — and the ADR must say it in these words.**
> With step 3c withdrawn (§4), nothing in this crate records an `Indeterminate` that *has*
> dependents: `verify()` always holds a document, and neither `ReferenceUnavailable` nor
> `VerifierCannotJudge` has a dependent check. The rule is retained because it is correct and
> because **MI-5 brings retrieval in-crate**, at which point it becomes live. **This change does not
> enforce it, and no test in §5 pins it** — T-16 was withdrawn with 3c. A rule and a test that look
> enforced and are not is precisely what this project keeps catching, so the status is stated here
> rather than left to be inferred from the absence of a test.

Note what does **not** move: four of the five existing `Skipped` sites. `Skipped` remains ADR 0014's
regression signal, undiluted, and F-09's alert keeps its input.

---

## 3. Decisions

### 3.1 An essential check that is `Indeterminate` makes the verdict untrustworthy — agreed

No fork. `is_trustworthy()` asserts that every essential property was **established**.
`Indeterminate` is, by construction, the statement that one was not. Any other reading ships a
verifier that answers "verified" about a property it could not check — the precise defect ADR 0014
exists to make impossible and the one `TcbStatus` had before T-11.

Mechanically this needs **no code change**: `missing_essentials()` filters `!passed`, so an
`Indeterminate` essential is already outstanding. That is the danger. Both this property and fact
5's (`unrun_essentials` excludes it, because it filters on *absence*) hold **incidentally**, and a
future refactor of either filter loses them with no test going red. T-1 and T-2 pin them.

**The corollary is the whole point of MA-6, and must be in the docs of every new item:**
`Indeterminate` changes *what the caller does about a refusal*, never *whether they may proceed*.
Proceeding is governed by `TrustworthyVerdict` and nothing else. If `Indeterminate` ever became a
route to proceeding, MA-6 would have implemented the loosening it was written to prevent.

### 3.2 The gateway criterion: where the outcome is produced, and where it is not

**Statement of the limit, plainly:** the acceptance criterion "a downed gateway yields
`Indeterminate`, not a mismatch" is **not satisfiable inside `verify()`, and this design does not
make it appear satisfied.** Neither `verify()` nor `connect_verified()` fetches the compose document
(fact 8, §1). The fetch happens in caller code — often in code that is not in this crate at all,
since `compose::Source` is a public trait.

**Rejected: teaching `verify()` about an absent document.** The obvious move is to change
`Evidence.compose_document: Vec<u8>` into something that can say "unavailable". Rejected for three
reasons:

1. It models the *absence* of evidence as an *input to verification*, which means every downstream
   check grows a "we had no document" arm — a second, weaker path through the crown jewel, added for
   a case that is not a verdict.
2. A failed retrieval is not a verdict. It is the refusal to produce one. The crate already says so
   at `connect.rs`, where `Refusal::NotReached` and `CollateralUnavailable` map to
   `RefusalKind::CouldNotEstablish`.
3. It breaks every construction site of a struct whose "no `Default`, no `Option` meaning skip"
   discipline (`verify.rs:41-45`) is deliberate and hard-won.

**What ships instead** — the vocabulary plus the two seams, so the layer that *did* the fetch can
produce the right outcome without inventing its own convention:

- `Outcome::Indeterminate` is **publicly constructible** (like `Failed`/`Skipped` are today), with an
  ergonomic constructor `Outcome::unestablished(cause, detail)`. An embedder implementing `Source`
  is a first-class producer of this outcome, not a second-class one.
- `impl From<&FetchError> for Unestablished` — a total, wildcard-free mapping owned by this crate,
  so the crate that defines the retrieval error also defines what it means for a verdict. Tested per
  variant; a new `FetchError` variant becomes a compile error.
- `Refusal::disposition()` in `connect.rs`, mapping `NotReached` and `CollateralUnavailable` to
  `RetryRetrieval`. This is what `connect.rs:652-655` already asks for by name.
- **`verify::compose_unavailable(cause, detail)`** (step 3c, added after §6a) — the named path a
  caller takes when their `Source` returned an error, applying §2's propagation rule so the three
  compose-side checks share one cause and one remedy. Not I/O, and not inside `verify()`: it is what
  a caller records *instead of* calling `verify()`, which cannot be called without a document.

**What is therefore true after this change:** a downed gateway is expressible as
`Indeterminate { cause: RetrievalFailed }` through a **named, tested constructor** in this crate,
dispositions to `RetryRetrieval` across all three compose-side checks, and is provably never a
mismatch. **What is not true:** no code path in this crate performs a *compose* fetch, so the crate
never detects **that** outage — the caller who did the fetch reports it.

**Correction, round 1: half the criterion is reachable in this crate today, on an executed path.**
The brief says "gateway **/ collateral** retrieval failure", and I answered only for the gateway.
The developer found the other half: `connect.rs:341` —
`let collateral = Arc::new(collateral.collateral_for(&raw_quote)?)` — is a retrieval that fails
*inside* `connect_verified`, producing `Refusal::CollateralUnavailable`, which §3.7 maps to
`RetryRetrieval`. And `verified_transport.rs:696-710` already drives the sibling `NotReached` case
against a real closed TCP port, in CI, for free. So *"a retrieval outage dispositions to
`RetryRetrieval` and is provably never a mismatch"* is **true on a code path that executes**, with an
existing test one assertion away from covering it. §3.2 said "no end-to-end demonstration"; that was
too strong, and it is why step 5 is not the cuttable step (§8.1).

**Endorsing the developer's rejection of the bolder version**, which they asked for a view on:
emitting a partial `Verdict` at `connect.rs:341` would make `unrun_essentials()` non-empty for five
checks that were never reached — and those five would be *honestly* unrun, which is precisely F-09's
"the verifier silently stopped checking" signal. Firing F-09 for a collateral outage is the same
category error as §6a's paging critical for one, one layer down. Verdict-less refusal plus
`Refusal::disposition()` is the right shape. The audit plan assigns that to **MI-5** ("a gateway outage
surfaces as `Indeterminate` (MA-6), not mismatch. Test: … gateway-down → `Indeterminate`",
`audit-implementation-plan.md:591-592`). MA-6's own acceptance list duplicates it. The duplication
should be resolved in MA-6's favour by *narrowing MA-6's criterion* — recorded in the ADR, not
silently.

### 3.3 `Indeterminate` carries a typed cause

The brief says `Indeterminate { reason }`. That shape cannot support `disposition()`.

`disposition()` must return one of `RetryRetrieval | UpdateVerifier | UpdateReference` for an
indeterminate check. Which one is **not a function of the `Check`**:

- `ComposeHash` indeterminate because the gateway timed out → `RetryRetrieval`.
- `ComposeHash` indeterminate because the document names a hash algorithm this verifier does not
  implement → `UpdateVerifier`.

Same check, different remedies. With only a string, `disposition()` must either sniff the prose —
which is the exact failure the brief says this change exists to prevent — or hardcode one remedy per
check and be wrong for the other. So the remedy class belongs in the type:

```rust
/// Why a check could not be established, as a class the caller can act on.
///
/// The remedy in typed form. `detail` beside it is for humans; **this** is what
/// [`disposition`] reads, so a caller never has to parse prose to decide what to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Unestablished {
    /// Evidence could not be retrieved. A later attempt may succeed.
    RetrievalFailed,
    /// No reference to compare against was available.
    ReferenceUnavailable,
    /// This verifier is not able to judge it — wrong build, missing collateral, unknown format.
    VerifierCannotJudge,
}
```

Cost: a slightly larger public surface, and `Indeterminate` is a struct variant while its two
siblings are tuple variants. Both accepted. `#[non_exhaustive]` on `Unestablished` per crate
convention; in-crate matches on it stay wildcard-free for the same reason `label()` does.

### 3.4 `disposition()` is a free function taking both

```rust
#[must_use]
pub fn disposition(check: Check, outcome: &Outcome) -> Disposition
```

In `verdict.rs`, beside `transcript_line`, whose signature it deliberately mirrors — same reason:
the answer is a property of the *pair*, and neither type owns the other.

Rejected:

- **Method on `Outcome`** — cannot see the check, so it cannot tell a skipped essential from a
  skipped advisory. That single row is the entire justification for the pair (§3.5), so an
  `Outcome`-only method is the one shape that provably cannot be correct.
- **Method on `Check` taking the outcome** — reads backwards (`check.disposition(&outcome)` suggests
  the check decides) and `Check` is a `Copy`, `const`-heavy value type.
- **Only a method on `Verdict`** — unreachable for a caller holding a `(Check, Outcome)` pair out of
  `results()`, and it forces every test to build a whole verdict to exercise one cell of a table.

Two thin conveniences on `Verdict`, both derived from the free function so there is exactly one
definition:

```rust
impl Verdict {
    /// What to do about one check. `None` when it was never recorded.
    pub fn disposition(&self, check: Check) -> Option<Disposition>;
    /// Every check and what to do about it, in the order performed.
    pub fn dispositions(&self) -> Vec<(Check, Disposition)>;
}
```

**Rejected: a single aggregate `Verdict::overall_disposition()`.** Three reasons. Remedies are a
*set*, not a lattice — a verdict can need a verifier update *and* a retrieval retry, and folding
picks one and hides the other, which is the collapse this crate refuses everywhere else. Nothing in
MA-6 asks for it. And a single actionable value on `Verdict` is one rename away from becoming the
thing agents branch on instead of `TrustworthyVerdict`, reintroducing the ignorable verdict MA-1
closed. `Refusal::disposition()` (§3.7) is the one place a single value is honest, because a refusal
is already singular.

**Exhaustiveness, and the future `Check` variant.** The body is two wildcard-free matches:

```rust
/// How much a check's outcome matters to the verdict. Private: this is the *only* thing
/// `disposition` needs from a `Check`, and exposing it would create a second public spelling of
/// `Check::essential`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Weight { Essential, Advisory }

const fn weight(check: Check) -> Weight {
    // Matched exhaustively and **without a wildcard**, deliberately — the same mechanism
    // `Outcome::label` documents. A new `Check` variant is a compile error here, which forces
    // whoever adds it to decide what its absence means rather than inherit a default.
    match check {
        Check::ComposeHash
        | Check::ImagesPinned
        | Check::LicensedImagePresent
        | Check::QuoteSignature
        | Check::TcbStatus
        | Check::MrConfigId
        | Check::ChannelBound => Weight::Essential,
        Check::BootMeasurements => Weight::Advisory,
    }
}
```

**Rejected: deriving the weight from `Check::essential().contains(&check)`.** It is shorter and it is
the wrong shape: a `contains` lookup silently classifies a *new* variant as advisory, which is the
fail-open default and exactly the "future variant" hazard the brief asked about. The duplication
between `weight` and `essential()` is real and is paid for by T-5, which asserts they agree for
every check.

**The honest limit:** Rust has no dependency-free, compiler-checked enumeration of an enum's
variants, so the table-driven tests iterate a hand-maintained `Check::ALL`. `ALL` staying stale
weakens *test coverage*, not the mapping — the mapping's guard is the compile error above. A
declarative macro generating enum + `ALL` would close it; **rejected** as over-engineering for an
eight-variant enum whose primary guard already exists, and because macro-defined enums cost every
future reader indirection at the most-read type in the crate. `Check::ALL` gets a doc comment saying
so.

**`Check::index()` is withdrawn, and T-6 with it — the developer's OBJECT is sustained.** It had no
consumer; it existed only so a test could check that `ALL` is ordered and duplicate-free, which is a
property nothing depends on. My own sentence two paragraphs up — staleness "weakens test coverage,
not the mapping" — is the argument against it, and I did not apply it to my own addition. New public
API on a third-party-facing crate to satisfy a test of a test is not a trade this crate makes.

**`Check::ALL` stays public**, and one thing must not follow from it: `verdict_semantics.rs:395-410`
hand-enumerates all eight checks as **string literals**, and must not be refactored onto `ALL`. Its
entire point is that a rename has to confront the literals — looping over `ALL` and calling `name()`
would assert `name() == name()`.

### 3.5 `Disposition`, and the sixth variant

```rust
/// What a caller should do about one check.
///
/// **This is advice about a check, never permission to proceed.** Whether an endpoint may be used
/// is answered by [`TrustworthyVerdict`] and by nothing else — including this. A `RetryRetrieval`
/// on an essential check means "retry, and until it succeeds you still have no verdict".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Disposition {
    /// The check ran and passed. Nothing to do.
    Satisfied,
    /// Refuse. Retrying cannot change it and no remedy applies.
    Refuse,
    /// Evidence could not be retrieved. Try again, or try another source.
    RetryRetrieval,
    /// This verifier cannot judge it. Use one that can.
    UpdateVerifier,
    /// No reference was available to compare against. Obtain one.
    UpdateReference,
    /// Not established, and the verdict does not depend on it.
    ProceedNonEssential,
}

impl Disposition {
    /// A stable identifier, for telemetry and the JavaScript surface.
    #[must_use]
    pub const fn name(self) -> &'static str;   // "satisfied", "refuse", "retry-retrieval", …
}
```

**Why `Satisfied` exists**, deviating from MA-6's five names: those five are *remedies*, and a
passing check has no remedy. The three alternatives were `Option<Disposition>` with `None` for
`Passed` (breaks "each pair maps to exactly one disposition", and invites
`.unwrap_or(proceed)` at the call site), reusing `ProceedNonEssential` (says "non-essential" about
an essential check that passed — wrong, and misleading in precisely the register this change exists
to fix), and a `Proceed`/`Passed` name (collides with `Outcome::Passed` at every call site). The
enum is `#[non_exhaustive]` and brand new, so the addition costs nothing; it must be recorded in the
ADR as a deviation.

**The mapping**, complete over all 8 × 6 pairs:

| Outcome | Essential check | `BootMeasurements` (advisory) |
|---|---|---|
| `Passed` | `Satisfied` | `Satisfied` |
| `Failed(_)` | `Refuse` | **`Refuse`** |
| `Skipped(_)` | `Refuse` | `ProceedNonEssential` |
| `Indeterminate { RetrievalFailed }` | `RetryRetrieval` | `RetryRetrieval` |
| `Indeterminate { ReferenceUnavailable }` | `UpdateReference` | `UpdateReference` |
| `Indeterminate { VerifierCannotJudge }` | `UpdateVerifier` | `UpdateVerifier` |

Three things to notice, each deliberate:

- **`Failed` is `Refuse` even for the advisory check.** A boot measurement that ran against a
  supplied reference and mismatched is a measured discrepancy. `is_trustworthy()` stays true — the
  check is not essential and this change does not promote it — so `disposition()` is here *stricter*
  than the boolean. That asymmetry is the point: it is the only way to report a real mismatch on a
  non-essential check without loosening a check to resolve it. `04:214-231` already takes this
  position in shell ("supplying a reference and not checking the outcome would leave
  `boot_measurements` free to report FAILED while the run stayed green").
- **`Indeterminate` maps to its remedy regardless of weight**, which is what the acceptance criterion
  "missing boot reference → `UpdateReference`" demands. So `ProceedNonEssential` occurs for exactly
  one pair: `(BootMeasurements, Skipped)`. It is not vestigial — it is the honest answer for the one
  case where a check did not run and the verdict genuinely does not depend on it.
- **`Skipped` is the only row where the `Check` argument does any work.** That single row is the
  entire justification for `disposition` taking both arguments, and T-4 is written from it.

**The safety invariant, tested (T-7):**

> `disposition(c, o) ∈ { Satisfied, ProceedNonEssential }` ⟹ a verdict whose only non-passing
> essential is `(c, o)` is trustworthy.

The developer is right that this cannot be checked as written, and it is **restated**: `Satisfied`
implies `o` is `Passed`, so there is no non-passing essential and the antecedent is vacuous; and
`ProceedNonEssential` occurs only at `(BootMeasurements, Skipped)`, which is not essential, so the
antecedent is ill-typed. The property actually wanted:

> For every `c` in `Check::essential()` and every `o` where `!o.passed()`:
> `disposition(c, o) ∉ { Satisfied, ProceedNonEssential }`.
>
> *No disposition ever advises proceeding on a non-passing essential.*

One loop over 7 × 5 pairs, with the negative already named — map `(Essential, Skipped)` to
`ProceedNonEssential` and watch it go red.

**And `Disposition::Refuse` must document that it can appear on a *trustworthy* verdict.** Conceded,
and it is a hole in my reasoning rather than a doc nicety. `(BootMeasurements, Failed) → Refuse`
while `is_trustworthy()` stays `true`, pinned today by `verdict_semantics.rs:270-281`. §3.4 rejected
`overall_disposition()` because a single actionable value competes with `TrustworthyVerdict` —
and shipping `dispositions()` without this warning hands every caller the ingredients to write *"any
`Refuse` ⇒ do not proceed"*, which is that same competing rule, reassembled at the call site. So
`Refuse`'s doc states both directions: **dispositions never override `TrustworthyVerdict`, and never
substitute for it.** T-18 pins the pair, so it reads as intended behaviour rather than a bug someone
tidies away.

### 3.6 The WASM surface is fixed here, not deferred

Fact 3 is right that the bindings compile unchanged. Deferring is still wrong, for three reasons —
and the third is the one that decides it:

1. `_ => Some("outcome variant unknown to these bindings; upgrade them")` becomes a **false
   statement**. The bindings derive their version from the core crate (ADR 0012's one-version rule,
   stated in that file's own header), so telling a JavaScript caller to upgrade names a remedy that
   does not exist. It would be prose telling a caller to do something impossible, shipped by the
   change whose thesis is that remedies must be typed.
2. `"unknown"` is the word the wildcard already occupies (§3.10), so a recognised `Indeterminate` and
   an unrecognised future variant would be indistinguishable in the JS surface.
3. ~~`transcript_contract.rs::the_labels_match_the_words_the_javascript_bindings_report` would pass
   while the surfaces drifted, because the JS side wildcards.~~ **FALSIFIED by the developer, who
   executed it. My mechanism was wrong, and the truth is worse than what I claimed.**

   That test lives in `crates/verity-verifier/tests/`, which **does not depend on the WASM crate at
   all**. It asserts `Outcome::label()` against three hardcoded literals and describes `to_js` in a
   *comment*. **It would pass if `to_js` were deleted.** So it is not a gate weakened by a wildcard;
   it is a gate structurally incapable of observing the surface it names — and adding an
   `Indeterminate` arm to `to_js`, as I proposed, would leave it guarding nothing.

   I asserted a mechanism I had not run. The conclusion survives on reasons 1 and 2, and the finding
   *strengthens* the case for acting now: there is no cross-surface drift guard to preserve, so one
   has to be built.

   **The repair, adopted:** the guard moves to the crate that can see both surfaces. In
   `verity-verifier-wasm`, assert for **all four** variants that
   `to_js(…).outcome == Outcome::label().to_lowercase()`. `to_js` is natively testable
   (`lib.rs:650` already calls it directly on host), so this costs nothing. The core-side test keeps
   its three literals and loses the comment claiming a relationship it cannot check.

Changes: an explicit `Indeterminate` arm (the wildcard stays, for genuinely future variants), and
`JsCheck` gains a `disposition` field carrying `Disposition::name()`. The disposition field is the
substantive part — the JavaScript surface is where an agent is most likely to fall back to reading
prose, so it is where a typed instruction is worth the most. `cause` is deliberately **not** exposed
separately: the three causes map onto three distinct dispositions, so it would be a second spelling
of the same fact.

**The `377/381` conversion is withdrawn.** I argued that "upgrade them" is unacceptable because the
bindings derive their version from the core, so no upgrade exists — and then proposed a typed
`update_verifier` telling a browser caller to update, about a limitation no update fixes. That is
the same false remedy, moved into the field this change exists to make trustworthy. The developer
caught it; under §2's adopted rule those two sites are `Skipped`, because this build can never
perform them: `verify_compose_only` takes no collateral parameter and holds no signature verifier, so
no later call of **that function** concludes them, and reaching the Rust API is a different call
(§2). Note this argument deliberately does **not** rest on `ring`'s `wasm32` support — see §2's
round-2 correction, where citing that was my error. The alternative — keep the conversion but rename the
disposition so it does not say "update" — would be a third vocabulary deviation bought for nothing.

So the WASM change is exactly: the `Indeterminate` arm in `to_js`, the `disposition` field, and the
relocated drift guard. No recording site in the bindings moves.

### 3.7 `connect.rs`: `Refusal::disposition()`, and the `kind()` note

`connect.rs:652-655` asks, by name, for `Refusal::kind()` to be derived from dispositions once MA-6
lands. Addressed in two parts:

```rust
impl Refusal {
    /// What to do about this refusal. Coarse, like [`Refusal::kind`] — read
    /// [`Verdict::dispositions`] for the per-check remedies whenever [`Refusal::verdict`] is `Some`.
    #[must_use]
    pub fn disposition(&self) -> Disposition;
}
```

`NotReached` and `CollateralUnavailable` → `RetryRetrieval`; everything else, including
`NotTrustworthy`, → `Refuse`. It is **not** a fold over the verdict's dispositions, for §3.4's
reason.

Second, `kind()` for `NotTrustworthy` currently returns `GuaranteeViolated` unconditionally. After
this change a verdict can be untrustworthy solely because an essential was `Indeterminate`, and
`CouldNotEstablish` is the accurate answer for that. **Recommended, as a separately committable
step:** `NotTrustworthy` returns `GuaranteeViolated` if any essential `Failed` or was `Skipped`, and
`CouldNotEstablish` when the only non-passing essentials are `Indeterminate`. Both are refusals;
neither licenses proceeding, so this is fail-closed either way.

**Cost to name:** `kind()` is `const fn` today and cannot remain so once it inspects a `Vec`.
Removing `const` from a public function is a breaking change in the general case; at version `0.0.0`
with no external consumers it is acceptable, and it must be stated in the commit message rather than
slipped in.

**If the round budget forces a cut, cut this step** — and then *edit the comment at
`connect.rs:652-655`* to say MA-6 landed and deliberately did not do this. A stale TODO that says
work is coming when it is not is a lie in the codebase, and this repo's rule is that records are
corrected, not left.

### 3.8 The two `Skipped` sites that must not move, and the definition being replaced

MA-6 inserts a third category between the crate's existing two. Fact 12 is right that the existing
boundary is written down as **legitimate-configuration-gap vs. evidence-is-unusable**, and that
leaving the new line unstated lets the three variants drift apart across call sites. Two specific
sites decide it.

**`ChannelBound` on `PeerCertificate::NotConnected` stays `Skipped`.** The caller *declined* to make
a connection; nothing is unestablished-pending-a-remedy, because there is no remedy that applies to
*this* verdict — an offline audit is a different question, honestly answered. Converting it would
cost the assertion at `04:236`, whose own comment says it exists so that a verifier which silently
stopped binding cannot pass the six greps above it. Two further reasons it must not move: the word
would change under a script that greps the literal `skipped`, and `Skipped` here is doing exactly
the job ADR 0014 gave it — a *declared* decline, distinguishable from a check that vanished.

**`BootMeasurements` on an unparseable quote stays `Skipped`, and the comment above it gets
rewritten.** Under §2's rule this is the "moot — a prior check already refused" arm: the quote is
garbage, `MrConfigId` is already `Failed`, and no remedy named in this verdict would change the
answer. Two alternatives considered and rejected:

- **`Indeterminate`** — would require a cause, and none is true. `VerifierCannotJudge` is a lie (the
  verifier judges fine; the input is garbage) and `RetrievalFailed` invents a remedy — "fetch it
  again" — that this verdict has no basis to promise. Naming a remedy that does not exist is the
  failure mode §3.6 rejects the WASM "upgrade them" string for.
- **`Failed`, for consistency with `ChannelBound` and `MrConfigId` in the same block** — would put a
  boot-measurement failure in `failures()` that never happened, sending an operator to re-capture a
  reference for a quote that was never parseable.

**Why `ChannelBound` is `Failed` on that same path and stays that way.** It is a deliberate,
documented, fail-closed strictness choice: an unparseable quote presented as an endpoint's
attestation is a refusal, and reporting it as a skip "would read as an ordinary configuration gap".
Under §2's rule it is a category stretch — the property was not evaluated either — but MA-6 must not
undo it. Note what the new layer changes: `Skipped` on an essential also dispositions to `Refuse`,
so that strictness is no longer load-bearing for the *action*. It now only affects `failures()` and
the transcript word, which is exactly where it was wanted.

**The definition being replaced.** `Skipped` = "considered and declined for a legitimate reason"
cannot survive, because the crate does not follow it one statement earlier (§1, fact 12). It is
replaced by §2's three-way rule. The comment at `verify.rs:218-221` is rewritten in the same change —
its *conclusion* (`ChannelBound` is `Failed` here) is preserved; its *premise* is superseded.

**And this is where the round-1 rule change earns its keep.** Under my original `Failed` clause —
"the property was evaluated and does not hold" — the rewritten comment would have stated a
definition that **the very line it annotates violates**, disclaimed as "a category stretch" in the
same breath, at the crate's only written definition of the vocabulary, in a change whose thesis is
that the vocabulary must be stated as a rule. The developer is right that a reader taking the rule
seriously would read the disclaimer as special pleading and eventually "fix" the line — which is the
outcome T-15 exists to prevent. Under the adopted clause — **`Failed` = the check reached a
refusal** — `verify.rs:222` is a first-class instance, the comment states a rule it obeys, and the
disclaimer disappears rather than being footnoted.

### 3.9 What is deliberately not changed

- **`Check::essential()`** — `BootMeasurements` is not promoted. MA-6 gates that on the signed feed,
  which does not exist. Fact 10 retires part 3's *capture* precondition only.
- **`unrun_essentials()` / `missing_essentials()`** — no code change. Both already behave correctly;
  §5 pins them.
- **Four of the five existing `Skipped` sites** (§2), two of them argued individually in §3.8.
- **`Evidence` / `ConnectRequest`** (§3.2, §1).

### 3.10 The fourth transcript word: `indeterminate`

Constraints: one token with no space (`transcript_line` renders `label (detail)` and the scripts
anchor `^  <name> +<label>`); no collision with `passed` / `skipped` / `FAILED` / `unknown`; and a
case that carries the right urgency.

**`unknown` is rejected** — taken by the WASM wildcard for "variant these bindings do not recognise"
(§3.6). **`inconclusive` / `unproven` / `undetermined` are rejected** for a reason worth stating: the
word an operator greps should be the word in the type, so that a transcript line and a `match` arm
are searchable by the same string. **`indeterminate`**, lower case.

Lower case, not shouted like `FAILED`, and this is a semantic choice rather than a style one.
`FAILED` shouts because a refusal caused by the endpoint must be visible without reading. An
indeterminate check is the system saying it could not tell — usually an outage. Shouting it would
train an operator to read infrastructure faults as attacks, which is the sensitisation MA-6 exists
to prevent and the loosening pressure ADR 0009 rule 3 resists.

Rendering follows the existing `Failed`/`Skipped` branch (label plus parenthesised detail); `Passed`
remains the only one with nothing to explain.

```
  boot_measurements      indeterminate (no OS image reference supplied)
```

Six spaces between name and label: `boot_measurements` is 17 characters, `{:<22}` pads with 5, and
the literal space in the format string adds the sixth. The implementer must confirm the literal
against the formatter rather than copying it from here.

The detail string stays **verbatim** from `verify.rs:203` — `"no OS image reference supplied"` — so
the diff changes the variant and nothing else, and a reader of a transcript sees one thing move.

**`Verdict`'s `Display` widens to a 14-column prefix.** §4 step 1 said only "a fourth line form" and
left this open; the developer is right that it is not free and must be decided here.
`Display` (`verdict.rs:424-428`) uses a fixed 8-column prefix — `"  pass    "`, `"  FAIL    "`,
`"  skipped "` — and `indeterminate` is 13 characters. The two options are a shorter token in
`Display` only, or widening every line.

**Widen.** A shorter token would put a fifth word into a vocabulary this change exists to reduce to
four, and it would break §3.10's own principle — the word an operator greps should be the word in
the type — at the one surface a human reads during a refusal. The cost is two test literals:
`verdict_semantics.rs:354-368` (`contains("pass    compose_hash")`) and `transcript_contract.rs:182`.
Both are *supposed* to break: they pin the human rendering, the human rendering changed, and a test
that did not notice would be the defect. `transcript_contract.rs:187`'s assertion that the two
renderers stay different survives untouched, which is the one that matters.

---

## 4. The change, as an ordered set of steps

Each step compiles and its tests pass before the next begins.

**Step 1 — `verdict.rs`: the type.** `Unestablished`; `Outcome::Indeterminate { cause, detail }`;
`Outcome::unestablished(cause, detail)`; `Outcome::cause() -> Option<Unestablished>`. Fix the three
matches the compiler breaks: `label()` (→ `"indeterminate"`), `transcript_line()` (joins the
`Failed | Skipped` arm), `Display for Verdict` (a fourth line form). **Decide explicitly, in a
comment, at the two sites the compiler does *not* break** — `failures()` and `passed()` — that an
`Indeterminate` is neither a failure nor a pass.

**Step 2 — `verdict.rs`: the disposition.** `Disposition` + `Disposition::name()`; private
`Weight` + `weight()`; free `disposition()`; `Verdict::disposition()` / `dispositions()`;
`Check::ALL` + `Check::index()`.

**Step 3 — `verify.rs`.** One site: `:201-204` becomes `Outcome::unestablished(
Unestablished::ReferenceUnavailable, "no OS image reference supplied")`. Update the step-7 comment
and the `boot: Option<&BootReference>` doc.

**Step 3b — `verify.rs`, the MR-CONFIG-ID arm.** §6b. Recommended; cuttable, and if cut it is said
out loud in the commit message.

**Step 3c — WITHDRAWN. `verify::compose_unavailable` does not ship.**

I specified a constructor that builds a `Verdict` for a document that was never retrieved. Three
sections later, in §3.2, I endorsed the developer's rejection of exactly that shape at
`connect.rs:341` — *"a failed retrieval is not a verdict, it is the refusal to produce one"* — and
did not notice I had specified one. **The F-09 finding is the symptom of that contradiction, and the
library-side witness is decisive:** `unrun_essentials()` on such a verdict returns four essentials,
and `verdict.rs:282-288` defines that as *"a check that silently stopped running"*. A routine gateway
outage would trip the crate's own regression predicate.

The offered repair was to document the exception — that on this verdict `unrun_essentials()` means
"never reached" rather than "regressed". **That is prose doing a type's work**, in the change whose
thesis is that prose must not be load-bearing, at the predicate ADR 0014 rests on. And the developer
is right that the alternative — recording the five quote-side checks — needs a seventh disposition
for "not attempted" that collides with `unrun_essentials`; I agree, and the deeper reason is that
`Indeterminate { RetrievalFailed }` on `channel_bound` would be **false**: we did not fail to
establish channel binding because a gateway was down, we never opened a connection.

**What replaces it.** A retrieval failure produces **no `Verdict`** — it is reported as a refusal,
with a disposition, exactly as `connect.rs` reports `CollateralUnavailable`. The fetch layer needs
one small addition to do that without inventing a convention:

```rust
impl Unestablished {
    /// The remedy this cause calls for, independent of any check.
    ///
    /// Lets a caller whose retrieval failed report `refused` **with a typed disposition** and no
    /// verdict at all — the shape `connect::Refusal` already uses. In `verdict.rs`, ungated, so the
    /// `default-features = false` embedder can reach it (§9).
    #[must_use]
    pub const fn disposition(self) -> Disposition;
}
```

`From<&FetchError> for Unestablished` (step 4) keeps its caller through this chain:
`FetchError → Unestablished → Disposition`, reported at the *verification* level. §6a is unaffected —
its critical keys on `disposition="refuse"`, and an outage that records no checks emits no such
label, while the warning still fires from `outcome="refused"`.

**And it removes a landmine the developer found independently:** `verify` is gated behind `attest`
(`lib.rs:155-156`), so anything placed in `verify.rs` is unreachable to an embedder building
`default-features = false` for `wasm32` — precisely the embedder most likely to hand-implement
`compose::Source`. `compose_unavailable` was accidentally feature-gated. Its replacement is in
`verdict.rs`, which is ungated, per §9's rule that the vocabulary never sits behind a feature.

*(Withdrawn specification retained below for the record, since the ADR needs to show what was
considered:)*

```rust
/// The compose-side outcomes for a document that could not be retrieved.
///
/// `ComposeHash`, `ImagesPinned` and `LicensedImagePresent` are recorded `Indeterminate` with the
/// **same** cause: one successful retrieval establishes all three, so they share one remedy.
/// Recording the dependents as `Skipped` would assert that a prior check refused, when none did.
///
/// Performs no I/O — this is what a caller whose `Source` returned an error records *instead of*
/// calling [`verify`], which cannot be called without a document.
#[must_use]
pub fn compose_unavailable(cause: Unestablished, detail: &str) -> Verdict;
```

The argument for it was that `verity.verify.refusal` already enumerates **`compose_unavailable`**
(`conventions.md:90`), so the contract expects a retrieval failure to be reported rather than to be
silence. **That argument survives; the shape does not.** A refusal *code on a span* does not require
a `Verdict` object with three recorded checks and five phantom absences — the span carries
`outcome=refused`, `refusal=compose_unavailable` and a disposition, and no per-check series is
touched.

**Consequence for §2's propagation rule: it keeps no implementation site in this change.** It was
discovered while specifying §6a and it is correct, but with 3c withdrawn nothing in the crate ever
records an `Indeterminate` that has dependents — `verify()` always holds a document, and neither
`ReferenceUnavailable` (boot) nor `VerifierCannotJudge` (V2) has a dependent check. It is retained
in §2 as a **written rule that becomes live if MI-5 brings retrieval in-crate**, and it is labelled
as such rather than presented as something this change enforces.

**Step 4 — `compose.rs`.** `impl From<&FetchError> for Unestablished`, wildcard-free:
`Transport | Status | TooLarge | Unsupported` → `RetrievalFailed`. `TooLarge` is arguably hostile
rather than an outage, but the caller's action is identical (retrieve elsewhere) and the verdict
cannot tell the two apart — say so in the comment rather than inventing a fourth cause.

**Step 5 — `connect.rs`.** `Refusal::disposition()`; the `kind()` refinement; delete or correct the
`:652-655` note. Cuttable per §3.7.

**Step 6 — `verity-verifier-wasm`.** The `Indeterminate` arm; `JsCheck.disposition`; the two
`VerifierCannotJudge` records.

**Step 7 — docs that become false.** **`verify.rs:218-221` first** — its conclusion survives, its
premise (what `Skipped` means) is superseded by §2's rule; leaving it would ship a definition the
change has just replaced, in the file that violates it. Then `verdict.rs` `Outcome::Skipped` doc (state the §2 rule),
`label()`'s "one-word transcript label: `passed`, `skipped` or `FAILED`", `essential()`'s
`BootMeasurements` paragraph, `ConnectRequest.boot` at `connect.rs:105` ("leaves the
boot-measurement check *skipped*"), `verify.rs` step-7 comment, `lib.rs` header if it enumerates
outcomes.

---

## 5. Test plan

The rule this repo applies: **write the check from a reproduced failure, not from a belief.** For
each guard below, the negative is produced first — break the code, watch the assertion go red,
capture the output, put it back — and the transcript goes in the commit message, which under ADR
0019 is the only place review findings can live.

Two of these negatives cost nothing and should be produced literally, because they are one-line
edits to code we are already writing:

| ID | File | Property | **The negative to build first** |
|---|---|---|---|
| **T-1** | `verdict_semantics.rs` | An essential that is `Indeterminate` is not trustworthy and *is* in `missing_essentials()`. | Change `missing_essentials` to `matches!(o, Some(Failed(_)))`-style filtering; watch it go green on an unestablished essential; revert. |
| **T-2** | `verdict_semantics.rs` | `Indeterminate` **never** appears in `unrun_essentials()`. | Change `unrun_essentials` to also count recorded-but-not-concluded outcomes; watch T-2 go red. Fact 5 is right that this holds today — which is exactly why it needs a pin. |
| **T-3** | `verdict_semantics.rs` | `Indeterminate` is not in `failures()` and `passed()` is false. | ~~The wildcard is already there; assert first and note it passed on arrival.~~ **Wrong, and the developer produced the real negative for free:** add `\| Outcome::Indeterminate { detail: why, .. }` to `failures()`'s arm and it goes red with `was [(BootMeasurements, "no OS image reference supplied")]`. "Assert, observe green, declare it pinned" is the exact pattern the taxonomy record warns about — a check written at the moment its author is convinced the property holds. **Three negatives cost nothing, not two.** |
| **T-4** | `verdict_semantics.rs` | `disposition(BootMeasurements, Skipped) == ProceedNonEssential` **and** `disposition(<every essential>, Skipped) == Refuse`. | Make `disposition` ignore its `check` argument; watch it go red. This is the only row where the pair matters. |
| **T-5** | `verdict_semantics.rs` | For every `c` in `Check::ALL`: `weight(c) == Essential` ⟺ `Check::essential().contains(&c)`. | Flip `BootMeasurements` to `Essential` in `weight`; watch it go red. Guards the §3.4 duplication. |
| **T-6** | `verdict_semantics.rs` | `Check::ALL[c.index()] == c` for every `c`, and `ALL` has no duplicates. | Duplicate an index in `index()`. |
| **T-7** | `verdict_semantics.rs` | `disposition ∈ {Satisfied, ProceedNonEssential}` ⟹ that verdict is trustworthy. | Map `(Essential, Skipped)` to `ProceedNonEssential`; watch it go red. **The safety belt for the whole table.** |
| **T-8** | `verdict_semantics.rs` | **The table, as data.** All 8 × 6 pairs, with the expected disposition written as a literal in the test. | ~~n/a~~ **The developer supplied one and it is the right one:** flip a single arm of `disposition()` and confirm **exactly one row** goes red. Two red ⇒ the literals were derived rather than written. Zero red ⇒ the table is `f(x) == f(x)`. That check *is* T-8's point, and leaving the likeliest defect in the change as the only row without a negative was indefensible. |
| **T-9** | `reference_and_verdict.rs` | `verify()` with `boot: None` records `Indeterminate { ReferenceUnavailable }` → `UpdateReference`, **and the verdict is still trustworthy** (check 8 was not promoted). | Revert `verify.rs:201` to `Skipped`; watch it go red. **T-9 must drive `verify()`.** Measured: the conversion leaves all 20 test binaries green, because `verdict_semantics.rs:258` builds the outcome by hand and nothing else touches the path. A hand-built T-9 reproduces the hole it exists to close. It also cannot fold into T-14 — see T-14. |
| **T-10** | `transcript_contract.rs` | The literal line for `(BootMeasurements, Indeterminate)`, plus `matches_grep(line, "boot_measurements", "indeterminate")` — the pattern `04` will grep. And `label()` returns four distinct words. | Render `Indeterminate` through the `Skipped` arm; watch both go red. |
| **T-11** | ~~`compose_fetch.rs`~~ → **a new ungated `dispositions.rs`** | Every `FetchError` variant maps to `RetrievalFailed`, and that dispositions to `RetryRetrieval` **for every check**. | The acceptance criterion, at the layer where it is true (§3.2). **File corrected:** `compose_fetch.rs:12` is `#![cfg(feature = "fetch")]` and its tests skip without a live IPFS daemon (CI runs it as a separate job with a service container). `FetchError` is ungated. Putting the acceptance-criterion test behind a feature flag *and* a daemon means it does not run on `cargo test` — an acceptance criterion guarded by a test most runs skip. |
| **T-12** | wasm `lib.rs` tests | The JS projection renders `"indeterminate"` with its detail and a `disposition` field. | **Free negative: write the assertion before adding the match arm.** It will render `"unknown"` with "upgrade them". Capture that output — it is the demonstration that fact 3's "compiles unchanged" is a silent under-report, and it belongs in the commit message. |
| **T-13** | wasm `lib.rs` tests | `QuoteSignature` / `TcbStatus` are `Indeterminate { VerifierCannotJudge }` → `UpdateVerifier`, and `unrun_essentials()` is still empty. | Updates `what_these_bindings_cannot_check_is_recorded_as_skipped_rather_than_left_out` — rename it; its *point* (declared, not vanished) survives unchanged. |
| **T-14** | `channel_binding.rs` | `ChannelBound` on `NotConnected` is **still** `Skipped`, still in `missing_essentials`, still absent from `unrun_essentials` — and now `disposition == Refuse`. | **Already exists** and the developer ran the negative: converting `verify.rs:70` gives `1 failed` in seconds. **Two corrections.** (a) It is *not* a general guard on that `verify()` call — it passes `boot: None` and asserts nothing about `BootMeasurements`, which is exactly why it survived the conversion, so **T-9 cannot fold into it**. (b) "Do not weaken it" is an instruction a future reader satisfies the wrong way; **name the shape in the test's own doc comment** — the weakening is replacing `Some(Outcome::Skipped(why))` with a wildcard that extracts a detail from any variant, which keeps all three axis assertions green while destroying what the arm does. |
| **T-15** | `verify_negative.rs` | On an unparseable quote: `BootMeasurements` is `Skipped` (→ `ProceedNonEssential`) and `ChannelBound` is `Failed` (→ `Refuse`), in the same verdict. | Pins §3.8's resolution. **Nearly free — the fixture exists:** `garbage_quote_fails_signature_and_mrconfigid` (`:184-196`) already reaches this state with `vec![0u8; 700]` and asserts neither outcome; `grep 'quote could not be parsed'` finds one production line and no test, so the asymmetry is pinned by **nothing at all** today. Write it as a **sibling** test, not an extension, so the existing name keeps describing what it asserts. |
| ~~**T-16**~~ | — | ~~`compose_unavailable` yields no `Refuse` disposition.~~ | **Withdrawn with step 3c.** Its property is now structural rather than tested: an outage that builds no verdict records no checks, so no `disposition="refuse"` label can exist. What remains testable is the chain `FetchError → Unestablished → Disposition`, which is T-11. |
| **T-17** | `verify_negative.rs` | §6b, if step 3b lands: `UnsupportedVersion` → `Indeterminate { VerifierCannotJudge }` → `UpdateVerifier`; **`UnknownVersion` (including an all-zero prefix) stays `Failed` → `Refuse`.** | Map `UnknownVersion` to the indeterminate arm too, and watch T-17 go red. The all-zero case is the boundary and is the reason the arms are split — assert it by value, not by "some error". |
| **T-18** | `verdict_semantics.rs` | **A trustworthy verdict can carry a `Refuse` disposition.** `(BootMeasurements, Failed)` → `Refuse` while `is_trustworthy()` is `true`. | New, from the critique (§3.5). No negative needed — it pins an intentional asymmetry that currently looks like a bug, so that the next reader "fixing" it fails a test instead of passing a review. Its doc comment carries the rule from `Disposition::Refuse`: dispositions never override `TrustworthyVerdict` and never substitute for it. |

**T-8 is the one to get right.** A table test that re-derives the expected value by calling the same
`weight()` the implementation calls asserts nothing — it is `f(x) == f(x)`. The expected column must
be **literal `Disposition` values written out in the test file**, so that changing the mapping
requires changing the test, and changing both is a visible act rather than a silent one.

Tests requiring updates because the shape changed, not the meaning: `verdict_semantics.rs`
`an_absent_boot_reference_does_not_make_a_verdict_untrustworthy` (constructs the outcome by hand —
it should now construct an `Indeterminate`, keeping its assertion that the verdict is trustworthy),
and the three wasm tests named at T-12/T-13. `verify_negative.rs:108-111` asserts `ImagesPinned` is
`Skipped` after a compose mismatch and is **unaffected** — §2 leaves that site alone.

---

## 6. Cross-repo coordination — this is a gate

Per `verity-foundation/CLAUDE.md`, repo boundaries and operational contracts are checkpoints. The
following are `verity-foundation` changes. **They are named here, not performed from this cycle, and
they need approval before anyone edits them.**

0. **`observability/alerts.yaml`, F-09's premise guard** — listed first because it is the one item
   here that is a **pre-existing defect**, not an MA-6 consequence: under the contract as written,
   any total verification outage silences every check series and pages `critical` per check. §6a.
1. **`closed-loop/04-refuses-on-mismatch.sh`** — no existing grep breaks (§1, fact 4). Required:
   correct the comment at `:149` and the operator message at `:174`. **The proposed grep is
   withdrawn.**

   I specified an assertion in the no-reference branch. The developer read `04:158-172`: `boot_ref`
   auto-resolves from `fixtures/boot-reference-dstack-0.5.9.json`, whose `os_image` matches the
   default `DSTACK_IMAGE`, so **on a default run that branch never executes** — and
   `BOOT_REFERENCE=""` falls through the `-z` test straight back to auto-resolution, so there is no
   way to force it. Not "will not be seen to pass": cannot run at all. **Note the irony and do not
   repeat it** — that assertion was my fix for a gate that ships unexercised.

   Of the two repairs offered, take the second: **drop it.** A `BOOT_REFERENCE=none` sentinel would
   add a code path to a money-costing, human-only script solely so a grep could run, and nobody sets
   an env var on a run that provisions a CVM — it buys a gate that is *possible* to exercise instead
   of one that is exercised. If the no-reference path is ever genuinely needed, the sentinel is the
   right mechanism and should land then.

   **What covers the word instead, and why it is enough here.** T-10 pins the rendering and the grep
   pattern on every commit, for free. The gap `transcript_contract.rs`'s header warns about —
   *"renderable here is not the same as reachable there"* — does not bite: that lesson came from a
   flag (`--licensed-compose-hash`) that had to be threaded through the runner, whereas `boot: None`
   is the **default** path, T-9 pins that `verify()` records `Indeterminate` on it, and the runner
   prints `transcript_line` for every recorded check unconditionally (`verify-attestation.rs:265`).
   Producer-reachability is covered by T-9; renderability by T-10; the shell adds nothing but a
   branch nobody takes.
2. **`observability/conventions.md`** — the outcome vocabulary and the `verity.verify.checks` note.
   The audit plan already lists this outstanding (`:629`).
3. **`observability/alerts.yaml` and `conventions.md`** — **approved by the operator 2026-08-22 to
   land with MA-6**, not as a follow-on. Fully specified in §6a.
4. **`docs/decisions/NNNN-indeterminate-outcome-and-per-check-disposition.md`** — MA-6's own gate
   lists an ADR as a required artifact, and `audit-implementation-plan.md:613` has it outstanding.
   It must record: the §2 semantic rule; §3.1's position; the two deviations from the brief's
   vocabulary (typed cause, `Satisfied`); §3.2's narrowing of the gateway criterion to MI-5; and the
   fourth transcript word as a shell contract.

Items 1, 3 and 4 land with the code; item 2 is documentation.

---

## 6a. The alert split — specified

Operator-approved 2026-08-22 to land with MA-6. Verified against `observability/alerts.yaml` and
`conventions.md:89` on the same day.

> ## §6a specifies a contract. It does not repair a live pager. Nothing here has ever fired.
>
> **Measured 2026-08-22, and I re-ran it rather than take it on report.** `verity_verify_total`,
> `verity_verify_check_total` and `verity.verify.checks` appear in **no source file in any repo** —
> only in `observability/{alerts.yaml,conventions.md,dashboards/verification.json}`, the audit plan,
> ADR 0027, and this team's own documents. `verity-verifier/crates` has **zero** matches for
> `opentelemetry`, `tracing` or `metrics`: the crate has no telemetry dependency at all.
>
> Three consequences, and every one of them has to be stated where the rules are, not inferred:
>
> 1. **The five-critical-pages scenario cannot happen today**, because F-09 cannot fire at all.
>    Neither can F-08, `NoVerificationsObserved`, or `VerifierAcceptedDegradedTcb`.
> 2. **Every rule in this section is unexercised by construction**, and by this project's own
>    standard — a gate is trustworthy only once it has been *seen to fail* — none of these alerts has
>    ever been seen to do anything. They describe a contract no code implements. **MA-5 owns the
>    emitter; until it lands, none of this is verified, and no wording here should suggest it is.**
> 3. **It makes the moment right rather than wrong.** Getting a telemetry contract correct before
>    anything emits it is the cheapest it will ever be, and it strengthens item 0's framing: F-09's
>    missing premise guard is a pre-existing defect in an *unimplemented* contract, which is the best
>    possible time to find one.
>
> This box exists because §6a otherwise reads as though it is fixing a pager that wakes someone. It
> is not, and that is exactly the class of claim this project's records exist to stop us making by
> accident.

**One artifact this does *not* add to the foundation list.** `dashboards/verification.json:43-47`
computes `count(sum by (check) (increase(verity_verify_check_total[1h])) > 0)` against a 24h offset —
the dashboard twin of F-09, with the same series-disappearance behaviour and **no** need for the
premise guard. A panel reading "3 of 8 checks active" during an outage is *informative*; a page
saying the same thing is not. The guard belongs on the alert precisely because the alert wakes
someone. Its other panels aggregate with `sum by (outcome)` and `sum by (check)`, so the new label
and the unchanged binary `outcome` both pass through untouched.

**Provenance, stated because this document feeds an immutable ADR.** The facilitator supplied
`alerts.yaml:23-24` (F-08's expression, severity and runbook target), the `{{ $labels.refusal }}`
interpolation, `conventions.md:89`'s binary outcome, and pointers to `NoVerificationsObserved`
(`:47`) and the F-09 group (`:62+`) with the question of whether either was affected. Everything
below that is not one of those came from reading `alerts.yaml`, `conventions.md` and `binding.rs`
during this section — including **the `UnsupportedMrConfigIdVersion` witness, the double-page, and
the existing `MrConfigIdError` distinction**, none of which were handed to me. Recorded at this
granularity because a provenance claim that is wrong here is wrong permanently once it reaches the
ADR.

### The decision: outcome stays binary; the disposition rides the **per-check** counter

Neither (a) nor (b) as posed. The answer is a third option:

> **`verity.verify.outcome` stays `accepted | refused`. `disposition` becomes a label on the
> *existing* `verity_verify_check_total`, and `verity.verify.dispositions` a span attribute beside
> `verity.verify.checks`.**

**(a) — a third `outcome` value — is rejected, and not narrowly.** Three reasons, the last decisive:

1. **It would make the metric disagree with the type system.** `outcome` mirrors `is_trustworthy()`,
   and after §3.1 there is no third answer to "may I proceed" — an indeterminate essential means the
   agent refuses. The agent *did* refuse; reporting anything else is false about what happened.
2. **It silently breaks every counter of refusals.** Anyone filtering `outcome="refused"` to measure
   refusal volume would see it drop during an outage. A monitoring rule that quietly stops seeing
   things is this project's named failure class.
3. **It fails open at the alerting layer.** Binary `outcome` carries a safety property — *everything
   not `accepted` is visible as a refusal*. A third value puts a fraction of non-acceptances outside
   the term F-08 matches, and any future miscategorisation lands there permanently and invisibly.

**(b) as posed — a `disposition` label on `verity_verify_total` — is rejected because it needs the
fold §3.4 refuses.** That counter is per *verification*, so a single `disposition` label demands one
value per verdict, which means collapsing a set of remedies into one. I rejected that in the library
for reasons that apply identically here, and adopting it in telemetry would smuggle it back in
through the side door — then the library would be pressured to grow `overall_disposition()` to match
the metric.

**What ships instead** uses a counter that already exists and already has the right key:

```yaml
# verity_verify_check_total{check, disposition}
#   `check`       — Check::name(),        8 values  (unchanged, F-09's key)
#   `disposition` — Disposition::name(),  6 values  (new)
# Bounded at 48 series. Both label sets are closed enums in the verifier, not free text.
```

No fold, and per-check fidelity preserved.

**F-09 is *not* unaffected — this sentence used to say it was, and that was falsified.** What the
`sum by (check) (…)` aggregation establishes is only that **adding a label** changes nothing.
It says nothing about **series disappearance**, which is the failure mode that matters here, and
F-09 needs a one-line premise guard as a result. See the F-09 entry below and §6 item 0.

### The coupling this exposes — and it is a library change, not a telemetry one

Specifying the alert surfaced a defect in the design as it stood. **Without the fix below, the split
fails on the exact case it was approved for.**

A downed gateway does not produce one indeterminate check. `ComposeHash` becomes
`Indeterminate { RetrievalFailed }` — but `ImagesPinned` and `LicensedImagePresent` are recorded
against the *verified* document, which does not exist, so under the design as written they were
`Skipped("compose hash did not match, so its contents were not examined")`. Both are **essential**,
so both disposition to `Refuse`, so an IPFS outage still fires the critical page. The split would
have shipped and done nothing.

The fix falls straight out of §2's rule, and it is right independently of the alert:

> **`Indeterminate` propagates to dependent checks; `Failed` does not.**
>
> A dependent of a **`Failed`** check is `Skipped` — moot, because the answer is already no.
> A dependent of an **`Indeterminate`** check is `Indeterminate` **with the same cause** — because
> it is equally unestablished, and the *same remedy* establishes all of them. Retrieving the
> document once answers all three.

Recording a dependent of an unestablished check as `Skipped` says "a prior check refused" when no
prior check refused. It was wrong before the alert made it visible. This is added to §2's table and
to step 3 of §4, and pinned by T-16.

### The rule changes

**Modified — `AttestationVerificationFailure` (F-08), stays `critical`, re-keyed:**

```yaml
expr: increase(verity_verify_check_total{disposition="refuse"}[5m]) > 0
```

The subject moves from "a verification refused" to "a check concluded that something is violated or
could not be attempted", which is what the annotation already claims it means. Keep `severity:
critical`, `invariant: I1`, `for: 0m`. The description needs one added paragraph: a refusal that
does *not* appear here is not an all-clear — it is the other alert, and the endpoint is still
refused.

**Two consequences of the re-key I did not work through, both conceded:**

- **The annotations break.** F-08 interpolates `{{ $labels.refusal }}` at `:31-32`, and `:41-43`
  asks *"is `refusal` a mismatch or an unsupported format?"* — and `refusal` is a label on
  `verity_verify_total`, **not** on the check counter. After the re-key the summary renders "reason "
  with nothing after it and the first diagnostic question is unanswerable. Repair, as proposed:
  interpolate **`{{ $labels.check }}`** — which is strictly more useful, since naming the check that
  refused is the diagnosis — and re-point the paragraph at `verity.verify.dispositions` on the span.
- **It becomes one alert per check**, because the expression has no `sum` and `for: 0m`. Three
  refusing checks page three times. **Named, and kept per-check deliberately:** the per-check
  identity is what makes `{{ $labels.check }}` meaningful, and collapsing related firings is
  Alertmanager's `group_by` job, not a rule's. Putting a `sum` in the expression to reduce paging
  would throw away the label the annotation now depends on.

**New — `VerificationCouldNotBeEstablished`, `severity: warning`:**

```yaml
expr: |
  sum(increase(verity_verify_total{outcome="refused"}[5m])) > 0
  unless
  sum(increase(verity_verify_check_total{disposition="refuse"}[5m])) > 0
for: 15m
```

Fires when verifications refused and **nothing** dispositioned `refuse` — i.e. every defect was
remediable. `for: 15m` because a single failed fetch is not an event; a quarter hour of them is.

**`warning`, and deliberately not `info`.** While this fires, nobody is being protected: the
guarantee is unavailable even though nothing is violated. Its description should say that in the
first line, and say what the remedy is — read `verity.verify.dispositions` on any recent span and
act on the named remedy, do **not** loosen anything, ADR 0009 rule 3.

**Unchanged, and checked:**

- `NoVerificationsObserved` — `sum(increase(verity_verify_total[30m])) == 0`, no `outcome` selector.
  Unaffected. It also remains the backstop if the split is ever misconfigured into silence.
- `VerifierAcceptedDegradedTcb` — selects `outcome="accepted"`. Unaffected.
- `VerifierStoppedChecking` (F-09) — ~~unaffected~~ **needs a one-line change. My claim was checked
  against the wrong failure mode, and this is the same defect class I caught one layer down.**

  What I verified was **label addition**: `sum by (check)` discards `disposition`, so adding it
  changes nothing. What I never checked was **series disappearance**. F-09 fires per check when a
  series goes quiet for an hour having been active in the prior 24 — and during a sustained
  retrieval outage, the quote-side checks run zero times. Five `critical` pages, with a runbook
  telling the operator to *"treat every acceptance since the transition as unverified."*

  **This is not caused by MA-6 and is not fixed by withdrawing anything** — that is the part worth
  being precise about. Under the telemetry contract as written, *any* total verification outage
  makes every check series go quiet, because during it no check runs. MA-6 is simply the change that
  makes it matter, and §6a is the section that should have caught it.

  **The fix (developer's part (b)), accepted — it encodes F-09's own stated premise:**

  ```yaml
  and on() (sum(increase(verity_verify_total{outcome="accepted"}[1h])) > 0)
  ```

  F-09's description already says *"Verifications are still being reported as accepted, but this
  comparison is no longer among the checks they performed."* **The expression never encoded the
  first clause.** Adding it costs nothing in signal: a verifier that quietly stopped checking still
  returns `accepted` — that is the whole of F-09's reasoning — and the guard is `> 0`, not a ratio,
  so a single acceptance anywhere in the fleet re-arms it. A build that stopped checking *and*
  stopped accepting is falsely reassuring nobody.

  **F-09 therefore joins the foundation list in §6, and the semantics note still stands:** an
  `Indeterminate` check is a check that **ran**, so it appears in `verity.verify.checks` and
  increments the counter, exactly as `unrun_essentials()` treats a recorded outcome as not-unrun.

### The witness: this split already exists, hand-rolled and inconsistent

`UnsupportedMrConfigIdVersion` (`alerts.yaml:118-129`) fires `warning` on
`refusal="mrconfigid_unsupported"`, and its description reads: *"Not a mismatch and not an attack:
the verifier branched on the prefix byte and found a construction it has no reference for."*

That is `Indeterminate { VerifierCannotJudge } → UpdateVerifier`, written a month early, in YAML,
for one refusal code. **And today it double-pages**: the same event also matches
`outcome="refused"`, so F-08 fires `critical` beside it. The observability layer already concluded
it needed this distinction and could only express it one case at a time. MA-6 generalises it, and
the double-page for this case disappears once the verifier reports it as indeterminate — which is
§6b.

Keep the alert. Re-point its comment to say it is now the specific case of
`VerificationCouldNotBeEstablished`, retained because the remedy is narrower and worth naming.

### Two questions a reviewer will ask, answered

**"Can an attacker suppress the critical page by inducing indeterminacy?"** No. The critical is
keyed on the *presence* of a `refuse` disposition, never on the absence of others. Blackholing a
gateway silences nothing that would otherwise fire — it produces refusals with no `refuse`
disposition, and it gains the attacker nothing, because every affected agent refuses to proceed.
A real violation occurring in the same window still fires F-08 unconditionally. Only the *warning*
is suppressible, and only by something that also fires the critical.

**"Is downgrading any refusal below critical a loosening?"** No — the verifier still refuses and the
agent still cannot proceed; what changes is who is woken. The argument for it is F-08's own premise:
it says a refusal "is never routine", and an alert that fires for every IPFS blip has already made
itself routine. Paging on outages is how an operator learns to reach for the check that made the
pager stop, which is the erosion ADR 0009 rule 3 exists to resist, one layer above the code.

**Known imprecision, recorded rather than discovered later — and it runs both ways.** The `unless`
correlates over a *5m window*, not per verification. A real violation and an outage inside the same
window suppress the warning and fire only the critical. The reverse is also possible across a rule
boundary: an outage in one evaluation and a violation in the next produce both, in either order.
Both are harmless — every case still fires at least the correct-or-stricter alert — and both are
written down here **so that nobody later "fixes" the rule into a per-verification join**, which
would need a label linking checks to their verification and would multiply the metric's cardinality
by the verification count. That is the desirable direction — the critical wins, a human
looks — but it is an approximation and the rule should carry a comment saying so.

### `conventions.md`

- `:89` — leave `verity.verify.outcome` **binary**, and add a sentence saying so on purpose, with
  the reason: it mirrors `is_trustworthy()`, and there is no third answer to "may I proceed".
- Add `verity.verify.dispositions` — `string[]`, members formatted `"<check>=<disposition>"`.
  Chosen over two positionally-aligned arrays (an invariant no reader of a trace can verify) and
  over one attribute key per check (an unbounded key set). Self-describing, order-independent,
  greppable in Loki.
- Add a `Disposition` value table beside the existing `Check` table, transcribed from
  `Disposition::name()`, carrying the same warning the check table carries: **if the two disagree,
  the code is right and this file is a bug.** That table is why `Disposition::name()` exists as one
  source (§3.5) rather than strings written at each surface.
- The check table at `:103-112` gains no rows. `boot_measurements` stays `Essential: no`.

### Flagged, not fixed here

- `AttestationVerificationFailure`'s description reads **"This is not a availability problem"**
  (`:37`). Grammar. Not mine to fix in this change — but note it is *also* about to become subtly
  misleading, because after the split the availability-shaped refusals move to the other alert, and
  that sentence is what distinguishes them. Worth MA-5's attention as content, not only as a typo.
- **A degraded verifier can hide behind a permanent `Indeterminate`.** F-09 detects a check
  *disappearing*; a check reported `Indeterminate` forever is present, so F-09 stays quiet while
  nothing is ever established. **This hazard is pre-existing and unchanged** — `Skipped` already
  provides identical cover, and has since F-09 was written — so it is not MA-6's to close, and MA-6
  does not widen it. But `Indeterminate` *sounds* more benign than `Skipped`, so it is recorded here
  rather than lost: the alert that would close it is "an essential check has not been `satisfied` in
  N hours while verifications continue", and its false-positive profile depends on deployment shapes
  we do not have yet (an offline-audit deployment holds `channel_bound` non-satisfied forever and
  legitimately). It belongs with MA-5, designed against real traffic — not invented here.
- Its `runbook: ../records/runbooks/attestation-failure.md` **does not exist**. MA-5 owns it.
  Consequently **`VerificationCouldNotBeEstablished` ships with no `runbook:` key**, with a comment
  saying MA-5 adds it — rather than pointing at a second file that does not exist. The audit plan
  already anticipates a doc-lint asserting every `runbook:` path resolves; writing a dangling one
  now would mean shipping a known-red input to a gate that is about to be built.

---

## 6b. The MR-CONFIG-ID arm — recommended, and cheaper than expected

Stated separately rather than buried, because it reverses advice I gave earlier in this document.
Found by reading `alerts.yaml` and `binding.rs` while specifying §6a — not supplied.

**This step survives §2's round-2 clause, and by a cleaner test than the one I first offered.** Under
"would a later attempt of **this same call** conclude it": `verify(licensed, evidence, boot, tcb)`
already receives everything a V2 comparison needs — only the library's knowledge is missing, so the
same call with an updated build concludes. Contrast wasm `377/381`, where the function has no
collateral parameter at all, so no later call of it can conclude regardless of what any dependency
gains. `VerifierCannotJudge` therefore means **"this same call, run against an updated build,
concludes"** — not "a later version might exist", which was my formulation and which the developer
correctly showed readmits the wasm sites.

`MrConfigIdError` (`binding.rs:255-276`) **already distinguishes** `UnknownVersion` and
`UnsupportedVersion` from `Mismatch`, and the doc comment on the first says: *"Distinct from a
mismatch on purpose: an unrecognised format is a platform-version problem, and reporting it as
'wrong configuration' would send someone hunting an attack that is not there."* That is MA-6's
thesis, already written, in another file. The distinction exists in the type and is **collapsed at
one site** — `verify.rs:186`, which maps every arm to `Outcome::Failed`.

So this is a four-line match, not error-taxonomy work. **Recommended for this change**, as step 3b:

```rust
Err(MrConfigIdError::UnsupportedVersion { .. }) =>
    Outcome::unestablished(Unestablished::VerifierCannotJudge, e.to_string()),
Err(e) => Outcome::Failed(e.to_string()),   // Mismatch *and* UnknownVersion
```

**`UnknownVersion` deliberately stays `Failed`, and this is the conservative boundary.**
`UnsupportedVersion` is a *recognised, documented* dStack construction that this verifier cannot yet
compute a reference for — our limitation, with a remedy we can name, and not attacker-influenced.
`UnknownVersion` is an unrecognised prefix **including all-zero, which is what an unpopulated field
looks like** (`binding.rs:206-207`) — evidence we cannot account for, with no remedy we can honestly
name. It belongs with the crate's existing treatment of unusable evidence (§3.8). Drawing the line
the other way would let an unaccountable measurement disposition to "update your verifier".

> **The argument that will be made against this is symmetry** — both arms come from the same
> `match`, both mean "we did not compute a reference", so why do they differ? Because the inputs
> differ in who controls them. `UnsupportedVersion` is reached only for a construction dStack
> documents; `UnknownVersion` is reached for *any* byte we do not recognise, including `0x00`.
> Symmetry between those two is symmetry between a known platform and an unknown input, which is
> not a property worth having. The facilitator concurred on 2026-08-22 and asked that the boundary
> not be moved on symmetry grounds; the reasoning is recorded here so the next reader does not have
> to reconstruct it from the diff.

Consequences: the verdict is untrustworthy either way (essential, not passed); `failures()` stops
listing `mr_config_id` for the V2 arm; the transcript word changes for it.

**No closed-loop gate breaks, and the reason is stronger than the one I first gave.** I argued
"`04` and `06` grep `mr_config_id +passed` and never `FAILED`", which is true but is an argument
from absence — it would stop holding the moment someone added such a grep. The real argument is
about reachability: **`04:310`'s `mr_config_id +passed` sits in the *tampered* step**, where it
proves the refusal is *targeted* rather than a verifier falling over. Step 3b cannot touch that
path, because tampering a compose document does not change the quote's `MR-CONFIG-ID` prefix byte —
the tampered run still takes the `V1` arm and still passes. The assertion is untouchable by this
change rather than merely unwritten.

**Cuttable, and it is now the *first* cut.** Round-1 correction: I had offered step 5 as the cut and
6b as recommended. That is backwards — **step 5 carries an acceptance criterion** (§3.2: it is the
only executed path where a retrieval outage dispositions to `RetryRetrieval`), while 6b carries a
double-page retirement. Cut order if the budget bites: **6b, then `kind()`, and step 5 last.** If
6b is cut, say so in the commit message rather than leaving a reader to infer that `verify.rs:186`
was never considered.

---

## 7. Rejected alternatives

| Rejected | Why |
|---|---|
| Overload `Skipped` for "could not establish" | MA-6's explicit instruction, and it destroys ADR 0014's regression signal that F-09's alert is built on. |
| **Sweep every existing `Skipped` into `Indeterminate`** | The natural move, and it costs the CR-1 regression gate: `ChannelBound` on `NotConnected` is a *decline*, not an unestablished property, and both `04:236` and `channel_binding.rs:311` assert the word (§3.8, fact 11). Four of five sites stay. |
| `BootMeasurements` → `Indeterminate` on an unparseable quote | Every available cause would be false: the verifier can judge it, and no retrieval remedy applies. Naming a remedy that does not exist is the defect §3.6 rejects elsewhere (§3.8). |
| `BootMeasurements` → `Failed` on an unparseable quote, for symmetry with `ChannelBound` | Puts a boot-measurement failure in `failures()` that never happened, sending an operator to re-capture a reference for a quote that never parsed (§3.8). |
| Keep `Skipped` = "considered and declined for a legitimate reason" | The crate violates it one statement earlier (§1, fact 12). Replaced by §2's rule, under which every site is expressible. |
| A third `verity.verify.outcome` value, `indeterminate` | Disagrees with the type system (there is no third answer to "may I proceed"); silently undercounts refusals for anyone filtering `outcome="refused"`; and moves a class of non-acceptance outside the term F-08 matches — fail-open at the alerting layer (§6a). |
| A `disposition` label on `verity_verify_total` | Per-verification, so it needs one value per verdict — the fold §3.4 rejects. Adopting it in telemetry would pressure the library to grow `overall_disposition()` to match the metric. |
| Dependents of an unestablished check recorded as `Skipped` | Asserts that a prior check refused when none did — and it defeats the §6a split on the exact case the split was approved for, because two of those dependents are essential and disposition to `Refuse` (§2). |
| `UnknownVersion` → `Indeterminate { VerifierCannotJudge }` | An unrecognised prefix includes all-zero, which is what an unpopulated field looks like. No remedy can honestly be named for evidence we cannot account for (§6b). |
| A `runbook:` path on the new alert | It would not resolve, and a doc-lint asserting every `runbook:` resolves is already planned. Shipping a known-red input to a gate about to be built (§6a). |
| `Indeterminate { reason: String }` only | `disposition()` would have to sniff prose or hardcode one remedy per check. The first is the failure this change prevents; the second is wrong for `ComposeHash` (§3.3). |
| `disposition()` on `Outcome` | Cannot see the check, so it cannot resolve the `Skipped` row — the one row that needs both (§3.4). |
| `disposition()` on `Check` | Reads backwards; `Check` is a `Copy` value type. |
| Only `Verdict::disposition()` | Unreachable from a `(Check, Outcome)` pair out of `results()`; forces whole-verdict construction to test one cell. |
| `Verdict::overall_disposition()` | Remedies are a set, not a lattice; folding hides one. And a single actionable value on `Verdict` competes with `TrustworthyVerdict` (§3.4). |
| `Option<Disposition>`, `None` for `Passed` | Breaks "exactly one disposition per pair" and invites `.unwrap_or(proceed)`. |
| Reuse `ProceedNonEssential` for `Passed` | Says "non-essential" about an essential check that passed. |
| Derive `weight` from `essential().contains()` | Silently classifies a future `Check` as advisory — fail-open, and the exact hazard the brief asked about. |
| A macro generating `Check` + `ALL` | Closes a gap that only weakens tests, at the cost of indirection on the most-read type in the crate (§3.4). |
| Change `Evidence.compose_document` to express "unavailable" | Models absent evidence as an input to verification; adds a second, weaker path through the crown jewel; breaks a deliberately break-y struct (§3.2). |
| Defer the WASM surface | Breaks a written cross-surface contract while its test stays green — a gate that does not guard (§3.6). |
| `unknown` as the fourth word | Already means "variant these bindings do not recognise" in the JS surface. |
| Shout it as `INDETERMINATE` | Trains operators to read outages as attacks — the sensitisation MA-6 exists to end (§3.9). |
| Promote `BootMeasurements` to `essential()` | MA-6 gates it on the signed feed. Fact 10 retires the *capture* precondition only. |
| Fold `Refusal::kind()` from the verdict's dispositions wholesale | `kind()` answers "attack or outage" about a connection attempt; disposition answers "what to do about a check". Only the `NotTrustworthy` arm is refined (§3.7). |

---

## 8. The three open questions — answered, round 1

All three are settled by the developer's evidence. Recorded here rather than deleted, because the
reasoning is what the ADR needs.

**8.1 Step 5 (`connect.rs`) — IN, and it is the wrong thing to cut.** I offered it as the clean cut.
It is not: per §3.2, `Refusal::disposition()` is the only place in this change where "a retrieval
outage dispositions to `RetryRetrieval`" becomes true on a path that **executes**, and
`verified_transport.rs:696-710` already drives a real `NotReached` refusal for free. Cut it and
`From<&FetchError> for Unestablished` becomes a mapping nothing in the repo calls, and the change
ships with zero executed evidence for one of its two acceptance criteria. **If the budget bites, cut
only the `kind()` refinement.**

Two things I missed on `kind()`, both conceded:

- The rule I wrote — *`GuaranteeViolated` if any essential `Failed` or was `Skipped`;
  `CouldNotEstablish` when the only non-passing essentials are `Indeterminate`* — **does not cover
  essentials that never ran**, and `verified_transport.rs:592-596` asserts exactly that case
  (`NotTrustworthy { verdict: Verdict::new() }` → `GuaranteeViolated`). Write the never-ran arm
  explicitly, and it stays `GuaranteeViolated`: a check that vanished is F-09's signal, and an empty
  verdict must never read as "could not establish".
- Losing `const` is unavoidable (`missing_essentials` allocates); all sixteen `.kind()` call sites
  are value contexts, and `closed-loop/08:619` greps only `endpoint_unusable`, so no shell gate is at
  risk.

**8.2 `Disposition::name()` — snake_case, not kebab.** My camelCase-keys argument does not survive
`RefusalKind::name()` (`connect.rs:723-725`), which already ships `"guarantee_violated"`,
`"could_not_establish"`, `"endpoint_unusable"` **through the same JSON surface**, documented as
"suitable for telemetry and for a shell harness to grep". Add `Check::name()`'s snake_case and
`conventions.md:73,90`'s `needs_holder_action` / `compose_hash_mismatch`, and kebab would make
`Disposition` the only non-snake_case identifier vocabulary in a two-repo telemetry contract — while
§6a turns these into **PromQL label values**. Use `satisfied`, `refuse`, `retry_retrieval`,
`update_verifier`, `update_reference`, `proceed_non_essential`.

**8.3 `Check::ALL` — public; `index()` dropped.** `Check` is `#[non_exhaustive]`, so a downstream
caller genuinely cannot enumerate the checks without it: a real consumer, not a test convenience.
`index()` had no consumer at all (§3.4).

---

## 9. The four ADR dimensions

Added after the fact: the `rust-architect` skill's ADR template requires these four stated
explicitly, and §6 makes an ADR a required MA-6 artifact. Two of them are "none", which is worth
writing down rather than leaving to inference.

**Public surface.** New `pub`, each a versioning commitment:

| Item | Why `pub` |
|---|---|
| `Outcome::Indeterminate { cause, detail }` | The variant is the change. Constructible downstream, deliberately — an embedder implementing `compose::Source` is a first-class producer (§3.2). |
| `Unestablished` | Read by `disposition()`; a caller matching on the remedy needs it. `#[non_exhaustive]`. |
| `Disposition` + `Disposition::name()` | The typed instruction agents branch on, and the one source for the telemetry and JSON strings (§6a). `#[non_exhaustive]`. |
| `disposition(check, outcome)` | The mapping, reachable from a `(Check, Outcome)` pair out of `results()` (§3.4). |
| `Verdict::disposition` / `dispositions` | Thin, derived from the free function so there is one definition. |
| `Outcome::unestablished` / `Outcome::cause` | Constructor and accessor. `unestablished(cause, detail: impl Into<String>)`. |
| `verify::compose_unavailable` | The propagation rule has to be reachable or embedders each invent one (step 3c). |
| `Refusal::disposition` | Feature-gated with `connect`, purely additive. |
| `Check::ALL` | Open question §8.3. |

Kept private, per the skill's `pub(crate)`-by-default rule: **`Weight` and `weight()`**. They are the
only thing `disposition` needs from a `Check`, and exposing them would create a second public
spelling of `Check::essential()` — two definitions of "essential" that can drift, which is the defect
`TrustworthyVerdict::check` avoids by calling `is_trustworthy` rather than re-implementing it.

**Error type.** None added. `Disposition`, `Unestablished` and `Outcome` are **not** errors and must
not become them — `verify.rs:95-99` is explicit that a failed check is an outcome rather than an
error, because collapsing which check refused into one error type throws away the distinction a
caller needs. Existing error types stay `thiserror`, unchanged. Note the direction of travel: §3.3's
typed cause moves this surface *toward* the skill's model, converting prose a caller would have to
parse into a value they can match.

**Async commitments.** None, and none acquired. The crate is deliberately synchronous —
`Cargo.toml:82-83` refuses an async HTTP client so as not to leak a runtime choice into every
embedder's process — and nothing here adds an `.await`, a runtime, or a `Send`/`Sync` obligation.

**Unsafe.** None. `unsafe_code = "forbid"` at the workspace (`Cargo.toml:15`) and nothing in this
change goes near it.

**One feature-gating consequence, since it is easy to get backwards.** `Disposition` and
`Unestablished` live in the **ungated** `verdict` module, and `connect` (feature-gated) depends on
them. Not the reverse: putting the disposition vocabulary in `connect` would make the crate's core
outcome vocabulary feature-dependent, so a default build would report outcomes it could not
disposition. Features are additive — `connect` adds `Refusal::disposition()` on top of a vocabulary
that is always present.

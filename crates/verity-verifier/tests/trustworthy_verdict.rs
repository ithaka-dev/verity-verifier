//! The structural gate: a verdict you cannot ignore.
//!
//! `Verdict::is_trustworthy` is a method a caller has to remember to call and then remember to act
//! on. `TrustworthyVerdict` applies the crate's *one constructor, and it performs the check*
//! discipline to it — the discipline `VerifiedCompose` and `ChannelBinding` already follow — so
//! that `VerifiedClient` cannot exist without one.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use verity_verifier::verdict::{Check, Outcome, TrustworthyVerdict, Verdict};

/// A verdict with every essential check passed.
fn full_house() -> Verdict {
    Check::essential()
        .iter()
        .fold(Verdict::new(), |v, c| v.record(*c, Outcome::Passed))
}

#[test]
fn a_verdict_with_every_essential_check_passed_is_accepted() {
    let verdict = full_house();
    let trustworthy = TrustworthyVerdict::check(verdict.clone()).expect("every essential passed");
    assert_eq!(trustworthy.verdict(), &verdict);
}

/// **Dropping any one essential check is enough to refuse.**
///
/// Parameterised over every essential rather than testing one: a gate that only noticed
/// `ComposeHash` would pass a single-case test while letting `ChannelBound` through, and
/// `ChannelBound` is the one CR-1 added.
#[test]
fn a_verdict_missing_any_single_essential_check_is_refused() {
    for omitted in Check::essential() {
        let verdict = Check::essential()
            .iter()
            .filter(|c| *c != omitted)
            .fold(Verdict::new(), |v, c| v.record(*c, Outcome::Passed));
        let returned = TrustworthyVerdict::check(verdict)
            .map(|_| ())
            .expect_err(&format!(
                "{omitted} was never run, so nothing establishes it"
            ));
        assert_eq!(returned.unrun_essentials(), vec![*omitted]);
    }
}

/// A check that ran and *failed* is refused, and is not the same as one that never ran.
///
/// `unrun_essentials` and `missing_essentials` exist to keep those apart — a check that failed is
/// the system working, and a check that silently stopped running is the failure mode ADR 0014 is
/// about. The gate treats both as untrustworthy; the returned verdict keeps them distinguishable.
#[test]
fn a_failed_essential_check_is_refused_and_stays_distinguishable_from_one_that_never_ran() {
    let verdict = Check::essential().iter().fold(Verdict::new(), |v, c| {
        let outcome = if *c == Check::ChannelBound {
            Outcome::Failed("channel binding failed".to_owned())
        } else {
            Outcome::Passed
        };
        v.record(*c, outcome)
    });

    let returned = TrustworthyVerdict::check(verdict)
        .map(|_| ())
        .expect_err("it failed");
    assert_eq!(returned.missing_essentials(), vec![Check::ChannelBound]);
    assert!(
        returned.unrun_essentials().is_empty(),
        "the check ran; reporting it as never-run would send someone after a regression that is \
         not there"
    );
}

/// **A skipped essential check is not a passed one.**
///
/// The single edit that would make a verifier approve everything it declined to check.
#[test]
fn a_skipped_essential_check_is_not_treated_as_passed() {
    let verdict = Check::essential().iter().fold(Verdict::new(), |v, c| {
        let outcome = if *c == Check::ChannelBound {
            Outcome::Skipped("no connection was made".to_owned())
        } else {
            Outcome::Passed
        };
        v.record(*c, outcome)
    });
    assert!(
        TrustworthyVerdict::check(verdict).is_err(),
        "a verdict about recorded evidence establishes what ran somewhere, never what you are \
         talking to"
    );
}

/// **The rejected verdict comes back unchanged.**
///
/// A refusal a caller cannot explain is a refusal they eventually route around. The whole
/// transcript survives the gate, so they can render exactly which check refused.
#[test]
fn the_rejected_verdict_is_returned_intact() {
    let verdict = Verdict::new()
        .record(Check::ComposeHash, Outcome::Passed)
        .record(
            Check::MrConfigId,
            Outcome::Failed("measured configuration is not the licensed one".to_owned()),
        );

    let returned = TrustworthyVerdict::check(verdict.clone())
        .map(|_| ())
        .expect_err("mr_config_id failed");

    assert_eq!(
        returned, verdict,
        "the verdict must survive the gate unchanged"
    );
    assert_eq!(
        returned.failures(),
        vec![(
            Check::MrConfigId,
            "measured configuration is not the licensed one"
        )]
    );
}

/// Unwrapping is free; wrapping is not. That asymmetry is what makes holding one mean something.
#[test]
fn a_trustworthy_verdict_unwraps_to_the_verdict_it_judged() {
    let verdict = full_house();
    let trustworthy = TrustworthyVerdict::check(verdict.clone()).expect("passes");
    assert_eq!(trustworthy.clone().into_verdict(), verdict);
    // Rendering goes through the same transcript a caller would see from the raw verdict; ADR 0014
    // requires the provenance to survive, and it does not lapse because the answer was yes.
    assert_eq!(trustworthy.to_string(), verdict.to_string());
    assert!(trustworthy.to_string().contains("=> trustworthy"));
}

/// A verdict with nothing recorded is refused, not vacuously accepted.
///
/// The degenerate case that an "are there any failures?" implementation would get wrong: there are
/// none, because nothing ran.
#[test]
fn an_empty_verdict_is_refused_rather_than_vacuously_accepted() {
    let returned = TrustworthyVerdict::check(Verdict::new())
        .map(|_| ())
        .expect_err("nothing ran, so nothing passed");
    assert_eq!(returned.unrun_essentials(), Check::essential());
}

// — VA-2 (audit VV-02), Part 1: characterization, not a bug fix —
//
// `TrustworthyVerdict` is documented to be a *content-judgment* about a transcript, never proof of
// where the evidence came from — see its "What holding one proves" / "What it does NOT prove" doc.
// A hand-fabricated all-`Passed` verdict passing `check` is therefore **by design**, not a hole:
// this test pins that documented behaviour so a future change cannot quietly alter it (e.g. by
// adding a witness) without a test noticing, per the round-2 design decision that no witness or
// sanctioned assembler is introduced.

/// **T-D, characterization pin.** A hand-fabricated all-`Passed` verdict — built with no `verify()`
/// call and no evidence examined — **does** produce `Ok(TrustworthyVerdict)`. This is the
/// documented content-judgment guarantee working as designed, not the audit finding reopened: VA-2
/// closes the `outcome()` first-wins/`failures()` contradiction (`Verdict::outcome`'s doc, exercised
/// in `tests/verdict_semantics.rs`) and hardens this type's own contract (see the "What holding one
/// proves" / "What it does NOT prove" doc above), but deliberately does not prevent construction —
/// `Verdict::new`/`record` stay public because the WASM bindings assemble a verdict cross-crate
/// through them.
///
/// The load-bearing half is what this wrapper **cannot** reach: there is no public path from a
/// `TrustworthyVerdict`, fabricated or genuine, to a [`crate::connect::VerifiedClient`].
/// `VerifiedClient`'s constructor is private, takes a `TrustworthyVerdict` produced from a live
/// handshake, and is called from exactly one place — see its own doc. That is a compile-time,
/// type-system property (no public constructor exists to call), not something a runtime assertion
/// can meaningfully strengthen, so it is pinned here as a doc-invariant rather than as a second
/// `#[test]` that would just restate "there is no such method" by failing to compile it.
#[test]
fn a_hand_fabricated_verdict_is_a_content_judgment_not_provenance() {
    let fabricated = Check::essential()
        .iter()
        .fold(Verdict::new(), |v, c| v.record(*c, Outcome::Passed));

    let trustworthy = TrustworthyVerdict::check(fabricated)
        .expect("by design: a content-judgment about a transcript, not proof of its origin");

    assert!(
        trustworthy.verdict().is_trustworthy(),
        "the wrapper reports what the transcript says"
    );
    // Doc-invariant, not a runtime check: `crate::connect::VerifiedClient` has no public
    // constructor at all, so there is no expression `trustworthy` (or any `TrustworthyVerdict`)
    // could be passed to here that would compile into one. See `VerifiedClient`'s own doc:
    // "There is no public constructor, and none obtainable from an untrustworthy verdict."
}

//! T-11: what a verdict *means*, over every combination of outcomes.
//!
//! `Verdict` is the whole of ADR 0014 decision 1 — "a verdict is never a bare boolean" — and the
//! reason that decision exists is that a loosened verifier still returns "verified". What it can no
//! longer do is *claim to have checked*. So the accessors that expose which checks ran are not
//! reporting conveniences; they are the mechanism, and they were the least-tested code in the
//! crate.
//!
//! The distinction these tests are mostly about: `missing_essentials` answers the **trust**
//! question, where "failed" and "never ran" are the same answer — you do not know. `unrun_essentials`
//! answers the **diagnostic** question, where they are opposites: a check that failed is the system
//! working, and a check that silently stopped running is the regression ADR 0014 was written to
//! make visible. Collapsing them was a real bug once; nothing had pinned them apart.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use verity_verifier::verdict::{Check, Outcome, Verdict};

/// A verdict with every essential check passing, and nothing else.
fn all_essentials_pass() -> Verdict {
    Check::essential()
        .iter()
        .fold(Verdict::new(), |v, c| v.record(*c, Outcome::Passed))
}

/// Every essential check passing except `target`, which gets `outcome`.
///
/// Built this way rather than by recording over a passing verdict, because `record` appends and
/// `outcome` returns the first match — so a second record for the same check is silently ignored.
/// See `recording_a_check_twice_keeps_the_first`.
fn essentials_with(target: Check, outcome: &Outcome) -> Verdict {
    Check::essential().iter().fold(Verdict::new(), |v, c| {
        let o = if *c == target {
            outcome.clone()
        } else {
            Outcome::Passed
        };
        v.record(*c, o)
    })
}

fn failed(why: &str) -> Outcome {
    Outcome::Failed(why.to_owned())
}

fn skipped(why: &str) -> Outcome {
    Outcome::Skipped(why.to_owned())
}

// — the baseline —

#[test]
fn every_essential_passing_is_trustworthy_and_nothing_is_outstanding() {
    let verdict = all_essentials_pass();
    assert!(verdict.is_trustworthy());
    assert!(verdict.missing_essentials().is_empty());
    assert!(verdict.unrun_essentials().is_empty());
    assert!(verdict.failures().is_empty());
}

/// An empty verdict must not be trustworthy. It is the state a verifier is in before it has done
/// anything, and the most dangerous default available: a bug that returns early would produce
/// exactly this, and "no checks recorded" reading as "nothing went wrong" is how a verifier comes
/// to approve everything.
#[test]
fn a_verdict_that_checked_nothing_is_not_trustworthy() {
    let verdict = Verdict::new();
    assert!(!verdict.is_trustworthy());
    assert_eq!(verdict.missing_essentials().len(), Check::essential().len());
    assert_eq!(verdict.unrun_essentials().len(), Check::essential().len());
    assert_eq!(Verdict::default(), verdict, "default must not differ");
}

// — the distinction: failed, skipped, absent —

/// **The three states pulled apart.** Each of these makes a verdict untrustworthy, and only the
/// third is "never ran". A check recorded as `Skipped` *was* considered — the verifier reached it
/// and declined, with a reason — which is a different event from one that never appeared at all.
#[test]
fn failed_and_skipped_are_outstanding_but_only_absence_is_unrun() {
    for outcome in [failed("mismatch"), skipped("no reference supplied")] {
        let verdict = essentials_with(Check::MrConfigId, &outcome);

        assert!(
            !verdict.is_trustworthy(),
            "{outcome:?} must not be trustworthy"
        );
        assert_eq!(verdict.missing_essentials(), vec![Check::MrConfigId]);
        assert!(
            verdict.unrun_essentials().is_empty(),
            "{outcome:?} was recorded, so the check ran and was not unrun"
        );
    }
}

/// The case the two accessors exist to separate: a check that produced no record at all.
#[test]
fn a_check_that_never_ran_appears_in_both() {
    let verdict = Check::essential()
        .iter()
        .filter(|c| **c != Check::QuoteSignature)
        .fold(Verdict::new(), |v, c| v.record(*c, Outcome::Passed));

    assert!(!verdict.is_trustworthy());
    assert_eq!(verdict.missing_essentials(), vec![Check::QuoteSignature]);
    assert_eq!(
        verdict.unrun_essentials(),
        vec![Check::QuoteSignature],
        "absence is the one case that is both untrusted and undiagnosed"
    );
    assert!(
        verdict.failures().is_empty(),
        "nothing failed — that is exactly what makes this dangerous"
    );
}

/// **`record` appends; `outcome` reads the first.** So a check recorded twice keeps its original
/// outcome and the second is silently dropped. No live caller does this — `verify` records each
/// check exactly once — but the shape is a footgun worth pinning: a future branch that records a
/// refusal over an earlier pass would have no effect, and nothing would say so.
///
/// This test asserts the behaviour that exists, not the behaviour that is desirable. If the
/// semantics are ever made last-wins, or duplicates rejected outright, this test should change with
/// it — it is here so that change is deliberate rather than accidental.
#[test]
fn recording_a_check_twice_keeps_the_first() {
    let verdict = Verdict::new()
        .record(Check::MrConfigId, Outcome::Passed)
        .record(Check::MrConfigId, failed("this is ignored"));

    assert_eq!(verdict.outcome(Check::MrConfigId), Some(&Outcome::Passed));
    assert_eq!(
        verdict.results().len(),
        2,
        "both are kept in the transcript"
    );
    assert!(
        !verdict.failures().is_empty(),
        "and the failure is still visible to anyone reading failures()"
    );
}

/// Every essential, one at a time, in each of the three states. The exhaustive version of the two
/// tests above: no essential check may be special.
#[test]
fn no_essential_check_can_be_left_out_quietly() {
    for target in Check::essential() {
        // absent
        let verdict = Check::essential()
            .iter()
            .filter(|c| *c != target)
            .fold(Verdict::new(), |v, c| v.record(*c, Outcome::Passed));
        assert!(
            !verdict.is_trustworthy(),
            "{target} absent must not be trustworthy"
        );
        assert_eq!(verdict.unrun_essentials(), vec![*target]);

        // failed, then skipped — outstanding, but not unrun
        for outcome in [failed("no"), skipped("no")] {
            let verdict = essentials_with(*target, &outcome);
            assert!(
                !verdict.is_trustworthy(),
                "{target} {outcome:?} must not be trustworthy"
            );
            assert_eq!(verdict.missing_essentials(), vec![*target]);
            assert!(verdict.unrun_essentials().is_empty());
        }
    }
}

// — TCB status is essential (ADR 0014 decision 2) —

/// **The check ADR 0014 calls mandatory, arriving at the boolean.**
///
/// `verify` records `QuoteSignature: Passed, TcbStatus: Failed` for a genuine quote from a platform
/// whose TCB is unacceptable — deliberately, so "not genuine" stays distinguishable from "genuine
/// but stale". That honesty is only worth anything if the boolean an agent branches on reflects it.
/// While `TcbStatus` sat outside `essential()`, it did not: a real quote from a platform with a
/// known-vulnerable TCB produced `is_trustworthy() == true`, and ADR 0014's "no option, no override"
/// was satisfied in the recording and lost in the summary.
#[test]
fn an_unacceptable_tcb_makes_the_verdict_untrustworthy() {
    let verdict = essentials_with(
        Check::TcbStatus,
        &failed("TCB status SWHardeningNeeded is not accepted"),
    );

    assert!(
        !verdict.is_trustworthy(),
        "a genuine quote from an out-of-date platform is not a trustworthy one"
    );
    assert!(verdict.missing_essentials().contains(&Check::TcbStatus));
}

#[test]
fn tcb_status_is_an_essential_check() {
    assert!(
        Check::essential().contains(&Check::TcbStatus),
        "ADR 0014 decision 2: TCB enforcement is mandatory and not configurable"
    );
}

/// When the signature does not verify, TCB is recorded as skipped — there is nothing to judge. The
/// verdict must be untrustworthy on both counts rather than on one.
#[test]
fn a_bad_signature_takes_the_tcb_check_down_with_it() {
    let verdict = Check::essential().iter().fold(Verdict::new(), |v, c| {
        let o = match *c {
            Check::QuoteSignature => failed("chain did not verify"),
            Check::TcbStatus => skipped("signature did not verify"),
            _ => Outcome::Passed,
        };
        v.record(*c, o)
    });

    assert!(!verdict.is_trustworthy());
    let missing = verdict.missing_essentials();
    assert!(missing.contains(&Check::QuoteSignature));
    assert!(missing.contains(&Check::TcbStatus));
}

// — non-essential checks —

/// `BootMeasurements` is genuinely optional: it compares against a reference the caller supplies,
/// and most callers have none. A verdict without it is still a verdict. This is the line between
/// "optional" and "mandatory", and it is worth a test precisely because `TcbStatus` was on the
/// wrong side of it.
#[test]
fn an_absent_boot_reference_does_not_make_a_verdict_untrustworthy() {
    let verdict = all_essentials_pass().record(
        Check::BootMeasurements,
        skipped("no boot reference supplied"),
    );
    assert!(verdict.is_trustworthy());
    assert!(verdict.unrun_essentials().is_empty());
}

/// But a boot measurement that ran and *failed* is still reported, even though it does not sink the
/// verdict. Silence there would hide a real mismatch.
#[test]
fn a_failed_boot_measurement_is_reported_even_though_it_is_not_essential() {
    let verdict =
        all_essentials_pass().record(Check::BootMeasurements, failed("MRTD did not match"));
    assert_eq!(
        verdict.failures(),
        vec![(Check::BootMeasurements, "MRTD did not match")]
    );
    assert!(
        verdict.is_trustworthy(),
        "not essential, so it does not sink the verdict"
    );
}

// — accessors —

#[test]
fn failures_reports_only_failures_with_their_reasons() {
    let verdict = Verdict::new()
        .record(Check::ComposeHash, Outcome::Passed)
        .record(Check::ImagesPinned, failed("tag-referenced image"))
        .record(Check::LicensedImagePresent, skipped("compose not examined"))
        .record(Check::MrConfigId, failed("prefix byte was 0x02"));

    assert_eq!(
        verdict.failures(),
        vec![
            (Check::ImagesPinned, "tag-referenced image"),
            (Check::MrConfigId, "prefix byte was 0x02"),
        ],
        "passes and skips are not failures, and the reason travels with the check"
    );
}

#[test]
fn outcome_distinguishes_never_considered_from_considered_and_declined() {
    let verdict = Verdict::new().record(Check::ComposeHash, skipped("no compose fetched"));

    assert_eq!(
        verdict.outcome(Check::ComposeHash),
        Some(&skipped("no compose fetched"))
    );
    assert_eq!(
        verdict.outcome(Check::MrConfigId),
        None,
        "None means nothing was recorded — not that the check passed"
    );
}

#[test]
fn results_preserve_the_order_checks_were_performed_in() {
    let verdict = Verdict::new()
        .record(Check::QuoteSignature, Outcome::Passed)
        .record(Check::ComposeHash, Outcome::Passed)
        .record(Check::MrConfigId, Outcome::Passed);

    let order: Vec<Check> = verdict.results().iter().map(|(c, _)| *c).collect();
    assert_eq!(
        order,
        vec![Check::QuoteSignature, Check::ComposeHash, Check::MrConfigId]
    );
}

#[test]
fn outcome_passed_is_true_only_for_passed() {
    assert!(Outcome::Passed.passed());
    assert!(!failed("x").passed());
    assert!(!skipped("x").passed());
}

/// Provenance travels with the verdict, which is the rest of ADR 0014 decision 1: a caller has to
/// be able to see *which* verifier said this and how old its reference data is.
#[test]
fn a_verdict_carries_its_own_provenance() {
    let verdict = Verdict::new();
    assert!(!verdict.verifier_version().is_empty());
    assert!(!verdict.reference_data_date().is_empty());
}

// — rendering —
//
// The `Display` output is what a human sees when a deployment is refused, so it is the difference
// between a debuggable refusal and a mysterious one.

#[test]
fn display_renders_pass_fail_and_skip_as_three_distinct_things() {
    let rendered = Verdict::new()
        .record(Check::ComposeHash, Outcome::Passed)
        .record(Check::ImagesPinned, failed("tag-referenced image"))
        .record(Check::LicensedImagePresent, skipped("compose not examined"))
        .to_string();

    assert!(rendered.contains("pass    compose_hash"));
    assert!(rendered.contains("FAIL    images_pinned: tag-referenced image"));
    assert!(rendered.contains("skipped licensed_image_present: compose not examined"));
    assert!(
        rendered.contains("verity-verifier"),
        "the verifier's own version belongs in anything a human reads"
    );
}

#[test]
fn display_names_what_is_missing_rather_than_only_that_something_is() {
    let rendered = essentials_with(Check::TcbStatus, &failed("out of date")).to_string();

    assert!(rendered.contains("NOT trustworthy"));
    assert!(
        rendered.contains("tcb_status"),
        "a refusal that does not say what failed cannot be acted on"
    );
}

#[test]
fn display_says_trustworthy_only_when_it_is() {
    let rendered = Check::essential()
        .iter()
        .fold(Verdict::new(), |v, c| v.record(*c, Outcome::Passed))
        .to_string();
    assert!(rendered.contains("=> trustworthy"));
    assert!(!rendered.contains("NOT trustworthy"));
}

/// Check names are telemetry identifiers and appear in the alert F-09 raises, so they are an
/// interface: renaming one silently breaks whatever is grouping by it. `Display` must agree with
/// `name`, since the alert and the human-readable output would otherwise diverge.
#[test]
fn check_names_are_stable_identifiers() {
    let expected = [
        (Check::ComposeHash, "compose_hash"),
        (Check::ImagesPinned, "images_pinned"),
        (Check::LicensedImagePresent, "licensed_image_present"),
        (Check::QuoteSignature, "quote_signature"),
        (Check::TcbStatus, "tcb_status"),
        (Check::MrConfigId, "mr_config_id"),
        (Check::BootMeasurements, "boot_measurements"),
    ];
    for (check, name) in expected {
        assert_eq!(check.name(), name);
        assert_eq!(
            check.to_string(),
            name,
            "Display must agree with the telemetry name"
        );
    }
}

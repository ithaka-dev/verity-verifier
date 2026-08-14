//! The runner's transcript is a shell contract, and until now nothing asserted it.
//!
//! # Why this file exists
//!
//! Two scripts in `verity-foundation/closed-loop/` are the **only** end-to-end gates over this
//! crate, and both decide pass or fail by grepping the per-check lines out of
//! `examples/verify-attestation.rs`'s stdout:
//!
//! - `04-refuses-on-mismatch.sh` — deploys a real CVM. Step 3 greps `^  <name> +passed` for each of
//!   the six non-channel essentials, plus `^  channel_bound +skipped`. Step 4 greps
//!   `^  compose_hash +FAILED` **and** `^  mr_config_id +passed` — the second is what makes the
//!   refusal targeted rather than a verifier falling over. Human-only (C5), costs money.
//! - `06-refuses-relayed-endpoint.sh` — the CR-1 red team. Step 3 greps `^  <name> +passed` for the
//!   same six; step 4 greps `^  channel_bound +FAILED`.
//!
//! That list is meant to be **complete**. An incomplete transcription is how the next drift gets
//! missed, since a pattern nobody wrote down here is a pattern nobody checks when the format moves.
//!
//! While that layout was formatted inside an example binary, no test could reach it, so both gates
//! rested on an unasserted `println!`. Worse, `Verdict`'s own `Display` renders the same three
//! outcomes *differently*, so the obvious tidy-up — "why are there two renderers? unify them" —
//! was green in every Rust test and silently broke both gates. That is this project's named failure
//! mode, and it was one plausible refactor away.
//!
//! So the layout moved into the library as [`verity_verifier::verdict::transcript_line`], and this
//! file pins it. The assertions are **literal expected strings**, not only the regexes: a regex
//! test passes on a line that drifted in a way the regex happens to tolerate, and then the *next*
//! drift breaks a gate nobody can run without a CVM.
//!
//! # What this file cannot tell you, and what caught it
//!
//! **A pattern being renderable here does not mean the runner can produce it.** This file exercises
//! `transcript_line` alone, and `transcript_line` will happily render `compose_hash FAILED` for any
//! caller who asks. The first version of `04`'s step-4 assertion grepped for exactly that — and it
//! could never match, because the runner was deriving the licensed hash from the document it was
//! handed, so check 1 compared `sha256(doc)` with `sha256(doc)` and could not fail for any input.
//! Green here, red on a gate that costs money to run.
//!
//! What closed it was `--licensed-compose-hash` on the runner, which gives check 1 a reference from
//! outside the document, plus a transcript line that says so out loud when it is absent. The lesson
//! is recorded rather than only fixed: **the second half of pinning a shell contract is checking
//! that the producer can reach the state the consumer greps for.**
//!
//! **If a test here fails, the fix is almost never to update the expected string.** It is to check
//! whether both closed-loop scripts still work, and to update them in the same change if not.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use verity_verifier::verdict::{transcript_line, Check, Outcome, Verdict};

/// The exact `grep -qE` patterns the two scripts run, transcribed here so a change to the format
/// has to confront them. Kept as strings and matched by hand rather than by a regex dependency —
/// the shapes are `^  <name> <spaces> <label>`, which is two `starts_with` calls.
fn matches_grep(line: &str, name: &str, label: &str) -> bool {
    let Some(rest) = line.strip_prefix("  ") else {
        return false;
    };
    let Some(rest) = rest.strip_prefix(name) else {
        return false;
    };
    let spaces = rest.len() - rest.trim_start_matches(' ').len();
    spaces >= 1 && rest.trim_start_matches(' ').starts_with(label)
}

/// **The contract, byte for byte.**
///
/// Every literal below is what `04` and `06` see on stdout. Padding included: the label column is
/// fixed at 22 because `licensed_image_present` is exactly 22 characters, and the scripts' `+`
/// between name and label depends on at least one space always being there.
#[test]
fn the_runner_transcript_is_a_shell_contract_two_closed_loop_gates_parse() {
    assert_eq!(
        transcript_line(Check::ComposeHash, &Outcome::Passed),
        "  compose_hash           passed"
    );
    assert_eq!(
        transcript_line(
            Check::ChannelBound,
            &Outcome::Failed("channel binding failed: …".to_owned())
        ),
        "  channel_bound          FAILED (channel binding failed: …)"
    );
    assert_eq!(
        transcript_line(
            Check::ChannelBound,
            &Outcome::Skipped("no connection was made".to_owned())
        ),
        "  channel_bound          skipped (no connection was made)"
    );
    // The longest name, which is what sets the column width. One space, and no more.
    assert_eq!(
        transcript_line(Check::LicensedImagePresent, &Outcome::Passed),
        "  licensed_image_present passed"
    );

    // — and the same lines, through the patterns the scripts actually run —

    // 06 step 4: `grep -qE "^  channel_bound +FAILED"`
    assert!(matches_grep(
        &transcript_line(Check::ChannelBound, &Outcome::Failed("relayed".to_owned())),
        "channel_bound",
        "FAILED"
    ));
    // Both scripts' step 3: `grep -qE "^  $check +passed"` for each of the six non-channel
    // essentials. `04` step 3 additionally greps `^  channel_bound +skipped`, and `04` step 4
    // greps `^  mr_config_id +passed` — the same pattern, covered by this loop.
    for check in [
        Check::ComposeHash,
        Check::ImagesPinned,
        Check::LicensedImagePresent,
        Check::QuoteSignature,
        Check::TcbStatus,
        Check::MrConfigId,
    ] {
        assert!(
            matches_grep(
                &transcript_line(check, &Outcome::Passed),
                check.name(),
                "passed"
            ),
            "04 step 3 greps `^  {} +passed`",
            check.name()
        );
    }
    assert!(matches_grep(
        &transcript_line(Check::ChannelBound, &Outcome::Skipped("none".to_owned())),
        "channel_bound",
        "skipped"
    ));
    // 04 step 4: `grep -qE "^  compose_hash +FAILED"`.
    //
    // **Renderable here is not the same as reachable there.** This assertion says the pattern is
    // well formed; what makes it *producible* is `04` passing `--licensed-compose-hash` computed
    // from the untampered document, so that check 1 has a reference from outside the document it is
    // judging. Without that the runner cannot emit this line for any input, and the grep silently
    // becomes an always-fail. See the module header.
    assert!(matches_grep(
        &transcript_line(Check::ComposeHash, &Outcome::Failed("one byte".to_owned())),
        "compose_hash",
        "FAILED"
    ));
}

/// A pass has nothing to explain; the other two carry their reason. Rendering all three the same
/// way would report a *skipped* check as though it had concluded something — the collapse this
/// crate refuses everywhere else, and the distinction F-09's alert is built on.
#[test]
fn a_pass_carries_no_detail_and_the_other_two_do() {
    assert_eq!(Outcome::Passed.label(), "passed");
    assert_eq!(Outcome::Failed(String::new()).label(), "FAILED");
    assert_eq!(Outcome::Skipped(String::new()).label(), "skipped");

    assert!(!transcript_line(Check::TcbStatus, &Outcome::Passed).contains('('));
    assert!(
        transcript_line(Check::TcbStatus, &Outcome::Failed("out of date".to_owned()))
            .contains("(out of date)")
    );
    assert!(transcript_line(
        Check::TcbStatus,
        &Outcome::Skipped("no collateral".to_owned())
    )
    .contains("(no collateral)"));
}

/// **The answer to "why are there two renderers?", written as a test.**
///
/// `Verdict`'s `Display` is for a human reading a refusal: it puts the outcome first so a column of
/// `FAIL` is scannable. `transcript_line` is parsed by two shell scripts and puts the *name* first,
/// because that is what they anchor on. They must not be unified.
///
/// This test exists so that the unification — which is a reasonable-looking cleanup, and which is
/// green in every other Rust test in this repo — fails here instead of failing silently in a gate
/// that needs a live CVM to run.
#[test]
fn the_human_display_and_the_machine_transcript_are_deliberately_different() {
    let human = Verdict::new()
        .record(Check::ComposeHash, Outcome::Passed)
        .to_string();
    let machine = transcript_line(Check::ComposeHash, &Outcome::Passed);

    assert!(
        human.contains("  pass    compose_hash"),
        "the human display leads with the outcome: {human}"
    );
    assert_eq!(machine, "  compose_hash           passed");
    assert!(
        !human.contains(&machine),
        "these two renderings are deliberately different and must stay that way — \
         see this test's doc comment before unifying them"
    );
}

/// The rendering is what the WASM bindings' outcome strings agree with, and what a JavaScript
/// caller sees under a different name. Pinned here so the two surfaces cannot drift into disagreeing
/// about what a skip is called.
#[test]
fn the_labels_match_the_words_the_javascript_bindings_report() {
    // `to_js` maps Passed/Failed/Skipped to "passed"/"failed"/"skipped". Only `FAILED` differs, and
    // it differs in case alone — shouted in a human transcript, lower-case in a JSON field.
    assert_eq!(Outcome::Passed.label(), "passed");
    assert_eq!(Outcome::Skipped(String::new()).label(), "skipped");
    assert_eq!(
        Outcome::Failed(String::new()).label().to_lowercase(),
        "failed"
    );
}

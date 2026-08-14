//! `fixtures/PROVENANCE.md` cites tests by name. This is what keeps those names true.
//!
//! # Why a test for a document
//!
//! `PROVENANCE.md` is the record of where every fixture came from and which test holds each property
//! it claims. Its own opening rule is that a wrong value there is fixed by a new capture, not a
//! patched byte — so a reference that quietly stops pointing at anything is a defect in the record,
//! not a typo.
//!
//! It used to cite tests by ordinal ("test 7"), and two of those references were wrong: one had
//! rotted when a test moved into `src/channel.rs`, the other had never matched. Both were found by a
//! reviewer reading carefully rather than by anything mechanical, which is not a process that scales.
//! A reader who follows a stale reference concludes the property is **untested** — in the crate whose
//! whole job is to be believed about what it checked.
//!
//! Function names fixed the rot in one direction: they are greppable. This test fixes the other,
//! by making the grep run.
//!
//! # What it checks, in both directions
//!
//! For every `(test name, source file)` pair below:
//!
//! 1. the name still appears in `PROVENANCE.md` — so the document cannot be edited to cite something
//!    else while this table still claims it does;
//! 2. the name still exists as a function in the file it is attributed to — so renaming or moving a
//!    test breaks here rather than silently orphaning a sentence.
//!
//! The table itself is the thing under review: adding a citation to `PROVENANCE.md` without adding a
//! row leaves the new one unguarded. That is a genuine limit and it is stated rather than papered
//! over — but a missing row is visible in a diff, and a rotted ordinal never was.

#![allow(clippy::expect_used, clippy::panic)]

const PROVENANCE: &str = include_str!("fixtures/PROVENANCE.md");

const CHANNEL_BINDING: &str = include_str!("channel_binding.rs");
const QUOTE_PARSING: &str = include_str!("quote_parsing.rs");
const CHANNEL_MODULE: &str = include_str!("../src/channel.rs");

/// Every test `PROVENANCE.md` names, and the file that must still define it.
const CITATIONS: &[(&str, &str, &str)] = &[
    (
        "the_extracted_spki_is_a_byte_for_byte_slice_of_the_certificate",
        "tests/channel_binding.rs",
        CHANNEL_BINDING,
    ),
    (
        "the_hardware_verified_commitment_reproduces_exactly",
        "tests/channel_binding.rs",
        CHANNEL_BINDING,
    ),
    (
        "the_gateways_publicly_trusted_certificate_does_not_bind",
        "tests/channel_binding.rs",
        CHANNEL_BINDING,
    ),
    (
        "the_0_5_9_quote_parses_and_carries_a_populated_report_data",
        "tests/quote_parsing.rs",
        QUOTE_PARSING,
    ),
    (
        "deriving_the_tag_from_cert_usage_would_refuse_a_genuine_certificate",
        "src/channel.rs",
        CHANNEL_MODULE,
    ),
];

#[test]
fn every_test_provenance_names_still_exists_where_it_says() {
    for (name, path, source) in CITATIONS {
        assert!(
            PROVENANCE.contains(name),
            "PROVENANCE.md no longer cites `{name}` — either the citation was removed and this \
             row is stale, or it was replaced by something nothing guards"
        );
        assert!(
            source.contains(&format!("fn {name}(")),
            "PROVENANCE.md cites `{name}` in `{path}`, and no such test is defined there. \
             A reader following that reference concludes the property is untested."
        );
    }
}

/// The convention itself, since it is the fix rather than the two instances.
///
/// Ordinal references rot on every insertion and nothing catches them. Prose in the header says so;
/// this makes the prose enforceable for the citation forms actually used — `Test 6`, `test 7`.
#[test]
fn provenance_cites_no_test_by_ordinal() {
    for (line_number, line) in PROVENANCE.lines().enumerate() {
        // The header paragraph explains the rule by quoting the old form, so it is exempt by name.
        if line.contains("never by ordinal") {
            continue;
        }
        let lowered = line.to_lowercase();
        let offending = lowered
            .match_indices("test ")
            .filter(|(i, _)| {
                lowered
                    .get(i + 5..i + 6)
                    .is_some_and(|c| c.chars().all(|c| c.is_ascii_digit()))
            })
            .count();
        assert_eq!(
            offending,
            0,
            "PROVENANCE.md:{} cites a test by ordinal: {line:?}. Use the function name — \
             ordinals rot silently and this file's own rule forbids patching a wrong value.",
            line_number + 1
        );
    }
}

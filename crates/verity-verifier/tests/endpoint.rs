//! Classifying an endpoint before dialling it.
//!
//! The rule under test used to live in `examples/verify-attestation.rs`, where no test could reach
//! it — the same defect `transcript_line` was moved out of the example to fix. Two of the cases
//! below are not hypotheses: the two hosts come from one capture against a live CVM
//! (`tests/fixtures/PROVENANCE.md`), and `ab-80.example.com` is a false positive this heuristic
//! actually produced once.
//!
//! **What is being tested is a diagnostic, not a gate.** The enforcement for every host here is
//! channel binding; the classification only decides whether a refusal names the endpoint form or
//! arrives as a bare hash mismatch. That distinction is worth a test because a bare mismatch on
//! dStack's *advertised* form reads as "the check is too strict", and working that out cost four
//! CVM runs.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use verity_verifier::endpoint::{Endpoint, EndpointError, EndpointForm};

/// The real passthrough host, from `tests/fixtures/PROVENANCE.md`.
const REAL_PASSTHROUGH: &str =
    "https://38817d24b2e3bd9cdeae1acc60aaec7ea0957d18-8443s.dstack-pha-prod5.phala.network";

/// The real terminating host, from the same capture. The two differ by one character.
const REAL_TERMINATING: &str =
    "https://38817d24b2e3bd9cdeae1acc60aaec7ea0957d18-8443.dstack-pha-prod5.phala.network";

#[test]
fn the_real_passthrough_host_classifies_as_passthrough() {
    let endpoint = Endpoint::parse(REAL_PASSTHROUGH).expect("a real captured host");
    assert_eq!(endpoint.form(), EndpointForm::DstackPassthrough);
    assert_eq!(endpoint.port(), 443, "the URL names no port, so 443");
    assert_eq!(
        endpoint.passthrough_form(),
        None,
        "there is no fix to offer for a host that is already the right form"
    );
}

#[test]
fn the_real_terminating_host_classifies_as_terminating() {
    let endpoint = Endpoint::parse(REAL_TERMINATING).expect("a real captured host");
    assert_eq!(endpoint.form(), EndpointForm::DstackTerminating);
}

/// The two forms differ by one character, and that character is the whole routing decision.
///
/// Asserted together rather than only apart: a classifier that returned the same answer for both
/// would pass each of the two tests above on its own if either expectation were ever relaxed.
#[test]
fn the_two_forms_of_the_same_deployment_do_not_classify_alike() {
    let passthrough = Endpoint::parse(REAL_PASSTHROUGH).expect("host");
    let terminating = Endpoint::parse(REAL_TERMINATING).expect("host");
    assert_ne!(
        passthrough.form(),
        terminating.form(),
        "these hosts differ by the `s` that decides whether the gateway terminates TLS; a \
         classifier that cannot tell them apart is not classifying anything"
    );
}

/// The refusal names the fix rather than leaving an operator to infer it.
#[test]
fn the_passthrough_form_is_offered_for_a_terminating_host() {
    let endpoint = Endpoint::parse(REAL_TERMINATING).expect("host");
    assert_eq!(
        endpoint.passthrough_form().as_deref(),
        Some("38817d24b2e3bd9cdeae1acc60aaec7ea0957d18-8443s.dstack-pha-prod5.phala.network"),
        "the suggestion must be the same host with `s` appended to the port label — anything else \
         sends an operator to an endpoint that does not exist"
    );
}

/// **The false positive that was already found once.**
///
/// Accepting "some hex" rather than exactly 40 characters made this host warn. A diagnostic that
/// cries wolf gets ignored on the day it is right, so the length is pinned and this is the test
/// that pins it.
#[test]
fn a_short_label_is_not_mistaken_for_an_app_id() {
    let endpoint = Endpoint::parse("https://ab-80.example.com").expect("host");
    assert_eq!(endpoint.form(), EndpointForm::Unrecognised);
}

/// `06-refuses-relayed-endpoint.sh`'s relay host must stay silent.
///
/// An unrecognised host is permitted and produces no warning — the refusal for a relay comes from
/// channel binding, which is the check that cannot be fooled by a hostname.
#[test]
fn an_unrelated_host_is_unrecognised_and_not_refused() {
    for host in [
        "https://relay.attacker.example",
        "https://example.com",
        "https://127.0.0.1:8443",
        "https://localhost",
    ] {
        let endpoint = Endpoint::parse(host).unwrap_or_else(|e| panic!("{host} should parse: {e}"));
        assert_eq!(
            endpoint.form(),
            EndpointForm::Unrecognised,
            "{host} is not a dStack gateway host and must not be classified as one"
        );
    }
}

/// A 40-hex label whose port part is not digits is still not a gateway host.
///
/// The near-miss that a looser rule would swallow: right app-id shape, wrong port label.
#[test]
fn a_forty_hex_label_with_a_non_numeric_port_is_unrecognised() {
    for host in [
        "https://38817d24b2e3bd9cdeae1acc60aaec7ea0957d18-http.example.com",
        "https://38817d24b2e3bd9cdeae1acc60aaec7ea0957d18-abcs.example.com",
        "https://38817d24b2e3bd9cdeae1acc60aaec7ea0957d18-.example.com",
    ] {
        let endpoint = Endpoint::parse(host).unwrap_or_else(|e| panic!("{host} should parse: {e}"));
        assert_eq!(endpoint.form(), EndpointForm::Unrecognised, "{host}");
    }
}

/// **A plaintext endpoint can never be channel bound, so it is refused rather than upgraded.**
///
/// This is not "a connection that would fail verification"; it is one that cannot be verified,
/// because there is no certificate for the quote to commit to.
#[test]
fn a_plaintext_endpoint_is_refused() {
    let error = Endpoint::parse("http://example.com").expect_err("http can never be bound");
    assert!(matches!(error, EndpointError::NotHttps { ref scheme } if scheme == "http"));
}

#[test]
fn a_url_without_a_scheme_is_refused() {
    let error = Endpoint::parse("example.com:8443").expect_err("no scheme");
    assert!(matches!(error, EndpointError::NotHttps { ref scheme } if scheme.is_empty()));
}

#[test]
fn a_url_with_no_host_is_refused() {
    let error = Endpoint::parse("https:///health").expect_err("no host");
    assert_eq!(error, EndpointError::NoHost);
}

#[test]
fn a_port_that_is_not_a_number_is_refused() {
    let error = Endpoint::parse("https://example.com:https").expect_err("not a port");
    assert!(matches!(error, EndpointError::BadPort { ref port } if port == "https"));
}

/// **Port 0 is refused, and it is a different case from unparseable text.**
///
/// `parse::<u16>()` accepts `0` happily; it means "any free port" when binding and names nothing to
/// connect to. Tested separately because the two live on one source line — so a per-line coverage
/// figure of 100% cannot distinguish "both patterns are exercised" from "only `Err(_)` is", which is
/// the "coverage cannot tell an assertion from a bystander" case `script/mutate.sh` was written for.
/// A refactor back to `parse::<u16>().map_err(..)?` would silently undo the refusal and this is what
/// catches it.
#[test]
fn port_zero_is_refused_even_though_it_parses_as_a_number() {
    let error = Endpoint::parse("https://example.com:0").expect_err("port 0 connects to nothing");
    assert!(
        matches!(error, EndpointError::BadPort { ref port } if port == "0"),
        "expected BadPort for port 0, got {error:?}"
    );
}

/// The boundary either side of the refusal, so "reject 0" cannot drift into "reject small ports".
#[test]
fn the_lowest_and_highest_usable_ports_are_accepted() {
    assert_eq!(
        Endpoint::parse("https://example.com:1")
            .expect("port 1")
            .port(),
        1
    );
    assert_eq!(
        Endpoint::parse("https://example.com:65535")
            .expect("port 65535")
            .port(),
        65535
    );
    assert!(
        Endpoint::parse("https://example.com:65536").is_err(),
        "65536 does not fit in a u16 and must be refused"
    );
}

/// Port, path and query are parsed off the authority rather than folded into the host.
///
/// A host that silently absorbed `/health` would be dialled as a name that does not resolve, and
/// the failure would look like a network problem rather than a parsing one.
#[test]
fn the_authority_is_separated_from_the_path_and_the_port_is_read() {
    let endpoint = Endpoint::parse("https://example.com:8443/health?x=1").expect("host");
    assert_eq!(endpoint.host(), "example.com");
    assert_eq!(endpoint.port(), 8443);
    assert_eq!(endpoint.url(), "https://example.com:8443/health?x=1");
}

/// An endpoint renders as the URL it was given.
///
/// `Display` is what the runners print, so a form that dropped the port or the scheme would make a
/// transcript ambiguous about which endpoint a verdict is about.
#[test]
fn an_endpoint_renders_as_the_url_it_was_parsed_from() {
    let endpoint = Endpoint::parse("  https://example.com:8443/health  ").expect("host");
    assert_eq!(endpoint.to_string(), "https://example.com:8443/health");
}

/// Every error renders something an operator can act on.
///
/// Not a formatting preference: these strings are what a refusal shows, and an error that says only
/// "invalid" sends someone to read source code.
#[test]
fn every_endpoint_error_says_what_was_wrong() {
    let cases = [
        Endpoint::parse("http://example.com").expect_err("http"),
        Endpoint::parse("https:///x").expect_err("no host"),
        Endpoint::parse("https://example.com:nope").expect_err("bad port"),
    ];
    for error in cases {
        let rendered = error.to_string();
        assert!(
            rendered.len() > 10 && !rendered.contains("Error"),
            "unhelpful error text: {rendered}"
        );
    }
}

//! CR-1: is the quote about the connection you are actually using?
//!
//! **What makes this file different from every other test file here.** The rest of the suite proves
//! that the verifier compares the right values. Every one of those comparisons is satisfied by a
//! genuine quote recorded from a CVM that was destroyed on 2026-08-08 — the crate accepts it today,
//! from a file, and that is CR-1 in its purest form: the quote is evidence about a *machine*, not
//! about a *connection*.
//!
//! The artifacts are a matched pair from real TDX. `ratls-leaf-dstack-0.5.9.pem` is the certificate
//! an agent is handed on the passthrough handshake with CVM `9be9f370`;
//! `ratls-leaf-dstack-0.5.9.quote.hex` is the quote carried *inside that certificate*. One artifact
//! read two ways, not two that happen to agree. Provenance, extraction command and the arithmetic
//! that makes the extraction correct are in `fixtures/PROVENANCE.md`.
//!
//! Both negatives are genuine too, and deliberately so. A random self-signed key would prove the
//! comparison rejects noise; these prove it rejects the two things that actually happen — a real
//! enclave's quote presented over somebody else's connection, and dStack's gateway terminating TLS
//! with a certificate that ordinary TLS verification *accepts*.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use verity_verifier::attest::Collateral;
use verity_verifier::binding::ComposeHash;
use verity_verifier::channel::{ChannelBindError, ChannelBinding, PeerCertificate};
use verity_verifier::quote::Quote;
use verity_verifier::verdict::{Check, Disposition, Outcome};
use verity_verifier::verify::{verify, Evidence, LicensedVersion};

// — the matched pair, CVM 9be9f370, dstack-0.5.9, captured 2026-08-09 —
const RATLS_LEAF_PEM: &[u8] = include_bytes!("fixtures/ratls-leaf-dstack-0.5.9.pem");
const RATLS_QUOTE_HEX: &str = include_str!("fixtures/ratls-leaf-dstack-0.5.9.quote.hex");

/// dStack's gateway on the TLS-*terminating* endpoint form. Publicly trusted, in date, issued for
/// the host the client asked for — everything a normal client checks is fine, and the peer is not
/// the enclave.
const GATEWAY_LEAF_PEM: &[u8] = include_bytes!("fixtures/gateway-leaf-letsencrypt.pem");

// — a genuine quote from a different, destroyed CVM (dstack 0.5.7) —
const OTHER_QUOTE_HEX: &str = include_str!("fixtures/quote-v4-dstack-0.5.7.hex");
const OTHER_COMPOSE: &[u8] = include_bytes!("fixtures/app-compose-0.5.7.json");
const OTHER_LICENSED_HASH: &str =
    "64690ef38b54187da11a41a54905f5f539e948a0414ceb312c8036c82f6529fd";
const OTHER_LICENSED_IMAGE: &str =
    "sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc";

/// The commitment this certificate's key produces, verified on hardware from both sides.
///
/// Equal to `spki_commitment` in the source experiment's `provenance.json` **and** to the
/// `report_data` the quote carries. A known-answer test against real TDX: if this constant and the
/// code ever disagree, one of them is wrong and it is not the hardware.
const HARDWARE_COMMITMENT: &str = concat!(
    "d86ffcba38610325b80f6e83121c0b367d907f9d9e6e5002759091133dbf1baf",
    "10796247b4e8695717151e5769c9d542d1c9e1120e5d31bac38914bfe19b439f",
);

fn hex_bytes(hex: &str) -> Vec<u8> {
    let hex = hex.trim();
    (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("fixture is hex"))
        .collect()
}

/// Fixtures are stored as PEM because that is the form an operator captures a certificate in. The
/// library takes DER, so decoding here mirrors what the runner does with `--leaf-cert`.
fn der(pem: &[u8]) -> Vec<u8> {
    let (label, der) = pem_rfc7468::decode_vec(pem).expect("fixture is PEM");
    assert_eq!(label, "CERTIFICATE", "fixture must be a certificate");
    der
}

fn ratls_leaf() -> Vec<u8> {
    der(RATLS_LEAF_PEM)
}

fn ratls_quote() -> Quote {
    Quote::parse(&hex_bytes(RATLS_QUOTE_HEX)).expect("the 0.5.9 fixture parses")
}

fn other_quote() -> Quote {
    Quote::parse(&hex_bytes(OTHER_QUOTE_HEX)).expect("the 0.5.7 fixture parses")
}

// ————————————————————————————————————————————————————————————————————————————
// 1-9: the comparison itself
// ————————————————————————————————————————————————————————————————————————————

/// **The whole scheme, in one assertion, against hardware.**
///
/// `report_data == sha512("ratls-cert:" ‖ SPKI DER)`, computed here from a certificate captured off
/// a live TLS handshake and compared against the quote that certificate carries. Nothing in this is
/// simulated; the constant came off the wire on 2026-08-09.
#[test]
fn the_hardware_verified_commitment_reproduces_exactly() {
    let binding = ChannelBinding::check(&ratls_leaf(), &ratls_quote())
        .expect("the certificate and its own quote must bind");

    assert_eq!(binding.commitment().to_string(), HARDWARE_COMMITMENT);
    assert_eq!(
        binding.commitment().as_bytes()[..],
        ratls_quote().report_data().as_bytes()[..],
        "by construction the commitment equals what the quote carried"
    );
    assert_eq!(
        format!("{:?}", binding.commitment()),
        HARDWARE_COMMITMENT,
        "Debug and Display agree, as they do for Measurement"
    );
}

/// **CR-1 at unit scale.** Two genuine artifacts from two real enclaves, which do not belong
/// together. This is the whole finding: without this comparison the pairing is accepted.
#[test]
fn a_genuine_certificate_from_another_enclave_does_not_bind() {
    match ChannelBinding::check(&ratls_leaf(), &other_quote()) {
        Err(ChannelBindError::Mismatch {
            certificate_commits_to,
            quote_carries,
        }) => {
            assert_eq!(certificate_commits_to.to_string(), HARDWARE_COMMITMENT);
            assert_ne!(quote_carries.to_string(), HARDWARE_COMMITMENT);
        }
        other => panic!("expected a Mismatch, got {other:?}"),
    }
}

/// **The dangerous negative**, and the reason it is a captured certificate rather than a random key.
///
/// dStack's gateway terminates TLS on the endpoint form the platform advertises, handing the client
/// a valid Let's Encrypt certificate for itself. Ordinary TLS verification succeeds. Nothing looks
/// wrong. The peer is the gateway, and the only thing that says so is this comparison.
#[test]
fn the_gateways_publicly_trusted_certificate_does_not_bind() {
    match ChannelBinding::check(&der(GATEWAY_LEAF_PEM), &ratls_quote()) {
        Err(ChannelBindError::Mismatch { .. }) => {}
        other => panic!("expected a Mismatch, got {other:?}"),
    }
}

/// "Committed to nothing" must never match an expectation that is also nothing.
///
/// A workload is free to leave `report_data` empty — a quote requested for some purpose other than
/// RA-TLS carries exactly this. Asserted by *variant*, not merely "an error": a `Mismatch` here
/// would mean the zero-refusal had been reordered after the comparison, which is only safe by
/// accident, and an `Ok` would mean an all-zero commitment had matched.
#[test]
fn an_all_zero_report_data_is_refused_as_a_commitment_to_nothing() {
    let mut bytes = hex_bytes(RATLS_QUOTE_HEX);
    // The TD report begins at 48; `report_data` is at offset 520 within it, 64 bytes long.
    for b in &mut bytes[48 + 520..48 + 584] {
        *b = 0;
    }
    let quote = Quote::parse(&bytes).expect("zeroing report_data leaves the structure intact");
    assert!(quote.report_data().is_zero());

    match ChannelBinding::check(&ratls_leaf(), &quote) {
        Err(ChannelBindError::NoCommitment) => {}
        other => panic!("expected NoCommitment, got {other:?}"),
    }
}

/// A caller cannot act on a refusal that does not say which. "Your input is not a certificate" and
/// "this endpoint is not the one attested" call for opposite responses — one is a mistake to fix,
/// the other is a machine not to talk to.
#[test]
fn bytes_that_are_not_a_certificate_are_a_different_refusal_from_a_mismatch() {
    let quote = ratls_quote();

    for input in [b"not a certificate".as_slice(), &ratls_leaf()[..200], &[]] {
        match ChannelBinding::check(input, &quote) {
            Err(ChannelBindError::UnreadableCertificate { .. }) => {}
            other => panic!("expected UnreadableCertificate for {input:?}, got {other:?}"),
        }
    }

    let unreadable = ChannelBinding::check(b"not a certificate", &quote).unwrap_err();
    let mismatch = ChannelBinding::check(&der(GATEWAY_LEAF_PEM), &quote).unwrap_err();
    assert_ne!(unreadable.to_string(), mismatch.to_string());
}

/// Kills the re-encoding hazard as an **observation** rather than an argument.
///
/// This crate decodes the certificate and re-encodes the `SubjectPublicKeyInfo` before hashing it,
/// while dStack hashed the bytes its own encoder produced. If the two encoders disagreed on a single
/// byte, every genuine certificate would be refused — a failure that looks exactly like an attack.
/// `RustCrypto`'s `der` is a strict DER codec, so the round trip is byte-identical or refused; being
/// a contiguous subslice of the original certificate is what proves that here.
#[test]
fn the_extracted_spki_is_a_byte_for_byte_slice_of_the_certificate() {
    let cert_der = ratls_leaf();
    let binding = ChannelBinding::check(&cert_der, &ratls_quote()).expect("binds");
    let spki = binding.spki_der();

    assert!(!spki.is_empty());
    assert!(
        cert_der.windows(spki.len()).any(|w| w == spki),
        "the re-encoded SPKI is not present verbatim in the certificate it came from"
    );
}

/// **ADR 0009 rule 3, as the one-character edit it would actually be.**
///
/// Nobody deletes this check; they weaken the comparison, and 32 bytes of a SHA-512 looks like
/// plenty to someone in a hurry. Every other negative in this file fails on the *first* byte, so all
/// of them pass against a verifier comparing only a prefix — the mutation harness found exactly that
/// gap, and this test is what closes it.
///
/// Built by flipping one byte in the **tail** of a genuine `report_data`, which is the only input
/// that separates the two implementations: a real prefix collision cannot be constructed, but a
/// quote that agrees for 32 bytes and then diverges is one XOR away.
#[test]
fn a_report_data_that_differs_only_in_its_tail_is_still_a_mismatch() {
    let mut bytes = hex_bytes(RATLS_QUOTE_HEX);
    // The last byte of `report_data`: as far from the start of the comparison as the field goes.
    let last = 48 + 583;
    bytes[last] ^= 0x01;
    let quote =
        Quote::parse(&bytes).expect("flipping a report_data bit leaves the structure valid");

    assert_eq!(
        quote.report_data().as_bytes()[..32],
        hex_bytes(RATLS_QUOTE_HEX)[48 + 520..48 + 552],
        "the first 32 bytes are deliberately unchanged — that is the whole point of this test"
    );
    match ChannelBinding::check(&ratls_leaf(), &quote) {
        Err(ChannelBindError::Mismatch { .. }) => {}
        other => panic!(
            "a one-bit difference in the tail must refuse; a verifier comparing a prefix \
             would return {other:?}"
        ),
    }
}

/// A refusal has to be actionable. Both hex values in the message is what lets an operator tell
/// "wrong endpoint" from "wrong certificate file" without a debugger.
#[test]
fn a_mismatch_names_both_the_commitment_and_what_the_quote_carried() {
    let error = ChannelBinding::check(&ratls_leaf(), &other_quote()).unwrap_err();
    let rendered = error.to_string();

    assert!(rendered.contains(HARDWARE_COMMITMENT), "{rendered}");
    assert!(
        rendered.contains(&other_quote().report_data().to_string()),
        "{rendered}"
    );
}

/// **No prefix of a certificate may trap.**
///
/// This parser eats attacker-influenced bytes in a crate that forbids `unsafe` and refuses to panic.
/// A panic inside an embedder gets wrapped in catch-and-continue by whoever embeds it, which arrives
/// at the same place as loosening a check — and compiled to wasm it is an unrecoverable trap for the
/// JavaScript caller rather than an exception it can catch. Mirrors the bindings' own
/// no-prefix-traps test over quotes.
#[test]
fn no_prefix_of_a_certificate_traps() {
    let cert_der = ratls_leaf();
    let quote = ratls_quote();

    // Every *proper* prefix — the range stops one short of the whole certificate, which is the
    // only length that may bind.
    for len in 0..cert_der.len() {
        assert!(
            ChannelBinding::check(&cert_der[..len], &quote).is_err(),
            "a {len}-byte prefix must not bind"
        );
    }
    assert!(ChannelBinding::check(&cert_der, &quote).is_ok());
}

// ————————————————————————————————————————————————————————————————————————————
// 10-13: through `verify()`, where the verdict is decided
// ————————————————————————————————————————————————————————————————————————————

/// Collateral this crate cannot verify against. Deliberate: these tests are about `ChannelBound`,
/// and `QuoteSignature` needs live Intel collateral no test may depend on.
fn placeholder_collateral() -> Collateral {
    Collateral {
        pck_crl_issuer_chain: String::new(),
        root_ca_crl: Vec::new(),
        pck_crl: Vec::new(),
        tcb_info_issuer_chain: String::new(),
        tcb_info: "{}".to_owned(),
        tcb_info_signature: Vec::new(),
        qe_identity_issuer_chain: String::new(),
        qe_identity: "{}".to_owned(),
        qe_identity_signature: Vec::new(),
        pck_certificate_chain: None,
    }
}

fn other_licensed() -> LicensedVersion {
    LicensedVersion {
        compose_hash: ComposeHash::parse_hex(OTHER_LICENSED_HASH).expect("hash"),
        image_digest: OTHER_LICENSED_IMAGE.to_owned(),
    }
}

/// **Acceptance criterion 1.** A verdict with no connection behind it cannot be trustworthy, and
/// says which of the three reasons applies.
///
/// All three axes matter and they are different questions: the check was *considered* (it has an
/// outcome), it did not *pass* (so it is in `missing_essentials`), and it did not *vanish* (so it is
/// absent from `unrun_essentials`). Collapsing the last two would make "the verifier stopped
/// checking" indistinguishable from "the verifier declined to check", which are opposite situations.
#[test]
fn a_verdict_without_a_connection_is_not_trustworthy_and_says_so() {
    let raw = hex_bytes(OTHER_QUOTE_HEX);
    let collateral = placeholder_collateral();
    let verdict = verify(
        &other_licensed(),
        &Evidence {
            raw_quote: &raw,
            compose_document: OTHER_COMPOSE.to_vec(),
            collateral: &collateral,
            now_secs: 1_800_000_000,
            peer_certificate: PeerCertificate::NotConnected,
        },
        None,
    );

    // T-14 (MA-6). **Not a general guard on this `verify()` call** — `boot: None` above traverses
    // MA-6's own boot-reference conversion site too, but nothing here asserts on `BootMeasurements`,
    // so this test alone would not have caught that conversion breaking. It guards one thing only:
    // that `ChannelBound` on `NotConnected` is *not* swept into `Indeterminate` along with it. **Name
    // the shape of the weakening this forbids**, because "do not weaken this" is satisfied the wrong
    // way by a reader who keeps the three assertions passing while destroying what they check: the
    // weakening is replacing `Some(Outcome::Skipped(why))` below with a wildcard that extracts a
    // detail string from *any* variant — which keeps "considered", "did not pass" and "did not
    // vanish" all green while admitting `Indeterminate` right through the arm meant to exclude it.
    match verdict.outcome(Check::ChannelBound) {
        Some(Outcome::Skipped(why)) => assert!(
            why.contains("no connection was made"),
            "the skip must say why: {why}"
        ),
        other => panic!("channel_bound must be recorded as skipped, was {other:?}"),
    }
    assert!(verdict.missing_essentials().contains(&Check::ChannelBound));
    assert!(
        !verdict.unrun_essentials().contains(&Check::ChannelBound),
        "a declared skip is not a check that vanished"
    );
    assert!(!verdict.is_trustworthy());
    assert_eq!(
        verdict.disposition(Check::ChannelBound),
        Some(Disposition::Refuse),
        "ChannelBound is essential, so a decline still dispositions to Refuse"
    );
}

/// **Acceptance criterion 3, and the property `06` proves end to end.**
///
/// The refusal has to be *targeted*. A verifier that refused everything would also fail this
/// endpoint, and would guarantee nothing — so the configuration checks passing in the same verdict
/// is as much the assertion as `channel_bound` failing.
#[test]
fn a_relayed_certificate_fails_channel_bound_while_the_configuration_checks_still_pass() {
    let raw = hex_bytes(OTHER_QUOTE_HEX);
    let leaf = ratls_leaf();
    let collateral = placeholder_collateral();
    let verdict = verify(
        &other_licensed(),
        &Evidence {
            raw_quote: &raw,
            compose_document: OTHER_COMPOSE.to_vec(),
            collateral: &collateral,
            now_secs: 1_800_000_000,
            peer_certificate: PeerCertificate::Presented(&leaf),
        },
        None,
    );

    match verdict.outcome(Check::ChannelBound) {
        Some(Outcome::Failed(why)) => {
            assert!(why.contains("channel binding failed"), "{why}");
        }
        other => panic!("channel_bound must have failed, was {other:?}"),
    }
    for still_passing in [
        Check::ComposeHash,
        Check::ImagesPinned,
        Check::LicensedImagePresent,
        Check::MrConfigId,
    ] {
        assert_eq!(
            verdict.outcome(still_passing),
            Some(&Outcome::Passed),
            "{still_passing} must still pass — the refusal is targeted, not indiscriminate"
        );
    }
    assert!(!verdict.is_trustworthy());
}

/// **Acceptance criterion 2**, and the only direction that can be got wrong silently.
///
/// **This asserts `ChannelBound` and nothing else, on purpose. Do not "fix" it into a whole-verdict
/// assertion.** No compose document exists for CVM `9be9f370` — we captured a certificate from it,
/// not a deployment — so `compose_hash` cannot pass here, and `quote_signature` cannot pass on
/// placeholder collateral. Widening this test would require inventing evidence, which is the one
/// thing a verifier's test suite must not do.
#[test]
fn the_matching_certificate_passes_channel_bound() {
    let raw = hex_bytes(RATLS_QUOTE_HEX);
    let leaf = ratls_leaf();
    let collateral = placeholder_collateral();
    let verdict = verify(
        &other_licensed(),
        &Evidence {
            raw_quote: &raw,
            compose_document: OTHER_COMPOSE.to_vec(),
            collateral: &collateral,
            now_secs: 1_800_000_000,
            peer_certificate: PeerCertificate::Presented(&leaf),
        },
        None,
    );

    assert_eq!(
        verdict.outcome(Check::ChannelBound),
        Some(&Outcome::Passed),
        "the certificate and the quote it carries came off the same enclave"
    );
}

/// An unparseable quote must *fail* channel binding, not leave it unrun.
///
/// `unrun_essentials` is the alert that a verifier silently stopped checking. A check missing
/// because a prior one failed would fire it for the wrong reason, and an operator would go looking
/// for a regression that is really a malformed input.
#[test]
fn an_unparseable_quote_fails_channel_bound_rather_than_leaving_it_unrun() {
    let leaf = ratls_leaf();
    let collateral = placeholder_collateral();
    let verdict = verify(
        &other_licensed(),
        &Evidence {
            raw_quote: b"not a quote",
            compose_document: OTHER_COMPOSE.to_vec(),
            collateral: &collateral,
            now_secs: 1_800_000_000,
            peer_certificate: PeerCertificate::Presented(&leaf),
        },
        None,
    );

    assert!(matches!(
        verdict.outcome(Check::ChannelBound),
        Some(Outcome::Failed(_))
    ));
    assert!(
        verdict.unrun_essentials().is_empty(),
        "every essential was considered, even though the evidence was unusable"
    );
    assert!(!verdict.is_trustworthy());
}

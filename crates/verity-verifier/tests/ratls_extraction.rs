//! Lifting the quote out of an RA-TLS certificate, checked against hardware rather than against
//! itself.
//!
//! The fixture pair — `ratls-leaf-dstack-0.5.9.pem` and `.quote.hex` — was captured from one live
//! CVM, one boot, one key (`tests/fixtures/PROVENANCE.md`). That is what makes the first test below
//! meaningful: an extractor tested only against an encoding the test itself produced can agree with
//! a broken extractor.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use verity_verifier::ratls::AttestationError;
use verity_verifier::ratls::{attestation_oid, extension_value_for_quote, quote_from_certificate};

const RATLS_LEAF_PEM: &[u8] = include_bytes!("fixtures/ratls-leaf-dstack-0.5.9.pem");
const RATLS_QUOTE_HEX: &str = include_str!("fixtures/ratls-leaf-dstack-0.5.9.quote.hex");
const GATEWAY_LEAF_PEM: &[u8] = include_bytes!("fixtures/gateway-leaf-letsencrypt.pem");

fn der(pem: &[u8]) -> Vec<u8> {
    let (label, der) = pem_rfc7468::decode_vec(pem).expect("fixture is PEM");
    assert_eq!(label, "CERTIFICATE");
    der
}

fn committed_quote() -> Vec<u8> {
    let hex = RATLS_QUOTE_HEX.trim();
    (0..hex.len() / 2)
        .map(|i| {
            u8::from_str_radix(hex.get(i * 2..i * 2 + 2).expect("in range"), 16)
                .expect("fixture is hex")
        })
        .collect()
}

/// **The extractor is correct against hardware, not against itself.**
///
/// Both sides of this comparison were captured from the same CVM: the certificate as served on the
/// passthrough handshake, and the quote as the guest agent reported it. If the extractor's
/// arithmetic were wrong, this would not match.
#[test]
fn the_quote_in_the_fixture_certificate_is_byte_identical_to_the_committed_quote() {
    let extracted = quote_from_certificate(&der(RATLS_LEAF_PEM)).expect("the fixture carries one");
    assert_eq!(
        extracted,
        committed_quote(),
        "the quote read out of the certificate differs from the one the hardware reported for the \
         same boot — do not adjust the offset until you know which side moved"
    );
}

/// What comes out is usable by the rest of the crate, and says what it should about the hardware.
///
/// A byte-identical blob that then failed to parse would mean the fixture pair agreed and neither
/// was a quote.
#[test]
fn the_extracted_quote_parses_as_a_tdx_v4_quote() {
    let extracted = quote_from_certificate(&der(RATLS_LEAF_PEM)).expect("the fixture carries one");
    let quote = verity_verifier::quote::Quote::parse(&extracted)
        .expect("the extracted bytes are a TDX v4 quote");
    assert!(
        !quote.report_data().is_zero(),
        "an RA-TLS quote commits to a certificate; all-zero report_data would mean it committed \
         to nothing"
    );
}

/// No re-encoding: the quote is a contiguous slice of the certificate it came from.
///
/// Mirrors `channel_binding.rs`'s SPKI test. A decode-then-re-encode that happened to round-trip
/// today would be a silent dependency on the codec's canonicalisation staying identical.
#[test]
fn the_extracted_quote_is_a_contiguous_subslice_of_the_certificate() {
    let cert = der(RATLS_LEAF_PEM);
    let extracted = quote_from_certificate(&cert).expect("the fixture carries one");
    assert!(
        cert.windows(extracted.len()).any(|w| w == extracted),
        "the extracted quote is not a slice of the certificate, so something re-encoded it"
    );
}

/// **The documented off-by-4, encoded as a test.**
///
/// X.509's mandatory outer OCTET STRING is stripped by the parser; dStack's value is *itself* an
/// OCTET STRING. Stopping after the outer one yields a buffer that still looks quote-shaped — it is
/// four bytes longer and starts with a DER tag — and would fail later, somewhere less obvious.
#[test]
fn stripping_the_outer_octet_string_only_does_not_yield_a_parseable_quote() {
    let quote = committed_quote();
    // What the extension value looks like before the nested layer is removed.
    let still_wrapped = extension_value_for_quote(&quote).expect("encodes");
    assert!(
        still_wrapped.len() > quote.len(),
        "the nested wrapper adds bytes; if it did not there would be no trap to guard against"
    );
    assert!(
        verity_verifier::quote::Quote::parse(&still_wrapped).is_err(),
        "a singly-unwrapped extension value must not parse as a quote — if it does, the off-by-4 \
         is silent rather than loud, which is the whole reason the strict unwrap exists"
    );
}

/// **The gateway's certificate carries no attestation — a second, independent refusal.**
///
/// This is the real, publicly trusted Let's Encrypt certificate the gateway serves on the
/// TLS-terminating form of a live CVM. It validates perfectly under ordinary TLS. `connect_verified`
/// refuses it twice over: once on hostname classification, and once here — which matters because
/// the classifier is a heuristic and this is not.
#[test]
fn the_gateways_letsencrypt_certificate_carries_no_attestation_extension() {
    let error =
        quote_from_certificate(&der(GATEWAY_LEAF_PEM)).expect_err("the gateway is not an enclave");
    assert_eq!(error, AttestationError::Missing);
}

/// **An envelope change refuses rather than being mis-sliced.**
///
/// `closed-loop/08` scans the extension for the TDX v4 header, which is right for a capture script
/// and wrong for the library: a scan finds a quote-shaped substring at whatever offset it happens
/// to sit. Here the extension holds something that is not a nested OCTET STRING, and the answer is
/// a refusal naming the envelope rather than a plausible-looking slice.
#[test]
fn an_extension_that_is_not_a_nested_octet_string_is_refused_not_scanned() {
    let quote = committed_quote();
    // A hypothetical future envelope: the quote inside some other structure. The bytes of a real
    // quote are in there, so a scanner would find them.
    let mut envelope = vec![0x30, 0x82]; // SEQUENCE, long form — not an OCTET STRING.
    envelope.extend_from_slice(&u16::try_from(quote.len()).unwrap_or(u16::MAX).to_be_bytes());
    envelope.extend_from_slice(&quote);

    let cert = certificate_with_attestation(&envelope);
    let error = quote_from_certificate(&cert).expect_err("an unknown envelope must refuse");
    assert!(
        matches!(error, AttestationError::UnreadableEnvelope { .. }),
        "expected an envelope refusal, got {error:?} — a scan would have returned the quote and \
         hidden the change"
    );
}

#[test]
fn bytes_that_are_not_a_certificate_are_a_different_problem_from_a_missing_extension() {
    let error = quote_from_certificate(b"-----BEGIN CERTIFICATE-----").expect_err("PEM is not DER");
    assert!(
        matches!(error, AttestationError::UnreadableCertificate { .. }),
        "an input problem must not be reported as a statement about the endpoint: {error:?}"
    );
}

/// A certificate this crate generated round-trips through its own extractor.
///
/// The bridge between the hardware fixture above and the locally generated certificates
/// `verified_transport.rs` serves: it establishes that a certificate built with
/// [`extension_value_for_quote`] is read back identically, so a failure over there is about the
/// connection rather than about the test's own encoding.
#[test]
fn a_locally_built_attestation_extension_round_trips() {
    let quote = committed_quote();
    let cert = certificate_with_attestation(&extension_value_for_quote(&quote).expect("encodes"));
    assert_eq!(
        quote_from_certificate(&cert).expect("carries one"),
        quote,
        "a certificate this crate encoded must read back byte-identically, or every locally \
         served certificate in the transport tests is testing the test"
    );
}

#[test]
fn the_attestation_oid_is_the_arc_dstack_uses() {
    assert_eq!(attestation_oid(), "1.3.6.1.4.1.62397.1.1");
}

/// Build a certificate carrying `extn_value` verbatim in dStack's attestation extension.
///
/// `extn_value` is the **already-encoded** extension value, so a test can supply either the correct
/// nested OCTET STRING or a deliberately wrong envelope.
fn certificate_with_attestation(extn_value: &[u8]) -> Vec<u8> {
    let mut params =
        rcgen::CertificateParams::new(vec!["127.0.0.1".to_owned()]).expect("certificate params");
    params.custom_extensions = vec![rcgen::CustomExtension::from_oid_content(
        // 1.3.6.1.4.1.62397.1.1
        &[1, 3, 6, 1, 4, 1, 62397, 1, 1],
        extn_value.to_vec(),
    )];
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("key");
    params
        .self_signed(&key)
        .expect("self-signed")
        .der()
        .to_vec()
}

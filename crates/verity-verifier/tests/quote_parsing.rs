//! Quote parsing against a real TDX quote.
//!
//! The fixture is not synthetic. It was captured from a CVM deployed to Phala Cloud on
//! dstack 0.5.7 and is committed alongside the experiment that produced it, in
//! `verity-foundation/records/experiments/artifacts/`. The `.expected.json` values are what the
//! Cloud API independently reported for the same instance — so these tests reproduce the
//! cross-check that validated the struct offsets in the first place, rather than asserting that
//! the parser agrees with itself.

// Tests assert by panicking; the production lints against it do not apply here.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use verity_verifier::quote::{ParseError, Quote, MEASUREMENT_LEN};

const QUOTE_HEX: &str = include_str!("fixtures/quote-v4-dstack-0.5.7.hex");
const EXPECTED: &str = include_str!("fixtures/quote-v4-dstack-0.5.7.expected.json");

/// Pull a hex string field out of the expected-values fixture without a JSON dependency.
fn expected(field: &str) -> String {
    let needle = format!("\"{field}\":");
    let rest = EXPECTED
        .split_once(&needle)
        .unwrap_or_else(|| panic!("fixture has no field {field}"))
        .1;
    let start = rest.find('"').expect("field value opens with a quote") + 1;
    let end = start
        + rest[start..]
            .find('"')
            .expect("field value closes with a quote");
    rest[start..end].to_owned()
}

fn parsed() -> Quote {
    Quote::parse_hex(QUOTE_HEX).expect("committed fixture is a valid TDX v4 quote")
}

#[test]
fn parses_the_real_quote() {
    let q = parsed();
    assert_eq!(q.version(), 4);
}

#[test]
fn measurements_match_what_the_cloud_api_reported() {
    let q = parsed();
    assert_eq!(q.mrtd().to_string(), expected("mrtd"), "MRTD");
    assert_eq!(q.rtmrs()[0].to_string(), expected("rtmr0"), "RTMR0");
    assert_eq!(q.rtmrs()[1].to_string(), expected("rtmr1"), "RTMR1");
    assert_eq!(q.rtmrs()[2].to_string(), expected("rtmr2"), "RTMR2");
    assert_eq!(q.rtmrs()[3].to_string(), expected("rtmr3"), "RTMR3");
}

/// The measured `MR-CONFIG-ID` is `0x01 ‖ sha256(app-compose.json) ‖ 0x00 × 15`.
///
/// This asserts the layout only. Computing the expected value from a licensed `composeHash` is
/// V-07's job; here we confirm the parser reads the field the reference will be compared against,
/// and that its payload is the same compose hash the platform measured into RTMR3.
#[test]
fn mrconfigid_carries_the_compose_hash() {
    let q = parsed();
    let m = q.mrconfigid().as_bytes();

    assert_eq!(m[0], 0x01, "V1 prefix on dstack 0.5.7");

    let payload = hex(&m[1..33]);
    assert_eq!(
        payload,
        expected("compose_hash_event"),
        "MR-CONFIG-ID payload is the compose-hash measured into RTMR3"
    );

    assert!(
        m[33..].iter().all(|b| *b == 0),
        "V1 pads the remaining 15 bytes with zero"
    );
}

/// Unpopulated fields are all-zero, and that is worth asserting rather than assuming: a reference
/// value someone left empty would compare equal to an unpopulated field.
#[test]
fn mrowner_fields_are_unpopulated_and_detectably_so() {
    let q = parsed();
    assert!(q.mrowner().is_zero());
    assert!(q.mrownerconfig().is_zero());
    assert!(!q.mrtd().is_zero());
}

#[test]
fn rtmr_index_is_bounds_checked() {
    let q = parsed();
    assert!(q.rtmr(3).is_some());
    assert!(q.rtmr(4).is_none(), "there is no RTMR4");
}

// — refusals —
//
// A parser that guesses is worse than one that fails. Each of these must produce an error rather
// than a partially populated Quote.

#[test]
fn refuses_truncated_quote() {
    let bytes = decode(QUOTE_HEX);
    let short = &bytes[..100];
    match Quote::parse(short) {
        Err(ParseError::TooShort { got, need }) => {
            assert_eq!(got, short.len());
            assert!(need > got);
        }
        other => panic!("expected TooShort, got {other:?}"),
    }
}

#[test]
fn refuses_quote_cut_one_byte_short_of_the_report_body() {
    let bytes = decode(QUOTE_HEX);
    let short = &bytes[..48 + 584 - 1];
    assert!(
        matches!(Quote::parse(short), Err(ParseError::TooShort { .. })),
        "a quote one byte short must not parse as a complete one"
    );
}

/// The measured fields sit before the signature section, so a quote whose signature has been
/// stripped still contains everything this parser reads. Refusing it anyway is deliberate: such a
/// quote can never verify, and reporting a successful parse would defer a certain failure.
#[test]
fn refuses_quote_with_signature_section_stripped() {
    let bytes = decode(QUOTE_HEX);
    let measured_only = &bytes[..48 + 584 + 4];
    match Quote::parse(measured_only) {
        Err(ParseError::SignatureTruncated { got, declared }) => {
            assert_eq!(got, measured_only.len());
            assert!(declared > got, "declared length exceeds what was supplied");
        }
        other => panic!("expected SignatureTruncated, got {other:?}"),
    }
}

#[test]
fn refuses_unsupported_version() {
    let mut bytes = decode(QUOTE_HEX);
    bytes[0] = 3;
    assert_eq!(
        Quote::parse(&bytes),
        Err(ParseError::UnsupportedVersion(3)),
        "version must be checked, not assumed"
    );
}

#[test]
fn refuses_non_tdx_tee_type() {
    let mut bytes = decode(QUOTE_HEX);
    bytes[4] = 0x00; // SGX rather than TDX
    match Quote::parse(&bytes) {
        Err(ParseError::NotTdx(t)) => assert_ne!(t, 0x81),
        other => panic!("expected NotTdx, got {other:?}"),
    }
}

#[test]
fn refuses_malformed_hex() {
    assert_eq!(Quote::parse_hex("zzzz"), Err(ParseError::InvalidHex));
    assert_eq!(Quote::parse_hex("abc"), Err(ParseError::InvalidHex));
}

#[test]
fn accepts_0x_prefix() {
    let with_prefix = format!("0x{}", QUOTE_HEX.trim());
    assert!(Quote::parse_hex(&with_prefix).is_ok());
}

// — helpers —

fn decode(hex: &str) -> Vec<u8> {
    let s = hex.trim();
    let s = s.strip_prefix("0x").unwrap_or(s);
    s.as_bytes()
        .chunks_exact(2)
        .map(|c| {
            let hi = char::from(c[0]).to_digit(16).expect("fixture is valid hex");
            let lo = char::from(c[1]).to_digit(16).expect("fixture is valid hex");
            u8::try_from((hi << 4) | lo).expect("nibbles fit in a byte")
        })
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

const _: () = assert!(MEASUREMENT_LEN == 48);

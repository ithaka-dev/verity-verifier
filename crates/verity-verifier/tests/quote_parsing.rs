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

use verity_verifier::quote::{ParseError, Quote, ReportData, MEASUREMENT_LEN, REPORT_DATA_LEN};

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

/// `report_data` is the last 64 bytes of the report body, and the parser must read exactly those.
///
/// The offset is asserted positionally against the raw fixture rather than against a constant the
/// parser also uses — an offset compared with itself agrees no matter how wrong it is. The report
/// body starts at 48 and is 584 long, so the field runs from 48+520 to 48+584.
#[test]
fn report_data_is_read_from_the_end_of_the_report_body() {
    let q = parsed();
    let bytes = decode(QUOTE_HEX);

    assert_eq!(
        hex(q.report_data().as_bytes()),
        hex(&bytes[48 + 520..48 + 584]),
        "report_data must be the final 64 bytes of the TD report body"
    );
}

/// This fixture's quote was issued for a certificate, so its `report_data` carries a key commitment.
///
/// Two separate properties, and the second is the one with teeth. That the field is *populated*
/// matters because an all-zero field would compare equal to an expected value someone left empty,
/// which is how a channel-binding check comes to pass against nothing.
///
/// That the **last 16 bytes** are populated is evidence about the *scheme*: dStack pads a shorter
/// digest into the 64-byte field, so a SHA-384 commitment would leave exactly this tail zero while
/// still satisfying every "is it non-empty" assertion. Checking the whole field for any non-zero
/// byte would have proved nothing beyond the first assertion — the two are the same predicate.
#[test]
fn report_data_is_populated_and_fills_the_whole_field() {
    let q = parsed();
    assert!(
        !q.report_data().is_zero(),
        "a certificate's quote commits to its key; an empty report_data means it did not"
    );
    assert!(
        q.report_data().as_bytes()[48..].iter().any(|b| *b != 0),
        "a 48-byte digest padded into 64 would leave this tail zero; SHA-512 does not"
    );
}

/// A constructed commitment must be comparable to a parsed one.
///
/// This is the whole mechanism of the channel-binding check: one side comes from the quote, the
/// other is computed from the connection's certificate via `from_bytes`. If the two representations
/// did not compare equal the check could never pass, and if they compared equal too readily it
/// could never fail.
#[test]
fn a_constructed_report_data_compares_against_a_parsed_one() {
    let q = parsed();
    let bytes = decode(QUOTE_HEX);

    let expected: [u8; REPORT_DATA_LEN] = bytes[48 + 520..48 + 584]
        .try_into()
        .expect("the slice is exactly 64 bytes");
    assert_eq!(*q.report_data(), ReportData::from_bytes(expected));

    let mut wrong = expected;
    wrong[63] ^= 0xff;
    assert_ne!(
        *q.report_data(),
        ReportData::from_bytes(wrong),
        "a differing commitment must not compare equal"
    );
}

/// An empty commitment must be detectable as empty however it was obtained.
///
/// The channel-binding check has to treat "the enclave committed to nothing" as a refusal to
/// establish the binding. If a caller ever computes an expected value that comes out all-zero, this
/// is the predicate that has to stop the two comparing equal.
#[test]
fn an_all_zero_commitment_is_detectable() {
    assert!(ReportData::from_bytes([0u8; REPORT_DATA_LEN]).is_zero());
    assert!(!parsed().report_data().is_zero());
}

/// The rendering is load-bearing: it is what a refusal prints when a binding fails.
///
/// A mismatch the operator cannot read is a mismatch they will be tempted to dismiss, and the
/// project's standing instruction is never to loosen a check to resolve one.
#[test]
fn report_data_renders_as_lowercase_hex() {
    let q = parsed();
    let shown = q.report_data().to_string();

    assert_eq!(shown.len(), REPORT_DATA_LEN * 2, "two hex digits per byte");
    assert!(
        shown
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "lowercase hex only, so a value can be grepped against a quote dump"
    );
    assert_eq!(
        shown,
        format!("{:?}", q.report_data()),
        "Debug matches Display"
    );
    assert_eq!(shown, hex(q.report_data().as_bytes()));
}

/// A one-byte change to `report_data` must be visible, because that is the granularity an attacker
/// operates at: a relay's key differs from the enclave's, and nothing guarantees the difference is
/// large.
#[test]
fn a_single_byte_change_to_report_data_is_detectable() {
    let mut bytes = decode(QUOTE_HEX);
    let original = Quote::parse(&bytes).expect("fixture parses");

    bytes[48 + 520] ^= 0x01;
    let altered = Quote::parse(&bytes).expect("still structurally valid");

    assert_ne!(
        original.report_data(),
        altered.report_data(),
        "a flipped bit in report_data must change the parsed value"
    );
    assert_eq!(
        original.rtmrs()[3],
        altered.rtmrs()[3],
        "and must not disturb RTMR3, the field immediately before it"
    );
    assert_eq!(original.mrconfigid(), altered.mrconfigid());
}

/// The converse boundary: the byte *before* `report_data` belongs to RTMR3 and must not be read.
///
/// Without this, an off-by-one that started the field a byte early would still pass every test
/// above — the flipped byte would land inside `report_data`, change it, and look correct. Asserting
/// only that the target moves proves the field overlaps the offset, never that it starts there.
#[test]
fn the_byte_before_report_data_belongs_to_rtmr3() {
    let mut bytes = decode(QUOTE_HEX);
    let original = Quote::parse(&bytes).expect("fixture parses");

    bytes[48 + 519] ^= 0x01; // last byte of RTMR3
    let altered = Quote::parse(&bytes).expect("still structurally valid");

    assert_eq!(
        original.report_data(),
        altered.report_data(),
        "report_data must not start one byte early"
    );
    assert_ne!(
        original.rtmrs()[3],
        altered.rtmrs()[3],
        "the flipped byte has to land somewhere, and RTMR3 is where"
    );
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
    use core::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

const _: () = assert!(MEASUREMENT_LEN == 48);

/// An implausible declared signature length is reported as such, not as "too short".
///
/// On 64-bit this specific overflow is unreachable, but `usize` is 32-bit on `wasm32` — a target
/// this crate ships bindings for — so the branch is live there. The test pins the *error
/// semantics* on every target: a length field the parser cannot act on is a distinct defect from
/// a buffer that ran out.
#[test]
fn implausible_signature_length_is_its_own_error() {
    let mut bytes = decode(QUOTE_HEX);
    bytes[48 + 584..48 + 584 + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    match Quote::parse(&bytes) {
        // 64-bit: the addition succeeds, so the buffer is simply short of a colossal declaration.
        Err(ParseError::SignatureTruncated { declared, .. }) => {
            assert!(declared > bytes.len());
        }
        // 32-bit: the addition overflows and the length itself is the defect.
        Err(ParseError::SignatureLengthImplausible { declared }) => {
            assert_eq!(declared, u32::MAX);
        }
        other => panic!("expected a signature-length error, got {other:?}"),
    }
}

// — dstack 0.5.9, a second platform version —

/// The quote carried inside the 0.5.9 RA-TLS leaf certificate. Same CVM, same boot, same key as
/// `fixtures/ratls-leaf-dstack-0.5.9.pem` — see `fixtures/PROVENANCE.md` for the extraction.
const QUOTE_HEX_059: &str = include_str!("fixtures/ratls-leaf-dstack-0.5.9.quote.hex");

/// **A parse regression against a platform version this crate had never seen.**
///
/// Every other quote assertion in this file is about a dstack 0.5.7 capture. The structure is not
/// guaranteed to be stable across guest images — 0.5.7 is no longer offered, and this project has
/// already been caught conflating node runtime, guest image and dstack component versions — so a
/// second version parsing through the same code is worth pinning rather than assuming.
///
/// It parsed unchanged, and **that is the finding**: no parser change was needed and none would
/// have been licensed. Had it failed, the correct response was to stop and report a finding about
/// 0.5.9's quote structure, never to loosen `Quote::parse` until it accepted.
///
/// The `report_data` assertions carry the same weight they do for 0.5.7, and one more: this quote's
/// commitment has been reproduced from the certificate's own public key on real hardware, so the
/// populated tail is evidence the scheme is SHA-512 rather than a shorter digest padded into the
/// field. `tests/channel_binding.rs` does the reproducing.
#[test]
fn the_0_5_9_quote_parses_and_carries_a_populated_report_data() {
    let bytes = decode(QUOTE_HEX_059);
    let q = Quote::parse(&bytes).expect("the 0.5.9 fixture must parse with no parser change");

    assert_eq!(q.version(), 4);
    assert_eq!(
        q.mrconfigid().as_bytes()[0],
        0x01,
        "V1 MR-CONFIG-ID construction, as on 0.5.7 — branch on this byte, never assume it"
    );
    assert_eq!(
        hex(q.report_data().as_bytes()),
        hex(&bytes[48 + 520..48 + 584]),
        "read positionally from the fixture, not from the constant the parser also uses"
    );
    assert!(!q.report_data().is_zero());
    assert!(
        q.report_data().as_bytes()[48..].iter().any(|b| *b != 0),
        "a 48-byte digest padded into 64 would leave this tail zero; SHA-512 does not"
    );
}

// — the field we compare is the field Intel signed —

/// **Closes the last gap between "Intel signed this quote" and "the bytes we compared are in it".**
///
/// `attest.rs` establishes that Intel's chain signs the quote. `channel.rs` compares `report_data`
/// against the connection's certificate. Nothing until now connected the two: this crate reads
/// `report_data` at offset 48+520 with its own hand-written offsets, and if that offset were wrong
/// the channel-binding check would be comparing against 64 bytes of *something else in a genuine,
/// correctly signed quote*. Every test would still pass — the fixture's own bytes are consistent
/// with themselves — and the check would establish nothing.
///
/// So this cross-checks against `dcap-qvl`, which is the crate that verifies the signature and
/// therefore the crate whose idea of "the report body" is the one Intel's signature covers. It
/// decodes structurally, field by field, rather than by literal offsets, so agreement is genuine
/// independent confirmation rather than two copies of the same constant.
///
/// Run over **both** platform versions, because the offset only has to be wrong on one of them.
#[test]
fn report_data_is_the_same_field_the_signature_verifier_reads() {
    for (name, hex_fixture) in [("dstack-0.5.7", QUOTE_HEX), ("dstack-0.5.9", QUOTE_HEX_059)] {
        let bytes = decode(hex_fixture);
        let ours = Quote::parse(&bytes).expect("our parser");
        let theirs = dcap_qvl::quote::Quote::parse(&bytes).expect("dcap-qvl parser");
        let td = theirs
            .report
            .as_td10()
            .expect("both fixtures are TDX 1.0 reports");

        assert_eq!(
            hex(ours.report_data().as_bytes()),
            hex(&td.report_data),
            "{name}: report_data must be the field the signature verifier reads"
        );
        // The same argument for the register the licence binds to, since it is read by the same
        // hand-written offset chain and carries the same consequence if it is off.
        assert_eq!(
            hex(ours.mrconfigid().as_bytes()),
            hex(&td.mr_config_id),
            "{name}: MR-CONFIG-ID must be the field the signature verifier reads"
        );
        assert_eq!(hex(ours.mrtd().as_bytes()), hex(&td.mr_td), "{name}: MRTD");
    }
}

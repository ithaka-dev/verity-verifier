//! The licensed-to-measured binding, against real hardware output.
//!
//! These tests close the chain the whole crate exists to close: a compose document hashes to the
//! value a licence names, and that value reconstructs the `MR-CONFIG-ID` a real TDX CVM measured.
//! Both fixtures came off Phala Cloud on dstack 0.5.7.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use verity_verifier::binding::{
    check_mrconfigid, expected_mrconfigid_v1, ComposeHash, HashParseError, MrConfigIdError,
    MrConfigIdVersion, VerifiedCompose,
};
use verity_verifier::quote::{Measurement, Quote, MEASUREMENT_LEN};

const COMPOSE: &[u8] = include_bytes!("fixtures/app-compose-0.5.7.json");
const QUOTE_HEX: &str = include_str!("fixtures/quote-v4-dstack-0.5.7.hex");
/// The `compose-hash` measured into RTMR3 on real hardware.
const LICENSED: &str = "64690ef38b54187da11a41a54905f5f539e948a0414ceb312c8036c82f6529fd";

fn licensed() -> ComposeHash {
    ComposeHash::parse_hex(LICENSED).expect("fixture hash")
}

// — the chain, end to end —

/// The whole point of the crate, in one test.
///
/// Compose document → its hash → the expected `MR-CONFIG-ID` → what the CVM actually measured.
/// Every link is real: the document is what was deployed, the quote is what the hardware signed.
#[test]
fn licensed_compose_reconstructs_the_measured_mrconfigid() {
    let quote = Quote::parse_hex(QUOTE_HEX).expect("fixture quote");

    // 1. The served document is the licensed one.
    let verified = VerifiedCompose::check(COMPOSE.to_vec(), &licensed()).expect("hash matches");

    // 2. Its hash reconstructs the measurement the hardware produced.
    check_mrconfigid(quote.mrconfigid(), verified.hash())
        .expect("licensed configuration matches what was measured");
}

#[test]
fn compose_hashes_to_the_value_measured_on_hardware() {
    assert_eq!(ComposeHash::of(COMPOSE).to_string(), LICENSED);
}

#[test]
fn expected_measurement_equals_the_one_hardware_produced() {
    let quote = Quote::parse_hex(QUOTE_HEX).expect("quote");
    assert_eq!(&expected_mrconfigid_v1(&licensed()), quote.mrconfigid());
}

// — V-04: unverified bytes are unusable —

/// A tampered document is refused, and the error names both values so the difference is
/// diagnosable rather than merely reported.
#[test]
fn tampered_compose_is_refused() {
    let mut tampered = COMPOSE.to_vec();
    tampered.push(b'\n'); // a single trailing byte

    let err = VerifiedCompose::check(tampered, &licensed()).expect_err("must refuse");
    assert_eq!(err.expected, licensed());
    assert_ne!(err.actual, licensed());
}

/// One flipped bit anywhere must refuse. Hashing makes this certain, but the test states the
/// property the crate depends on rather than assuming the reader knows it.
#[test]
fn single_bit_flip_is_refused() {
    for position in [0usize, COMPOSE.len() / 2, COMPOSE.len() - 1] {
        let mut tampered = COMPOSE.to_vec();
        tampered[position] ^= 0b0000_0001;
        assert!(
            VerifiedCompose::check(tampered, &licensed()).is_err(),
            "a flipped bit at {position} must be refused"
        );
    }
}

#[test]
fn empty_document_is_refused() {
    assert!(VerifiedCompose::check(Vec::new(), &licensed()).is_err());
}

// — V-07: branch on the prefix, never assume —

#[test]
fn recognises_the_v1_prefix() {
    let quote = Quote::parse_hex(QUOTE_HEX).expect("quote");
    assert_eq!(
        MrConfigIdVersion::from_measurement(quote.mrconfigid()),
        Some(MrConfigIdVersion::V1)
    );
}

/// A V2 measurement is recognised and explicitly refused, rather than silently mismatching.
///
/// This is the distinction that matters: an unsupported *format* and a wrong *configuration* look
/// identical if you only compare bytes, and they call for completely different responses — one is
/// upgrade the verifier, the other is do not trust this endpoint.
#[test]
fn v2_is_refused_as_unsupported_not_as_a_mismatch() {
    let mut bytes = [0u8; MEASUREMENT_LEN];
    bytes[0] = 0x02;
    let v2 = Measurement::from_bytes(bytes);

    match check_mrconfigid(&v2, &licensed()) {
        Err(MrConfigIdError::UnsupportedVersion { version }) => {
            assert_eq!(version, MrConfigIdVersion::V2);
        }
        other => panic!("expected UnsupportedVersion, got {other:?}"),
    }
}

/// An unpopulated (all-zero) field must not be mistaken for a valid measurement.
///
/// The simulator's canned quote has exactly this shape, and treating it as V1-with-a-zero-hash
/// would compare successfully against a reference someone also left empty.
#[test]
fn all_zero_measurement_is_refused_as_unknown_version() {
    let zero = Measurement::from_bytes([0u8; MEASUREMENT_LEN]);
    match check_mrconfigid(&zero, &licensed()) {
        Err(MrConfigIdError::UnknownVersion { prefix }) => assert_eq!(prefix, 0),
        other => panic!("expected UnknownVersion, got {other:?}"),
    }
}

#[test]
fn unknown_prefix_is_refused() {
    for prefix in [0x03u8, 0x7f, 0xff] {
        let mut bytes = [0u8; MEASUREMENT_LEN];
        bytes[0] = prefix;
        match check_mrconfigid(&Measurement::from_bytes(bytes), &licensed()) {
            Err(MrConfigIdError::UnknownVersion { prefix: got }) => assert_eq!(got, prefix),
            other => panic!("expected UnknownVersion for 0x{prefix:02x}, got {other:?}"),
        }
    }
}

/// A V1 measurement carrying a different compose hash is a mismatch — the case that means
/// "something else is running".
#[test]
fn wrong_compose_hash_is_a_mismatch() {
    let quote = Quote::parse_hex(QUOTE_HEX).expect("quote");
    let other =
        ComposeHash::parse_hex("0000000000000000000000000000000000000000000000000000000000000001")
            .expect("hash");

    match check_mrconfigid(quote.mrconfigid(), &other) {
        Err(MrConfigIdError::Mismatch { expected, measured }) => {
            assert_ne!(expected, measured);
            assert_eq!(&measured, quote.mrconfigid());
        }
        other => panic!("expected Mismatch, got {other:?}"),
    }
}

#[test]
fn v1_reference_has_the_documented_shape() {
    let m = expected_mrconfigid_v1(&licensed());
    let bytes = m.as_bytes();
    assert_eq!(bytes[0], 0x01, "version prefix");
    assert_eq!(&bytes[1..33], licensed().as_bytes(), "compose hash payload");
    assert!(bytes[33..].iter().all(|b| *b == 0), "zero padding");
}

// — hash parsing —

#[test]
fn parses_with_and_without_prefix() {
    assert_eq!(
        ComposeHash::parse_hex(&format!("0x{LICENSED}")).expect("0x form"),
        licensed()
    );
    assert_eq!(
        ComposeHash::parse_hex(&format!("  {LICENSED}\n")).expect("whitespace"),
        licensed()
    );
}

#[test]
fn refuses_wrong_length_and_non_hex() {
    assert!(matches!(
        ComposeHash::parse_hex("abcd"),
        Err(HashParseError::WrongLength { got: 4 })
    ));
    let non_hex: String = "z".repeat(64);
    assert_eq!(
        ComposeHash::parse_hex(&non_hex),
        Err(HashParseError::NotHex)
    );
}

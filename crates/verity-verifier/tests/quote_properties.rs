//! Property tests for the quote parser.
//!
//! The handbook calls for property-based tests on parsers specifically, and the reason applies
//! sharply here: this parser reads attacker-influenced bytes, and the failure that matters is not
//! a wrong answer but a *confident* one. These properties assert the parser never panics and never
//! succeeds on input it should refuse — across inputs no example test would think to write.
//!
//! # Why `quote.rs` will not reach 100%, and should not be made to
//!
//! Its remaining uncovered regions are the `.map_err(|_| too_short(..))` arms behind each
//! `try_into`. `bytes.get(off..off + N)` yields a slice of exactly `N` bytes whenever it yields
//! anything, so converting it to `[u8; N]` cannot fail — those arms are unreachable by
//! construction, and no input reaches them because none exists.
//!
//! They could be removed, and the number would go up. That would mean editing the parser at the
//! centre of the verifier to satisfy a metric, which is the trade this project has already decided
//! against: coverage is a floor, and the measure of this file is that it refuses everything it
//! should. The tests below were added for the checks they exercise, not for the percentage — and
//! the percentage did not move, which is the honest outcome to record rather than hide.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]

use proptest::prelude::*;
use verity_verifier::quote::{Quote, MEASUREMENT_LEN};

const VALID: &str = include_str!("fixtures/quote-v4-dstack-0.5.7.hex");

/// The shortest prefix of the fixture that parses: header, TD report and the signature-length
/// field, but not the signature payload.
///
/// Determined by probing the parser rather than derived from the spec, so it is a fact about this
/// implementation. That makes it exactly the right thing to pin: if a change moves the boundary,
/// `boundary_is_where_it_is_believed_to_be` fails and says so, rather than the truncation property
/// quietly testing a range that no longer means anything.
const MIN_PARSEABLE: usize = 4940;

fn valid_bytes() -> Vec<u8> {
    let s = VALID.trim();
    s.as_bytes()
        .chunks_exact(2)
        .map(|c| {
            let hi = char::from(c[0]).to_digit(16).unwrap();
            let lo = char::from(c[1]).to_digit(16).unwrap();
            u8::try_from((hi << 4) | lo).unwrap()
        })
        .collect()
}

proptest! {
    /// Arbitrary bytes must never panic the parser.
    ///
    /// A panicking verifier gets wrapped in catch-and-continue by whoever embeds it, which
    /// arrives at the same place as loosening a check.
    #[test]
    fn never_panics_on_arbitrary_input(bytes in prop::collection::vec(any::<u8>(), 0..2048)) {
        let _ = Quote::parse(&bytes);
    }

    /// Arbitrary strings must never panic the hex parser.
    #[test]
    fn never_panics_on_arbitrary_hex(s in ".*") {
        let _ = Quote::parse_hex(&s);
    }

    /// Any prefix of a valid quote that stops short of the declared length must be refused.
    ///
    /// Truncation is the cheapest attack on a length-prefixed format, and the parser must not
    /// treat a partial quote as a whole one.
    ///
    /// The range runs to the real acceptance boundary rather than to 636, where it used to stop.
    /// Everything the parser reads *after* 636 — the signature-length field and all six
    /// measurements — is behind an offset check that only fires when a quote is truncated inside
    /// that particular field, so a range ending early left each of those checks unexercised. They
    /// are the checks standing between a short read and a measurement assembled from whatever
    /// followed in memory.
    #[test]
    fn refuses_every_truncation(cut in 0usize..MIN_PARSEABLE) {
        let bytes = valid_bytes();
        prop_assert!(
            Quote::parse(&bytes[..cut]).is_err(),
            "a quote truncated to {cut} bytes must not parse"
        );
    }

    /// Corrupting the version field always refuses, whatever the value.
    #[test]
    fn refuses_any_version_but_four(v in any::<u16>().prop_filter("not 4", |v| *v != 4)) {
        let mut bytes = valid_bytes();
        bytes[0..2].copy_from_slice(&v.to_le_bytes());
        prop_assert!(Quote::parse(&bytes).is_err(), "version {v} must be refused");
    }

    /// Corrupting the TEE type always refuses, whatever the value.
    #[test]
    fn refuses_any_tee_type_but_tdx(t in any::<u32>().prop_filter("not TDX", |t| *t != 0x81)) {
        let mut bytes = valid_bytes();
        bytes[4..8].copy_from_slice(&t.to_le_bytes());
        prop_assert!(Quote::parse(&bytes).is_err(), "tee_type {t:#x} must be refused");
    }

    /// Parsing is deterministic and free of interior mutation: the same bytes always give the
    /// same measurements.
    #[test]
    fn parsing_is_deterministic(noise in prop::collection::vec(any::<u8>(), 0..64)) {
        let mut bytes = valid_bytes();
        bytes.extend_from_slice(&noise); // trailing bytes beyond the declared length
        let a = Quote::parse(&bytes);
        let b = Quote::parse(&bytes);
        prop_assert_eq!(a, b);
    }
}

// — the boundary itself, and the accessors behind it —

/// Pins the constant the truncation property depends on. One byte below the boundary must refuse
/// and exactly at it must parse: an off-by-one in the other direction would refuse genuine quotes,
/// which fails closed but fails.
#[test]
fn boundary_is_where_it_is_believed_to_be() {
    let bytes = valid_bytes();
    assert!(
        Quote::parse(&bytes[..MIN_PARSEABLE - 1]).is_err(),
        "one byte below the boundary must not parse"
    );
    assert!(
        Quote::parse(&bytes[..MIN_PARSEABLE]).is_ok(),
        "exactly at the boundary must parse"
    );
}

/// A quote truncated *inside* each measurement must be refused, at every byte of every one of
/// them.
///
/// This is the check that stands between a short read and a measurement assembled from whatever
/// happened to follow in the buffer — and a wrong measurement is not a parse failure, it is a
/// verifier comparing the licensed configuration against noise. Each measurement is 48 bytes, so
/// stopping one byte into one is the case that matters.
#[test]
fn a_quote_truncated_inside_a_measurement_is_refused() {
    let bytes = valid_bytes();
    // The measurement block ends at the boundary; walk back across all of it a byte at a time.
    for cut in (MIN_PARSEABLE - 6 * MEASUREMENT_LEN)..MIN_PARSEABLE {
        assert!(
            Quote::parse(&bytes[..cut]).is_err(),
            "truncating mid-measurement at {cut} must not yield a quote"
        );
    }
}

/// Every measurement renders as lowercase hex of exactly the right width, and rendering is
/// injective for the ones that differ.
///
/// These strings are what a human compares when a deployment is refused and what telemetry groups
/// by, so a truncated or upper-case rendering is a real defect even though nothing branches on it.
#[test]
fn measurements_render_as_full_width_lowercase_hex() {
    let quote = Quote::parse(&valid_bytes()).expect("fixture parses");

    let mut all = vec![quote.mrconfigid(), quote.mrtd()];
    for n in 0..4 {
        all.push(
            quote
                .rtmr(n)
                .expect("RTMR0-3 are present in every TDX quote"),
        );
    }
    assert!(
        quote.rtmr(4).is_none(),
        "there are four RTMRs; asking for a fifth must return None rather than the nearest thing"
    );

    for m in all {
        let rendered = m.to_string();
        assert_eq!(
            rendered.len(),
            MEASUREMENT_LEN * 2,
            "a measurement is {MEASUREMENT_LEN} bytes and must render as {} hex digits",
            MEASUREMENT_LEN * 2
        );
        assert!(
            rendered
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "rendered as {rendered}"
        );
    }

    assert_ne!(
        quote.mrtd().to_string(),
        quote.rtmr(0).expect("RTMR0").to_string(),
        "distinct measurements must not render identically"
    );
}

/// `parse_hex` refuses what is not hex, rather than parsing part of it.
///
/// Odd length is the interesting case: a hex string with a byte missing has an obvious "helpful"
/// reading — pad it — and padding a measurement is how a comparison starts succeeding against
/// something nobody supplied.
#[test]
fn hex_parsing_refuses_rather_than_repairs() {
    for bad in ["a", "abc", "zz", "00zz", " 0011", "0011 ", "0x0011"] {
        assert!(
            Quote::parse_hex(bad).is_err(),
            "{bad:?} is not a hex quote and must be refused, not repaired"
        );
    }
}

/// The hex and byte paths must agree. Two entry points that disagreed would let the same quote
/// verify through one and fail through the other.
#[test]
fn hex_and_byte_parsing_agree() {
    let from_bytes = Quote::parse(&valid_bytes()).expect("fixture parses");
    let from_hex = Quote::parse_hex(VALID.trim()).expect("fixture parses as hex");
    assert_eq!(from_bytes, from_hex);
}

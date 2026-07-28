//! Property tests for the quote parser.
//!
//! The handbook calls for property-based tests on parsers specifically, and the reason applies
//! sharply here: this parser reads attacker-influenced bytes, and the failure that matters is not
//! a wrong answer but a *confident* one. These properties assert the parser never panics and never
//! succeeds on input it should refuse — across inputs no example test would think to write.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]

use proptest::prelude::*;
use verity_verifier::quote::Quote;

const VALID: &str = include_str!("fixtures/quote-v4-dstack-0.5.7.hex");

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
    #[test]
    fn refuses_every_truncation(cut in 0usize..636) {
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

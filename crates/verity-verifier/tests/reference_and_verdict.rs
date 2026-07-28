//! Reference data (V-09/V-12) and verdict semantics (V-10/V-11).

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use verity_verifier::quote::Quote;
use verity_verifier::reference::{
    meets_minimum_version, os_image_by_hash, BootError, BootReference, KNOWN_OS_IMAGES,
    REFERENCE_DATA_DATE,
};
use verity_verifier::verdict::{Check, Outcome, Verdict};

const QUOTE_HEX: &str = include_str!("fixtures/quote-v4-dstack-0.5.7.hex");

#[test]
fn known_images_include_the_one_we_measured() {
    let img = os_image_by_hash("761c05d282c81abeae2d1a8f6d5b1e039c8ce14cc95a6da020b9ed2ff1056816")
        .expect("dstack-0.5.7 is known");
    assert_eq!(img.name, "dstack-0.5.7");
    assert!(!img.revoked);
}

#[test]
fn no_bundled_image_is_below_the_spec_minimum() {
    for image in KNOWN_OS_IMAGES {
        assert!(
            meets_minimum_version(image.name),
            "{} is below spec §2.5's 0.5.6 floor and must not be bundled as acceptable",
            image.name
        );
    }
}

#[test]
fn version_floor_rejects_older_and_unparseable() {
    assert!(!meets_minimum_version("dstack-0.5.5"));
    assert!(!meets_minimum_version("dstack-0.5.0"));
    assert!(meets_minimum_version("dstack-0.5.6"));
    assert!(meets_minimum_version("dstack-0.5.10"));
    assert!(meets_minimum_version("dstack-1.0.0"));
    assert!(!meets_minimum_version("not-a-dstack-image"));
    assert!(!meets_minimum_version(""));
}

/// Staleness must be legible. A verdict that cannot say how old its world-view is leaves a caller
/// unable to tell a current verifier from one shipped two years ago.
#[test]
fn reference_data_is_dated() {
    assert_eq!(REFERENCE_DATA_DATE.len(), 10, "YYYY-MM-DD");
    assert!(REFERENCE_DATA_DATE.starts_with("20"));
}

#[test]
fn boot_measurements_match_the_real_quote() {
    let quote = Quote::parse_hex(QUOTE_HEX).expect("quote");
    let reference = BootReference {
        mrtd: Some(*quote.mrtd()),
        rtmr0: Some(quote.rtmrs()[0]),
        rtmr1: Some(quote.rtmrs()[1]),
        rtmr2: Some(quote.rtmrs()[2]),
    };
    verity_verifier::reference::check_boot_measurements(&quote, &reference).expect("match");
}

#[test]
fn a_wrong_boot_measurement_names_the_register() {
    let quote = Quote::parse_hex(QUOTE_HEX).expect("quote");
    let reference = BootReference {
        mrtd: Some(verity_verifier::quote::Measurement::from_bytes([0u8; 48])),
        ..BootReference::default()
    };
    match verity_verifier::reference::check_boot_measurements(&quote, &reference) {
        Err(BootError::Mismatch { register, .. }) => assert_eq!(register, "MRTD"),
        other => panic!("expected a named mismatch, got {other:?}"),
    }
}

/// An absent reference means "do not compare", never "compare against nothing".
#[test]
fn absent_references_are_not_silently_satisfied() {
    let quote = Quote::parse_hex(QUOTE_HEX).expect("quote");
    verity_verifier::reference::check_boot_measurements(&quote, &BootReference::default())
        .expect("no references supplied means nothing to disagree with");
}

// — verdict —

/// Failed and never-run are grouped for trustworthiness on purpose: from the position of deciding
/// whether to trust an endpoint, both answer "you do not know".
#[test]
fn a_skipped_essential_is_as_bad_as_a_failed_one() {
    let skipped = Verdict::new()
        .record(Check::ComposeHash, Outcome::Passed)
        .record(Check::ImagesPinned, Outcome::Passed)
        .record(Check::LicensedImagePresent, Outcome::Passed)
        .record(Check::MrConfigId, Outcome::Passed)
        .record(
            Check::QuoteSignature,
            Outcome::Skipped("not attempted".to_owned()),
        );
    assert!(!skipped.is_trustworthy());
    assert!(skipped
        .missing_essentials()
        .contains(&Check::QuoteSignature));
}

#[test]
fn all_essentials_passing_is_trustworthy() {
    let mut v = Verdict::new();
    for check in Check::essential() {
        v = v.record(*check, Outcome::Passed);
    }
    assert!(v.is_trustworthy());
    assert!(v.missing_essentials().is_empty());
}

/// Boot measurements are not essential — a caller may legitimately not know which OS image to
/// expect — but every check that establishes the licensed configuration is.
#[test]
fn essentials_are_the_checks_without_which_a_verdict_is_meaningless() {
    let essential = Check::essential();
    for required in [
        Check::ComposeHash,
        Check::ImagesPinned,
        Check::LicensedImagePresent,
        Check::QuoteSignature,
        Check::MrConfigId,
    ] {
        assert!(
            essential.contains(&required),
            "{required} must be essential"
        );
    }
    assert!(!essential.contains(&Check::BootMeasurements));
}

#[test]
fn verdict_display_names_failures() {
    let v = Verdict::new().record(Check::MrConfigId, Outcome::Failed("mismatch".to_owned()));
    let text = v.to_string();
    assert!(text.contains("FAIL"));
    assert!(text.contains("mr_config_id"));
    assert!(text.contains("NOT trustworthy"));
}

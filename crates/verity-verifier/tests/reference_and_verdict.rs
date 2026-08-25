//! Reference data (V-09/V-12) and verdict semantics (V-10/V-11).

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use verity_verifier::attest::Collateral;
use verity_verifier::binding::ComposeHash;
use verity_verifier::channel::PeerCertificate;
use verity_verifier::quote::Quote;
use verity_verifier::reference::{
    meets_minimum_version, os_image_by_hash, BootError, BootReference, KNOWN_OS_IMAGES,
    REFERENCE_DATA_DATE,
};
use verity_verifier::verdict::{Check, Disposition, Outcome, Unestablished, Verdict};
use verity_verifier::verify::{verify, Evidence, LicensedVersion};

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
        Check::TcbStatus,
        Check::MrConfigId,
        // CR-1's check, and the one this list existed without. Covered behaviourally elsewhere
        // (`channel_binding.rs`, and a mutant that drops it from `essential()`), but this file's
        // whole job is to pin essentiality against a list written out by hand — so an omission here
        // is the omission that matters.
        Check::ChannelBound,
    ] {
        assert!(
            essential.contains(&required),
            "{required} must be essential"
        );
    }
    assert!(!essential.contains(&Check::BootMeasurements));
}

// — MA-6: T-9, driven through `verify()` rather than constructed by hand —
//
// `verdict_semantics.rs`'s boot-reference tests build the outcome directly and never call
// `verify()`, so nothing exercised the conversion at `verify.rs:201-204` before this. Reverting that
// site back to `Outcome::Skipped` turns this test red; the hand-built tests above stay green either
// way, which is exactly the hole this test exists to close.

const T9_COMPOSE: &[u8] = include_bytes!("fixtures/app-compose-0.5.7.json");
const T9_QUOTE_HEX: &str = include_str!("fixtures/quote-v4-dstack-0.5.7.hex");
const T9_LICENSED_HASH: &str = "64690ef38b54187da11a41a54905f5f539e948a0414ceb312c8036c82f6529fd";
const T9_LICENSED_IMAGE: &str =
    "sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc";

fn t9_quote_bytes() -> Vec<u8> {
    let hex = T9_QUOTE_HEX.trim();
    (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("fixture is hex"))
        .collect()
}

fn t9_collateral() -> Collateral {
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

/// T-9: `verify()` called with `boot: None` records `BootMeasurements` as `Indeterminate {
/// ReferenceUnavailable }`, dispositioning to `UpdateReference` — and the verdict is still
/// trustworthy, because `BootMeasurements` is not promoted to essential by this change.
#[test]
fn verify_with_no_boot_reference_records_indeterminate_reference_unavailable() {
    let licensed = LicensedVersion {
        compose_hash: ComposeHash::parse_hex(T9_LICENSED_HASH).expect("hash"),
        image_digest: T9_LICENSED_IMAGE.to_owned(),
    };
    let collateral = t9_collateral();
    let quote = t9_quote_bytes();

    let verdict = verify(
        &licensed,
        &Evidence {
            raw_quote: &quote,
            compose_document: T9_COMPOSE.to_vec(),
            collateral: &collateral,
            now_secs: 1_800_000_000,
            peer_certificate: PeerCertificate::NotConnected,
        },
        None,
    );

    match verdict.outcome(Check::BootMeasurements) {
        Some(Outcome::Indeterminate { cause, detail }) => {
            assert_eq!(*cause, Unestablished::ReferenceUnavailable);
            assert_eq!(detail, "no OS image reference supplied");
        }
        other => panic!("expected Indeterminate, got {other:?}"),
    }
    assert_eq!(
        verdict.disposition(Check::BootMeasurements),
        Some(Disposition::UpdateReference)
    );
    assert!(
        !verdict
            .missing_essentials()
            .contains(&Check::BootMeasurements),
        "BootMeasurements is not essential; this change does not promote it"
    );
}

#[test]
fn verdict_display_names_failures() {
    let v = Verdict::new().record(Check::MrConfigId, Outcome::Failed("mismatch".to_owned()));
    let text = v.to_string();
    assert!(text.contains("FAIL"));
    assert!(text.contains("mr_config_id"));
    assert!(text.contains("NOT trustworthy"));
}

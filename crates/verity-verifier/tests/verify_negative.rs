//! V-13: the negative suite.
//!
//! **This file carries the weight of the crate.** [ADR 0009] guarantees spurious mismatches —
//! `mr-kms` varies per boot — and the tempting response is to loosen a check until CI goes green.
//! These tests are what makes loosening fail loudly here rather than quietly in production.
//!
//! Every case asserts the *specific* refusal, not merely that something was refused. A test that
//! accepts any error would pass against a verifier that had stopped checking entirely.
//!
//! [ADR 0009]: https://github.com/ithaka-dev/verity-foundation/blob/main/docs/decisions/0009-verification-model.md

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use verity_verifier::attest::{Collateral, TcbPolicy};
use verity_verifier::binding::ComposeHash;
use verity_verifier::channel::PeerCertificate;
use verity_verifier::quote::Quote;
use verity_verifier::reference::BootReference;
use verity_verifier::verdict::{Check, Disposition, Outcome, Unestablished};
use verity_verifier::verify::{verify, Evidence, LicensedVersion};

const COMPOSE: &[u8] = include_bytes!("fixtures/app-compose-0.5.7.json");
const QUOTE_HEX: &str = include_str!("fixtures/quote-v4-dstack-0.5.7.hex");
const LICENSED_HASH: &str = "64690ef38b54187da11a41a54905f5f539e948a0414ceb312c8036c82f6529fd";
const LICENSED_IMAGE: &str =
    "sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc";

fn quote_bytes() -> Vec<u8> {
    let s = QUOTE_HEX.trim();
    s.as_bytes()
        .chunks_exact(2)
        .map(|c| {
            let hi = char::from(c[0]).to_digit(16).expect("hex");
            let lo = char::from(c[1]).to_digit(16).expect("hex");
            u8::try_from((hi << 4) | lo).expect("byte")
        })
        .collect()
}

fn collateral() -> Collateral {
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

fn licensed() -> LicensedVersion {
    LicensedVersion {
        compose_hash: ComposeHash::parse_hex(LICENSED_HASH).expect("hash"),
        image_digest: LICENSED_IMAGE.to_owned(),
    }
}

fn evidence(quote: Vec<u8>, compose: Vec<u8>) -> (Vec<u8>, Vec<u8>) {
    (quote, compose)
}

macro_rules! run {
    ($quote:expr, $compose:expr, $licensed:expr) => {{
        let c = collateral();
        let (q, comp) = evidence($quote, $compose);
        verify(
            &$licensed,
            &Evidence {
                raw_quote: &q,
                compose_document: comp,
                collateral: &c,
                now_secs: 1_800_000_000,
                // These are refusals about *configuration*, established from recorded evidence with
                // no connection behind it. `NotConnected` is the honest input, and it means every
                // verdict here is untrustworthy twice over — which is fine, because each test
                // asserts the specific check it is about rather than the boolean. Channel binding
                // has its own file, `tests/channel_binding.rs`.
                peer_certificate: PeerCertificate::NotConnected,
            },
            None,
            &TcbPolicy::default(),
        )
    }};
}

// — the compose is not the licensed one —

#[test]
fn tampered_compose_fails_the_hash_check_and_skips_its_contents() {
    let mut tampered = COMPOSE.to_vec();
    tampered.push(b' ');
    let v = run!(quote_bytes(), tampered, licensed());

    assert!(matches!(
        v.outcome(Check::ComposeHash),
        Some(Outcome::Failed(_))
    ));
    // Contents must not be examined: they belong to a document nobody licensed.
    assert!(matches!(
        v.outcome(Check::ImagesPinned),
        Some(Outcome::Skipped(_))
    ));
    assert!(!v.is_trustworthy());
}

// — I8: a tag anywhere —

#[test]
fn tagged_image_fails_pinning_even_when_the_hash_matches() {
    let yaml = "services:\n  app:\n    image: alpine:latest\n";
    let doc = serde_json::to_vec(&serde_json::json!({
        "manifest_version": 2, "runner": "docker-compose", "docker_compose_file": yaml,
    }))
    .expect("json");
    // Licence the tampered document, so the hash check passes and pinning is what must catch it.
    let lic = LicensedVersion {
        compose_hash: ComposeHash::of(&doc),
        image_digest: LICENSED_IMAGE.to_owned(),
    };
    let v = run!(quote_bytes(), doc, lic);

    assert!(matches!(
        v.outcome(Check::ComposeHash),
        Some(Outcome::Passed)
    ));
    assert!(matches!(
        v.outcome(Check::ImagesPinned),
        Some(Outcome::Failed(_))
    ));
    assert!(!v.is_trustworthy(), "a tag must sink the verdict");
}

/// A correctly pinned image that is not the licensed one.
#[test]
fn wrong_pinned_image_fails_the_cross_check() {
    let other = format!("sha256:{}", "b".repeat(64));
    let yaml = format!("services:\n  app:\n    image: alpine@{other}\n");
    let doc = serde_json::to_vec(&serde_json::json!({
        "manifest_version": 2, "runner": "docker-compose", "docker_compose_file": yaml,
    }))
    .expect("json");
    let lic = LicensedVersion {
        compose_hash: ComposeHash::of(&doc),
        image_digest: LICENSED_IMAGE.to_owned(),
    };
    let v = run!(quote_bytes(), doc, lic);

    assert!(matches!(
        v.outcome(Check::ImagesPinned),
        Some(Outcome::Passed)
    ));
    assert!(matches!(
        v.outcome(Check::LicensedImagePresent),
        Some(Outcome::Failed(_))
    ));
    assert!(!v.is_trustworthy());
}

// — the measurement does not match —

#[test]
fn licensing_a_different_configuration_fails_mrconfigid() {
    let lic = LicensedVersion {
        compose_hash: ComposeHash::of(b"a different configuration entirely"),
        image_digest: LICENSED_IMAGE.to_owned(),
    };
    let v = run!(quote_bytes(), COMPOSE.to_vec(), lic);
    assert!(matches!(
        v.outcome(Check::MrConfigId),
        Some(Outcome::Failed(_))
    ));
}

// — the quote itself —

#[test]
fn garbage_quote_fails_signature_and_mrconfigid() {
    let v = run!(vec![0u8; 700], COMPOSE.to_vec(), licensed());
    assert!(matches!(
        v.outcome(Check::QuoteSignature),
        Some(Outcome::Failed(_))
    ));
    assert!(matches!(
        v.outcome(Check::MrConfigId),
        Some(Outcome::Failed(_))
    ));
    assert!(!v.is_trustworthy());
}

/// T-15: on an unparseable quote, `BootMeasurements` stays `Skipped` — moot, because `MrConfigId`
/// already refused for the exact same reason — while `ChannelBound` is `Failed` — a refusal in its
/// own right, since the evidence itself is unusable rather than merely absent. Both in the same
/// verdict. Nearly free: `garbage_quote_fails_signature_and_mrconfigid` above already reaches this
/// state and asserted neither outcome before this change.
#[test]
fn garbage_quote_leaves_boot_measurements_skipped_and_channel_bound_failed() {
    let v = run!(vec![0u8; 700], COMPOSE.to_vec(), licensed());

    match v.outcome(Check::BootMeasurements) {
        Some(Outcome::Skipped(why)) => assert!(
            why.contains("quote could not be parsed"),
            "boot_measurements must name why it was skipped, was {why:?}"
        ),
        other => panic!("expected Skipped, got {other:?}"),
    }
    match v.outcome(Check::ChannelBound) {
        Some(Outcome::Failed(why)) => assert!(
            why.contains("quote could not be parsed"),
            "channel_bound must name why it failed, was {why:?}"
        ),
        other => panic!("expected Failed, got {other:?}"),
    }
}

// — MR-CONFIG-ID version boundary (§6b) —

/// T-17: a recognised-but-unsupported `MR-CONFIG-ID` construction (V2) is `Indeterminate`, not
/// `Failed` — this verifier's own limitation, with a named remedy: run a build that supports it.
#[test]
fn mrconfigid_v2_is_indeterminate_and_updates_the_verifier() {
    let mut q = quote_bytes();
    // MR-CONFIG-ID sits at 48 + 184 within the quote (`quote.rs`'s `HEADER_LEN` +
    // `OFF_MRCONFIGID`, the same "48 +" convention `rtmr3_drift_is_tolerated` above uses); only
    // the prefix byte decides which construction `MrConfigIdVersion::from_measurement`
    // recognises.
    q[48 + 184] = 0x02;
    let v = run!(q, COMPOSE.to_vec(), licensed());

    match v.outcome(Check::MrConfigId) {
        Some(Outcome::Indeterminate { cause, .. }) => {
            assert_eq!(*cause, Unestablished::VerifierCannotJudge);
        }
        other => panic!("expected Indeterminate, got {other:?}"),
    }
    assert_eq!(
        v.disposition(Check::MrConfigId),
        Some(Disposition::UpdateVerifier)
    );
    assert!(!v.is_trustworthy());
}

/// T-17's boundary: an unrecognised prefix — **including all-zero, what an unpopulated field looks
/// like** — stays `Failed`, not `Indeterminate`. Drawing this the other way would let evidence
/// nobody can account for disposition to "update your verifier"; the facilitator asked that this
/// boundary not move on symmetry grounds with the case above.
#[test]
fn mrconfigid_unrecognised_prefix_including_all_zero_stays_failed() {
    let mut q = quote_bytes();
    q[48 + 184] = 0x00;
    let v = run!(q, COMPOSE.to_vec(), licensed());

    assert!(matches!(
        v.outcome(Check::MrConfigId),
        Some(Outcome::Failed(_))
    ));
    assert_eq!(v.disposition(Check::MrConfigId), Some(Disposition::Refuse));
    assert!(!v.is_trustworthy());
}

#[test]
fn truncated_quote_is_refused() {
    let mut q = quote_bytes();
    q.truncate(100);
    let v = run!(q, COMPOSE.to_vec(), licensed());
    assert!(!v.is_trustworthy());
}

// — RTMR3 must NOT be compared: the one case that must PASS —

/// `mr-kms` varies per boot, so `RTMR3` differs between two runs of the same configuration.
/// A verifier comparing it would produce intermittent false refusals — and the fix somebody
/// reaches for is loosening a check that should not move.
///
/// This test asserts `RTMR3` drift is tolerated. It is the reason the boot reference type has no
/// field for it: leaving it out of the type is stronger than documenting that it should be skipped.
#[test]
fn rtmr3_drift_is_tolerated() {
    let mut drifted = quote_bytes();
    // RTMR3 sits at 48 + 472 within the quote.
    let off = 48 + 472;
    drifted[off] ^= 0xff;
    drifted[off + 1] ^= 0xff;

    let quote = Quote::parse(&drifted).expect("still a valid quote");
    let reference = BootReference {
        mrtd: Some(*quote.mrtd()),
        rtmr0: Some(quote.rtmrs()[0]),
        rtmr1: Some(quote.rtmrs()[1]),
        rtmr2: Some(quote.rtmrs()[2]),
    };
    verity_verifier::reference::check_boot_measurements(&quote, &reference)
        .expect("RTMR3 drift must not fail boot verification");
}

/// A `BootReference` cannot express RTMR3 at all. Compile-time proof, not a promise.
#[test]
fn boot_reference_has_no_rtmr3_field() {
    let r = BootReference::default();
    assert!(r.mrtd.is_none() && r.rtmr0.is_none() && r.rtmr1.is_none() && r.rtmr2.is_none());
}

// — the verdict itself —

/// A verdict must never claim more than it checked.
#[test]
fn skipped_essentials_are_not_trustworthy() {
    let v = run!(quote_bytes(), COMPOSE.to_vec(), licensed());
    // Signature cannot pass with placeholder collateral, so this must not be trustworthy —
    // whatever else passed.
    assert!(!v.is_trustworthy());
    assert!(v.missing_essentials().contains(&Check::QuoteSignature));
}

#[test]
fn verdict_reports_which_checks_ran() {
    let v = run!(quote_bytes(), COMPOSE.to_vec(), licensed());
    // Provenance is present and the report is not a bare boolean.
    assert!(!v.verifier_version().is_empty());
    assert!(!v.reference_data_date().is_empty());
    assert!(v.results().len() >= 6, "every check must be accounted for");
    assert!(v.to_string().contains("mr_config_id"));
}

/// The checks that *do* pass with a real compose and real quote still pass — otherwise the
/// negative tests above would be passing for the wrong reason.
#[test]
fn control_the_genuine_parts_still_pass() {
    let v = run!(quote_bytes(), COMPOSE.to_vec(), licensed());
    assert!(matches!(
        v.outcome(Check::ComposeHash),
        Some(Outcome::Passed)
    ));
    assert!(matches!(
        v.outcome(Check::ImagesPinned),
        Some(Outcome::Passed)
    ));
    assert!(matches!(
        v.outcome(Check::LicensedImagePresent),
        Some(Outcome::Passed)
    ));
    assert!(matches!(
        v.outcome(Check::MrConfigId),
        Some(Outcome::Passed)
    ));
}

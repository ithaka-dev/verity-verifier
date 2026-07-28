//! The bindings must agree with the core crate, including on version.

#![allow(clippy::expect_used, clippy::panic)]

use verity_verifier_wasm as bindings;

const COMPOSE: &[u8] =
    include_bytes!("../../verity-verifier/tests/fixtures/app-compose-0.5.7.json");
const LICENSED_HASH: &str = "64690ef38b54187da11a41a54905f5f539e948a0414ceb312c8036c82f6529fd";
const LICENSED_IMAGE: &str =
    "sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc";

/// ADR 0012: every distribution surface reports the same version.
///
/// A binding reporting a different version from the code it wraps makes "which verifier produced
/// this verdict?" unanswerable — the question ADR 0014 exists to keep answerable.
#[test]
fn version_matches_the_core_crate() {
    assert_eq!(
        bindings::verifier_version(),
        verity_verifier::verdict::VERIFIER_VERSION
    );
    assert_eq!(
        bindings::reference_data_date(),
        verity_verifier::reference::REFERENCE_DATA_DATE
    );
}

#[test]
fn compose_hash_agrees_with_the_core_crate() {
    assert_eq!(bindings::compose_hash(COMPOSE), LICENSED_HASH);
}

#[test]
fn image_check_agrees_with_the_core_crate() {
    assert!(bindings::check_images(COMPOSE, LICENSED_IMAGE).is_none());
    let wrong = format!("sha256:{}", "0".repeat(64));
    assert!(bindings::check_images(COMPOSE, &wrong).is_some());
}

/// A tagged image must be refused through the bindings exactly as through Rust. A binding laxer
/// than the core would be the easiest way to obtain a weakened verifier.
#[test]
fn bindings_are_not_laxer_than_the_core() {
    let tagged = serde_json::to_vec(&serde_json::json!({
        "manifest_version": 2,
        "runner": "docker-compose",
        "docker_compose_file": "services:\n  app:\n    image: alpine:latest\n",
    }))
    .expect("json");
    assert!(bindings::check_images(&tagged, LICENSED_IMAGE).is_some());
}

#[test]
fn malformed_quote_yields_no_measurement() {
    assert!(bindings::quote_mrconfigid(&[0u8; 16]).is_none());
}

#[test]
fn mrconfigid_check_refuses_a_malformed_hash() {
    assert!(bindings::check_mrconfigid(&[0u8; 700], "not-a-hash").is_some());
}

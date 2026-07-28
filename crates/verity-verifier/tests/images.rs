//! Digest-pinning (I8) and the compose ↔ imageDigest cross-check.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use verity_verifier::images::{check_references_licensed_digest, pinned_images, ImageError};

const COMPOSE: &[u8] = include_bytes!("fixtures/app-compose-0.5.7.json");
/// The digest the real fixture pins.
const LICENSED_DIGEST: &str =
    "sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc";

/// Build a compose document around an arbitrary docker-compose YAML body.
fn compose_with(yaml: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "manifest_version": 2,
        "name": "test",
        "runner": "docker-compose",
        "docker_compose_file": yaml,
    }))
    .expect("json")
}

// — the real fixture —

#[test]
fn real_compose_is_digest_pinned() {
    let images = pinned_images(COMPOSE).expect("fixture is pinned");
    assert_eq!(images.len(), 1);
    assert_eq!(images[0].digest(), LICENSED_DIGEST);
}

#[test]
fn real_compose_references_the_licensed_digest() {
    check_references_licensed_digest(COMPOSE, LICENSED_DIGEST).expect("cross-check passes");
}

#[test]
fn cross_check_fails_for_a_different_digest() {
    let other = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
    match check_references_licensed_digest(COMPOSE, other) {
        Err(ImageError::LicensedDigestAbsent { licensed }) => assert_eq!(licensed, other),
        other => panic!("expected LicensedDigestAbsent, got {other:?}"),
    }
}

// — I8: tags are refused, in every shape they take —

#[test]
fn refuses_bare_repository_reference() {
    // The shape dStack's own reference compose uses.
    let c = compose_with("services:\n  app:\n    image: quay.io/jupyter/base-notebook\n");
    assert!(matches!(
        pinned_images(&c),
        Err(ImageError::NotPinned { .. })
    ));
}

#[test]
fn refuses_explicit_tag() {
    for tag in ["alpine:3.20", "alpine:latest", "registry.io/org/app:v1.2.3"] {
        let c = compose_with(&format!("services:\n  app:\n    image: {tag}\n"));
        assert!(
            matches!(pinned_images(&c), Err(ImageError::NotPinned { .. })),
            "{tag} must be refused"
        );
    }
}

/// A truncated or malformed digest is not a weaker pin — it is not a pin.
#[test]
fn refuses_malformed_digests() {
    let bad = [
        "alpine@sha256:abc",                                   // too short
        "alpine@md5:d9e853e87e55526f6b2917df91a2115c36dd7c69", // wrong algorithm
        &format!("alpine@sha256:{}", "z".repeat(64)),          // not hex
    ];
    for reference in bad {
        let c = compose_with(&format!("services:\n  app:\n    image: {reference}\n"));
        assert!(
            matches!(pinned_images(&c), Err(ImageError::NotPinned { .. })),
            "{reference} must be refused"
        );
    }
}

/// A reference with an empty digest is refused — but as `NoImage`, not `NotPinned`.
///
/// `image: alpine@sha256:` ends in a colon, so YAML reads it as a nested mapping rather than a
/// string, and the value never reaches digest classification. Asserting only "refused" here is
/// deliberate: **which** refusal is a property of the YAML grammar, not of this crate, and pinning
/// it would make the test fail on a parser change that broke nothing.
///
/// What matters is that an unrecognised shape does not pass. That is fail-closed working, observed
/// rather than assumed.
#[test]
fn empty_digest_is_refused_by_falling_closed() {
    let c = compose_with("services:\n  app:\n    image: alpine@sha256:\n");
    assert!(
        pinned_images(&c).is_err(),
        "an unclassifiable image reference must not pass"
    );
}

/// **A sidecar on a floating tag is the same hole with a smaller entrance.**
///
/// Checking only the first service would pass this document while leaving a container whose code
/// can change under the licence.
#[test]
fn refuses_a_tagged_sidecar_beside_a_pinned_primary() {
    let c = compose_with(&format!(
        "services:\n  app:\n    image: alpine@{LICENSED_DIGEST}\n  sidecar:\n    image: nginx:latest\n"
    ));
    match pinned_images(&c) {
        Err(ImageError::NotPinned { service, .. }) => assert_eq!(service, "sidecar"),
        other => panic!("expected the sidecar to be caught, got {other:?}"),
    }
}

/// The cross-check must not be satisfiable by a *different* pinned image while the licensed one is
/// absent — a compose that pins the wrong thing correctly is still the wrong thing.
#[test]
fn cross_check_is_not_satisfied_by_some_other_pinned_image() {
    let other_digest = format!("sha256:{}", "a".repeat(64));
    let c = compose_with(&format!(
        "services:\n  app:\n    image: alpine@{other_digest}\n"
    ));
    assert!(matches!(
        check_references_licensed_digest(&c, LICENSED_DIGEST),
        Err(ImageError::LicensedDigestAbsent { .. })
    ));
}

// — fail closed —

#[test]
fn refuses_a_service_with_no_image() {
    // `build:` is legitimate in ordinary compose usage and not here: what it produces is not
    // content-addressed, so nothing pins what would run.
    let c = compose_with("services:\n  app:\n    build: .\n");
    assert!(matches!(pinned_images(&c), Err(ImageError::NoImage { .. })));
}

#[test]
fn refuses_a_compose_with_no_services() {
    assert!(matches!(
        pinned_images(&compose_with("services: {}\n")),
        Err(ImageError::NoServices)
    ));
    assert!(matches!(
        pinned_images(&compose_with("version: '3'\n")),
        Err(ImageError::NoServices)
    ));
}

#[test]
fn refuses_unparseable_input() {
    assert!(matches!(
        pinned_images(b"not json at all"),
        Err(ImageError::NotJson { .. })
    ));
    assert!(matches!(
        pinned_images(br#"{"manifest_version":2}"#),
        Err(ImageError::MissingComposeFile)
    ));
    assert!(matches!(
        pinned_images(&compose_with("services:\n  app:\n   image: [unclosed\n")),
        Err(ImageError::NotYaml { .. } | ImageError::NoServices)
    ));
}

/// An unparseable document must never reach the cross-check as a pass.
#[test]
fn cross_check_inherits_every_refusal() {
    let tagged = compose_with("services:\n  app:\n    image: alpine:latest\n");
    assert!(check_references_licensed_digest(&tagged, LICENSED_DIGEST).is_err());
    assert!(check_references_licensed_digest(b"garbage", LICENSED_DIGEST).is_err());
}

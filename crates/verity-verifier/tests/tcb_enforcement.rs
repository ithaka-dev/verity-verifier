//! VA-1 negative (a), layer 2: a compile-time guard against a caller-configurable TCB knob
//! reappearing.
//!
//! The load-bearing layer is the CI grep (`.github/workflows/ci.yml`, the
//! `no-dangerous-attestation` job) — a regex is toolchain-robust and does not rot the way a
//! `trybuild` `.stderr` snapshot would across the pinned 1.97.1 / local 1.98 split this repo
//! straddles. This file is the second, independent layer the brief's acceptance criterion 1 asks
//! for: every public route that could carry a TCB policy is called here at the *exact* arity VA-1
//! left it at. Re-adding a `tcb: &TcbPolicy` parameter to `verify`, `attest::verify_quote`, or
//! `ConnectRequest::new` breaks compilation of this file — and, because it is one crate, the rest of
//! the test suite — rather than silently reappearing as an optional argument nobody has to pass.
//!
//! Nothing here asserts on the *outcome* of these calls; `verify_negative.rs`, `tests/attest.rs` and
//! `verified_transport.rs` already do that. This file exists to fail to compile, not to fail at
//! runtime.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use verity_verifier::attest::Collateral;
use verity_verifier::binding::ComposeHash;
use verity_verifier::channel::PeerCertificate;
use verity_verifier::connect::ConnectRequest;
use verity_verifier::verify::{verify, Evidence, LicensedVersion};

fn placeholder_collateral() -> Collateral {
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
        compose_hash: ComposeHash::of(b"{}"),
        image_digest: "sha256:00".to_owned(),
    }
}

/// `attest::verify_quote` takes exactly three arguments: raw quote, collateral, verification time.
/// A fourth — a policy of any shape — must not compile against this call.
#[test]
fn verify_quote_takes_no_tcb_policy() {
    let collateral = placeholder_collateral();
    let result = verity_verifier::attest::verify_quote(&[0u8; 128], &collateral, 0);
    assert!(result.is_err(), "garbage bytes cannot verify");
}

/// `verify` takes exactly three arguments: the licensed version, the evidence, and an optional boot
/// reference. A fourth — a policy of any shape — must not compile against this call.
#[test]
fn verify_takes_no_tcb_policy() {
    let licensed = licensed();
    let collateral = placeholder_collateral();
    let verdict = verify(
        &licensed,
        &Evidence {
            raw_quote: &[0u8; 128],
            compose_document: b"{}".to_vec(),
            collateral: &collateral,
            now_secs: 0,
            peer_certificate: PeerCertificate::NotConnected,
        },
        None,
    );
    assert!(!verdict.is_trustworthy(), "garbage bytes cannot verify");
}

/// `ConnectRequest::new` takes exactly three arguments: endpoint, licensed version, compose
/// document. A fourth — a policy of any shape — must not compile against this call.
#[test]
fn connect_request_new_takes_no_tcb_policy() {
    let endpoint = verity_verifier::endpoint::Endpoint::parse("https://example.com:8443")
        .expect("a well-formed endpoint");
    let licensed = licensed();
    let request = ConnectRequest::new(&endpoint, &licensed, b"{}".to_vec());
    assert!(request.boot.is_none(), "new() defaults boot to None");
}

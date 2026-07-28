//! Signature-chain verification and TCB policy.
//!
//! The real quote fixture cannot be *positively* verified offline: doing so needs Intel collateral
//! for that specific platform at that specific time, which is not committed and would expire.
//! What is tested here is everything that must hold regardless — refusals, policy, and the
//! separation between "not genuine" and "genuine but out of date".

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use verity_verifier::attest::{collateral_from_json, AttestError, CollateralError, TcbPolicy};

const QUOTE_HEX: &str = include_str!("fixtures/quote-v4-dstack-0.5.7.hex");

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

// — TCB policy —

/// The default must be the strict one. A permissive default is how an out-of-date platform gets
/// accepted by someone who never thought about it.
#[test]
fn default_policy_accepts_only_up_to_date() {
    assert_eq!(TcbPolicy::default(), TcbPolicy::up_to_date_only());
}

/// There is deliberately no "accept anything" constructor — tolerating a degraded platform must be
/// spelled out at the call site.
#[test]
fn looser_policy_requires_naming_the_statuses() {
    let policy = TcbPolicy::accepting(["UpToDate".to_owned(), "SWHardeningNeeded".to_owned()]);
    assert_ne!(policy, TcbPolicy::default());
}

// — refusals —

/// Garbage must be refused as a signature failure, not accepted or panicked on.
#[test]
fn garbage_is_refused() {
    let collateral = minimal_collateral();
    match verity_verifier::attest::verify_quote(&[0u8; 128], &collateral, 0, &TcbPolicy::default())
    {
        Err(AttestError::SignatureInvalid { .. }) => {}
        other => panic!("expected SignatureInvalid, got {other:?}"),
    }
}

/// A real quote without valid collateral must still refuse. Being genuine hardware output is not
/// sufficient — the chain has to check out against Intel.
#[test]
fn real_quote_without_valid_collateral_is_refused() {
    let result = verity_verifier::attest::verify_quote(
        &quote_bytes(),
        &minimal_collateral(),
        1_800_000_000,
        &TcbPolicy::default(),
    );
    assert!(
        result.is_err(),
        "a quote must not verify against collateral that does not attest it"
    );
}

// — collateral parsing —

#[test]
fn malformed_collateral_is_refused() {
    assert!(matches!(
        collateral_from_json(b"not json"),
        Err(CollateralError::Malformed { .. })
    ));
    assert!(matches!(
        collateral_from_json(b"{}"),
        Err(CollateralError::Malformed { .. })
    ));
}

/// Structurally valid but cryptographically useless collateral, so refusal paths can be exercised.
///
/// **Constructed infallibly and asserted, not returned as an `Option`.** An earlier version handed
/// back `None` when the upstream shape did not match and every caller returned early — which meant
/// two refusal tests passed by never running. A test that silently does nothing is worse than a
/// missing test, because it reports success.
/// Structurally valid but cryptographically useless collateral, so refusal paths can be exercised.
///
/// **Constructed directly rather than parsed, and infallibly rather than as an `Option`.** An
/// earlier version returned `None` when the upstream shape did not match, and every caller returned
/// early — which meant two refusal tests passed by never running. A test that silently does nothing
/// is worse than a missing test, because it reports success.
fn minimal_collateral() -> verity_verifier::attest::Collateral {
    verity_verifier::attest::Collateral {
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

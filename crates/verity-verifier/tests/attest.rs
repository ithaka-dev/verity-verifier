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

// — T-01: the mechanism ADR 0014 makes mandatory —
//
// Until these existed, the policy was asserted only by *identity* — that the default equalled
// `up_to_date_only()` — and never by *behaviour*. Nothing demonstrated it refusing anything,
// because the predicate was private and reachable only through a verification needing live Intel
// collateral. A rule exercised only against the network has no unit test.

/// The refusal the whole policy exists for.
#[test]
fn the_default_policy_refuses_every_degraded_status() {
    let policy = TcbPolicy::default();
    assert!(policy.accepts("UpToDate"));

    // Every status Intel actually emits other than UpToDate. Each means the platform is running
    // with known weaknesses, and accepting one silently is the outcome ADR 0014 forbids.
    for degraded in [
        "OutOfDate",
        "OutOfDateConfigurationNeeded",
        "SWHardeningNeeded",
        "ConfigurationNeeded",
        "ConfigurationAndSWHardeningNeeded",
        "Revoked",
    ] {
        assert!(
            !policy.accepts(degraded),
            "{degraded} must be refused by default"
        );
    }
}

/// An unknown status is refused rather than treated as benign. A status this crate has never heard
/// of is a status it cannot reason about, and the safe reading of "I do not know" is "no".
#[test]
fn an_unrecognised_status_is_refused() {
    let policy = TcbPolicy::default();
    for unknown in ["", "Fine", "UpToDateish", "UPTODATE_BUT_ACTUALLY_NOT", "🙂"] {
        assert!(!policy.accepts(unknown), "{unknown:?} must be refused");
    }
}

/// Widening accepts exactly what it names and nothing adjacent.
#[test]
fn accepting_widens_only_what_it_names() {
    let policy = TcbPolicy::accepting(["SWHardeningNeeded".to_owned()]);

    assert!(policy.accepts("SWHardeningNeeded"));
    // Not even UpToDate, unless it was named — the list is the whole policy, not an addition to a
    // default. A caller who forgets that gets a refusal, which is the safe direction.
    assert!(!policy.accepts("UpToDate"));
    assert!(!policy.accepts("ConfigurationAndSWHardeningNeeded"));
    assert!(!policy.accepts("OutOfDate"));
}

/// Intel's casing is not something a caller should have to match exactly.
#[test]
fn status_comparison_is_case_insensitive() {
    let policy = TcbPolicy::default();
    for spelling in ["uptodate", "UPTODATE", "UpToDate", "uPtOdAtE"] {
        assert!(policy.accepts(spelling), "{spelling} must be accepted");
    }
}

/// An empty policy accepts nothing. There is deliberately no "accept anything" constructor, so this
/// is the most permissive mistake available and it fails closed.
#[test]
fn an_empty_policy_accepts_nothing() {
    let policy = TcbPolicy::accepting(Vec::new());
    for status in ["UpToDate", "OutOfDate", ""] {
        assert!(!policy.accepts(status));
    }
}

// — T-02: the two failure kinds must stay distinguishable —

/// **Genuine-but-out-of-date and not-genuine call for completely different responses**, and
/// collapsing them into one error would hide which happened: one means update the platform, the
/// other means do not trust this endpoint at all.
#[test]
fn tcb_failure_and_signature_failure_are_different_errors() {
    let tcb = AttestError::TcbUnacceptable {
        status: "OutOfDate".to_owned(),
        advisory_ids: vec!["INTEL-SA-00615".to_owned()],
    };
    let signature = AttestError::SignatureInvalid {
        detail: "chain did not verify".to_owned(),
    };

    assert_ne!(tcb, signature);
    assert!(!matches!(tcb, AttestError::SignatureInvalid { .. }));
    assert!(!matches!(signature, AttestError::TcbUnacceptable { .. }));
}

/// Advisories are surfaced rather than swallowed: a caller deciding how much to trust an endpoint
/// should be able to see what Intel has published about the platform.
#[test]
fn a_tcb_refusal_names_the_status_and_its_advisories() {
    let rendered = AttestError::TcbUnacceptable {
        status: "OutOfDate".to_owned(),
        advisory_ids: vec!["INTEL-SA-00615".to_owned(), "INTEL-SA-00657".to_owned()],
    }
    .to_string();

    assert!(rendered.contains("OutOfDate"), "{rendered}");
    assert!(rendered.contains("INTEL-SA-00615"), "{rendered}");
    assert!(rendered.contains("INTEL-SA-00657"), "{rendered}");
}

/// No advisories is a clean message rather than an empty bracket — the absence of advisories is
/// itself information, and it should not read like a formatting bug.
#[test]
fn a_tcb_refusal_without_advisories_reads_cleanly() {
    let rendered = AttestError::TcbUnacceptable {
        status: "Revoked".to_owned(),
        advisory_ids: Vec::new(),
    }
    .to_string();

    assert!(rendered.contains("Revoked"));
    assert!(!rendered.contains("()"), "{rendered}");
    assert!(!rendered.contains("advisories"), "{rendered}");
}

/// A tampered quote must be refused as a signature failure — not accepted, and not misreported as
/// a TCB problem.
#[test]
fn a_tampered_quote_is_refused_as_a_signature_failure() {
    let collateral = minimal_collateral();
    let mut tampered = quote_bytes();

    // Flip a byte deep in the signature region rather than in the header, so the quote still parses
    // and the failure is genuinely the signature rather than the shape.
    let position = tampered.len() - 64;
    tampered[position] ^= 0b0000_0001;

    match verity_verifier::attest::verify_quote(&tampered, &collateral, 0, &TcbPolicy::default()) {
        Err(AttestError::SignatureInvalid { .. }) => {}
        other => panic!("expected SignatureInvalid, got {other:?}"),
    }
}

/// A truncated quote is refused rather than panicking. Every read in the parser is fallible for
/// exactly this reason: malformed input arrives from the network.
#[test]
fn a_truncated_quote_is_refused_rather_than_panicking() {
    let collateral = minimal_collateral();
    let full = quote_bytes();

    for fraction in [1, 2, 4, 8, 16] {
        let truncated = &full[..full.len() / fraction];
        let result =
            verity_verifier::attest::verify_quote(truncated, &collateral, 0, &TcbPolicy::default());
        assert!(
            result.is_err(),
            "a {fraction}-way truncation must be refused"
        );
    }
}

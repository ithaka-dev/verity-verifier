//! WASM and Node bindings for [`verity_verifier`].
//!
//! Carries the verifier into agents that are not Rust. The bindings are deliberately thin: they
//! translate types and nothing else, so there is one implementation of the checks and three ways
//! to reach it rather than three implementations that can drift.
//!
//! # One version, one source
//!
//! [ADR 0012] requires every distribution surface to report the same version. It is derived from
//! the core crate rather than maintained here — a binding that could report a different version
//! from the code it wraps would make "which verifier produced this verdict?" unanswerable, which
//! is the question [ADR 0014] exists to keep answerable.
//!
//! # There is no `connect_verified` here, and there cannot be
//!
//! The Rust crate's blessed API dials the endpoint itself, so the certificate it checks is provably
//! the one its own handshake returned. **That is not implementable for `wasm32-unknown-unknown`:** a
//! browser cannot open a raw TLS connection, and `fetch()` does not expose the peer certificate at
//! all. Shipping something *called* a verified transport here would be the defect this crate exists
//! to refuse — an answer that looks authoritative and establishes nothing.
//!
//! So a JavaScript caller carries an obligation the Rust caller no longer does:
//!
//! - **In Node**, obtain the leaf DER from your own TLS layer —
//!   `socket.getPeerX509Certificate().raw` on a `tls.TLSSocket` — and pass it as `leafCertDer`. It
//!   must come from the handshake with the endpoint being judged; nothing here can check that, and
//!   a certificate obtained anywhere else yields a truthful answer about a connection you are not
//!   using.
//! - **In a browser**, this cannot be done at all. `verifyComposeOnly` remains available and its
//!   verdict is never trustworthy, which is the honest answer rather than a partial one.
//!
//! Closing that gap needs a Node-native binding that can own the handshake. It is separate work, and
//! until it exists this surface's provenance gap is documented rather than closed.
//!
//! [ADR 0012]: https://github.com/ithaka-dev/verity-foundation/blob/main/docs/decisions/0012-language-allocation.md
//! [ADR 0014]: https://github.com/ithaka-dev/verity-foundation/blob/main/docs/decisions/0014-verifier-update-discipline.md

use serde::Serialize;
use verity_verifier::binding::ComposeHash;
use verity_verifier::channel::ChannelBinding;
use verity_verifier::images;
use verity_verifier::quote::Quote;
use verity_verifier::verdict::Outcome;
use wasm_bindgen::prelude::*;

/// The verifier version, identical to the core crate's.
#[wasm_bindgen(js_name = verifierVersion)]
#[must_use]
pub fn verifier_version() -> String {
    verity_verifier::verdict::VERIFIER_VERSION.to_owned()
}

/// The date of the bundled reference data.
#[wasm_bindgen(js_name = referenceDataDate)]
#[must_use]
pub fn reference_data_date() -> String {
    verity_verifier::reference::REFERENCE_DATA_DATE.to_owned()
}

/// One check and what it concluded, as seen from JavaScript.
#[derive(Serialize)]
struct JsCheck {
    check: String,
    outcome: &'static str,
    detail: Option<String>,
    /// A typed instruction: what to do about this outcome. See
    /// [`verity_verifier::verdict::Disposition::name`] for the closed set of values — a caller
    /// should match this, never parse `detail`. The remedy class (`Unestablished`) that produces an
    /// `"indeterminate"` outcome is deliberately **not** exposed as its own field: the three causes
    /// map onto three distinct dispositions one-to-one, so a second field would be a second
    /// spelling of the same fact.
    disposition: &'static str,
}

/// A verdict, as seen from JavaScript.
///
/// Mirrors the Rust shape: provenance, per-check outcomes, and a derived boolean — never a bare
/// boolean on its own.
#[derive(Serialize)]
struct JsVerdict {
    #[serde(rename = "verifierVersion")]
    verifier_version: String,
    #[serde(rename = "referenceDataDate")]
    reference_data_date: String,
    checks: Vec<JsCheck>,
    #[serde(rename = "isTrustworthy")]
    is_trustworthy: bool,
    #[serde(rename = "missingEssentials")]
    missing_essentials: Vec<String>,
}

fn to_js(verdict: &verity_verifier::verdict::Verdict) -> JsVerdict {
    JsVerdict {
        verifier_version: verdict.verifier_version().to_owned(),
        reference_data_date: verdict.reference_data_date().to_owned(),
        checks: verdict
            .results()
            .iter()
            .map(|(check, outcome)| JsCheck {
                check: check.name().to_owned(),
                // Outcome is #[non_exhaustive], so a wildcard is required — and it reports
                // "unknown" rather than anything a caller might read as success. A binding that
                // guessed optimistically about a variant it did not recognise would turn a core
                // upgrade into a silent downgrade of every JavaScript caller.
                outcome: match outcome {
                    Outcome::Passed => "passed",
                    Outcome::Failed(_) => "failed",
                    Outcome::Skipped(_) => "skipped",
                    Outcome::Indeterminate { .. } => "indeterminate",
                    _ => "unknown",
                },
                detail: match outcome {
                    Outcome::Passed => None,
                    Outcome::Failed(d) | Outcome::Skipped(d) => Some(d.clone()),
                    Outcome::Indeterminate { detail, .. } => Some(detail.clone()),
                    _ => Some("outcome variant unknown to these bindings; upgrade them".to_owned()),
                },
                disposition: verity_verifier::verdict::disposition(*check, outcome).name(),
            })
            .collect(),
        is_trustworthy: verdict.is_trustworthy(),
        missing_essentials: verdict
            .missing_essentials()
            .iter()
            .map(|c| c.name().to_owned())
            .collect(),
    }
}

/// Compute the SHA-256 of a compose document, as lowercase hex.
#[wasm_bindgen(js_name = composeHash)]
#[must_use]
pub fn compose_hash(document: &[u8]) -> String {
    ComposeHash::of(document).to_string()
}

/// Check a compose document is digest-pinned and names the licensed image.
///
/// Returns `null` on success, or a message describing the refusal. **A caller must treat a
/// non-null result as a refusal**, not as advisory text.
#[wasm_bindgen(js_name = checkImages)]
#[must_use]
pub fn check_images(document: &[u8], licensed_digest: &str) -> Option<String> {
    images::check_references_licensed_digest(document, licensed_digest)
        .err()
        .map(|e| e.to_string())
}

/// Extract `MR-CONFIG-ID` from a raw TDX quote, as lowercase hex.
///
/// Returns `null` if the quote cannot be parsed — which is itself a refusal, not an absence.
#[wasm_bindgen(js_name = quoteMrConfigId)]
#[must_use]
pub fn quote_mrconfigid(raw_quote: &[u8]) -> Option<String> {
    Quote::parse(raw_quote)
        .ok()
        .map(|q| q.mrconfigid().to_string())
}

/// Check a quote's `MR-CONFIG-ID` against a licensed compose hash.
///
/// Returns `null` when it matches, or a message describing why not.
#[wasm_bindgen(js_name = checkMrConfigId)]
#[must_use]
pub fn check_mrconfigid(raw_quote: &[u8], licensed_compose_hash_hex: &str) -> Option<String> {
    let licensed = match ComposeHash::parse_hex(licensed_compose_hash_hex) {
        Ok(h) => h,
        Err(e) => return Some(e.to_string()),
    };
    let quote = match Quote::parse(raw_quote) {
        Ok(q) => q,
        Err(e) => return Some(e.to_string()),
    };
    verity_verifier::binding::check_mrconfigid(quote.mrconfigid(), &licensed)
        .err()
        .map(|e| e.to_string())
}

/// Check that a quote commits to the certificate a connection presented.
///
/// Returns `null` when the quote is about this connection, or a message describing why not. **A
/// caller must treat a non-null result as a refusal**, not as advisory text — a genuine quote
/// paired with somebody else's endpoint lands here, and it is the only check that can tell.
///
/// `leafCertDer` is the DER of the leaf from the TLS handshake **with the endpoint being judged**.
/// These bindings perform no I/O and cannot check that provenance; a certificate from anywhere else
/// yields a truthful answer about a connection you are not using.
///
/// This says nothing about whether Intel signed the quote — that needs collateral, and the Rust API.
/// A forged quote whose `report_data` commits to the caller's own certificate passes this function.
#[wasm_bindgen(js_name = checkChannelBinding)]
#[must_use]
pub fn check_channel_binding(raw_quote: &[u8], leaf_cert_der: &[u8]) -> Option<String> {
    let quote = match Quote::parse(raw_quote) {
        Ok(q) => q,
        Err(e) => return Some(e.to_string()),
    };
    ChannelBinding::check(leaf_cert_der, &quote)
        .err()
        .map(|e| e.to_string())
}

/// Serialise a verdict for JavaScript.
///
/// # Errors
///
/// Returns a `JsValue` error if serialisation fails.
fn verdict_to_value(v: &verity_verifier::verdict::Verdict) -> Result<JsValue, JsValue> {
    serde_wasm_bindgen::to_value(&to_js(v)).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Verify compose-side checks and return a structured verdict.
///
/// `verifyComposeOnly(document, licensedComposeHashHex, licensedImageDigest, rawQuote, leafCertDer?)`
///
/// Signature verification is **not** included here: it needs Intel collateral, and a binding that
/// quietly omitted it while still returning a verdict would be the most dangerous thing in this
/// crate. The omission is explicit in the returned verdict, where `quote_signature` is reported as
/// skipped and the verdict is therefore not trustworthy.
///
/// `leafCertDer` is optional and may be omitted, which arrives here as `None` — so existing
/// JavaScript callers keep working, and their verdicts were already untrustworthy. Supplying it
/// performs channel binding, which these bindings *can* do: it needs SHA-512 and an X.509 parse,
/// not Intel collateral.
///
/// # Errors
///
/// Returns a `JsValue` error if the verdict cannot be serialised.
// `Option<Box<[u8]>>` and not `Option<&[u8]>`: wasm-bindgen's ABI for an *optional* byte slice
// requires an owned value, because there is no nullable borrowed slice to hand across the boundary.
#[wasm_bindgen(js_name = verifyComposeOnly)]
pub fn verify_compose_only(
    document: &[u8],
    licensed_compose_hash_hex: &str,
    licensed_image_digest: &str,
    raw_quote: &[u8],
    leaf_cert_der: Option<Box<[u8]>>,
) -> Result<JsValue, JsValue> {
    verdict_to_value(&compose_only_verdict_from_js_args(
        document,
        licensed_compose_hash_hex,
        licensed_image_digest,
        raw_quote,
        leaf_cert_der,
    ))
}

/// The argument adapter between the JavaScript boundary and [`compose_only_verdict`].
///
/// **This exists as its own function so that a test can reach it.** `verify_compose_only` cannot be
/// called from a native test at all — wasm-bindgen's imported functions panic off-target, which is
/// the same reason `compose_only_verdict` was split out in the first place. While
/// `leaf_cert_der.as_deref()` lived inside it, the single line deciding whether a JavaScript
/// caller's certificate reaches the check was covered by nothing.
///
/// The failure that line can have is CR-1's own shape at the binding boundary: passing `None` here
/// would skip channel binding for **every** JavaScript caller, silently, with an `isTrustworthy:
/// false` that was already false for other reasons — so nothing downstream would look different.
// The value is only read, which is what clippy objects to; the ownership is the boundary's
// requirement rather than this function's, and this is the function that discharges it.
#[allow(clippy::needless_pass_by_value)]
fn compose_only_verdict_from_js_args(
    document: &[u8],
    licensed_compose_hash_hex: &str,
    licensed_image_digest: &str,
    raw_quote: &[u8],
    leaf_cert_der: Option<Box<[u8]>>,
) -> verity_verifier::verdict::Verdict {
    compose_only_verdict(
        document,
        licensed_compose_hash_hex,
        licensed_image_digest,
        raw_quote,
        leaf_cert_der.as_deref(),
    )
}

/// The decisions behind [`verify_compose_only`], separated from the JavaScript boundary.
///
/// Split out because `JsValue` only exists on wasm32, so while this logic lived inside the exported
/// function it could not be executed by any test on a development machine — and this crate is built
/// for wasm32 in CI but never run anywhere. That is why these bindings sat at 21% coverage while
/// the core they wrap was at 79%: not because the code was hard to test, but because it was welded
/// to a type that cannot exist natively.
///
/// The distribution surface matters more than the percentage. ADR 0012 ships three of these — Rust
/// crate, WASM, Node bindings — and ADR 0014 notes each has its own version and its own opportunity
/// to lag. A binding that disagrees with the core about what "trustworthy" means is the failure
/// nobody would see, because the core's own tests all pass.
fn compose_only_verdict(
    document: &[u8],
    licensed_compose_hash_hex: &str,
    licensed_image_digest: &str,
    raw_quote: &[u8],
    leaf_cert_der: Option<&[u8]>,
) -> verity_verifier::verdict::Verdict {
    use verity_verifier::verdict::{Check, Verdict};

    let mut verdict = Verdict::new();

    let licensed = match ComposeHash::parse_hex(licensed_compose_hash_hex) {
        Ok(h) => h,
        Err(e) => return verdict.record(Check::ComposeHash, Outcome::Failed(e.to_string())),
    };

    match verity_verifier::binding::VerifiedCompose::check(document.to_vec(), &licensed) {
        Ok(_) => {
            verdict = verdict.record(Check::ComposeHash, Outcome::Passed);
            match images::pinned_images(document) {
                Ok(_) => verdict = verdict.record(Check::ImagesPinned, Outcome::Passed),
                Err(e) => {
                    verdict = verdict.record(Check::ImagesPinned, Outcome::Failed(e.to_string()));
                }
            }
            match images::check_references_licensed_digest(document, licensed_image_digest) {
                Ok(()) => verdict = verdict.record(Check::LicensedImagePresent, Outcome::Passed),
                Err(e) => {
                    verdict =
                        verdict.record(Check::LicensedImagePresent, Outcome::Failed(e.to_string()));
                }
            }
        }
        Err(e) => {
            let why = "compose hash did not match, so its contents were not examined".to_owned();
            verdict = verdict
                .record(Check::ComposeHash, Outcome::Failed(e.to_string()))
                .record(Check::ImagesPinned, Outcome::Skipped(why.clone()))
                .record(Check::LicensedImagePresent, Outcome::Skipped(why));
        }
    }

    match Quote::parse(raw_quote) {
        Ok(quote) => {
            match verity_verifier::binding::check_mrconfigid(quote.mrconfigid(), &licensed) {
                Ok(()) => verdict = verdict.record(Check::MrConfigId, Outcome::Passed),
                // Recognised, but this build cannot yet compute a reference for it: the same
                // remedy as the core's `mrconfigid_outcome` (`verify.rs`) — an updated build
                // judges the same call — so this site needs the identical split or the two
                // surfaces disagree about the same input. `UnknownVersion` (including all-zero,
                // what an unpopulated field looks like) and `Mismatch` have no such remedy and
                // stay `Failed`.
                Err(e @ verity_verifier::binding::MrConfigIdError::UnsupportedVersion { .. }) => {
                    verdict = verdict.record(
                        Check::MrConfigId,
                        Outcome::unestablished(
                            verity_verifier::verdict::Unestablished::VerifierCannotJudge,
                            e.to_string(),
                        ),
                    );
                }
                Err(e) => {
                    verdict = verdict.record(Check::MrConfigId, Outcome::Failed(e.to_string()));
                }
            }
            // Channel binding is performed here rather than declared impossible, because these
            // bindings *can* perform it: it needs SHA-512 and an X.509 parse, not Intel collateral.
            // Adding an essential check the bindings never recorded would have made them laxer than
            // the core in the one dimension CR-1 is about, and a bare `Skipped` would have been an
            // excuse rather than an answer.
            match leaf_cert_der {
                Some(der) => match ChannelBinding::check(der, &quote) {
                    Ok(_) => verdict = verdict.record(Check::ChannelBound, Outcome::Passed),
                    Err(e) => {
                        verdict =
                            verdict.record(Check::ChannelBound, Outcome::Failed(e.to_string()));
                    }
                },
                None => {
                    verdict = verdict.record(
                        Check::ChannelBound,
                        Outcome::Skipped(
                            "no certificate supplied; channel binding was not attempted".to_owned(),
                        ),
                    );
                }
            }
        }
        Err(e) => {
            verdict = verdict
                .record(Check::MrConfigId, Outcome::Failed(e.to_string()))
                .record(Check::ChannelBound, Outcome::Failed(e.to_string()));
        }
    }

    // Both, and explicitly. `TcbStatus` used to be omitted rather than recorded, which left it as
    // a check that *never ran* — and `unrun_essentials` treats that as the signal that a verifier
    // silently stopped checking, which is the one thing ADR 0014 is built to surface. Here it is a
    // legitimate, structural omission: TCB status is a property of the platform that signed the
    // quote, so it cannot be judged without the collateral needed to verify that signature. Saying
    // so keeps an honest skip distinguishable from a regression.
    //
    // **And this is what makes every other check here provisional, `channel_bound` included.**
    // Nothing above establishes that Intel signed this quote, so an attacker who writes their own
    // quote — with whatever `MR-CONFIG-ID` and whatever `report_data` commits to their own
    // certificate — gets `passed` on both. That is not a defect being tolerated: it is why the
    // verdict this function returns can never be trustworthy, and why the skips below are recorded
    // rather than omitted.
    let needs_collateral = "needs Intel collateral; use the Rust API".to_owned();
    verdict
        .record(
            Check::QuoteSignature,
            Outcome::Skipped(format!("signature verification {needs_collateral}")),
        )
        .record(
            Check::TcbStatus,
            Outcome::Skipped(format!("TCB status {needs_collateral}")),
        )
}

#[cfg(test)]
mod tests {
    //! T-12: the verdict logic, which no test could previously reach.
    //!
    //! `verify_compose_only` returned `Result<JsValue, JsValue>`, and `JsValue` exists only on
    //! wasm32 — so every decision inside it was unreachable from a native test. Splitting
    //! `compose_only_verdict` out from the serialisation is what makes these possible; the exported
    //! function is now a one-line wrapper with nothing left to get wrong.

    // These live inside the crate, so the workspace lints apply — including the ones that exist to
    // stop library code panicking. In a test a panic is the reporting mechanism, so indexing a
    // fixture directly is the clearer expression: an out-of-range index fails the test loudly,
    // which is what should happen.
    #![allow(
        clippy::expect_used,
        clippy::unwrap_used,
        clippy::panic,
        clippy::indexing_slicing
    )]

    use super::{compose_only_verdict, compose_only_verdict_from_js_args, to_js};
    use verity_verifier::verdict::{Check, Outcome, Unestablished, Verdict};

    const COMPOSE: &[u8] =
        include_bytes!("../../verity-verifier/tests/fixtures/app-compose-0.5.7.json");
    const QUOTE_HEX: &str =
        include_str!("../../verity-verifier/tests/fixtures/quote-v4-dstack-0.5.7.hex");
    const LICENSED: &str = "64690ef38b54187da11a41a54905f5f539e948a0414ceb312c8036c82f6529fd";
    const IMAGE: &str = "sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc";

    fn quote() -> Vec<u8> {
        let hex = QUOTE_HEX.trim();
        (0..hex.len() / 2)
            .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("fixture is hex"))
            .collect()
    }

    // The matched pair from CVM 9be9f370 — the quote lives inside the certificate. See
    // `crates/verity-verifier/tests/fixtures/PROVENANCE.md`.
    const RATLS_LEAF_PEM: &[u8] =
        include_bytes!("../../verity-verifier/tests/fixtures/ratls-leaf-dstack-0.5.9.pem");
    const RATLS_QUOTE_HEX: &str =
        include_str!("../../verity-verifier/tests/fixtures/ratls-leaf-dstack-0.5.9.quote.hex");

    fn ratls_quote_bytes() -> Vec<u8> {
        let hex = RATLS_QUOTE_HEX.trim();
        (0..hex.len() / 2)
            .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("fixture is hex"))
            .collect()
    }

    fn ratls_leaf_der() -> Vec<u8> {
        let (label, der) = pem_rfc7468::decode_vec(RATLS_LEAF_PEM).expect("fixture is PEM");
        assert_eq!(label, "CERTIFICATE");
        der
    }

    fn outcome_of(verdict: &Verdict, check: Check) -> Option<&Outcome> {
        verdict.outcome(check)
    }

    /// **The most important property in this crate**, and it had no test: a compose-only verdict is
    /// never trustworthy. These bindings cannot verify a signature — the dependency that does it
    /// will not build for wasm32 — so the one thing they must never do is return a verdict that
    /// reads as verified. The refusal is structural rather than a policy someone could relax.
    #[test]
    fn a_compose_only_verdict_is_never_trustworthy_even_when_everything_it_can_check_passes() {
        let verdict = compose_only_verdict(COMPOSE, LICENSED, IMAGE, &quote(), None);

        assert_eq!(
            outcome_of(&verdict, Check::ComposeHash),
            Some(&Outcome::Passed)
        );
        assert_eq!(
            outcome_of(&verdict, Check::ImagesPinned),
            Some(&Outcome::Passed)
        );
        assert_eq!(
            outcome_of(&verdict, Check::LicensedImagePresent),
            Some(&Outcome::Passed)
        );
        assert_eq!(
            outcome_of(&verdict, Check::MrConfigId),
            Some(&Outcome::Passed)
        );

        assert!(
            !verdict.is_trustworthy(),
            "everything checkable passed, and that is still not verification"
        );
    }

    /// A recognised-but-unsupported `MR-CONFIG-ID` construction (V2) is `Indeterminate`, not
    /// `Failed`, through the WASM path too — by the same "this same call, on an updated build,
    /// concludes" rule that gives the core its split (`verify.rs`'s `mrconfigid_outcome`). This
    /// site is a *second*, independent recording of `MrConfigId` from the same
    /// `MrConfigIdError` type, so it needs the same split or the two surfaces disagree about the
    /// same input.
    #[test]
    fn mrconfigid_v2_is_indeterminate_through_the_wasm_path_too() {
        let mut q = quote();
        // MR-CONFIG-ID sits at 48 + 184 within the quote (`quote.rs`'s `HEADER_LEN` +
        // `OFF_MRCONFIGID`); only the prefix byte decides which construction
        // `MrConfigIdVersion::from_measurement` recognises.
        q[48 + 184] = 0x02;
        let verdict = compose_only_verdict(COMPOSE, LICENSED, IMAGE, &q, None);

        match outcome_of(&verdict, Check::MrConfigId) {
            Some(Outcome::Indeterminate { cause, .. }) => {
                assert_eq!(
                    *cause,
                    verity_verifier::verdict::Unestablished::VerifierCannotJudge
                );
            }
            other => panic!("expected Indeterminate, got {other:?}"),
        }
        assert!(
            !verdict.is_trustworthy(),
            "MrConfigId is essential, so Indeterminate must still sink the verdict"
        );
    }

    /// The skips must be *recorded*, not merely absent. `unrun_essentials` treats an absent check
    /// as the signal that a verifier silently stopped checking — the regression ADR 0014 exists to
    /// surface — so an honest structural omission has to say so explicitly to stay distinguishable
    /// from one. `TcbStatus` was absent here until T-11 made it essential.
    #[test]
    fn what_these_bindings_cannot_check_is_recorded_as_skipped_rather_than_left_out() {
        let verdict = compose_only_verdict(COMPOSE, LICENSED, IMAGE, &quote(), None);

        for check in [Check::QuoteSignature, Check::TcbStatus] {
            match outcome_of(&verdict, check) {
                Some(Outcome::Skipped(why)) => {
                    assert!(
                        why.contains("collateral"),
                        "{check} must say why it was skipped"
                    );
                }
                other => panic!("{check} must be recorded as skipped, was {other:?}"),
            }
        }
        assert!(
            verdict.unrun_essentials().is_empty(),
            "a declared skip is not the same as a check that vanished"
        );
    }

    /// The same obligation, for the essential that CR-1 added.
    ///
    /// `ChannelBound` joining `essential()` would have made the test above fail — a seventh
    /// essential these bindings never recorded is a check that *vanished*, which is exactly the
    /// regression `unrun_essentials` exists to surface. The wrong repair was to record a bare skip
    /// and move on; these bindings can genuinely perform channel binding, so the omission has to be
    /// a *declaration* about this call rather than about the bindings' capabilities.
    #[test]
    fn channel_binding_absent_is_recorded_rather_than_omitted() {
        let verdict = compose_only_verdict(COMPOSE, LICENSED, IMAGE, &quote(), None);

        match outcome_of(&verdict, Check::ChannelBound) {
            Some(Outcome::Skipped(why)) => assert!(
                why.contains("no certificate supplied"),
                "the skip must name what was missing, was {why:?}"
            ),
            other => panic!("channel_bound must be recorded as skipped, was {other:?}"),
        }
        assert!(
            verdict.unrun_essentials().is_empty(),
            "channel_bound must be declared, not left out"
        );
        assert!(!verdict.is_trustworthy());
    }

    /// The one line that decides whether a JavaScript caller's certificate reaches the check.
    ///
    /// `verify_compose_only` itself cannot be called natively — wasm-bindgen's imported functions
    /// panic off-target — so the `as_deref()` adapter was covered by nothing until it was split into
    /// `compose_only_verdict_from_js_args`. Dropping the certificate there would skip channel
    /// binding for every JavaScript caller with no downstream symptom, since the verdict is
    /// untrustworthy either way. Both arms are asserted, because only the difference between them
    /// shows the argument arrived.
    #[test]
    fn a_certificate_supplied_from_javascript_reaches_the_check() {
        let ratls_quote = ratls_quote_bytes();
        let ratls_leaf: Box<[u8]> = ratls_leaf_der().into_boxed_slice();

        let bound = compose_only_verdict_from_js_args(
            COMPOSE,
            LICENSED,
            IMAGE,
            &ratls_quote,
            Some(ratls_leaf.clone()),
        );
        assert_eq!(
            outcome_of(&bound, Check::ChannelBound),
            Some(&Outcome::Passed),
            "the certificate and the quote it carries must bind through the JS argument path"
        );

        let dropped =
            compose_only_verdict_from_js_args(COMPOSE, LICENSED, IMAGE, &ratls_quote, None);
        assert!(
            matches!(
                outcome_of(&dropped, Check::ChannelBound),
                Some(Outcome::Skipped(_))
            ),
            "and omitting it must be the *only* way to get a skip"
        );

        // A certificate from elsewhere still refuses through the same path, so `Passed` above is the
        // comparison succeeding rather than the argument being ignored.
        let relayed =
            compose_only_verdict_from_js_args(COMPOSE, LICENSED, IMAGE, &quote(), Some(ratls_leaf));
        assert!(matches!(
            outcome_of(&relayed, Check::ChannelBound),
            Some(Outcome::Failed(_))
        ));
    }

    /// A compose that does not hash to the licensed value stops the examination: its contents are
    /// not evidence of anything, so reporting on them would be reporting on an attacker's document.
    #[test]
    fn a_wrong_compose_skips_the_checks_that_depend_on_it_rather_than_failing_them() {
        let mut tampered = COMPOSE.to_vec();
        tampered.push(b' ');
        let verdict = compose_only_verdict(&tampered, LICENSED, IMAGE, &quote(), None);

        assert!(matches!(
            outcome_of(&verdict, Check::ComposeHash),
            Some(Outcome::Failed(_))
        ));
        assert!(matches!(
            outcome_of(&verdict, Check::ImagesPinned),
            Some(Outcome::Skipped(_))
        ));
        assert!(matches!(
            outcome_of(&verdict, Check::LicensedImagePresent),
            Some(Outcome::Skipped(_))
        ));
        assert!(!verdict.is_trustworthy());
    }

    /// An unparseable licensed hash must not be treated as "nothing to compare against". It is the
    /// caller's input, and a verifier that shrugged at it would pass every deployment.
    #[test]
    fn an_unreadable_licensed_hash_fails_the_compose_check_immediately() {
        let verdict = compose_only_verdict(COMPOSE, "not-a-hash", IMAGE, &quote(), None);
        assert!(matches!(
            outcome_of(&verdict, Check::ComposeHash),
            Some(Outcome::Failed(_))
        ));
        assert!(!verdict.is_trustworthy());
    }

    #[test]
    fn an_unparseable_quote_fails_the_binding_check() {
        let verdict = compose_only_verdict(COMPOSE, LICENSED, IMAGE, b"not a quote", None);
        assert!(matches!(
            outcome_of(&verdict, Check::MrConfigId),
            Some(Outcome::Failed(_))
        ));
        assert!(!verdict.is_trustworthy());
    }

    /// A tag-referenced image (ADR 0007) fails while the hash still matches — the case that keeps
    /// `composeHash` stable while the code inside changes freely.
    #[test]
    fn a_pinned_hash_does_not_excuse_an_unpinned_image() {
        let tagged = serde_json::to_vec(&serde_json::json!({
            "manifest_version": 2,
            "runner": "docker-compose",
            "docker_compose_file": "services:\n  app:\n    image: alpine:latest\n",
        }))
        .expect("json");
        let its_hash = super::ComposeHash::of(&tagged).to_string();

        let verdict = compose_only_verdict(&tagged, &its_hash, IMAGE, &quote(), None);
        assert_eq!(
            outcome_of(&verdict, Check::ComposeHash),
            Some(&Outcome::Passed),
            "the document really is the one named"
        );
        assert!(
            matches!(
                outcome_of(&verdict, Check::ImagesPinned),
                Some(Outcome::Failed(_))
            ),
            "and it is still refused, because a tag is not a pin"
        );
    }

    // — the JavaScript projection —

    /// The mapping into the JavaScript shape must not lose the distinction between the four
    /// outcomes, since that shape is all a JavaScript caller ever sees.
    #[test]
    fn the_js_projection_preserves_pass_fail_skip_and_indeterminate() {
        let verdict = Verdict::new()
            .record(Check::ComposeHash, Outcome::Passed)
            .record(Check::ImagesPinned, Outcome::Failed("tagged".to_owned()))
            .record(Check::MrConfigId, Outcome::Skipped("no quote".to_owned()))
            .record(
                Check::BootMeasurements,
                Outcome::unestablished(Unestablished::ReferenceUnavailable, "no reference"),
            );
        let js = to_js(&verdict);

        assert_eq!(js.checks[0].outcome, "passed");
        assert_eq!(js.checks[0].detail, None, "a pass has nothing to explain");
        assert_eq!(js.checks[1].outcome, "failed");
        assert_eq!(js.checks[1].detail.as_deref(), Some("tagged"));
        assert_eq!(js.checks[2].outcome, "skipped");
        assert_eq!(js.checks[2].detail.as_deref(), Some("no quote"));
        assert_eq!(js.checks[3].outcome, "indeterminate");
        assert_eq!(js.checks[3].detail.as_deref(), Some("no reference"));
        assert!(!js.is_trustworthy);
    }

    /// The typed instruction a JavaScript caller reads instead of parsing `detail`.
    ///
    /// T-12: reverting `JsCheck.disposition` back out and re-running this test reproduces
    /// `error[E0609]` — no field `disposition` on type `JsCheck` — on every line below that reads
    /// it, the closest a struct-literal-free test gets to "watch it fail first" for a field
    /// addition. This test builds its `Verdict` by hand rather than through `verify()` or
    /// `compose_only_verdict()`, so it says nothing about either function's `MrConfigId` arm; that
    /// path is covered separately by `mrconfigid_v2_is_indeterminate_through_the_wasm_path_too`.
    #[test]
    fn the_js_projection_carries_a_typed_disposition() {
        let verdict = Verdict::new()
            .record(Check::ComposeHash, Outcome::Passed)
            .record(Check::ImagesPinned, Outcome::Failed("tagged".to_owned()))
            .record(Check::MrConfigId, Outcome::Skipped("no quote".to_owned()))
            .record(
                Check::BootMeasurements,
                Outcome::unestablished(Unestablished::ReferenceUnavailable, "no reference"),
            );
        let js = to_js(&verdict);

        assert_eq!(js.checks[0].disposition, "satisfied");
        assert_eq!(js.checks[1].disposition, "refuse");
        assert_eq!(
            js.checks[2].disposition, "refuse",
            "mr_config_id is essential, so a skip still dispositions to refuse"
        );
        assert_eq!(js.checks[3].disposition, "update_reference");
    }

    /// **The drift guard relocated from `verity-verifier/tests/transcript_contract.rs`.**
    ///
    /// That test asserted `Outcome::label()` against three hardcoded literals with a *comment*
    /// describing `to_js` — it would have passed even if `to_js` were deleted, because its crate
    /// does not depend on this one. This is the version that can actually observe drift: both
    /// surfaces are in scope here, so a JavaScript rendering that stopped agreeing with the core
    /// label fails this assertion rather than nothing at all.
    #[test]
    fn the_wasm_outcome_string_stays_in_lockstep_with_the_core_label_for_every_outcome() {
        let cases = [
            Outcome::Passed,
            Outcome::Failed("x".to_owned()),
            Outcome::Skipped("x".to_owned()),
            Outcome::unestablished(Unestablished::RetrievalFailed, "x"),
        ];
        for outcome in cases {
            let verdict = Verdict::new().record(Check::ComposeHash, outcome.clone());
            let js = to_js(&verdict);
            assert_eq!(
                js.checks[0].outcome,
                outcome.label().to_lowercase(),
                "the WASM projection must never drift from the core label for {outcome:?}"
            );
        }
    }

    /// Check names cross the boundary unchanged: they are the identifiers JavaScript groups and
    /// alerts on, so a binding that renamed them would break telemetry silently.
    #[test]
    fn the_js_projection_carries_names_provenance_and_what_is_missing() {
        let js = to_js(&compose_only_verdict(
            COMPOSE,
            LICENSED,
            IMAGE,
            &quote(),
            None,
        ));

        assert!(js.checks.iter().any(|c| c.check == "compose_hash"));
        assert!(!js.verifier_version.is_empty());
        assert!(!js.reference_data_date.is_empty());
        assert!(
            js.missing_essentials
                .contains(&"quote_signature".to_owned()),
            "the JavaScript caller must be told what was not established, by name"
        );
        assert!(js.missing_essentials.contains(&"tcb_status".to_owned()));
    }
}

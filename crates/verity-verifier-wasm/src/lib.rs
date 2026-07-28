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
//! [ADR 0012]: https://github.com/ithaka-dev/verity-foundation/blob/main/docs/decisions/0012-language-allocation.md
//! [ADR 0014]: https://github.com/ithaka-dev/verity-foundation/blob/main/docs/decisions/0014-verifier-update-discipline.md

use serde::Serialize;
use verity_verifier::binding::ComposeHash;
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
                    _ => "unknown",
                },
                detail: match outcome {
                    Outcome::Passed => None,
                    Outcome::Failed(d) | Outcome::Skipped(d) => Some(d.clone()),
                    _ => Some("outcome variant unknown to these bindings; upgrade them".to_owned()),
                },
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
/// Signature verification is **not** included here: it needs Intel collateral, and a binding that
/// quietly omitted it while still returning a verdict would be the most dangerous thing in this
/// crate. The omission is explicit in the returned verdict, where `quote_signature` is reported as
/// skipped and the verdict is therefore not trustworthy.
///
/// # Errors
///
/// Returns a `JsValue` error if the verdict cannot be serialised.
#[wasm_bindgen(js_name = verifyComposeOnly)]
pub fn verify_compose_only(
    document: &[u8],
    licensed_compose_hash_hex: &str,
    licensed_image_digest: &str,
    raw_quote: &[u8],
) -> Result<JsValue, JsValue> {
    use verity_verifier::verdict::{Check, Verdict};

    let mut verdict = Verdict::new();

    let licensed = match ComposeHash::parse_hex(licensed_compose_hash_hex) {
        Ok(h) => h,
        Err(e) => {
            return verdict_to_value(
                &verdict.record(Check::ComposeHash, Outcome::Failed(e.to_string())),
            )
        }
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
                Err(e) => {
                    verdict = verdict.record(Check::MrConfigId, Outcome::Failed(e.to_string()));
                }
            }
        }
        Err(e) => verdict = verdict.record(Check::MrConfigId, Outcome::Failed(e.to_string())),
    }

    verdict = verdict.record(
        Check::QuoteSignature,
        Outcome::Skipped(
            "signature verification needs Intel collateral; use the Rust API".to_owned(),
        ),
    );

    verdict_to_value(&verdict)
}

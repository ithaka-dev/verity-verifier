//! Verifying that Intel signed the quote.
//!
//! Everything else in this crate compares values. This module establishes that the values came
//! from real hardware in the first place — without it, a well-formed quote with the right
//! `MR-CONFIG-ID` could be written by anyone with a hex editor.
//!
//! # Collateral is supplied, not fetched
//!
//! DCAP verification needs collateral: Intel's TCB info and QE identity for the platform. This
//! module takes it as an argument rather than retrieving it, so **verification itself performs no
//! I/O** — it can run offline, in `wasm32`, or inside another enclave, and it can be audited
//! without reasoning about the network.
//!
//! Retrieval is **not** wrapped here at all — see [`collateral_from_json`] for why.
//!
//! # TCB status is enforced, and that is not configurable
//!
//! `dcap-qvl` exposes a `danger-allow-tcb-override` feature. **It is never enabled**, and CI
//! asserts its absence. [ADR 0014] makes TCB enforcement mandatory precisely because a flag that
//! turns a security check off is the flag someone eventually leaves off — and Intel's own
//! Jan–Feb 2026 remediation moved in the same direction, making QE identity verification a
//! mandatory core check rather than a caller's decision.
//!
//! [ADR 0014]: https://github.com/ithaka-dev/verity-foundation/blob/main/docs/decisions/0014-verifier-update-discipline.md

use dcap_qvl::{verify::verify as qvl_verify, QuoteCollateralV3};

use crate::verdict::is_tcb_acceptable;

/// Intel collateral needed to verify a quote.
///
/// Obtained from a PCCS or Intel PCS. Re-exported rather than wrapped so callers can supply
/// collateral they already hold — from a cache, a bundle, or a previous verification.
pub type Collateral = QuoteCollateralV3;

/// What a quote's signature chain established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attested {
    tcb_status: String,
    advisory_ids: Vec<String>,
}

impl Attested {
    /// Intel's TCB status for this platform, e.g. `UpToDate`.
    #[must_use]
    pub fn tcb_status(&self) -> &str {
        &self.tcb_status
    }

    /// Advisory identifiers Intel associates with this platform's TCB level.
    ///
    /// Non-empty means Intel has published security advisories that apply. Surfaced rather than
    /// swallowed: a caller deciding how much to trust an endpoint should be able to see them.
    #[must_use]
    pub fn advisory_ids(&self) -> &[String] {
        &self.advisory_ids
    }

    /// Whether Intel considers this platform's TCB up to date.
    #[must_use]
    pub fn is_up_to_date(&self) -> bool {
        is_tcb_acceptable(&self.tcb_status)
    }
}

#[cfg(test)]
impl Attested {
    /// Build a value directly, bypassing `verify_quote`.
    ///
    /// Test-only: production never constructs one except inside `verify_quote` itself, as a struct
    /// literal in this same module. This exists so `verify.rs`'s `record_attestation` tests can
    /// drive the *exact* production mapping over every TCB status without a live Intel signature —
    /// VA-1 §6. `#[cfg(test)]` rather than a permanent `pub(crate) fn` keeps it out of ordinary
    /// builds; it is visible crate-wide only while `cfg(test)` is set, which is what lets
    /// `verify.rs`'s own `#[cfg(test)]` module reach it.
    pub(crate) fn for_test(tcb_status: impl Into<String>, advisory_ids: Vec<String>) -> Self {
        Self {
            tcb_status: tcb_status.into(),
            advisory_ids,
        }
    }
}

/// Why a quote's signature chain was not accepted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AttestError {
    /// The signature chain did not verify against Intel's roots.
    ///
    /// The quote was not produced by hardware Intel vouches for, or was altered after signing.
    #[error("quote signature verification failed: {detail}")]
    SignatureInvalid {
        /// What the verifier reported.
        detail: String,
    },
    /// Verification succeeded but the platform's TCB is not acceptable.
    ///
    /// Separate from a signature failure on purpose: the hardware is genuine, and out of date.
    /// Those call for different responses, and collapsing them would hide which one happened.
    #[error("platform TCB status is `{status}`{}", advisories(.advisory_ids))]
    TcbUnacceptable {
        /// Intel's status for the platform.
        status: String,
        /// Applicable advisories.
        advisory_ids: Vec<String>,
    },
}

fn advisories(ids: &[String]) -> String {
    if ids.is_empty() {
        String::new()
    } else {
        format!(" (advisories: {})", ids.join(", "))
    }
}

/// Verify a quote's signature chain against Intel, using supplied collateral.
///
/// `now_secs` is the verification time as a Unix timestamp, passed in rather than read from a clock
/// so the function stays pure and testable — and so a caller in an environment without a trusted
/// clock is forced to think about where the time came from.
///
/// # Errors
///
/// Returns [`AttestError::SignatureInvalid`] if the chain does not verify, or
/// [`AttestError::TcbUnacceptable`] if it does but the platform's TCB status is not `UpToDate`.
/// That rule is not a parameter — see [ADR 0014] decision 2.
///
/// [ADR 0014]: https://github.com/ithaka-dev/verity-foundation/blob/main/docs/decisions/0014-verifier-update-discipline.md
pub fn verify_quote(
    raw_quote: &[u8],
    collateral: &Collateral,
    now_secs: u64,
) -> Result<Attested, AttestError> {
    let report =
        qvl_verify(raw_quote, collateral, now_secs).map_err(|e| AttestError::SignatureInvalid {
            detail: format!("{e:?}"),
        })?;

    let status = report.status.clone();
    let advisory_ids = report.advisory_ids.clone();

    if !is_tcb_acceptable(&status) {
        return Err(AttestError::TcbUnacceptable {
            status,
            advisory_ids,
        });
    }

    Ok(Attested {
        tcb_status: status,
        advisory_ids,
    })
}

/// Parse collateral from JSON.
///
/// # Why retrieval is not wrapped here
///
/// `dcap-qvl` fetches collateral asynchronously. Wrapping that would mean this crate choosing an
/// async runtime on behalf of every embedder — a decision that leaks into their process and one
/// the handbook is explicit about not making in a library.
///
/// So collateral arrives as bytes. Callers retrieve it however suits them — a PCCS, Intel's PCS, a
/// bundled copy, a cache — and the verification path stays free of I/O and runtime choices.
///
/// # Errors
///
/// Returns [`CollateralError`] if the input is not collateral this crate understands.
pub fn collateral_from_json(json: &[u8]) -> Result<Collateral, CollateralError> {
    serde_json::from_slice(json).map_err(|e| CollateralError::Malformed {
        detail: e.to_string(),
    })
}

/// Why collateral could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CollateralError {
    /// The input is not well-formed collateral.
    #[error("collateral is malformed: {detail}")]
    Malformed {
        /// What the parser reported.
        detail: String,
    },
}

/// Phala's PCCS, the default collateral source for dstack deployments.
///
/// Provided for callers assembling their own retrieval; this crate never contacts it.
pub const PHALA_PCCS_URL: &str = "https://pccs.phala.network";

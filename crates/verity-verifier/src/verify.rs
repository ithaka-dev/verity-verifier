//! The whole verification, in one call.
//!
//! Composes every check into a [`Verdict`]. Individual modules remain public so a caller can do
//! this themselves — but the assembled version is what should be used, because it is the one that
//! cannot forget a step.

use crate::attest::{self, Collateral, TcbPolicy};
use crate::binding::{check_mrconfigid, ComposeHash, VerifiedCompose};
use crate::images;
use crate::quote::Quote;
use crate::reference::{check_boot_measurements, BootReference};
use crate::verdict::{Check, Outcome, Verdict};

/// What a licence names, read from an `AppManifest` version record.
#[derive(Debug, Clone)]
pub struct LicensedVersion {
    /// The configuration the licence binds to.
    pub compose_hash: ComposeHash,
    /// The image digest the compose must reference, e.g. `sha256:d9e8…`.
    pub image_digest: String,
}

/// Everything needed to verify an endpoint, with no I/O performed inside.
#[derive(Debug, Clone)]
pub struct Evidence<'a> {
    /// The raw TDX quote, from the RA-TLS leaf certificate.
    ///
    /// **Not** a cloud provider's parsed `tcb_info`: that trusts the provider's rendering of the
    /// hardware's statement, where the raw quote trusts Intel's signature over the statement
    /// itself.
    pub raw_quote: &'a [u8],
    /// The `app-compose.json` retrieved via the record's `composeURI`.
    pub compose_document: Vec<u8>,
    /// Intel collateral for the platform.
    pub collateral: &'a Collateral,
    /// Verification time, as a Unix timestamp.
    pub now_secs: u64,
}

/// Verify an endpoint against what was licensed.
///
/// Returns a [`Verdict`] rather than a `Result`: **a failed check is an outcome, not an error.** A
/// caller needs to know *which* check failed in order to tell a misconfiguration from an attack,
/// and collapsing that into one error type throws the distinction away.
///
/// Call [`Verdict::is_trustworthy`] for the boolean.
#[must_use]
pub fn verify(
    licensed: &LicensedVersion,
    evidence: &Evidence<'_>,
    boot: Option<&BootReference>,
    tcb: &TcbPolicy,
) -> Verdict {
    let mut verdict = Verdict::new();

    // 1. Is the served document the licensed one?
    let verified =
        match VerifiedCompose::check(evidence.compose_document.clone(), &licensed.compose_hash) {
            Ok(v) => {
                verdict = verdict.record(Check::ComposeHash, Outcome::Passed);
                Some(v)
            }
            Err(e) => {
                verdict = verdict.record(Check::ComposeHash, Outcome::Failed(e.to_string()));
                None
            }
        };

    // 2. Is every image digest-pinned, and 3. does the compose name the licensed image?
    //
    // Both run against the *verified* document only. Checking an unverified one would be checking
    // a document nobody licensed.
    if let Some(verified) = verified.as_ref() {
        match images::pinned_images(verified.document()) {
            Ok(_) => verdict = verdict.record(Check::ImagesPinned, Outcome::Passed),
            Err(e) => verdict = verdict.record(Check::ImagesPinned, Outcome::Failed(e.to_string())),
        }
        match images::check_references_licensed_digest(verified.document(), &licensed.image_digest)
        {
            Ok(()) => verdict = verdict.record(Check::LicensedImagePresent, Outcome::Passed),
            Err(e) => {
                verdict =
                    verdict.record(Check::LicensedImagePresent, Outcome::Failed(e.to_string()));
            }
        }
    } else {
        let why = "compose hash did not match, so its contents were not examined".to_owned();
        verdict = verdict
            .record(Check::ImagesPinned, Outcome::Skipped(why.clone()))
            .record(Check::LicensedImagePresent, Outcome::Skipped(why));
    }

    // 4/5. Did Intel sign this quote, and is the platform's TCB acceptable?
    match attest::verify_quote(
        evidence.raw_quote,
        evidence.collateral,
        evidence.now_secs,
        tcb,
    ) {
        Ok(attested) => {
            verdict = verdict
                .record(Check::QuoteSignature, Outcome::Passed)
                .record(Check::TcbStatus, Outcome::Passed);
            let _ = attested;
        }
        Err(e @ attest::AttestError::TcbUnacceptable { .. }) => {
            // The signature verified; the platform is out of date. Recording the signature as
            // passed is the honest reading, and it keeps "not genuine" distinguishable from
            // "genuine but stale".
            verdict = verdict
                .record(Check::QuoteSignature, Outcome::Passed)
                .record(Check::TcbStatus, Outcome::Failed(e.to_string()));
        }
        Err(e) => {
            verdict = verdict
                .record(Check::QuoteSignature, Outcome::Failed(e.to_string()))
                .record(
                    Check::TcbStatus,
                    Outcome::Skipped("signature did not verify".to_owned()),
                );
        }
    }

    // 6. Does the measured configuration match the licensed one?
    match Quote::parse(evidence.raw_quote) {
        Ok(quote) => {
            match check_mrconfigid(quote.mrconfigid(), &licensed.compose_hash) {
                Ok(()) => verdict = verdict.record(Check::MrConfigId, Outcome::Passed),
                Err(e) => {
                    verdict = verdict.record(Check::MrConfigId, Outcome::Failed(e.to_string()));
                }
            }
            // 7. Boot measurements, when the caller supplied a reference.
            //
            // RTMR3 is absent from BootReference by construction and cannot be compared here.
            match boot {
                Some(reference) => match check_boot_measurements(&quote, reference) {
                    Ok(()) => verdict = verdict.record(Check::BootMeasurements, Outcome::Passed),
                    Err(e) => {
                        verdict =
                            verdict.record(Check::BootMeasurements, Outcome::Failed(e.to_string()));
                    }
                },
                None => {
                    verdict = verdict.record(
                        Check::BootMeasurements,
                        Outcome::Skipped("no OS image reference supplied".to_owned()),
                    );
                }
            }
        }
        Err(e) => {
            let why = format!("quote could not be parsed: {e}");
            verdict = verdict
                .record(Check::MrConfigId, Outcome::Failed(why.clone()))
                .record(Check::BootMeasurements, Outcome::Skipped(why));
        }
    }

    verdict
}

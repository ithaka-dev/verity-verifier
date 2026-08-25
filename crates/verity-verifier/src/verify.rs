//! The whole verification, in one call.
//!
//! Composes every check into a [`Verdict`]. Individual modules remain public so a caller can do
//! this themselves — but the assembled version is what should be used, because it is the one that
//! cannot forget a step.

use crate::attest::{self, Collateral};
use crate::binding::{check_mrconfigid, ComposeHash, MrConfigIdError, VerifiedCompose};
use crate::channel::{ChannelBinding, PeerCertificate};
use crate::images;
use crate::quote::Quote;
use crate::reference::{check_boot_measurements, BootReference};
use crate::verdict::{AttestedTcb, Check, Outcome, Unestablished, Verdict};

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
    /// The certificate presented on the connection this verdict is about.
    ///
    /// **Has no default, on purpose.** Adding this field broke every existing construction site,
    /// and that break is the feature: a `Default` or an `Option` silently meaning "skip" would let
    /// integrations keep compiling while establishing nothing about the endpoint — the precise
    /// shape of CR-1. Spell [`PeerCertificate::NotConnected`] to opt out, and read `REFUSED`.
    pub peer_certificate: PeerCertificate<'a>,
}

/// Step 6: does the measured configuration match the licensed one?
///
/// Extracted so [`verify`] stays readable — this is the one arm MA-6 gave a third outcome to.
fn mrconfigid_outcome(measured: &crate::quote::Measurement, licensed: &ComposeHash) -> Outcome {
    match check_mrconfigid(measured, licensed) {
        Ok(()) => Outcome::Passed,
        // Recognised, but this verifier cannot yet compute a reference for it: our limitation,
        // with a named remedy — run a build that supports V2 — and nothing attacker-influenced
        // about it. Distinct from `UnknownVersion` below, which is any unrecognised prefix
        // including all-zero (an unpopulated field): there is no remedy to name for evidence we
        // cannot account for, so that arm stays `Failed`. Drawing the line the other way would let
        // an unaccountable measurement disposition to "update your verifier".
        Err(e @ MrConfigIdError::UnsupportedVersion { .. }) => {
            Outcome::unestablished(Unestablished::VerifierCannotJudge, e.to_string())
        }
        // `Mismatch` and `UnknownVersion` both reached a refusal: one is a measurement that does
        // not match, the other is a prefix byte this crate cannot account for at all.
        Err(e) => Outcome::Failed(e.to_string()),
    }
}

/// Step 8: is this quote about the connection in front of us?
///
/// Every other check `verify` performs is satisfied by evidence recorded from a machine that no
/// longer exists — a genuine quote from a destroyed CVM still hashes correctly and still carries the
/// licensed `MR-CONFIG-ID`. This one is not: `report_data` carries the enclave's commitment to its
/// own TLS key, and a relay cannot reproduce it without the enclave's private key, at which point it
/// would be the enclave rather than a relay.
///
/// The comparison itself lives in [`ChannelBinding::check`] rather than here, so that it cannot be
/// performed without the all-zero refusal that precedes it.
fn channel_bound(peer: PeerCertificate<'_>, quote: &Quote) -> Outcome {
    match peer {
        PeerCertificate::Presented(leaf_cert_der) => {
            match ChannelBinding::check(leaf_cert_der, quote) {
                Ok(_) => Outcome::Passed,
                Err(e) => Outcome::Failed(e.to_string()),
            }
        }
        // Recorded, not omitted. `ChannelBound` is essential, so this already sinks
        // `is_trustworthy` — but saying *why* keeps an honest offline audit distinguishable from a
        // verifier that silently stopped performing the check, which is the distinction
        // `unrun_essentials` exists for.
        PeerCertificate::NotConnected => Outcome::Skipped(
            "no connection was made: this verdict is about recorded evidence, \
             not about an endpoint"
                .to_owned(),
        ),
    }
}

/// 4/5. Did Intel sign this quote, and is the platform's TCB acceptable?
///
/// Extracted out of [`verify`] so the mapping from an `attest::verify_quote` result to
/// `(Check::QuoteSignature, Check::TcbStatus, AttestedTcb)` is testable offline without a live
/// Intel signature — see VA-1 §6. `verify` calls this with the *literal* return value of
/// `attest::verify_quote`, so there is exactly one implementation of this mapping in the crate;
/// nothing here can drift from what `verify` actually records.
///
/// `attest::AttestError` is matched by name, not with a catch-all: it is this crate's own
/// `#[non_exhaustive]` enum, and `#[non_exhaustive]` only forces a wildcard on *external* crates —
/// in here a third variant would be a compile error at this match, the same discipline
/// [`Outcome::label`] and `verdict::weight` use, rather than silently falling into the wrong arm.
fn record_attestation(
    verdict: Verdict,
    result: Result<attest::Attested, attest::AttestError>,
) -> Verdict {
    match result {
        Ok(attested) => {
            // `tcb_status` is `UpToDate` here, by construction: `verify_quote` only reaches `Ok`
            // after its own acceptance check passed.
            let tcb = AttestedTcb::new(
                attested.tcb_status().to_owned(),
                attested.advisory_ids().to_vec(),
            );
            verdict
                .record(Check::QuoteSignature, Outcome::Passed)
                .record(Check::TcbStatus, Outcome::Passed)
                .record_attested_tcb(tcb)
        }
        Err(
            ref e @ attest::AttestError::TcbUnacceptable {
                ref status,
                ref advisory_ids,
            },
        ) => {
            // Signature verified; platform is out of date. Keep "genuine but stale" distinguishable
            // from "not genuine" — and surface the real status structurally as well as in the
            // string.
            let tcb = AttestedTcb::new(status.clone(), advisory_ids.clone());
            let detail = e.to_string();
            verdict
                .record(Check::QuoteSignature, Outcome::Passed)
                .record(Check::TcbStatus, Outcome::Failed(detail))
                .record_attested_tcb(tcb)
        }
        Err(e @ attest::AttestError::SignatureInvalid { .. }) => verdict
            .record(Check::QuoteSignature, Outcome::Failed(e.to_string()))
            .record(
                Check::TcbStatus,
                Outcome::Skipped("signature did not verify".to_owned()),
            ),
        // No `AttestedTcb` on either arm above: nothing was attested.
    }
}

/// Verify an endpoint against what was licensed.
///
/// # Prefer `connect_verified` when you are about to use the connection
///
/// This function binds a quote to a certificate **it was handed**. It performs no I/O, so it cannot
/// establish that the certificate came from the handshake being judged — a caller who supplies one
/// obtained anywhere else gets a truthful verdict about a connection they are not using. And it
/// returns a [`Verdict`] that can be ignored.
///
/// `verity_verifier::connect::connect_verified` (feature `connect`) dials the endpoint itself and
/// yields a client only on a trustworthy verdict, so neither obligation reaches the caller. **That
/// is the one to reach for from an agent.**
///
/// This one remains right for auditors reasoning about recorded evidence, for pre-purchase
/// inspection where there is no connection yet, and for any embedder without a TCP stack — offline,
/// `wasm32`, or inside another enclave. Which is why it, and not the wrapper, is the default build.
///
/// # Why a verdict and not a `Result`
///
/// **A failed check is an outcome, not an error.** A caller needs to know *which* check failed in
/// order to tell a misconfiguration from an attack, and collapsing that into one error type throws
/// the distinction away.
///
/// Call [`Verdict::is_trustworthy`] for the boolean, or [`crate::verdict::TrustworthyVerdict`] for
/// a value that cannot be held unless every essential check passed.
#[must_use]
pub fn verify(
    licensed: &LicensedVersion,
    evidence: &Evidence<'_>,
    boot: Option<&BootReference>,
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
    verdict = record_attestation(
        verdict,
        attest::verify_quote(evidence.raw_quote, evidence.collateral, evidence.now_secs),
    );

    // 6. Does the measured configuration match the licensed one?
    match Quote::parse(evidence.raw_quote) {
        Ok(quote) => {
            verdict = verdict.record(
                Check::MrConfigId,
                mrconfigid_outcome(quote.mrconfigid(), &licensed.compose_hash),
            );
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
                    // Indeterminate, not Skipped: a named remedy applies to this same call — supply
                    // a reference and call `verify` again with it. `BootMeasurements` is advisory,
                    // so this does not by itself sink the verdict, but it is no longer silent about
                    // there being an action available.
                    verdict = verdict.record(
                        Check::BootMeasurements,
                        Outcome::unestablished(
                            Unestablished::ReferenceUnavailable,
                            "no OS image reference supplied",
                        ),
                    );
                }
            }
            // 8. Is this quote about the connection in front of us?
            verdict = verdict.record(
                Check::ChannelBound,
                channel_bound(evidence.peer_certificate, &quote),
            );
        }
        Err(e) => {
            let why = format!("quote could not be parsed: {e}");
            verdict = verdict
                .record(Check::MrConfigId, Outcome::Failed(why.clone()))
                // `Skipped`, not `Indeterminate`: `MrConfigId` already reached a refusal for this
                // exact reason, so nothing here is a remedy — a caller cannot retry into a
                // different answer. Moot, not unestablished.
                .record(Check::BootMeasurements, Outcome::Skipped(why.clone()))
                // `Failed`, not `Skipped`: an unparseable quote presented as an endpoint's
                // attestation is a refusal in its own right. `Failed` throughout this file means
                // "the check reached a refusal" — contrast `channel_bound` above, where
                // `NotConnected` stays `Skipped` because there the caller declined and no property
                // was evaluated either way. Here the evidence itself is unusable, which is what
                // makes this a refusal rather than a decline.
                .record(Check::ChannelBound, Outcome::Failed(why));
        }
    }

    verdict
}

#[cfg(test)]
mod tests {
    //! The assembled-verdict coverage for VA-1 negative (b) that is reachable offline: this runs
    //! the *exact* production mapping `verify` calls, over constructed `attest` results — a live
    //! Intel signature over a degraded platform cannot be fabricated offline (no committed fixture
    //! can be one; collateral is platform-and-time-specific and expires), so this is where
    //! "every degraded status stays untrustworthy" is actually exercised. See VA-1 §6.

    // In a test a panic is the reporting mechanism, matching `channel.rs` and
    // `connect/http.rs`'s in-module test blocks.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::record_attestation;
    use crate::attest::{AttestError, Attested};
    use crate::verdict::{Check, Outcome, Verdict};

    /// Every degraded/revoked status Intel actually emits, plus one it never would. The refusal
    /// this whole change exists for.
    fn every_degraded_status() -> [&'static str; 7] {
        [
            "OutOfDate",
            "OutOfDateConfigurationNeeded",
            "SWHardeningNeeded",
            "ConfigurationNeeded",
            "ConfigurationAndSWHardeningNeeded",
            "Revoked",
            "SomethingIntelHasNeverEmitted",
        ]
    }

    /// A verdict with every essential check *other than* `QuoteSignature`/`TcbStatus` already
    /// passing — everything `record_attestation` itself does not touch.
    ///
    /// Used so `!is_trustworthy()` below demonstrates the TCB refusal sinking an otherwise
    /// trustworthy verdict, rather than an empty `Verdict::new()` that would read as untrustworthy
    /// regardless of what `record_attestation` does to it.
    fn every_other_essential_passing() -> Verdict {
        Verdict::new()
            .record(Check::ComposeHash, Outcome::Passed)
            .record(Check::ImagesPinned, Outcome::Passed)
            .record(Check::LicensedImagePresent, Outcome::Passed)
            .record(Check::MrConfigId, Outcome::Passed)
            .record(Check::ChannelBound, Outcome::Passed)
    }

    /// **The VV-01 bug, reproduced and refused.** A `TcbUnacceptable` — signature genuine, platform
    /// degraded — must sink the verdict and surface the real status, never read as trustworthy.
    ///
    /// Seeded with every other essential already `Passed`, so `!is_trustworthy()` below actually
    /// demonstrates the TCB refusal sinking an otherwise-trustworthy verdict — not merely restating
    /// that an all-but-empty `Verdict` is untrustworthy regardless of what this test does to it,
    /// which an earlier version of this test did (VA-1 review finding 3).
    ///
    /// Seen-to-fail: this test was run against a deliberately reverted arm that recorded
    /// `Check::TcbStatus, Outcome::Passed` on `TcbUnacceptable` instead of `Failed` (the original
    /// VV-01 shape) — `is_trustworthy()` returned `true` and the assertion below went red. Restored
    /// to the arm in `record_attestation`, it is green. See the commit message for the transcript.
    #[test]
    fn a_degraded_status_fails_tcb_and_sinks_the_verdict() {
        for status in every_degraded_status() {
            let advisory_ids = vec!["INTEL-SA-00615".to_owned()];
            let verdict = record_attestation(
                every_other_essential_passing(),
                Err(AttestError::TcbUnacceptable {
                    status: status.to_owned(),
                    advisory_ids: advisory_ids.clone(),
                }),
            );

            assert!(
                matches!(
                    verdict.outcome(Check::QuoteSignature),
                    Some(Outcome::Passed)
                ),
                "{status}: the hardware is genuine, and that must stay visible"
            );
            assert!(
                matches!(verdict.outcome(Check::TcbStatus), Some(Outcome::Failed(_))),
                "{status}: a degraded TCB must reach a refusal, not a pass"
            );
            assert!(
                !verdict.is_trustworthy(),
                "{status}: every other essential check passed, so the degraded TCB status alone \
                 must be what sinks this verdict"
            );

            let tcb = verdict
                .attested_tcb()
                .unwrap_or_else(|| panic!("{status}: the real status must still be legible"));
            assert_eq!(tcb.status(), status);
            assert_eq!(tcb.advisory_ids(), advisory_ids.as_slice());
            assert!(
                !tcb.is_up_to_date(),
                "{status}: AttestedTcb::is_up_to_date must agree with the refusal above — \
                 pins that it shares one definition with is_tcb_acceptable rather than a second, \
                 driftable copy"
            );
        }
    }

    /// Acceptance criterion 3: the real status must be legible **on a passing verdict**, not only
    /// on a refusal.
    ///
    /// Seen-to-fail: dropping `.record_attested_tcb(tcb)` on the `Ok` arm of `record_attestation`
    /// makes `attested_tcb()` `None` here — reverted and confirmed red, then restored. See the
    /// commit message for the transcript.
    #[test]
    fn a_passing_verdict_shows_which_status_passed() {
        let verdict = record_attestation(
            Verdict::new(),
            Ok(Attested::for_test(
                "UpToDate",
                vec!["INTEL-SA-00001".to_owned()],
            )),
        );

        assert!(matches!(
            verdict.outcome(Check::TcbStatus),
            Some(Outcome::Passed)
        ));
        let tcb = verdict
            .attested_tcb()
            .expect("the status must be legible on a pass, not only on a refusal");
        assert_eq!(tcb.status(), "UpToDate");
        assert_eq!(tcb.advisory_ids(), ["INTEL-SA-00001".to_owned()].as_slice());
        assert!(tcb.is_up_to_date());
    }

    /// A signature that never verified attests nothing — there is no platform statement to trust,
    /// genuine or otherwise.
    #[test]
    fn a_bad_signature_records_no_attested_tcb() {
        let verdict = record_attestation(
            Verdict::new(),
            Err(AttestError::SignatureInvalid {
                detail: "chain did not verify".to_owned(),
            }),
        );

        assert!(matches!(
            verdict.outcome(Check::QuoteSignature),
            Some(Outcome::Failed(_))
        ));
        assert!(matches!(
            verdict.outcome(Check::TcbStatus),
            Some(Outcome::Skipped(_))
        ));
        assert!(verdict.attested_tcb().is_none());
    }
}

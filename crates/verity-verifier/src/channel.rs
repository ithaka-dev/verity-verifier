//! Whether the quote is about the connection you are actually using.
//!
//! Every other module in this crate compares an *artifact* against a *reference*: this compose
//! against that hash, this measurement against that licensed configuration. All of them can be
//! satisfied by evidence recorded from a machine that no longer exists. This module is the one that
//! asks whether the evidence describes the endpoint in front of you.
//!
//! # The mechanism
//!
//! dStack's RA-TLS puts a commitment to the TLS key into the quote's `report_data` — the one field
//! the hardware signs but does not choose:
//!
//! ```text
//! report_data == sha512( "ratls-cert:" ‖ SubjectPublicKeyInfo DER )
//! ```
//!
//! An attacker relaying a genuine quote beside their own endpoint cannot satisfy that, because they
//! do not hold the enclave's private key — if they did, they would be the enclave rather than a
//! relay. So the comparison here is what converts a quote from evidence about *a machine* into
//! evidence about *this connection*.
//!
//! Verified end-to-end on real TDX (CVM `9be9f370`, dstack-0.5.9, 2026-08-09), from both sides:
//! `d86ffcba…e19b439f`. See `tests/fixtures/PROVENANCE.md`.
//!
//! # What this module does not establish
//!
//! **Provenance.** This crate performs no I/O, so it cannot know that the certificate it was handed
//! is the one a TLS handshake actually returned. A caller who passes a certificate fetched from
//! somewhere else gets a truthful verdict about a connection they are not using. Closing that is
//! MA-1's `connect_verified`, which owns the handshake; until it lands, the obligation sits with the
//! caller and is documented on [`PeerCertificate::Presented`] rather than pretended away.
//!
//! **Chain validity.** The leaf is issued by the Dstack App CA and is deliberately *not* chain
//! validated. Intel's signature over the quote is what establishes authenticity; a CA that vouches
//! for the key would be a second, weaker opinion about the same fact.
//!
//! # Unverified bytes are not usable
//!
//! [`ChannelBinding`] follows [`crate::binding::VerifiedCompose`]: one constructor, and it performs
//! the comparison. There is no way to hold a `ChannelBinding` that was not compared against a
//! parsed quote — so a caller cannot forget the check, and a reviewer does not have to search for
//! whether it happened.

use core::fmt;

use sha2::{Digest as _, Sha512};
use x509_cert::der::{Decode as _, Encode as _};
use x509_cert::Certificate;

use crate::quote::{Quote, ReportData, REPORT_DATA_LEN};

/// The commitment tag dStack uses for **every** guest-agent-issued certificate.
///
/// Fixed, and deliberately not derived from anything on the certificate. The `cert_usage` extension
/// (`1.3.6.1.4.1.62397.1.4`) reads `app:custom` on genuine certificates — observed on hardware,
/// CVM `9be9f370` — so a verifier that read *that* as the tag would refuse every legitimate
/// application certificate. This trap has been demonstrated, not merely imagined; the test module
/// below encodes it.
///
/// If dStack ever changes the scheme, the correct outcome is a refusal we investigate. Trying
/// candidate tags until one matches is loosening expressed as a loop.
///
/// **Private, like [`commitment_over`] and [`spki_der_of`], and for the same reason.** Those two are
/// private so that the compute-it-yourself-then-compare path does not exist; publishing the tag
/// hands back two thirds of it — everything except the all-zero refusal, which is the part that
/// matters. In a crate where every `pub` is a permanent [ADR 0014] commitment, the tag is documented
/// here and in the module header rather than exported. The test that pins it lives inside this
/// module instead of in `tests/`.
///
/// [ADR 0014]: https://github.com/ithaka-dev/verity-foundation/blob/main/docs/decisions/0014-verifier-update-discipline.md
const RATLS_TAG: &str = "ratls-cert";

/// What a public key commits to: `sha512(RATLS_TAG ‖ ":" ‖ SPKI DER)`.
///
/// Deliberately **not** comparable to [`ReportData`], and with no public constructor. The only
/// comparison this crate performs is inside [`ChannelBinding::check`], which refuses an all-zero
/// `report_data` *first*. A type that could be `==`'d against a `ReportData` would make skipping
/// that refusal the path of least resistance — and "the enclave committed to nothing" matching "I
/// expected nothing" is the one comparison that must never succeed.
///
/// `Hash` is deliberately not derived: nothing needs it, a `pub` derive is a versioning commitment
/// that can be added later and never removed, and an unexercised impl counts against this crate's
/// function-coverage floor.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Commitment([u8; REPORT_DATA_LEN]);

impl Commitment {
    /// The raw 64 bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; REPORT_DATA_LEN] {
        &self.0
    }
}

impl fmt::Debug for Commitment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Display for Commitment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// A connection whose certificate is the one the quote committed to.
///
/// The only way to construct this is [`ChannelBinding::check`], which performs the comparison.
/// Holding one is therefore evidence the check passed — it cannot be fabricated by a caller who
/// skipped it.
///
/// `verify` discards the value today; it exists as a type rather than a `bool` so MA-1's
/// `connect_verified` can require one in order to hand out a client, the way `VerifiedCompose` is
/// required in order to read a compose document.
#[derive(Debug, Clone)]
pub struct ChannelBinding {
    spki_der: Vec<u8>,
    commitment: Commitment,
}

impl ChannelBinding {
    /// Check that `leaf_cert_der` is the certificate `quote` committed to.
    ///
    /// Takes a parsed [`Quote`] rather than a [`ReportData`] on purpose: `ReportData::from_bytes`
    /// is public, and an expectation supplied on *both* sides of a comparison is not a check.
    ///
    /// # Errors
    ///
    /// Returns [`ChannelBindError`]. **All three variants are refusals**, and none of them has a
    /// degraded mode in which proceeding is correct. In particular a mismatch is not a warning: it
    /// means the quote describes a different connection from the one presented, which is the exact
    /// scenario this check exists to catch.
    // `ChannelBindError::Mismatch` carries a 64-byte `Commitment` and a 64-byte `ReportData`, a
    // shade over clippy's 128-byte threshold. `binding.rs`'s `MrConfigIdError::Mismatch` carries the
    // same shape at 48 bytes each and sits just under it, so this is a size accident rather than a
    // design difference.
    //
    // Boxing is refused rather than merely skipped. Both values *are* the content of the refusal —
    // "this certificate commits to X, the quote carries Y" is how an operator tells "wrong endpoint"
    // from "wrong certificate file" — and a `Box` would put that behind an indirection in the public
    // API for no benefit. This is a cold path that already heap-allocates the SPKI on the success
    // path, so no allocation is saved; one is only moved onto the error path.
    #[allow(clippy::result_large_err)]
    pub fn check(leaf_cert_der: &[u8], quote: &Quote) -> Result<Self, ChannelBindError> {
        let report_data = quote.report_data();

        // Before anything is compared. A workload is free to leave `report_data` empty — a quote
        // requested for some purpose other than RA-TLS carries exactly this — and an all-zero field
        // must never be allowed to match an expectation that is also empty. "Committed to nothing"
        // is a refusal to establish the binding, never a binding to nothing.
        if report_data.is_zero() {
            return Err(ChannelBindError::NoCommitment);
        }

        let spki_der = spki_der_of(leaf_cert_der)?;
        let commitment = commitment_over(&spki_der);

        // A plain `==` and not a constant-time compare, deliberately. Both operands are public
        // values: a TDX quote's `report_data` and a certificate's public key. There is no secret
        // whose timing could leak, so `subtle` here would be cargo-cult.
        if commitment.0 == *report_data.as_bytes() {
            Ok(Self {
                spki_der,
                commitment,
            })
        } else {
            Err(ChannelBindError::Mismatch {
                certificate_commits_to: commitment,
                quote_carries: *report_data,
            })
        }
    }

    /// The DER `SubjectPublicKeyInfo` this binding was established over.
    #[must_use]
    pub fn spki_der(&self) -> &[u8] {
        &self.spki_der
    }

    /// The commitment, which by construction equals the quote's `report_data`.
    #[must_use]
    pub const fn commitment(&self) -> &Commitment {
        &self.commitment
    }
}

/// Compute `sha512(RATLS_TAG ‖ ":" ‖ spki_der)`.
///
/// Crate-private, like [`spki_der_of`], and for the same reason: a public "compute the expected
/// commitment" function re-opens the compute-it-yourself-then-compare path that [`ChannelBinding`]
/// exists to close.
fn commitment_over(spki_der: &[u8]) -> Commitment {
    let mut h = Sha512::new();
    h.update(RATLS_TAG.as_bytes());
    h.update(b":");
    h.update(spki_der);
    let out = h.finalize();
    let mut bytes = [0u8; REPORT_DATA_LEN];
    bytes.copy_from_slice(&out);
    Commitment(bytes)
}

/// Lift the DER `SubjectPublicKeyInfo` out of an X.509 certificate.
///
/// **Crate-private on purpose.** Exposing a free extractor would re-open exactly the "extract it
/// yourself, then compare" path this module is shaped to close — and the extraction is the half a
/// caller can get wrong (SEC1 point instead of SPKI, CA certificate instead of end-entity, PEM body
/// instead of DER), each producing a refusal that looks like an attack.
///
/// The decode-then-re-encode is safe because `der` is a strict DER codec: it rejects non-canonical
/// encodings rather than normalising them, so an input either round-trips byte-identically or is
/// refused. That is an argument, and
/// `tests/channel_binding.rs::the_extracted_spki_is_a_byte_for_byte_slice_of_the_certificate` turns
/// it into an observation by asserting the result is a contiguous subslice of the certificate it
/// came from.
// See `ChannelBinding::check` for why the large error variant is kept rather than boxed.
#[allow(clippy::result_large_err)]
fn spki_der_of(cert_der: &[u8]) -> Result<Vec<u8>, ChannelBindError> {
    let cert =
        Certificate::from_der(cert_der).map_err(|e| ChannelBindError::UnreadableCertificate {
            reason: e.to_string(),
        })?;
    cert.tbs_certificate()
        .subject_public_key_info()
        .to_der()
        .map_err(|e| ChannelBindError::UnreadableCertificate {
            reason: e.to_string(),
        })
}

/// Why a quote and a connection could not be bound together.
///
/// `#[non_exhaustive]` for the reason [ADR 0014] gives: this crate ships inside agents that cannot
/// easily be updated, so adding a variant must stay a minor version rather than a breaking one.
///
/// [ADR 0014]: https://github.com/ithaka-dev/verity-foundation/blob/main/docs/decisions/0014-verifier-update-discipline.md
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ChannelBindError {
    /// `report_data` is all zero: the enclave committed to nothing.
    ///
    /// Checked **before** any comparison, and reported separately from a mismatch because the
    /// situations differ. A mismatch says the quote describes a different connection; this says the
    /// quote makes no claim about any connection at all, which is what a quote requested for some
    /// other purpose looks like.
    #[error("the quote's report_data is all zero: this enclave committed to no certificate")]
    NoCommitment,

    /// The bytes supplied are not an X.509 certificate this crate can read.
    ///
    /// Distinct from a mismatch on purpose: this is a problem with the *input*, not a statement
    /// about the endpoint. Collapsing the two would send someone hunting an attack that is not
    /// there — most often after handing PEM to something that takes DER.
    #[error("the presented certificate could not be parsed: {reason}")]
    UnreadableCertificate {
        /// What the DER decoder reported.
        reason: String,
    },

    /// The connection's key is not the one the quote attested.
    ///
    /// **The refusal CR-1 exists to produce.** A genuine quote presented over somebody else's
    /// connection lands here, with every other check still passing.
    ///
    /// Fields are named after their **source** rather than after a role. `binding.rs` uses
    /// `expected` for the licensed reference and `measured` for what the quote carried; here the
    /// quote *is* the reference and the certificate is the untrusted input, so reusing those names
    /// one module away would invert them — in the crate whose whole discipline is knowing which
    /// side is trusted.
    #[error(
        "channel binding failed: this certificate commits to {certificate_commits_to}, \
             the quote carries {quote_carries}"
    )]
    Mismatch {
        /// Computed from the presented certificate — **untrusted input**.
        certificate_commits_to: Commitment,
        /// Read from the Intel-signed quote — **the reference**.
        quote_carries: ReportData,
    },
}

/// What the caller can say about the connection being verified.
///
/// A named type rather than `Option<&[u8]>`, because `boot: Option<&BootReference>` sits in the
/// same [`crate::verify::verify`] call and means the *opposite*: optional, verdict unaffected. Two
/// `Option`s with opposite consequences, one line apart, in the function CR-1 was found in, is how
/// this mistake gets made twice. Absence here is spelled `NotConnected`, so an author has to type
/// the word and then read `REFUSED`.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum PeerCertificate<'a> {
    /// DER of the leaf presented on the TLS handshake **with the endpoint being verified**.
    ///
    /// It must come from *that* handshake. This crate performs no I/O and cannot check its
    /// provenance, so a certificate obtained anywhere else yields a truthful verdict about a
    /// connection you are not using. The path that removes this obligation from the caller is
    /// MA-1's `connect_verified`, which dials the endpoint itself.
    ///
    /// dStack's gateway matters here: on `<app_id>-<port>.<domain>` it *terminates* TLS and hands
    /// the client a valid Let's Encrypt certificate for the gateway, so ordinary TLS verification
    /// succeeds while the peer is not the enclave. Only the `s`-suffixed passthrough form reaches
    /// the enclave's own certificate. A verifier handed the terminating form's certificate refuses
    /// — which is correct, and is the enforcement, rather than a hostname heuristic in a library
    /// that does no hostname validation.
    Presented(&'a [u8]),
    /// No connection was opened.
    ///
    /// `ChannelBound` cannot pass, so the verdict cannot be trustworthy. This is the honest input
    /// for offline audit of recorded evidence — reading a quote out of a file establishes what ran
    /// somewhere, never what you are talking to.
    NotConnected,
}

#[cfg(test)]
mod tests {
    //! The tag, pinned where it lives.
    //!
    //! This is here rather than in `tests/channel_binding.rs` because [`RATLS_TAG`] is private —
    //! see its doc comment. A test that required publishing it would be a test dictating public API
    //! in a crate where every `pub` is a permanent ADR 0014 commitment, which is backwards.

    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use sha2::{Digest as _, Sha512};

    use super::{commitment_over, spki_der_of, RATLS_TAG};
    use crate::quote::Quote;
    use crate::quote::REPORT_DATA_LEN;

    const RATLS_LEAF_PEM: &[u8] = include_bytes!("../tests/fixtures/ratls-leaf-dstack-0.5.9.pem");
    const RATLS_QUOTE_HEX: &str =
        include_str!("../tests/fixtures/ratls-leaf-dstack-0.5.9.quote.hex");

    fn ratls_leaf_der() -> Vec<u8> {
        let (label, der) = pem_rfc7468::decode_vec(RATLS_LEAF_PEM).expect("fixture is PEM");
        assert_eq!(label, "CERTIFICATE");
        der
    }

    fn ratls_quote() -> Quote {
        let hex = RATLS_QUOTE_HEX.trim();
        let bytes: Vec<u8> = (0..hex.len() / 2)
            .map(|i| {
                u8::from_str_radix(hex.get(i * 2..i * 2 + 2).expect("in range"), 16)
                    .expect("fixture is hex")
            })
            .collect();
        Quote::parse(&bytes).expect("the 0.5.9 fixture parses")
    }

    /// **The trap, encoded.** Demonstrated on hardware, not inferred.
    ///
    /// The genuine certificate in `tests/fixtures/` carries a `cert_usage` extension reading
    /// `app:custom`. Deriving the commitment tag from `cert_usage` is an entirely reasonable-looking
    /// thing to do, and it would refuse **every** legitimate application certificate — a failure
    /// that arrives as a mismatch and looks exactly like an attack.
    ///
    /// So the tag is fixed, nothing reads the certificate to determine it, and this test holds both
    /// halves: that `ratls-cert` is what the hardware used, and that `app:custom` is not.
    #[test]
    fn deriving_the_tag_from_cert_usage_would_refuse_a_genuine_certificate() {
        assert_eq!(RATLS_TAG, "ratls-cert");

        let spki = spki_der_of(&ratls_leaf_der()).expect("the fixture is a certificate");
        let quote = ratls_quote();

        assert_eq!(
            commitment_over(&spki).0,
            *quote.report_data().as_bytes(),
            "`ratls-cert` is the tag the hardware actually used"
        );

        // The same key, the same hash, the tag `cert_usage` would have suggested.
        let mut wrong = Sha512::new();
        wrong.update(b"app:custom:");
        wrong.update(&spki);
        let wrong: [u8; REPORT_DATA_LEN] = wrong.finalize().into();

        assert_ne!(
            wrong,
            *quote.report_data().as_bytes(),
            "if this ever matches, the scheme changed — re-verify the crate, do not loosen it"
        );
    }
}

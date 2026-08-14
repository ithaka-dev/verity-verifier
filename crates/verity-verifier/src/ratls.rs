//! Lifting the raw TDX quote out of an RA-TLS certificate.
//!
//! dStack's guest agent issues its TLS certificate with the quote carried in a private X.509
//! extension, `1.3.6.1.4.1.62397.1.1`. That is what makes a *connection* self-describing: the
//! evidence and the key it commits to travel together, so a verifier that reads both out of the
//! same certificate is reasoning about one object rather than correlating two.
//!
//! This module performs no I/O. It is ungated for the same reason [`crate::channel`] is — it needs
//! only a DER parse, no Intel collateral and no `ring` — so a caller who already holds a
//! certificate can use it offline, in `wasm32`, or inside another enclave.
//!
//! # The double wrapper, and the trap under it
//!
//! X.509 puts every `extnValue` in an OCTET STRING. dStack's value is *itself* a DER OCTET STRING,
//! so the quote begins **8 bytes** after the OID, not 4 (`tests/fixtures/PROVENANCE.md` records the
//! arithmetic against the captured certificate):
//!
//! ```text
//! 06 0A 2B 06 01 04 01 83 E7 3D 01 01   OID 1.3.6.1.4.1.62397.1.1
//! 04 82 13 96                            extnValue OCTET STRING, 5014 bytes
//!    04 82 13 92                         nested   OCTET STRING, 5010 bytes
//!       04 00 02 00 81 00 00 00          the quote: version 4, TDX
//! ```
//!
//! Stripping four bytes instead of eight yields a buffer that still *looks* like a quote — right
//! length, right neighbourhood — and fails later, somewhere less obvious. `script/mutate.sh` scores
//! that exact edit.
//!
//! # It unwraps; it does not scan
//!
//! `closed-loop/08-gateway-tls-termination.sh` searches the extension for the TDX v4 header
//! (`0400020081000000`) because a shell script capturing evidence should be forgiving about an
//! encoding it did not write. **The library must not**, and the difference is deliberate: a scan
//! finds a quote-shaped substring at whatever offset it happens to sit, so if dStack ever wraps the
//! quote in a versioned envelope, a scanner would silently mis-slice it while a strict unwrap
//! refuses. Validating what comes out — structure version 4, `tee_type == 0x81` — is
//! [`crate::quote::Quote::parse`]'s existing job, so an envelope change surfaces as a clear refusal
//! we investigate. That is ADR 0009 rule 3 applied to a parser: narrow *what* is read, never loosen
//! *how strictly* it is read.

use x509_cert::der::asn1::{ObjectIdentifier, OctetString};
use x509_cert::der::Decode as _;
use x509_cert::Certificate;

/// dStack's attestation extension: the raw TDX quote for the key in this certificate.
///
/// Private (`1.3.6.1.4.1.62397` is Phala's PEN arc), fixed, and deliberately not discovered by
/// searching the certificate for something quote-shaped — see the module docs.
const DSTACK_QUOTE_OID_STR: &str = "1.3.6.1.4.1.62397.1.1";

/// The same arc, parsed. Derived from [`DSTACK_QUOTE_OID_STR`] rather than written out a second
/// time, so the value this crate *searches for* and the value it *reports* cannot drift apart.
const DSTACK_QUOTE_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap(DSTACK_QUOTE_OID_STR);

/// The raw TDX quote carried in an RA-TLS certificate's attestation extension.
///
/// The bytes come back exactly as dStack wrote them, ready for
/// [`crate::quote::Quote::parse`] and [`crate::attest::verify_quote`]. Nothing here validates that
/// they *are* a quote — that is `Quote::parse`'s job, and keeping the two apart is what makes an
/// envelope change refuse rather than mis-parse.
///
/// # Errors
///
/// - [`AttestationError::UnreadableCertificate`] — not an X.509 certificate this crate can read.
/// - [`AttestationError::Missing`] — no attestation extension. **This is what a gateway's Let's
///   Encrypt certificate looks like, and what any non-enclave endpoint looks like.** It is a
///   refusal, not a reason to look elsewhere for a quote.
/// - [`AttestationError::UnreadableEnvelope`] — the extension is present and not shaped the way
///   this verifier understands.
pub fn quote_from_certificate(cert_der: &[u8]) -> Result<Vec<u8>, AttestationError> {
    let cert =
        Certificate::from_der(cert_der).map_err(|e| AttestationError::UnreadableCertificate {
            reason: e.to_string(),
        })?;

    let extension = cert
        .tbs_certificate()
        .extensions()
        .into_iter()
        .flatten()
        .find(|e| e.extn_id == DSTACK_QUOTE_OID)
        .ok_or(AttestationError::Missing)?;

    // The nested layer. `x509-cert` has already removed the outer OCTET STRING that X.509 mandates;
    // `extn_value.as_bytes()` is its content, which for dStack is itself a DER OCTET STRING.
    //
    // Decoded with the strict `der` codec rather than by stepping over a length prefix by hand: the
    // codec rejects non-canonical BER instead of normalising it, so an input either is a
    // well-formed nested OCTET STRING or is refused. A hand-rolled skip would accept a long-form
    // length it did not expect and hand back a slice at the wrong offset — the same class of defect
    // as the off-by-4 above, and silent in the same way.
    let inner = OctetString::from_der(extension.extn_value.as_bytes()).map_err(|e| {
        AttestationError::UnreadableEnvelope {
            reason: e.to_string(),
        }
    })?;
    Ok(inner.into_bytes().into_vec())
}

/// The OID dStack uses for its attestation extension, as a dotted string.
///
/// A *label*, not a lever: no check in this crate is configurable by it, and
/// [`quote_from_certificate`] does not take it as an argument. It is here so that anything building
/// an RA-TLS certificate — the tests below, a capture tool, a probe — names the same arc this
/// verifier looks for, rather than re-deriving it from documentation and getting one sub-identifier
/// wrong.
#[must_use]
pub const fn attestation_oid() -> &'static str {
    DSTACK_QUOTE_OID_STR
}

/// Encode a raw quote the way dStack writes it into `extnValue`: as a DER OCTET STRING.
///
/// The exact inverse of the unwrap in [`quote_from_certificate`], and the reason it is public is
/// narrow and specific: **a test that hand-assembles this encoding can agree with a broken
/// extractor.** Writing `04 82 <hi> <lo> ‖ quote` by hand in a test always produces long-form
/// lengths, so an extractor that mishandled the short form would pass; going through the same
/// strict `der` codec means the tests exercise the encoding the hardware actually emits, which
/// `tests/ratls_extraction.rs` then pins against a captured certificate.
///
/// It writes; it decides nothing. There is no check in this crate that this function can loosen.
///
/// # Errors
///
/// [`AttestationError::UnreadableEnvelope`] if the input cannot be encoded as an OCTET STRING,
/// which for any real quote cannot happen.
pub fn extension_value_for_quote(raw_quote: &[u8]) -> Result<Vec<u8>, AttestationError> {
    use x509_cert::der::Encode as _;

    OctetString::new(raw_quote)
        .and_then(|o| o.to_der())
        .map_err(|e| AttestationError::UnreadableEnvelope {
            reason: e.to_string(),
        })
}

/// Why a quote could not be lifted out of a certificate.
///
/// `#[non_exhaustive]` per [ADR 0014]: this crate ships inside agents that cannot easily be
/// updated, so adding a variant must stay a minor version rather than a breaking one.
///
/// [ADR 0014]: https://github.com/ithaka-dev/verity-foundation/blob/main/docs/decisions/0014-verifier-update-discipline.md
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AttestationError {
    /// The bytes are not an X.509 certificate this crate can read.
    ///
    /// Distinct from [`AttestationError::Missing`] on purpose: this is a problem with the *input*,
    /// not a statement about the endpoint. Collapsing the two would send someone hunting an attack
    /// that is not there — most often after handing PEM to something that takes DER.
    #[error("the presented certificate could not be parsed: {reason}")]
    UnreadableCertificate {
        /// What the DER decoder reported.
        reason: String,
    },
    /// The certificate carries no dStack attestation extension.
    ///
    /// **This endpoint is not presenting an enclave's certificate.** It is what a gateway's Let's
    /// Encrypt certificate looks like on the TLS-terminating form, and what any ordinary web server
    /// looks like. Reported separately from a parse failure because the certificate is perfectly
    /// valid — it simply belongs to something that is not an enclave.
    #[error("this certificate carries no dStack attestation extension: it is not an enclave's")]
    Missing,
    /// The extension is present and not shaped the way this verifier understands.
    ///
    /// The refusal an envelope change is meant to produce. **Do not respond by scanning for the
    /// quote header** — see the module docs; that trades a loud refusal for a silent mis-slice.
    #[error("the attestation extension is not a nested DER OCTET STRING: {reason}")]
    UnreadableEnvelope {
        /// What the DER decoder reported.
        reason: String,
    },
}

//! Agent-side attestation verification for Project Verity.
//!
//! Given an endpoint, its attestation evidence, and the licensed version record, decide whether
//! what is running is what was licensed — and refuse on mismatch.
//!
//! # Not yet functional
//!
//! This crate is scaffolding. **No result it produces means anything yet.** Do not wire it into
//! anything that makes a trust decision until this notice is removed and a version is tagged.
//!
//! ## Specifically: there is no channel binding, and its absence is not visible in a verdict
//!
//! Every check this crate performs treats the TDX quote as a **detached artifact**. Nothing ties
//! the quote to the connection an agent actually opens, so a genuine quote recorded from one CVM —
//! including one that has since been destroyed — paired with an endpoint an attacker controls
//! passes every essential check and yields `is_trustworthy() == true`.
//!
//! This needs no man-in-the-middle and no network position: a hostile or buggy orchestrator
//! returning a real `cvm_id`'s quote beside its own endpoint is sufficient. The agent then sends
//! the holder's data to the attacker while `licensed_composeHash == attested_composeHash` holds
//! throughout, and while every invariant the design states reads as satisfied.
//!
//! The primitive that closes this exists — dStack's RA-TLS commits the TLS key into the quote's
//! `report_data`, which [`quote::Quote::report_data`] now parses — but **the comparison is not
//! implemented**, `Evidence` cannot yet carry a certificate, and `ChannelBound` is not in
//! [`verdict::Check::essential`]. Until all three land, treat a trustworthy verdict from this crate
//! as establishing *what is running somewhere*, never *what you are talking to*.
//!
//! Tracked as CR-1 of the 2026-08-09 system-design review. The refusal this crate cannot yet
//! produce is demonstrated by `verity-foundation/closed-loop/06-refuses-relayed-endpoint.sh`,
//! which is expected to fail until the check exists.
//!
//! # The three rules
//!
//! Recorded here because they are the ones violated under deadline pressure, and because a reader
//! who never opens the specification will still see them.
//!
//! 1. **Never compare `RTMR3`.** It accumulates `app-id`, `instance-id` and `mr-kms`, and the last
//!    of those varies per boot. No stable reference exists, so comparing it produces intermittent
//!    false mismatches.
//! 2. **Branch on the `MR-CONFIG-ID` prefix byte; never assume `0x01`.** V1 and V2 are different
//!    formats and which one applies is a property of the platform version, not of this crate.
//! 3. **Never loosen a check to resolve a mismatch.** Rule 1 guarantees somebody eventually sees a
//!    spurious failure, and relaxing a comparison until it passes converts this crate into
//!    decoration while everything continues to look like it works. The correct response is to
//!    narrow *what* is compared to values that are legitimately stable — never to weaken *how
//!    strictly* they are compared.
//!
//! # Using it
//!
//! ```no_run
//! use verity_verifier::verify::{verify, Evidence, LicensedVersion};
//! use verity_verifier::{attest::TcbPolicy, binding::ComposeHash};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let (raw_quote, compose_document, collateral) = (vec![], vec![], unimplemented!());
//! let licensed = LicensedVersion {
//!     compose_hash: ComposeHash::parse_hex("64690ef3…")?,
//!     image_digest: "sha256:d9e853e8…".to_owned(),
//! };
//!
//! let verdict = verify(
//!     &licensed,
//!     &Evidence { raw_quote: &raw_quote, compose_document, collateral: &collateral, now_secs: 0 },
//!     None,
//!     &TcbPolicy::default(),
//! );
//!
//! // Never a bare boolean: the verdict says which checks ran, and what each concluded.
//! if !verdict.is_trustworthy() {
//!     eprintln!("{verdict}");
//!     return Err("refusing to trust this endpoint".into());
//! }
//! # Ok(()) }
//! ```
//!
//! See [ADR 0009] for the full verification model.
//!
//! [ADR 0009]: https://github.com/ithaka-dev/verity-foundation/blob/main/docs/decisions/0009-verification-model.md

#![doc(html_root_url = "https://docs.rs/verity-verifier")]

#[cfg(feature = "attest")]
pub mod attest;
pub mod binding;
pub mod compose;
pub mod images;
pub mod quote;
pub mod reference;
pub mod verdict;
#[cfg(feature = "attest")]
pub mod verify;

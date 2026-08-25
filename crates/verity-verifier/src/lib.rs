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
//! ## Channel binding: what it now establishes, and what it still trusts you for
//!
//! Until CR-1 of the 2026-08-09 system-design review, every check here treated the TDX quote as a
//! **detached artifact**: a genuine quote recorded from one CVM — including one since destroyed —
//! paired with an endpoint an attacker controls passed every essential check and returned
//! `is_trustworthy() == true`. That is closed. [`channel::ChannelBinding::check`] compares the
//! quote's `report_data` against the certificate presented on the connection, and
//! [`verdict::Check::ChannelBound`] is in [`verdict::Check::essential`], so a verdict that did not
//! establish it cannot be trustworthy.
//!
//! ## The provenance gap, and what closes it
//!
//! [`verify::verify`] binds a quote to a certificate **it was handed**. Performing no I/O, it cannot
//! know that certificate came from your TLS handshake — so a caller who supplies one obtained
//! elsewhere gets a truthful verdict about a connection they are not using. The second half of the
//! same finding: a [`verdict::Verdict`] can be ignored, so invariant I1 rested on every agent author
//! remembering `if !verdict.is_trustworthy() { return }`.
//!
//! [`connect::connect_verified`] closes both, behind the non-default `connect` feature. It owns the
//! socket, the handshake, the certificate and the quote; the caller supplies none of them. And a
//! [`connect::VerifiedClient`] has no public constructor and no path from an untrustworthy verdict,
//! so the check cannot be skipped by forgetting it. **It is the one to reach for from an agent.**
//!
//! **`verify()` is not deprecated by that.** It is the right call for auditors reasoning about
//! recorded evidence, for pre-purchase inspection where there is no connection yet, and for any
//! embedder without a TCP stack — offline, `wasm32`, or inside another enclave. That path stays the
//! default build; the wrapper is additive to it.
//!
//! Two more things a reader should not have to discover the hard way:
//!
//! - **dStack's default endpoint form cannot be channel bound.** The gateway terminates TLS on
//!   `<app_id>-<port>.<domain>` and hands the client a valid Let's Encrypt certificate for the
//!   *gateway*, so ordinary TLS verification succeeds while the peer is not the enclave. Only the
//!   `s`-suffixed passthrough form reaches the enclave's own certificate. This crate refuses the
//!   terminating form rather than falling back, because the certificate simply does not match.
//! - **The leaf is not chain validated.** Intel's signature over the quote is what establishes
//!   authenticity; the Dstack App CA's opinion about the key would be a second, weaker one.
//!
//! The refusal is demonstrated end-to-end by
//! `verity-foundation/closed-loop/06-refuses-relayed-endpoint.sh`.
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
//! use verity_verifier::binding::ComposeHash;
//! use verity_verifier::channel::PeerCertificate;
//! use verity_verifier::verify::{verify, Evidence, LicensedVersion};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let (raw_quote, compose_document, collateral) = (vec![], vec![], unimplemented!());
//! # let leaf_cert_der: Vec<u8> = vec![];
//! let licensed = LicensedVersion {
//!     compose_hash: ComposeHash::parse_hex("64690ef3…")?,
//!     image_digest: "sha256:d9e853e8…".to_owned(),
//! };
//!
//! let verdict = verify(
//!     &licensed,
//!     &Evidence {
//!         raw_quote: &raw_quote,
//!         compose_document,
//!         collateral: &collateral,
//!         now_secs: 0,
//!         // The leaf from *this endpoint's* handshake. `PeerCertificate::NotConnected` is the
//!         // honest alternative for offline audit — and makes the verdict untrustworthy, because
//!         // a quote in a file says what ran somewhere, not what you are talking to.
//!         peer_certificate: PeerCertificate::Presented(&leaf_cert_der),
//!     },
//!     None,
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

// The `connect` feature opens a socket. It cannot build for wasm32 — `ring` has no backend for
// that target — and, more to the point, it could not do its job there if it did: see the message.
//
// This is a deliberate, narrow exception to Cargo's additivity rule, and it is the safe direction.
// The combination it rejects could not link anyway; all this does is replace a wall of build-script
// output with a sentence. Keep it in `lib.rs` rather than in `connect.rs` so it is the first thing
// rustc prints.
//
// **CI invariant, and it is load-bearing:** never combine `--all-features` with
// `--target wasm32-unknown-unknown`. The wasm job builds `-p verity-verifier-wasm`, which depends
// on this crate with `default-features = false` and enables no feature, so nothing leaks under
// resolver v2.
#[cfg(all(feature = "connect", target_arch = "wasm32"))]
compile_error!(
    "the `connect` feature opens a TCP socket and performs a TLS handshake; it cannot build for \
     wasm32. A browser cannot open a raw TLS connection or inspect a peer certificate, so the \
     provenance `connect_verified` exists to establish is not obtainable there. Use `verify()` \
     with a certificate your host environment supplies — in Node, \
     `socket.getPeerX509Certificate().raw`."
);

#[cfg(feature = "attest")]
pub mod attest;
pub mod binding;
// Ungated, unlike `verify`. Channel binding needs only SHA-512 and an X.509 parse — no Intel
// collateral and no `ring` — so putting it behind `attest` would leave the WASM bindings unable to
// perform the one check CR-1 is about.
pub mod channel;
pub mod compose;
#[cfg(feature = "connect")]
pub mod connect;
// Ungated, and adds no dependency: `endpoint` is string logic and `ratls` needs only the `x509-cert`
// parse that `channel` already requires. They are the parts of MA-1 that are useful without a
// socket — classifying an endpoint before deciding to dial it, and reading a quote out of a
// certificate captured by something else — so gating them behind `connect` would have put pure
// functions behind a TCP stack.
pub mod endpoint;
pub mod images;
pub mod quote;
pub mod ratls;
pub mod reference;
pub mod verdict;
#[cfg(feature = "attest")]
pub mod verify;

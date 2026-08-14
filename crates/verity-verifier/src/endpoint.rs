//! What kind of endpoint this is, decided before a socket is opened.
//!
//! # Why a hostname classifier lives in a crate that does no hostname validation
//!
//! dStack's gateway routes on an SNI suffix (`gateway/src/proxy.rs`, v0.5.9):
//!
//! ```text
//! <app_id>-<port>.<domain>     the gateway TERMINATES TLS
//! <app_id>-<port>s.<domain>    the gateway passes TLS through to the app
//! ```
//!
//! On the terminating form the client completes its handshake **with the gateway**, which presents
//! a valid Let's Encrypt certificate for itself. Ordinary TLS verification *succeeds* while the
//! peer is not the enclave, so nothing looks wrong — and channel binding cannot succeed, because
//! `report_data` commits to a key the client never sees.
//!
//! The refusal is already produced by consequence: the gateway's certificate does not match the
//! quote, so [`crate::channel::ChannelBinding::check`] fails. **This module changes nothing about
//! whether that refusal happens; it changes what a human is told when it does.** A bare
//! `channel_bound FAILED` on the form the platform's own API advertises reads as "the check is too
//! strict", and inviting that reading is inviting the loosening ADR 0009 rule 3 forbids. Working it
//! out cost four CVM runs once already
//! (`records/experiments/2026-08-09-gateway-tls-mode.md`).
//!
//! So: **a classifier, never a gate.** [`EndpointForm::Unrecognised`] is permitted and silent — a
//! self-hosted deployment, a local test server and a relay all land there, and the enforcement for
//! all three is channel binding. The only thing the classification buys is a distinct, actionable
//! refusal on the one shape that is known to be unbindable.
//!
//! # Two policies, one rule
//!
//! `connect_verified` owns the connection, so it refuses [`EndpointForm::DstackTerminating`] before
//! dialling. `examples/verify-attestation.rs` takes a caller-supplied certificate and only prints a
//! warning. The rule is here, in one place tests can reach; the policies are at the two call sites.
//! While the rule lived in the example nothing could test it, which is the defect
//! [`crate::verdict::transcript_line`] was moved out of the example to fix.

use core::fmt;

/// dStack's app-id: 20 bytes, rendered as hex.
///
/// Pinned at 40 characters rather than "some hex", because that is what the platform emits —
/// `38817d24b2e3bd9cdeae1acc60aaec7ea0957d18`, recorded in `tests/fixtures/PROVENANCE.md`.
/// Accepting any length made `ab-80.example.com` classify as a gateway host, and a diagnostic that
/// cries wolf gets ignored on the day it is right. `tests/endpoint.rs` keeps that false positive as
/// a test rather than as a comment.
const APP_ID_HEX_LEN: usize = 40;

/// The only scheme that can ever be channel bound.
const HTTPS: &str = "https";

/// The port an `https` endpoint uses when it names none.
const DEFAULT_HTTPS_PORT: u16 = 443;

/// Which dStack gateway route an endpoint names.
///
/// `#[non_exhaustive]` for [ADR 0014]'s reason: this crate ships inside agents that cannot easily be
/// updated, so recognising a further form must stay a minor version.
///
/// [ADR 0014]: https://github.com/ithaka-dev/verity-foundation/blob/main/docs/decisions/0014-verifier-update-discipline.md
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EndpointForm {
    /// `<40 hex>-<port>s.<domain>` — the gateway passes TLS through to the app.
    ///
    /// The only dStack form whose handshake reaches the enclave's own certificate.
    DstackPassthrough,
    /// `<40 hex>-<port>.<domain>` — **the gateway terminates TLS.**
    ///
    /// It presents a valid, publicly trusted certificate for *itself*. Ordinary TLS verification
    /// succeeds; channel binding cannot. This is the form the platform's API advertises, which is
    /// why it is worth naming rather than letting it arrive as a bare mismatch.
    DstackTerminating,
    /// Not a dStack gateway host this crate recognises.
    ///
    /// **Permitted, and not a warning.** A self-hosted deployment, a local test server and a relay
    /// all land here; the enforcement for all three is the channel-binding check. A hostname
    /// heuristic is a diagnostic, never a gate.
    Unrecognised,
}

/// A parsed `https` endpoint, classified by form.
///
/// Deliberately not a general URL type. It holds what dialling and verifying need — host, port, and
/// the classification — and nothing else, so it cannot grow into a second, weaker place where
/// somebody decides what an endpoint means.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    url: String,
    host: String,
    port: u16,
    form: EndpointForm,
}

impl Endpoint {
    /// Parse an endpoint URL.
    ///
    /// # Errors
    ///
    /// Returns [`EndpointError`] for a missing or non-`https` scheme, an empty host, or a port that
    /// is not a number.
    ///
    /// **`http://` is refused outright.** A plaintext endpoint carries no certificate, so it can
    /// never be channel bound — accepting one would mean accepting a connection whose verification
    /// is impossible in principle, which is worse than a connection whose verification failed.
    ///
    /// # Examples
    ///
    /// ```
    /// use verity_verifier::endpoint::{Endpoint, EndpointForm};
    ///
    /// let e = Endpoint::parse("https://example.com")?;
    /// assert_eq!(e.port(), 443);
    /// assert_eq!(e.form(), EndpointForm::Unrecognised);
    /// # Ok::<(), verity_verifier::endpoint::EndpointError>(())
    /// ```
    pub fn parse(url: &str) -> Result<Self, EndpointError> {
        let url = url.trim();
        // Hand-split rather than pulled in as a URL crate. This is not the workspace's
        // "never hand-roll a parser for structured input" case: that rule is about formats whose
        // *content* an attacker chooses and where a missed case hides something (a tag among image
        // digests, a key among YAML anchors). Here the input is one operator-supplied string, every
        // component is required to be present and well formed, and anything unrecognised becomes
        // `Unrecognised`, which is the permissive-and-still-checked outcome. A URL crate would add
        // a dependency to an *ungated* module that currently adds none — see `lib.rs`.
        let (scheme, rest) = url
            .split_once("://")
            .ok_or_else(|| EndpointError::NotHttps {
                scheme: String::new(),
            })?;
        if !scheme.eq_ignore_ascii_case(HTTPS) {
            return Err(EndpointError::NotHttps {
                scheme: scheme.to_owned(),
            });
        }

        // Authority is everything before the first `/`, `?` or `#`.
        let authority = rest
            .split(['/', '?', '#'])
            .next()
            .unwrap_or_default()
            .to_owned();
        // Split the port off the *last* colon so an IPv6 literal keeps its own. Bracketed hosts are
        // not otherwise handled: dStack gateway hosts are names, and an operator dialling a raw
        // IPv6 literal gets `Unrecognised` plus whatever the resolver makes of it.
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) if !h.ends_with(']') => (
                h.to_owned(),
                // Port 0 is refused as well as unparseable text. `parse::<u16>()` accepts it, and it
                // means "any free port" to `bind` — there is nothing to *connect* to, so accepting
                // it would turn a nonsense endpoint into a confusing connection failure later rather
                // than a clear refusal here. `BadPort` documents `1..=65535`; this is what makes
                // that true rather than aspirational.
                match p.parse::<u16>() {
                    Ok(0) | Err(_) => return Err(EndpointError::BadPort { port: p.to_owned() }),
                    Ok(port) => port,
                },
            ),
            _ => (authority, DEFAULT_HTTPS_PORT),
        };
        if host.is_empty() {
            return Err(EndpointError::NoHost);
        }

        let form = classify(&host);
        Ok(Self {
            url: url.to_owned(),
            host,
            port,
            form,
        })
    }

    /// The host to dial and to send as SNI.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The port to dial. 443 when the URL named none.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// The URL as supplied, trimmed.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Which gateway route this host names.
    #[must_use]
    pub const fn form(&self) -> EndpointForm {
        self.form
    }

    /// The passthrough host this terminating host should have been.
    ///
    /// `Some` only for [`EndpointForm::DstackTerminating`]. This is what a refusal quotes back, so
    /// the operator is told the fix rather than left to infer it from a hash mismatch.
    #[must_use]
    pub fn passthrough_form(&self) -> Option<String> {
        if self.form != EndpointForm::DstackTerminating {
            return None;
        }
        // `classify` already established the shape, so both splits succeed. Written as a chain of
        // `?` rather than asserted, because a `const`-shaped invariant that is re-derived is one
        // that cannot drift out of step with the classifier above it.
        let (first_label, domain) = self.host.split_once('.')?;
        let (app_id, port) = first_label.rsplit_once('-')?;
        Some(format!("{app_id}-{port}s.{domain}"))
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.url)
    }
}

/// Decide which gateway route a host names.
///
/// The rule, moved verbatim from `examples/verify-attestation.rs::warn_if_tls_terminating`:
/// `<40 hex chars>-<port>` terminates, `<40 hex chars>-<port>s` passes through. Splitting on the
/// **last** `-` puts the `s` suffix into `port`, where `is_ascii_digit` rejects it — which is
/// exactly right, because the passthrough form must not be classified as terminating.
fn classify(host: &str) -> EndpointForm {
    let Some((first_label, _)) = host.split_once('.') else {
        return EndpointForm::Unrecognised;
    };
    let Some((app_id, port)) = first_label.rsplit_once('-') else {
        return EndpointForm::Unrecognised;
    };
    if app_id.len() != APP_ID_HEX_LEN || !app_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return EndpointForm::Unrecognised;
    }
    match port.strip_suffix('s') {
        // `<app-id>-<digits>s` — passthrough. The port part must still be all digits, so a host
        // like `<app-id>-abcs.example.com` stays unrecognised rather than being promoted to a form
        // this crate claims to understand.
        Some(digits) if !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit()) => {
            EndpointForm::DstackPassthrough
        }
        _ if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => {
            EndpointForm::DstackTerminating
        }
        _ => EndpointForm::Unrecognised,
    }
}

/// Why an endpoint URL could not be used.
///
/// `#[non_exhaustive]` per [ADR 0014].
///
/// [ADR 0014]: https://github.com/ithaka-dev/verity-foundation/blob/main/docs/decisions/0014-verifier-update-discipline.md
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum EndpointError {
    /// The scheme is missing or is not `https`.
    ///
    /// Refused rather than upgraded. A plaintext endpoint presents no certificate at all, so there
    /// is nothing for the quote to commit to — this is not a connection that would fail
    /// verification, it is one that cannot be verified.
    #[error("endpoint scheme is `{scheme}`, and only https can be channel bound")]
    NotHttps {
        /// What was found before `://`, empty if there was no `://` at all.
        scheme: String,
    },
    /// The URL has no host.
    #[error("endpoint has no host")]
    NoHost,
    /// The port is not a number in `1..=65535`.
    ///
    /// Includes `0`, which parses as a `u16` and means "any free port" when binding. Nothing can be
    /// connected to on port 0, so it is refused here rather than becoming a puzzling connection
    /// failure further down.
    #[error("endpoint port `{port}` is not a usable port number")]
    BadPort {
        /// The text that was not a port.
        port: String,
    },
}

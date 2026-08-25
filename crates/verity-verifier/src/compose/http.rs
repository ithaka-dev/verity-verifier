//! HTTP-backed [`Source`] implementations: an IPFS gateway and a Kubo RPC node.
//!
//! Both are thin. Neither is trusted — see the module docs on [`super`].

use core::fmt::Write as _;
use std::io::Read as _;

use super::{
    ComposeUri, FetchError, Source, DEFAULT_CONNECT_TIMEOUT, DEFAULT_SIZE_LIMIT,
    DEFAULT_TOTAL_TIMEOUT,
};

/// Percent-encode any byte outside the URL "unreserved" set (RFC 3986 §2.3: `A-Za-z0-9-._~`).
///
/// Defense-in-depth alongside [`super::Cid`]'s charset gate, at the two points a CID is
/// interpolated below. Every byte `Cid::parse` accepts is already in the unreserved set, so this is
/// a no-op on every value that reaches it today — it exists so that a future relaxation of the
/// charset gate, or some other caller reaching these sinks, cannot reopen the injection/traversal
/// vectors VA-3 closes. A byte→`%XX` map is exhaustively testable, unlike a parser, which is why
/// this is preferred over trusting the charset gate alone.
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            // `write!` to a `String` is infallible; the `Result` is discarded deliberately.
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

/// Read a response body, refusing anything over `limit`.
///
/// Reads one byte past the limit deliberately: a body exactly at the limit is fine, and the extra
/// byte is what distinguishes "exactly at" from "over". Streaming rather than buffering the whole
/// response first means a hostile endpoint cannot make us allocate gigabytes before we notice.
fn read_capped(
    mut reader: impl std::io::Read,
    uri: &str,
    limit: usize,
) -> Result<Vec<u8>, FetchError> {
    let mut buf = Vec::new();
    let read = reader
        .by_ref()
        .take(u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(|e| FetchError::Transport {
            uri: uri.to_owned(),
            detail: e.to_string(),
        })?;
    if read > limit {
        return Err(FetchError::TooLarge {
            uri: uri.to_owned(),
            limit,
        });
    }
    Ok(buf)
}

/// A client with explicit timeouts.
///
/// Not left to library defaults. Whether a verification can hang forever is a security property,
/// and "whatever the HTTP crate currently does" is not a property — it is a version-dependent
/// accident. A source that accepts a connection and then stalls must eventually lose.
fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_connect(Some(DEFAULT_CONNECT_TIMEOUT))
        .timeout_global(Some(DEFAULT_TOTAL_TIMEOUT))
        // A content-addressed gateway has no legitimate reason to bounce us elsewhere. Following a
        // redirect would carry the fetch to a host nobody chose — into loopback/private space —
        // and the harm is the *request*, since it lands before the hash check. With this at 0,
        // ureq returns the 3xx response itself; its small body then fails the hash check →
        // refusal. Mirrors `connect::http::agent_config` (`connect/http.rs`); `script/mutate.sh`'s
        // "the compose agent follows redirects" mutant is what catches a regression here.
        .max_redirects(0)
        .build()
        .into()
}

fn get(url: &str, limit: usize) -> Result<Vec<u8>, FetchError> {
    let response = agent().get(url).call().map_err(|e| match &e {
        ureq::Error::StatusCode(code) => FetchError::Status {
            uri: url.to_owned(),
            status: *code,
        },
        _ => FetchError::Transport {
            uri: url.to_owned(),
            detail: e.to_string(),
        },
    })?;
    read_capped(response.into_body().into_reader(), url, limit)
}

fn post(url: &str, limit: usize) -> Result<Vec<u8>, FetchError> {
    let response = agent().post(url).send_empty().map_err(|e| match &e {
        ureq::Error::StatusCode(code) => FetchError::Status {
            uri: url.to_owned(),
            status: *code,
        },
        _ => FetchError::Transport {
            uri: url.to_owned(),
            detail: e.to_string(),
        },
    })?;
    read_capped(response.into_body().into_reader(), url, limit)
}

/// Retrieves through an IPFS HTTP gateway.
///
/// Works against a public gateway or a local one. The gateway is not trusted — it is a delivery
/// mechanism for content whose hash is committed on chain, so a hostile gateway can withhold the
/// document but cannot substitute a different one undetected.
#[derive(Debug, Clone)]
pub struct Gateway {
    base: String,
    limit: usize,
}

impl Gateway {
    /// A gateway at `base`, e.g. `http://127.0.0.1:8080`.
    #[must_use]
    pub fn new(base: impl Into<String>) -> Self {
        Self {
            base: base.into().trim_end_matches('/').to_owned(),
            limit: DEFAULT_SIZE_LIMIT,
        }
    }

    /// Override the response size limit.
    #[must_use]
    pub const fn with_size_limit(mut self, limit: usize) -> Self {
        self.limit = limit;
        self
    }
}

impl Source for Gateway {
    fn fetch(&self, uri: &ComposeUri) -> Result<Vec<u8>, FetchError> {
        match uri {
            ComposeUri::Ipfs(cid) => get(
                &format!("{}/ipfs/{}", self.base, percent_encode(cid.as_str())),
                self.limit,
            ),
            // A gateway is for content-addressed retrieval. Silently proxying an arbitrary URL
            // through it would make the source's behaviour depend on the URI in a way the caller
            // did not ask for; refusing keeps the two paths distinguishable.
            ComposeUri::Http(url) => Err(FetchError::Unsupported {
                source_kind: "Gateway",
                uri: url.clone(),
            }),
        }
    }
}

/// Retrieves through a Kubo RPC API, e.g. a local `ipfs daemon`.
///
/// Prefer this where a node is already running: it does not depend on a gateway being exposed,
/// and an offline node serves content it already holds without touching the network.
#[derive(Debug, Clone)]
pub struct KuboRpc {
    api: String,
    limit: usize,
}

impl KuboRpc {
    /// A node whose RPC API is at `api`, e.g. `http://127.0.0.1:5001`.
    #[must_use]
    pub fn new(api: impl Into<String>) -> Self {
        Self {
            api: api.into().trim_end_matches('/').to_owned(),
            limit: DEFAULT_SIZE_LIMIT,
        }
    }

    /// Override the response size limit.
    #[must_use]
    pub const fn with_size_limit(mut self, limit: usize) -> Self {
        self.limit = limit;
        self
    }
}

impl Source for KuboRpc {
    fn fetch(&self, uri: &ComposeUri) -> Result<Vec<u8>, FetchError> {
        match uri {
            // The RPC API is POST-only, including for reads.
            ComposeUri::Ipfs(cid) => post(
                &format!(
                    "{}/api/v0/cat?arg={}",
                    self.api,
                    percent_encode(cid.as_str())
                ),
                self.limit,
            ),
            ComposeUri::Http(url) => Err(FetchError::Unsupported {
                source_kind: "KuboRpc",
                uri: url.clone(),
            }),
        }
    }
}

/// Retrieves plain HTTP(S) URLs.
///
/// For manifests that point at an ordinary URL rather than content-addressed storage. Carries no
/// content-addressing guarantee of its own — the hash check against the licensed `composeHash` is
/// doing all the work here, and without it this source would be trusting a web server.
///
/// # Retrieval policy (deliberate, not an oversight)
///
/// Fetches exactly the URL it is given. Follows no redirects — it shares the module's internal
/// client configuration with [`Gateway`] and [`KuboRpc`]. Caps response size and total time via the
/// same timeouts they use. Performs **no** private-range, loopback, or scheme filtering beyond
/// `http`/`https`.
///
/// A static IP/loopback blocklist would be security theater here: DNS rebinding defeats it, and —
/// decisively — the sibling sources in this module are *designed* to target loopback
/// (`Gateway::new("http://127.0.0.1:8080")`, `KuboRpc::new("http://127.0.0.1:5001")` are the
/// intended local-node deployments), so a blocklist cannot distinguish an SSRF probe from the
/// legitimate local case without knowing the embedder's deployment intent.
///
/// Whether to enable this source at all — and what it is allowed to point at — is therefore the
/// embedder's decision, not this crate's. Retrieval is outside the trust model (see the module
/// docs), and the hash check against the licensed `composeHash` is authoritative regardless of what
/// this source returns.
#[derive(Debug, Clone)]
pub struct HttpUrl {
    limit: usize,
}

impl Default for HttpUrl {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpUrl {
    /// A source that fetches `http`/`https` URLs directly.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            limit: DEFAULT_SIZE_LIMIT,
        }
    }

    /// Override the response size limit.
    #[must_use]
    pub const fn with_size_limit(mut self, limit: usize) -> Self {
        self.limit = limit;
        self
    }
}

impl Source for HttpUrl {
    fn fetch(&self, uri: &ComposeUri) -> Result<Vec<u8>, FetchError> {
        match uri {
            ComposeUri::Http(url) => get(url, self.limit),
            ComposeUri::Ipfs(cid) => Err(FetchError::Unsupported {
                source_kind: "HttpUrl",
                uri: format!("ipfs://{cid}"),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::percent_encode;
    use proptest::prelude::*;

    /// `Cid::parse` only ever accepts alphanumerics, `-`, and `_` — all within RFC 3986's
    /// unreserved set — so encoding is a no-op on every value that reaches these sinks today. This
    /// is the "belt" half of belt-and-suspenders: the charset gate is what actually keeps a bad
    /// byte out, and this pins that the encoder does not distort a value the gate already accepted.
    #[test]
    fn is_a_no_op_on_every_byte_a_cid_can_hold() {
        let sample = "abcXYZ019-_";
        assert_eq!(percent_encode(sample), sample);
    }

    /// The "suspenders" half: even if a bad byte ever reached this function directly — a future
    /// relaxation of the charset gate, or some other caller — it neutralizes the exact bytes VA-3
    /// is about, matching the module docs' own worked examples.
    #[test]
    fn neutralizes_url_significant_bytes() {
        assert_eq!(percent_encode("../admin"), "..%2Fadmin");
        assert_eq!(percent_encode("cid&timeout=0"), "cid%26timeout%3D0");
        assert_eq!(percent_encode("cid?x#y"), "cid%3Fx%23y");
    }

    proptest! {
        /// Total and exhaustively verifiable: every allowed byte round-trips unchanged and every
        /// disallowed byte survives *encoded*, never dropped or misinterpreted as structure.
        #[test]
        fn every_byte_is_either_unchanged_or_percent_encoded(s in ".{0,64}") {
            let encoded = percent_encode(&s);
            // Reconstruct the input from the encoded form and confirm it round-trips: every `%XX`
            // decodes back to the original byte, and nothing outside unreserved bytes appears literally.
            let mut bytes = encoded.bytes();
            let mut decoded = Vec::new();
            while let Some(b) = bytes.next() {
                if b == b'%' {
                    let hi = bytes.next().expect("percent-encoding always emits two hex digits");
                    let lo = bytes.next().expect("percent-encoding always emits two hex digits");
                    let hex = [hi, lo];
                    let byte = u8::from_str_radix(
                        std::str::from_utf8(&hex).expect("hex digits are ASCII"),
                        16,
                    )
                    .expect("percent_encode only ever emits valid hex pairs");
                    decoded.push(byte);
                } else {
                    prop_assert!(
                        b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'),
                        "a byte outside the unreserved set appeared unencoded in the output"
                    );
                    decoded.push(b);
                }
            }
            prop_assert_eq!(decoded, s.as_bytes());
        }
    }
}

//! HTTP-backed [`Source`] implementations: an IPFS gateway and a Kubo RPC node.
//!
//! Both are thin. Neither is trusted — see the module docs on [`super`].

use std::io::Read as _;

use super::{ComposeUri, FetchError, Source, DEFAULT_SIZE_LIMIT};

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
        .take(
            u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1),
        )
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

fn get(url: &str, limit: usize) -> Result<Vec<u8>, FetchError> {
    let response = ureq::get(url)
        .call()
        .map_err(|e| match &e {
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
    let response = ureq::post(url)
        .send_empty()
        .map_err(|e| match &e {
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
            ComposeUri::Ipfs(cid) => get(&format!("{}/ipfs/{cid}", self.base), self.limit),
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
                &format!("{}/api/v0/cat?arg={cid}", self.api),
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

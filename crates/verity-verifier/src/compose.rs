//! Retrieving the published `app-compose.json`.
//!
//! # What this module does not do
//!
//! **It does not verify anything.** Bytes returned here are untrusted: whoever served them chose
//! what to send. Checking that they hash to the licensed `composeHash` is a separate step, and
//! nothing in this module should be read as implying it happened.
//!
//! That separation is deliberate. Verification takes bytes and performs no I/O, so it can be
//! audited without reasoning about the network, and an embedder that already holds the document —
//! from a cache, a bundle, or a previous run — never constructs a client at all.
//!
//! # Pluggable by construction
//!
//! [`Source`] is the seam. Two implementations ship behind the `fetch` feature — an IPFS gateway
//! and a Kubo RPC node — but the trait is the contract, and an embedder with its own retrieval
//! path (a local blockstore, a bundled copy, a corporate proxy) implements it and is done.
//!
//! Retrieval is deliberately **not** part of the trust model. Because the document is
//! content-addressed and its hash is committed on-chain, a wrong or hostile answer is detectable —
//! so *where* it came from does not need to be trusted, only *what* came back.

use core::fmt;

/// Where a compose document lives.
///
/// Parsed rather than passed around as a string so that a caller cannot accidentally hand a
/// gateway an arbitrary URL and a Kubo node an `ipfs://` scheme it will not understand.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ComposeUri {
    /// A content identifier, addressed by `ipfs://<cid>`.
    ///
    /// The preferred form: content addressing means a wrong answer is detectable by hashing,
    /// independently of who served it.
    Ipfs(String),
    /// An absolute `http`/`https` URL.
    ///
    /// Supported because a manifest may point anywhere, but it carries no content-addressing
    /// guarantee of its own — the hash check is doing all the work.
    Http(String),
}

impl ComposeUri {
    /// Parse a URI from a manifest record.
    ///
    /// # Examples
    ///
    /// ```
    /// use verity_verifier::compose::ComposeUri;
    ///
    /// let uri = ComposeUri::parse("ipfs://bafkreidenehphc2udb62cgsbuveql5pvhhuuricbjtvtcleag3ec6zjj7u")?;
    /// assert!(matches!(uri, ComposeUri::Ipfs(_)));
    /// # Ok::<(), verity_verifier::compose::UriError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`UriError`] for an empty CID, an unsupported scheme, or a missing scheme.
    pub fn parse(s: &str) -> Result<Self, UriError> {
        let s = s.trim();
        if let Some(cid) = s.strip_prefix("ipfs://") {
            if cid.is_empty() {
                return Err(UriError::EmptyCid);
            }
            return Ok(Self::Ipfs(cid.to_owned()));
        }
        if s.starts_with("https://") || s.starts_with("http://") {
            return Ok(Self::Http(s.to_owned()));
        }
        match s.split_once("://") {
            Some((scheme, _)) => Err(UriError::UnsupportedScheme(scheme.to_owned())),
            None => Err(UriError::NoScheme),
        }
    }

    /// The content identifier, when this is an `ipfs://` URI.
    #[must_use]
    pub fn cid(&self) -> Option<&str> {
        match self {
            Self::Ipfs(cid) => Some(cid),
            Self::Http(_) => None,
        }
    }
}

impl fmt::Display for ComposeUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ipfs(cid) => write!(f, "ipfs://{cid}"),
            Self::Http(url) => f.write_str(url),
        }
    }
}

/// Why a compose URI could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum UriError {
    /// `ipfs://` with nothing after it.
    #[error("ipfs:// URI has an empty CID")]
    EmptyCid,
    /// A scheme this crate does not retrieve.
    #[error("unsupported scheme `{0}`")]
    UnsupportedScheme(String),
    /// No scheme at all.
    #[error("URI has no scheme")]
    NoScheme,
}

/// Why retrieval failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FetchError {
    /// The source could not be reached, or the transfer failed.
    #[error("transport error fetching {uri}: {detail}")]
    Transport {
        /// What was being fetched.
        uri: String,
        /// Why it failed.
        detail: String,
    },
    /// The source answered, but not with success.
    #[error("fetching {uri} returned HTTP {status}")]
    Status {
        /// What was being fetched.
        uri: String,
        /// The status returned.
        status: u16,
    },
    /// The response exceeded the configured size limit.
    ///
    /// A compose document is a few kilobytes. A response far larger than that is either a
    /// misconfiguration or someone testing whether the client will read whatever it is sent.
    #[error("{uri} exceeded the {limit} byte limit")]
    TooLarge {
        /// What was being fetched.
        uri: String,
        /// The limit that was exceeded.
        limit: usize,
    },
    /// This source cannot retrieve that kind of URI.
    #[error("{source_kind} cannot fetch {uri}")]
    Unsupported {
        /// The source that refused.
        source_kind: &'static str,
        /// The URI it was given.
        uri: String,
    },
}

/// Somewhere a compose document can be retrieved from.
///
/// Implement this to plug in a local blockstore, a bundled copy, or any other retrieval path.
/// Returned bytes are **untrusted** until hashed against the licensed `composeHash`.
pub trait Source {
    /// Retrieve the document at `uri`.
    ///
    /// # Errors
    ///
    /// Returns [`FetchError`] if the document could not be retrieved.
    fn fetch(&self, uri: &ComposeUri) -> Result<Vec<u8>, FetchError>;
}

/// A compose document is small. Anything much larger is not one.
pub const DEFAULT_SIZE_LIMIT: usize = 1024 * 1024;

/// How long to wait for a connection before giving up.
pub const DEFAULT_CONNECT_TIMEOUT: core::time::Duration = core::time::Duration::from_secs(10);

/// How long a whole retrieval may take.
///
/// Bounded because a source that accepts a connection and then trickles bytes forever would
/// otherwise stall a verification indefinitely — a denial of service that needs no exploit, only
/// patience.
pub const DEFAULT_TOTAL_TIMEOUT: core::time::Duration = core::time::Duration::from_secs(30);

/// How many documents [`Cached`] holds before it starts discarding.
pub const DEFAULT_CACHE_CAPACITY: usize = 64;

#[cfg(feature = "fetch")]
mod http;

#[cfg(feature = "fetch")]
pub use http::{Gateway, HttpUrl, KuboRpc};

/// Caches what a wrapped [`Source`] returns.
///
/// Compose documents are small and immutable per version, so re-fetching one is waste and an
/// avoidable dependency on the source still being reachable.
///
/// # Why caching cannot cause a wrong answer
///
/// A cache is normally a correctness risk: serve something stale and the caller acts on it. Here it
/// is not, because **the hash check happens after retrieval, on every call.** A stale or wrong entry
/// fails that check exactly as a stale or wrong network response would. The worst a poisoned cache
/// can do is cause a spurious *refusal* — never a spurious success.
///
/// That is worth stating plainly, because it is the reason this wrapper is allowed to exist at all
/// in a component whose job is to not be fooled.
#[derive(Debug)]
pub struct Cached<S> {
    inner: S,
    capacity: usize,
    entries: std::sync::Mutex<std::collections::HashMap<ComposeUri, Vec<u8>>>,
}

impl<S> Cached<S> {
    /// Wrap `inner` with an in-memory cache.
    ///
    /// Deliberately not persistent: a cache surviving process restart is a different design with
    /// its own invalidation and on-disk-tampering questions, and nothing yet needs it.
    #[must_use]
    pub fn new(inner: S) -> Self {
        Self::with_capacity(inner, DEFAULT_CACHE_CAPACITY)
    }

    /// Wrap `inner` with a cache holding at most `capacity` documents.
    ///
    /// **Bounded deliberately.** An agent verifying many licences accumulates one entry per
    /// distinct URI, and an unbounded map keyed by something the caller does not control is a
    /// memory-growth vector that needs no attacker, only time.
    #[must_use]
    pub fn with_capacity(inner: S, capacity: usize) -> Self {
        Self {
            inner,
            capacity: capacity.max(1),
            entries: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// The most documents this cache will hold.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// How many documents are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.lock().map_or(0, |e| e.len())
    }

    /// Whether nothing is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Discard everything cached.
    pub fn clear(&self) {
        if let Ok(mut e) = self.entries.lock() {
            e.clear();
        }
    }
}

impl<S: Source> Source for Cached<S> {
    fn fetch(&self, uri: &ComposeUri) -> Result<Vec<u8>, FetchError> {
        // A poisoned lock means another thread panicked mid-cache. That is not a reason to fail a
        // fetch — fall through to the source rather than propagating someone else's panic into a
        // verification path.
        if let Ok(entries) = self.entries.lock() {
            if let Some(hit) = entries.get(uri) {
                return Ok(hit.clone());
            }
        }
        let bytes = self.inner.fetch(uri)?;
        if let Ok(mut entries) = self.entries.lock() {
            // At capacity, drop an arbitrary entry rather than growing. Not LRU: every entry is
            // equally cheap to re-fetch and equally safe to lose, because the hash check runs
            // regardless of where the bytes came from. Ranking them would buy nothing.
            if entries.len() >= self.capacity && !entries.contains_key(uri) {
                if let Some(victim) = entries.keys().next().cloned() {
                    entries.remove(&victim);
                }
            }
            entries.insert(uri.clone(), bytes.clone());
        }
        Ok(bytes)
    }
}

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
//!
//! # Synchronous, deliberately
//!
//! [`Source::fetch`] is plain, synchronous `&self` → `Result` — no `async`, matching the crate as a
//! whole (the workspace `Cargo.toml` has the full rationale for the `fetch` feature's HTTP client).
//! That keeps a caller with no async runtime at all — a WASM host, an offline audit tool — able to
//! retrieve a document without the crate imposing one. One consequence for a combinator like
//! [`Fallback`]: trying several sources happens in sequence, never concurrently, which is why its
//! own docs treat their timeouts as additive rather than overlapping.

use core::fmt;

/// A content identifier whose string form is safe to interpolate into a request URL.
///
/// The invariant is **interpolation-safety, not CID validity**: the inner string contains only
/// ASCII alphanumeric characters, `-`, or `_` — a conservative *subset* of the multibase alphabets
/// IPFS actually uses for `ipfs://` addressing (base32 `b…`, the `CIDv1` default; base58btc `Qm…`;
/// base36 `k…`; base16 `f…` are all within this set). It is deliberately **not** a claim that the
/// value is a structurally valid CID — retrieval is outside the trust model (see the module docs),
/// so CID validity is not this type's job, and a wrong document is caught by the hash check
/// regardless of where it came from or what shape it claims to be.
///
/// # Why this is an allowlist, not a blacklist
///
/// Every byte not explicitly permitted is rejected — `/ ? # & % : @ [ ] .`, all whitespace
/// (including CR/LF), every ASCII control byte, and every non-ASCII byte are all excluded because
/// none of them is on the list, not because someone remembered to name them. That is what makes the
/// check exhaustively verifiable: there is nothing here to under-enumerate the way a blacklist of
/// "known dangerous characters" can be.
///
/// One consequence worth stating honestly: multibase's `u`-prefixed base64url form uses exactly
/// this alphabet (`-` and `_` are what make base64*url*, unlike base64-standard's `+ /`, URL-safe),
/// so a base64url string also passes. Passing this check is not a claim about which multibase form
/// a string is — only that it is safe to interpolate.
///
/// The only constructor is [`Cid::parse`]; the inner field is private so that no caller — however
/// indirect — can build a [`ComposeUri::Ipfs`] holding an unvalidated string.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Cid(String);

impl Cid {
    /// Parse a CID, accepting only bytes that cannot alter the structure of a URL it is
    /// interpolated into.
    ///
    /// # Errors
    ///
    /// Returns [`UriError::EmptyCid`] if `s` is empty, or [`UriError::InvalidCid`] if `s` contains
    /// any byte outside `[A-Za-z0-9_-]`.
    pub fn parse(s: &str) -> Result<Self, UriError> {
        if s.is_empty() {
            return Err(UriError::EmptyCid);
        }
        if !s
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(UriError::InvalidCid);
        }
        Ok(Self(s.to_owned()))
    }

    /// The CID's string form.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Cid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A parsed `http`/`https` compose URL.
///
/// The invariant is **scheme-validity, and only that**: the inner string begins with `http://` or
/// `https://`. It is deliberately *not* a claim about the host, port, path, or reachability, and
/// carries **no** content-addressing guarantee — unlike [`Cid`], the value is fetched verbatim
/// (never interpolated into a larger URL), so there is no injection surface to defend and no host
/// policy to enforce here. Whether an embedder should point retrieval at a given URL, and any
/// private-range concern, is the embedder's decision (see `HttpUrl`'s retrieval-policy docs);
/// retrieval is outside the trust model and the hash check against the licensed `composeHash` is
/// authoritative regardless of what comes back.
///
/// The only constructor is [`ComposeUrl::parse`]; the inner field is private so that no caller can
/// build a [`ComposeUri::Http`] holding a string that did not pass the scheme check — the same
/// "parsed, not a raw string" guarantee [`Cid`] gives the `Ipfs` arm. Rust has no per-field
/// visibility on an enum tuple variant, so this newtype is not one option among several for
/// achieving that guarantee — it is the only one today. That "today" is doing real work: nothing
/// stops a *future* `From<String>`, `FromStr`, or derived `Deserialize` impl from reopening the same
/// bypass by a different door, which is why the example below is kept as a compiled regression
/// guard rather than only a prose claim.
///
/// # Examples
///
/// The private field means a raw tuple literal cannot be built even from within this crate's own
/// dependents:
///
/// ```compile_fail
/// use verity_verifier::compose::ComposeUri;
///
/// let bad = ComposeUri::Http("file:///etc/passwd".to_owned());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ComposeUrl(String);

impl ComposeUrl {
    /// Parse an `http`/`https` URL, accepting only the two schemes this crate retrieves.
    ///
    /// Performs **no** host, port, path, or private-range validation — see the type docs for why
    /// that is deliberate, not an oversight.
    ///
    /// Performs **no** trimming of its own. [`ComposeUri::parse`] trims before handing this
    /// constructor a string, so a whitespace-padded URL that succeeds through `ComposeUri::parse`
    /// (e.g. `" http://x "`) is rejected here if called directly with the padding still attached —
    /// trimming is the caller's step, not this constructor's. What the two entry points share is the
    /// scheme-validity verdict on a given string, not whitespace handling.
    ///
    /// # Errors
    ///
    /// Returns [`UriError::UnsupportedScheme`] if `s` carries a scheme other than `http`/`https`,
    /// or [`UriError::NoScheme`] if it carries none. Shares its verdict vocabulary with
    /// [`ComposeUri::parse`], which routes through this constructor, so the two cannot disagree
    /// about whether a given (already-trimmed) string has a valid `http`/`https` scheme.
    pub fn parse(s: &str) -> Result<Self, UriError> {
        if s.starts_with("https://") || s.starts_with("http://") {
            return Ok(Self(s.to_owned()));
        }
        match s.split_once("://") {
            Some((scheme, _)) => Err(UriError::UnsupportedScheme(scheme.to_owned())),
            None => Err(UriError::NoScheme),
        }
    }

    /// The URL's string form.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ComposeUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

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
    Ipfs(Cid),
    /// An absolute `http`/`https` URL.
    ///
    /// Supported because a manifest may point anywhere, but it carries no content-addressing
    /// guarantee of its own — the hash check is doing all the work.
    Http(ComposeUrl),
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
    /// Returns [`UriError`] for an empty CID, a CID containing a character unsafe to interpolate,
    /// an unsupported scheme, or a missing scheme.
    pub fn parse(s: &str) -> Result<Self, UriError> {
        let s = s.trim();
        if let Some(cid) = s.strip_prefix("ipfs://") {
            return Cid::parse(cid).map(Self::Ipfs);
        }
        // The http(s):// decision lives in ONE place. `ComposeUri::parse` does not branch on the
        // prefix itself — it hands the string to `ComposeUrl::parse` and lets the single definition
        // decide. This is the VA-3 finding-2 no-drift lesson applied: two copies of "what is a valid
        // http URL" cannot disagree because there is only one.
        ComposeUrl::parse(s).map(Self::Http)
    }

    /// The content identifier, when this is an `ipfs://` URI.
    #[must_use]
    pub fn cid(&self) -> Option<&str> {
        match self {
            Self::Ipfs(cid) => Some(cid.as_str()),
            Self::Http(_) => None,
        }
    }
}

impl fmt::Display for ComposeUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ipfs(cid) => write!(f, "ipfs://{cid}"),
            Self::Http(url) => f.write_str(url.as_str()),
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
    /// A CID containing a byte that could alter the structure of a URL it is interpolated into.
    ///
    /// Rejected before it can reach a gateway path (`/ipfs/<cid>`) or a Kubo query
    /// (`?arg=<cid>`) — see [`Cid`] for exactly what is and is not allowed, and why.
    #[error("ipfs:// CID contains a character unsafe to interpolate")]
    InvalidCid,
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

impl From<&FetchError> for crate::verdict::Unestablished {
    /// Every retrieval failure is a remedy the caller can retry: fetch again, or from another
    /// source. `TooLarge` is arguably hostile rather than an outage, but the caller's action is
    /// identical and a verdict cannot tell the two apart, so it is not given a cause of its own.
    ///
    /// Matched exhaustively and without a wildcard, so a future `FetchError` variant is a compile
    /// error here rather than silently inheriting a default.
    fn from(err: &FetchError) -> Self {
        match err {
            FetchError::Transport { .. }
            | FetchError::Status { .. }
            | FetchError::TooLarge { .. }
            | FetchError::Unsupported { .. } => Self::RetrievalFailed,
        }
    }
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

impl<S: Source + ?Sized> Source for Box<S> {
    /// Lets a heterogeneous chain — e.g. `Fallback<Box<dyn Source>>` — mix source kinds (an IPFS
    /// gateway alongside a Kubo RPC node, say) that a homogeneous [`Fallback<S>`](Fallback) cannot
    /// express.
    fn fetch(&self, uri: &ComposeUri) -> Result<Vec<u8>, FetchError> {
        (**self).fetch(uri)
    }
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

/// Tries each source in order; the first success wins, and a miss falls through to the next.
///
/// Public gateways are flaky. A single reachable source is enough to establish a verdict, because
/// the compose document is the same content-addressed object no matter which source served it —
/// trying the next source on a miss costs nothing but time.
///
/// # Why a bad source in the chain cannot cause a wrong answer
///
/// Same argument as [`Cached`]: the hash check runs on whatever bytes eventually come back,
/// regardless of which source in the chain produced them. A misconfigured, unreachable, or
/// outright hostile entry can therefore only ever make `fetch` slower, or — if every entry is bad —
/// cause a refusal. It can never manufacture a spurious success, because nothing here is trusted
/// any more than a lone `Source` already is.
///
/// # Only all-down surfaces as a failure
///
/// If every source errors, [`Source::fetch`] returns the last error encountered. Like every
/// [`FetchError`], that error maps to [`crate::verdict::Unestablished::RetrievalFailed`] through the
/// existing `From<&FetchError>` impl above — reused here, not forked. At the verdict level, a
/// `Fallback` where every source is down is indistinguishable from any single source being down.
///
/// # Bounded duration is additive, not amortized
///
/// Each inner source already carries its own timeouts. A chain of `N` sources that are all
/// unreachable costs up to the *sum* of every source's timeout, not just one — retrieval here is
/// deliberately synchronous (see the module docs), and a compose document is a few kilobytes, not
/// something worth fanning a request out for. Keep chains short (two or three entries) and consider
/// tightening a source's own timeout when it is used behind a `Fallback`.
#[derive(Debug)]
pub struct Fallback<S> {
    first: S,
    rest: Vec<S>,
}

impl<S> Fallback<S> {
    /// A fallback chain that tries `first`, then each of `rest` in order.
    ///
    /// Takes a guaranteed first source rather than a `Vec` behind a fallible constructor: an empty
    /// chain is a caller mistake, not a retrieval outcome it makes sense to hand back as a
    /// [`FetchError`] — so, as with [`Cid`], the illegal state is made unrepresentable instead of
    /// checked for at construction.
    #[must_use]
    pub fn new(first: S, rest: Vec<S>) -> Self {
        Self { first, rest }
    }
}

impl<S: Source> Source for Fallback<S> {
    fn fetch(&self, uri: &ComposeUri) -> Result<Vec<u8>, FetchError> {
        // No `FetchError` variant is special-cased — in particular, `Unsupported` (the wrong kind
        // of `ComposeUri` for a given source) is treated exactly like any other miss and falls
        // through to the next source. That matters for a heterogeneous chain
        // (`Fallback<Box<dyn Source>>`) mixing sources that each only handle one URI kind.
        let first = self.first.fetch(uri);
        if first.is_ok() {
            return first;
        }
        let mut last = first;
        for source in &self.rest {
            last = source.fetch(uri);
            if last.is_ok() {
                return last;
            }
        }
        last
    }
}

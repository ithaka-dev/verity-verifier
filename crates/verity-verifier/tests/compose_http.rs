//! Retrieval failure modes: the paths a hostile or broken gateway takes.
//!
//! # Why these do not use IPFS
//!
//! `compose_fetch.rs` needs a running IPFS daemon and **silently skips when there is none** — so on
//! any machine without one, and in CI, most of that file never executes. That is how this module
//! sat at 38% while appearing well tested: the tests exist and do not run.
//!
//! A gateway and a Kubo RPC node are HTTP servers. Nothing about the size cap, the timeout, or the
//! status handling needs content addressing, so these run against an in-process listener and
//! therefore run everywhere, every time.
//!
//! # What is being defended against
//!
//! The gateway is **not trusted** — it delivers a document whose hash is committed on chain, so it
//! can withhold but not substitute. What it can still do is stall forever, or send a very large
//! body, and the client has to survive both without the caller having to think about it.

// Pre-existing gap, fixed in passing (VA-3): every item this file imports from `compose` —
// `Gateway`, `HttpUrl`, `KuboRpc`, `Source` — is `#[cfg(feature = "fetch")]`, but this file carried
// no matching guard. `compose_fetch.rs` has one; this one did not, so on a clean checkout `cargo
// test` with `fetch` off (the default feature set, and `--features connect` alone) failed to
// *compile* this test binary, unrelated to anything else in this change.
#![cfg(feature = "fetch")]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use verity_verifier::compose::{
    ComposeUri, FetchError, Gateway, HttpUrl, KuboRpc, Source, DEFAULT_SIZE_LIMIT,
};

/// How the fake server should answer.
#[derive(Clone, Copy)]
enum Behaviour {
    /// A normal response with a body of this length.
    Body(usize),
    /// A non-2xx status.
    Status(u16),
    /// Accept the connection, send headers, then never finish the body.
    Stall,
}

/// A single-shot HTTP server on a loopback port. Returns its base URL.
fn serve(behaviour: Behaviour) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();

    thread::spawn(move || {
        for stream in listener.incoming().take(4) {
            let Ok(mut stream) = stream else { continue };
            // Read the request line so the client is not left writing into a closed socket.
            let mut scratch = [0u8; 1024];
            let _ = stream.read(&mut scratch);
            respond(&mut stream, behaviour);
        }
    });

    format!("http://127.0.0.1:{port}")
}

fn respond(stream: &mut TcpStream, behaviour: Behaviour) {
    match behaviour {
        Behaviour::Body(len) => {
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n"
            );
            // Written in chunks so a large body does not need to exist in memory at once — the
            // point is what the *client* does with it.
            let chunk = vec![b'x'; 8192];
            let mut sent = 0;
            while sent < len {
                let take = chunk.len().min(len - sent);
                if stream.write_all(&chunk[..take]).is_err() {
                    return; // the client hung up, which for the size-limit test is the pass
                }
                sent += take;
            }
            let _ = stream.flush();
        }
        Behaviour::Status(code) => {
            let _ = write!(
                stream,
                "HTTP/1.1 {code} Nope\r\nContent-Length: 4\r\nConnection: close\r\n\r\nnope"
            );
        }
        Behaviour::Stall => {
            // Headers promising a body that never arrives. The client must give up on its own.
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: 1000\r\nConnection: close\r\n\r\n"
            );
            let _ = stream.flush();
            thread::sleep(Duration::from_mins(1));
        }
    }
}

const CID: &str = "bafkreiabcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuv";

fn ipfs() -> ComposeUri {
    ComposeUri::parse(&format!("ipfs://{CID}")).expect("uri")
}

// — the size cap —

/// A compose document is a few kilobytes. A response far larger is either a misconfiguration or
/// someone testing whether the client will read whatever it is sent.
#[test]
fn a_body_over_the_limit_is_refused() {
    let base = serve(Behaviour::Body(4096));
    let source = Gateway::new(base).with_size_limit(1024);

    match source.fetch(&ipfs()) {
        Err(FetchError::TooLarge { limit, .. }) => assert_eq!(limit, 1024),
        other => panic!("expected TooLarge, got {other:?}"),
    }
}

/// A body *exactly* at the limit is fine. The client reads one byte past the cap deliberately, and
/// an off-by-one here would reject legitimate documents at the boundary.
#[test]
fn a_body_exactly_at_the_limit_is_accepted() {
    let base = serve(Behaviour::Body(1024));
    let source = Gateway::new(base).with_size_limit(1024);

    let body = source
        .fetch(&ipfs())
        .expect("a body at the limit must be accepted");
    assert_eq!(body.len(), 1024);
}

#[test]
fn one_byte_over_the_limit_is_refused() {
    let base = serve(Behaviour::Body(1025));
    let source = Gateway::new(base).with_size_limit(1024);
    assert!(matches!(
        source.fetch(&ipfs()),
        Err(FetchError::TooLarge { .. })
    ));
}

/// The default is a megabyte — generous for a document that is a few kilobytes, and finite.
#[test]
fn the_default_limit_is_finite() {
    assert_eq!(DEFAULT_SIZE_LIMIT, 1024 * 1024);
}

// — stalling —

/// **Whether a verification can hang forever is a security property**, and "whatever the HTTP crate
/// currently does" is not a property — it is a version-dependent accident. A source that accepts a
/// connection and then stalls must eventually lose.
#[test]
fn a_stalling_server_does_not_hang_forever() {
    let base = serve(Behaviour::Stall);
    let source = Gateway::new(base);

    let started = Instant::now();
    let result = source.fetch(&ipfs());
    let elapsed = started.elapsed();

    assert!(result.is_err(), "a stalled fetch must fail, not return");
    assert!(
        elapsed < Duration::from_secs(45),
        "gave up after {elapsed:?}; the total timeout is 30s"
    );
}

// — status handling —

/// A gateway that does not have the document is a different situation from one that is broken, and
/// the status is what lets a caller tell them apart.
#[test]
fn a_non_success_status_is_reported_with_its_code() {
    for code in [400u16, 403, 404, 500, 502] {
        let base = serve(Behaviour::Status(code));
        match Gateway::new(base).fetch(&ipfs()) {
            Err(FetchError::Status { status, .. }) => assert_eq!(status, code),
            other => panic!("expected Status({code}), got {other:?}"),
        }
    }
}

#[test]
fn an_unreachable_server_is_a_transport_error() {
    // Nothing is listening on this port.
    let source = Gateway::new("http://127.0.0.1:1");
    assert!(matches!(
        source.fetch(&ipfs()),
        Err(FetchError::Transport { .. })
    ));
}

// — each source serves only what it owns —

/// Silently proxying an arbitrary URL through a gateway would make a source's behaviour depend on
/// the URI in a way the caller did not ask for. Refusing keeps the two paths distinguishable.
#[test]
fn a_gateway_refuses_a_plain_http_uri() {
    let uri = ComposeUri::parse("https://example.com/compose.json").expect("uri");
    match Gateway::new("http://127.0.0.1:1").fetch(&uri) {
        Err(FetchError::Unsupported { source_kind, .. }) => assert_eq!(source_kind, "Gateway"),
        other => panic!("expected Unsupported, got {other:?}"),
    }
}

#[test]
fn a_kubo_node_refuses_a_plain_http_uri() {
    let uri = ComposeUri::parse("https://example.com/compose.json").expect("uri");
    match KuboRpc::new("http://127.0.0.1:1").fetch(&uri) {
        Err(FetchError::Unsupported { source_kind, .. }) => assert_eq!(source_kind, "KuboRpc"),
        other => panic!("expected Unsupported, got {other:?}"),
    }
}

#[test]
fn an_http_source_refuses_an_ipfs_uri() {
    match HttpUrl::new().fetch(&ipfs()) {
        Err(FetchError::Unsupported { source_kind, .. }) => assert_eq!(source_kind, "HttpUrl"),
        other => panic!("expected Unsupported, got {other:?}"),
    }
}

// — the Kubo RPC path is POST, including for reads —

#[test]
fn the_kubo_source_retrieves_over_the_rpc_api() {
    let base = serve(Behaviour::Body(64));
    let body = KuboRpc::new(base).fetch(&ipfs()).expect("fetch");
    assert_eq!(body.len(), 64);
}

#[test]
fn the_kubo_source_enforces_its_own_size_limit() {
    let base = serve(Behaviour::Body(4096));
    let source = KuboRpc::new(base).with_size_limit(512);
    assert!(matches!(
        source.fetch(&ipfs()),
        Err(FetchError::TooLarge { .. })
    ));
}

// — plain HTTP —

/// Carries no content-addressing guarantee of its own: the hash check against the licensed
/// `composeHash` is doing all the work, and without it this source would be trusting a web server.
#[test]
fn the_http_source_retrieves_and_caps() {
    let base = serve(Behaviour::Body(128));
    let uri = ComposeUri::parse(&format!("{base}/compose.json")).expect("uri");
    assert_eq!(HttpUrl::new().fetch(&uri).expect("fetch").len(), 128);

    let big = serve(Behaviour::Body(4096));
    let big_uri = ComposeUri::parse(&format!("{big}/compose.json")).expect("uri");
    assert!(matches!(
        HttpUrl::new().with_size_limit(100).fetch(&big_uri),
        Err(FetchError::TooLarge { .. })
    ));
}

// — the cache —
//
// Previously exercised only by tests gated on a running IPFS daemon, so on any machine without one
// it went untested entirely. Nothing about the caching behaviour needs content addressing.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use verity_verifier::compose::{Cached, DEFAULT_CACHE_CAPACITY};

/// Counts fetches, so a test can tell a cache hit from a repeat call.
#[derive(Clone)]
struct Counting {
    calls: Arc<AtomicUsize>,
    fail_after: usize,
}

impl Counting {
    fn new() -> Self {
        Self {
            calls: Arc::new(AtomicUsize::new(0)),
            fail_after: usize::MAX,
        }
    }

    fn failing_after(n: usize) -> Self {
        Self {
            calls: Arc::new(AtomicUsize::new(0)),
            fail_after: n,
        }
    }

    fn count(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl Source for Counting {
    fn fetch(&self, uri: &ComposeUri) -> Result<Vec<u8>, FetchError> {
        let n = self.calls.fetch_add(1, Ordering::SeqCst);
        if n >= self.fail_after {
            return Err(FetchError::Transport {
                uri: format!("{uri:?}"),
                detail: "source is gone".to_owned(),
            });
        }
        Ok(format!("document for {uri:?}").into_bytes())
    }
}

fn cid_uri(n: usize) -> ComposeUri {
    ComposeUri::parse(&format!("ipfs://bafkrei{n:0>52}")).expect("uri")
}

#[test]
fn the_cache_serves_a_second_read_without_the_source() {
    let inner = Counting::new();
    let cached = Cached::new(inner.clone());

    let first = cached.fetch(&cid_uri(1)).expect("first");
    let second = cached.fetch(&cid_uri(1)).expect("second");

    assert_eq!(first, second);
    assert_eq!(inner.count(), 1, "the source must be consulted once");
}

/// A document is content-addressed, so a cached copy cannot go stale — and that is what makes a
/// hit survivable when the source has gone away entirely.
#[test]
fn a_cache_hit_survives_an_unreachable_source() {
    let inner = Counting::failing_after(1);
    let cached = Cached::new(inner);

    cached
        .fetch(&cid_uri(1))
        .expect("first read populates the cache");
    assert!(cached.fetch(&cid_uri(2)).is_err(), "a miss must still fail");
    assert!(
        cached.fetch(&cid_uri(1)).is_ok(),
        "the hit must still be served"
    );
}

/// Bounded on purpose: an unbounded cache fed by an untrusted source is a memory-growth path, and
/// the source here is explicitly not trusted.
#[test]
fn the_cache_is_bounded() {
    let inner = Counting::new();
    let cached = Cached::with_capacity(inner, 4);
    assert_eq!(cached.capacity(), 4);
    assert!(cached.is_empty());

    for n in 0..10 {
        cached.fetch(&cid_uri(n)).expect("fetch");
    }

    assert!(
        cached.len() <= 4,
        "held {} entries with capacity 4",
        cached.len()
    );
    assert!(!cached.is_empty());
}

#[test]
fn clearing_empties_the_cache_and_the_next_read_reaches_the_source() {
    let inner = Counting::new();
    let cached = Cached::new(inner.clone());

    cached.fetch(&cid_uri(1)).expect("first");
    cached.clear();
    assert!(cached.is_empty());

    cached.fetch(&cid_uri(1)).expect("second");
    assert_eq!(
        inner.count(),
        2,
        "after a clear the source must be consulted again"
    );
}

/// Bounded rather than merely non-zero: an unbounded cache fed by an untrusted source is a
/// memory-growth path. Checked at compile time, because clippy is right that an `assert!` over
/// constants is no test at all — it cannot fail at runtime, so it would only look like one.
const _: () = assert!(DEFAULT_CACHE_CAPACITY > 0 && DEFAULT_CACHE_CAPACITY <= 1024);

#[test]
fn the_default_capacity_is_used_when_none_is_given() {
    assert_eq!(
        Cached::new(Counting::new()).capacity(),
        DEFAULT_CACHE_CAPACITY
    );
}

/// A failed fetch must not be remembered as a result — otherwise one transient outage would be
/// cached as an answer.
#[test]
fn failures_are_not_cached() {
    let inner = Counting::failing_after(0);
    let cached = Cached::new(inner.clone());

    assert!(cached.fetch(&cid_uri(1)).is_err());
    assert!(cached.fetch(&cid_uri(1)).is_err());
    assert_eq!(
        inner.count(),
        2,
        "a failure must be retried, not served from cache"
    );
    assert!(cached.is_empty());
}

// — VA-3: redirects are not followed —
//
// Mirrors `connect::http`'s `a_redirect_to_another_host_is_not_followed`
// (`crates/verity-verifier/src/connect/http.rs`). Before this change the compose `agent()` set no
// redirect policy at all: a fake server recording whether it was contacted showed the current agent
// *did* follow a 302 to a second host — that RED evidence is what these tests now pin as GREEN.

/// Starts a single-shot server that records whether it was contacted at all (and the request line,
/// for the CID tests below), then answers 200 with an empty body.
fn serve_recording() -> (String, std::sync::Arc<std::sync::Mutex<Option<String>>>) {
    let recorded = std::sync::Arc::new(std::sync::Mutex::new(None));
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let slot = recorded.clone();
    thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).unwrap_or(0);
            let request = String::from_utf8_lossy(&buf[..n]);
            let request_line = request.lines().next().unwrap_or("").to_owned();
            *slot.lock().expect("lock") = Some(request_line);
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        }
    });
    (format!("http://127.0.0.1:{port}"), recorded)
}

/// Server A always answers with a 302 pointing at `target`.
fn serve_redirect_to(target: &str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let location = format!("{target}/ipfs/x");
    thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut scratch = [0u8; 1024];
            let _ = stream.read(&mut scratch);
            let _ = write!(
                stream,
                "HTTP/1.1 302 Found\r\nlocation: {location}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
            );
        }
    });
    format!("http://127.0.0.1:{port}")
}

#[test]
fn a_redirect_is_not_followed_by_the_http_url_source() {
    let (base_b, recorded_b) = serve_recording();
    let base_a = serve_redirect_to(&base_b);
    let uri = ComposeUri::parse(&format!("{base_a}/compose.json")).expect("uri");

    // ureq only treats 4xx/5xx as an error, so a 302 comes back as `Ok` — its (empty) body then
    // fails the hash check upstream, which is the caller's own concern, not this source's.
    let result = HttpUrl::new().fetch(&uri);
    assert!(
        result.is_ok(),
        "a 302 must come back as data rather than an error: {result:?}"
    );

    // `fetch` is synchronous: by the time it has returned, any redirect it was going to follow has
    // already completed, so there is nothing to wait for here.
    assert!(
        recorded_b.lock().expect("lock").is_none(),
        "the redirect target must never be contacted — following it would carry the request to a \
         host nobody chose, before the hash check ever runs"
    );
}

#[test]
fn a_redirect_is_not_followed_by_the_gateway_source() {
    let (base_b, recorded_b) = serve_recording();
    let base_a = serve_redirect_to(&base_b);

    let result = Gateway::new(base_a).fetch(&ipfs());
    assert!(
        result.is_ok(),
        "a 302 must come back as data rather than an error: {result:?}"
    );

    // `fetch` is synchronous — see the note in the `HttpUrl` test above.
    assert!(
        recorded_b.lock().expect("lock").is_none(),
        "the redirect target must never be contacted"
    );
}

// — VA-3: a malformed CID never reaches the wire —
//
// `Cid::parse` (exercised more exhaustively in `compose_uri.rs`) already refuses these strings, so
// `ComposeUri::Ipfs` can never be *constructed* with them — there is no `ComposeUri` value here to
// pass to `Gateway`/`KuboRpc` at all. These two tests pin that the request-line-level RED evidence
// gathered for `../admin` and `cid&timeout=0` during development is now unreachable by construction,
// not merely intercepted downstream.

#[test]
fn a_traversal_cid_cannot_reach_the_gateway_because_it_cannot_be_parsed() {
    assert_eq!(
        ComposeUri::parse("ipfs://../admin"),
        Err(verity_verifier::compose::UriError::InvalidCid)
    );
}

#[test]
fn a_query_injection_cid_cannot_reach_kubo_because_it_cannot_be_parsed() {
    assert_eq!(
        ComposeUri::parse("ipfs://cid&timeout=0"),
        Err(verity_verifier::compose::UriError::InvalidCid)
    );
}

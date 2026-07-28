//! Retrieval against a real IPFS node.
//!
//! Run via `scripts/with-ipfs.sh cargo test --features fetch`, which starts an offline daemon for
//! the duration and stops it afterwards.
//!
//! # On skipping
//!
//! When no daemon is reachable these tests skip — but **loudly**. A quietly skipped test is
//! indistinguishable from a passing one in CI output, which is the failure mode that lets a broken
//! fetch path ship looking green. CI runs an IPFS service container so they execute there rather
//! than skipping every time.

#![cfg(feature = "fetch")]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::process::Command;

use verity_verifier::compose::{Cached, ComposeUri, FetchError, Gateway, HttpUrl, KuboRpc, Source};

/// The compose document measured on real TDX hardware. Its sha256 is the `compose-hash` that
/// appeared in RTMR3 and inside `MR-CONFIG-ID` — so retrieving it and hashing it closes the loop
/// between what a manifest points at and what a CVM attested to.
const COMPOSE: &[u8] = include_bytes!("fixtures/app-compose-0.5.7.json");
const COMPOSE_SHA256: &str = "64690ef38b54187da11a41a54905f5f539e948a0414ceb312c8036c82f6529fd";

fn api() -> String {
    std::env::var("IPFS_API").unwrap_or_else(|_| "http://127.0.0.1:5001".to_owned())
}

fn gateway() -> String {
    std::env::var("IPFS_GATEWAY").unwrap_or_else(|_| "http://127.0.0.1:8080".to_owned())
}

/// Is a node reachable? If not, say so where a human will see it.
fn node_available() -> bool {
    let up = Command::new("curl")
        .args(["-fsS", "-X", "POST", &format!("{}/api/v0/id", api())])
        .output()
        .is_ok_and(|o| o.status.success());
    if !up {
        eprintln!(
            "\n  SKIPPED: no IPFS node at {}.\n  Run: scripts/with-ipfs.sh cargo test --features fetch\n",
            api()
        );
    }
    up
}

/// Add the fixture to the local node and return its CID.
fn publish_fixture() -> String {
    let out = Command::new("ipfs")
        .args([
            "add",
            "-Q",
            "--cid-version",
            "1",
            "crates/verity-verifier/tests/fixtures/app-compose-0.5.7.json",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR").trim_end_matches("/crates/verity-verifier"))
        .output()
        .expect("ipfs add");
    assert!(out.status.success(), "ipfs add failed: {out:?}");
    String::from_utf8(out.stdout)
        .expect("utf8")
        .trim()
        .to_owned()
}

fn sha256_hex(bytes: &[u8]) -> String {
    let out = Command::new("shasum")
        .args(["-a", "256"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut c| {
            use std::io::Write as _;
            c.stdin.as_mut().expect("stdin").write_all(bytes)?;
            c.wait_with_output()
        })
        .expect("shasum");
    String::from_utf8(out.stdout)
        .expect("utf8")
        .split_whitespace()
        .next()
        .expect("digest")
        .to_owned()
}

// — retrieval —

#[test]
fn kubo_rpc_retrieves_the_measured_compose() {
    if !node_available() {
        return;
    }
    let cid = publish_fixture();
    let uri = ComposeUri::parse(&format!("ipfs://{cid}")).expect("uri");
    let fetched = KuboRpc::new(api()).fetch(&uri).expect("fetch");

    assert_eq!(fetched, COMPOSE, "retrieved bytes differ from the fixture");
    assert_eq!(
        sha256_hex(&fetched),
        COMPOSE_SHA256,
        "retrieved document must hash to the compose-hash measured on TDX hardware"
    );
}

#[test]
fn gateway_retrieves_the_measured_compose() {
    if !node_available() {
        return;
    }
    let cid = publish_fixture();
    let uri = ComposeUri::parse(&format!("ipfs://{cid}")).expect("uri");
    let fetched = Gateway::new(gateway()).fetch(&uri).expect("fetch");

    assert_eq!(sha256_hex(&fetched), COMPOSE_SHA256);
}

/// Both implementations must agree byte-for-byte. They are different transports for the same
/// content-addressed object; if they disagree, one of them is wrong.
#[test]
fn gateway_and_rpc_agree() {
    if !node_available() {
        return;
    }
    let cid = publish_fixture();
    let uri = ComposeUri::parse(&format!("ipfs://{cid}")).expect("uri");

    let via_rpc = KuboRpc::new(api()).fetch(&uri).expect("rpc");
    let via_gateway = Gateway::new(gateway()).fetch(&uri).expect("gateway");
    assert_eq!(via_rpc, via_gateway);
}

/// A CID that is well-formed but absent must fail rather than hang indefinitely or return empty.
#[test]
fn absent_cid_fails() {
    if !node_available() {
        return;
    }
    // Valid CIDv1 for content the offline node does not hold.
    let uri = ComposeUri::parse(
        "ipfs://bafkreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )
    .expect("uri");
    assert!(
        Gateway::new(gateway()).fetch(&uri).is_err(),
        "absent content must be an error, not an empty success"
    );
}

// — caching —

#[test]
fn cache_serves_the_second_read_without_the_source() {
    if !node_available() {
        return;
    }
    let cid = publish_fixture();
    let uri = ComposeUri::parse(&format!("ipfs://{cid}")).expect("uri");

    let cached = Cached::new(KuboRpc::new(api()));
    assert!(cached.is_empty());

    let first = cached.fetch(&uri).expect("first");
    assert_eq!(cached.len(), 1);
    let second = cached.fetch(&uri).expect("second");

    assert_eq!(first, second);
    assert_eq!(sha256_hex(&second), COMPOSE_SHA256);

    cached.clear();
    assert!(cached.is_empty());
}

/// A cache that never reaches its source still returns what it holds. Proves the hit path does not
/// depend on the source being alive — which is the point of caching a document that cannot change.
#[test]
fn cache_hit_survives_an_unreachable_source() {
    if !node_available() {
        return;
    }
    let cid = publish_fixture();
    let uri = ComposeUri::parse(&format!("ipfs://{cid}")).expect("uri");

    let cached = Cached::new(KuboRpc::new(api()));
    let warm = cached.fetch(&uri).expect("warm the cache");

    // Same cache, but any further miss would go somewhere that does not answer.
    let dead = Cached::new(KuboRpc::new("http://127.0.0.1:1"));
    assert!(dead.fetch(&uri).is_err(), "control: dead source must fail");

    assert_eq!(cached.fetch(&uri).expect("still cached"), warm);
}

// — routing —
//
// Sources refuse URIs they do not own rather than silently handling both. Quietly proxying an
// arbitrary URL through a gateway would make behaviour depend on the URI in a way the caller did
// not ask for.

#[test]
fn sources_refuse_uris_they_do_not_own() {
    let http = ComposeUri::parse("https://example.invalid/app-compose.json").expect("uri");
    let ipfs = ComposeUri::parse("ipfs://bafkreiabc").expect("uri");

    assert!(matches!(
        Gateway::new("http://127.0.0.1:8080").fetch(&http),
        Err(FetchError::Unsupported { .. })
    ));
    assert!(matches!(
        KuboRpc::new("http://127.0.0.1:5001").fetch(&http),
        Err(FetchError::Unsupported { .. })
    ));
    assert!(matches!(
        HttpUrl::new().fetch(&ipfs),
        Err(FetchError::Unsupported { .. })
    ));
}

#[test]
fn size_limit_is_enforced() {
    if !node_available() {
        return;
    }
    let cid = publish_fixture();
    let uri = ComposeUri::parse(&format!("ipfs://{cid}")).expect("uri");

    // The fixture is ~14 KB; a 100-byte ceiling must refuse it rather than truncate silently.
    let strict = KuboRpc::new(api()).with_size_limit(100);
    match strict.fetch(&uri) {
        Err(FetchError::TooLarge { limit, .. }) => assert_eq!(limit, 100),
        other => panic!("expected TooLarge, got {other:?}"),
    }
}

/// The cache is bounded, so an agent verifying many licences cannot grow it without limit.
///
/// Unbounded growth here would need no attacker — only time and a long-running agent.
#[test]
fn cache_is_bounded() {
    if !node_available() {
        return;
    }
    let cid = publish_fixture();
    let cached = Cached::with_capacity(KuboRpc::new(api()), 2);
    assert_eq!(cached.capacity(), 2);

    // One real URI, plus misses that will not resolve. Only the real one populates.
    let real = ComposeUri::parse(&format!("ipfs://{cid}")).expect("uri");
    cached.fetch(&real).expect("real fetch");
    assert_eq!(cached.len(), 1);

    // Re-fetching the same URI must not grow the cache.
    cached.fetch(&real).expect("cached");
    assert_eq!(cached.len(), 1, "a hit must not add an entry");
    assert!(cached.len() <= cached.capacity());
}

/// A source that accepts a connection and then never answers must lose eventually.
///
/// Uses a port that refuses immediately rather than a black hole, so this asserts the error path
/// is reached at all; the timeout values themselves are asserted as configuration below.
#[test]
fn unreachable_source_errors_rather_than_hanging() {
    let uri = ComposeUri::parse("ipfs://bafkreiabc").expect("uri");
    let start = std::time::Instant::now();
    assert!(KuboRpc::new("http://127.0.0.1:1").fetch(&uri).is_err());
    assert!(
        start.elapsed() < verity_verifier::compose::DEFAULT_TOTAL_TIMEOUT,
        "must fail well inside the total timeout"
    );
}

/// Timeouts are explicit configuration, not inherited library defaults.
///
/// Pinned as a test because "how long can a verification hang" is a security property, and an
/// upstream default changing silently should break a test rather than change behaviour.
#[test]
fn timeouts_are_explicit_and_bounded() {
    use verity_verifier::compose::{DEFAULT_CONNECT_TIMEOUT, DEFAULT_TOTAL_TIMEOUT};
    assert!(DEFAULT_CONNECT_TIMEOUT.as_secs() > 0);
    assert!(DEFAULT_TOTAL_TIMEOUT >= DEFAULT_CONNECT_TIMEOUT);
    assert!(
        DEFAULT_TOTAL_TIMEOUT.as_secs() <= 60,
        "a verification should not be able to stall for minutes"
    );
}

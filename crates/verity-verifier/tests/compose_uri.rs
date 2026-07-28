//! URI parsing. No network, no feature flag — this is pure logic and should be testable without
//! either.

#![allow(clippy::expect_used, clippy::panic)]

use verity_verifier::compose::{ComposeUri, UriError};

#[test]
fn parses_ipfs() {
    let uri =
        ComposeUri::parse("ipfs://bafkreidenehphc2udb62cgsbuveql5pvhhuuricbjtvtcleag3ec6zjj7u")
            .expect("valid");
    assert_eq!(
        uri.cid(),
        Some("bafkreidenehphc2udb62cgsbuveql5pvhhuuricbjtvtcleag3ec6zjj7u")
    );
    assert_eq!(
        uri.to_string(),
        "ipfs://bafkreidenehphc2udb62cgsbuveql5pvhhuuricbjtvtcleag3ec6zjj7u"
    );
}

#[test]
fn parses_http_and_https() {
    for s in [
        "http://example.invalid/c.json",
        "https://example.invalid/c.json",
    ] {
        let uri = ComposeUri::parse(s).expect("valid");
        assert_eq!(uri.cid(), None, "an HTTP URI has no CID");
        assert_eq!(uri.to_string(), s);
    }
}

#[test]
fn trims_surrounding_whitespace() {
    assert!(ComposeUri::parse("  ipfs://bafkreiabc \n").is_ok());
}

#[test]
fn refuses_empty_cid() {
    assert_eq!(ComposeUri::parse("ipfs://"), Err(UriError::EmptyCid));
}

#[test]
fn refuses_unsupported_scheme() {
    // file:// is the one that matters: a manifest pointing at a local path would make verification
    // depend on the verifying machine's filesystem.
    match ComposeUri::parse("file:///etc/passwd") {
        Err(UriError::UnsupportedScheme(s)) => assert_eq!(s, "file"),
        other => panic!("expected UnsupportedScheme, got {other:?}"),
    }
}

#[test]
fn refuses_bare_string() {
    assert_eq!(
        ComposeUri::parse("app-compose.json"),
        Err(UriError::NoScheme)
    );
    assert_eq!(ComposeUri::parse(""), Err(UriError::NoScheme));
}

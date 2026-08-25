//! URI parsing. No network, no feature flag — this is pure logic and should be testable without
//! either.

#![allow(clippy::expect_used, clippy::panic)]

use proptest::prelude::*;
use verity_verifier::compose::{Cid, ComposeUri, UriError};

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

// — VA-3: a malformed CID is rejected at parse —
//
// Seen-to-fail evidence (captured during implementation, before `Cid` existed): with the CID
// interpolated unencoded into `{base}/ipfs/{cid}` (`compose/http.rs`), a fake server recording the
// request line showed `ipfs://../admin` reaching it as a literal `/ipfs/../admin` path — real
// traversal — and `ipfs://cid&timeout=0` reaching Kubo's RPC as `?arg=cid&timeout=0`, with
// `timeout=0` parsed as a second query parameter — real injection. Both are RED against the
// unpatched tree; the two tests below are GREEN against this one, and hold *before* any request is
// built, because `Cid`'s inner field is private — there is no way to construct a `ComposeUri::Ipfs`
// holding either string at all.

#[test]
fn refuses_a_traversal_cid() {
    assert_eq!(
        ComposeUri::parse("ipfs://../admin"),
        Err(UriError::InvalidCid)
    );
}

#[test]
fn refuses_a_query_injection_cid() {
    assert_eq!(
        ComposeUri::parse("ipfs://cid&timeout=0"),
        Err(UriError::InvalidCid)
    );
}

#[test]
fn refuses_cids_containing_url_significant_or_control_bytes() {
    for bad in [
        "cid/x", "cid?x", "cid#x", "cid&x", "cid%2F", "cid:x", "cid@x", "cid[x]", "cid.x",
        "cid x",  // space
        "cid\tx", // tab
        "cid\nx", // newline — request-splitting-shaped
        "cid\rx", // carriage return
        "cid\0x", // NUL
        "cidé",   // non-ASCII
        "cid\\x", // backslash
        "cid;x", "cid'x", "cid\"x", "cid<x>", "cid{x}", "cid|x", "cid^x", "cid`x",
    ] {
        assert_eq!(
            Cid::parse(bad),
            Err(UriError::InvalidCid),
            "expected {bad:?} to be rejected"
        );
    }
}

#[test]
fn accepts_cids_from_every_common_multibase_form_ipfs_actually_uses() {
    // base32 (CIDv1 default, `b…`), base58btc (`Qm…`), base36 (`k…`), base16 (`f…`) — all within
    // `[A-Za-z0-9]`, so the allowlist accepts every form addressing actually uses.
    for cid in [
        "bafkreidenehphc2udb62cgsbuveql5pvhhuuricbjtvtcleag3ec6zjj7u",
        "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG",
        "k51qzi5uqu5dlvj2baxnqndepeb86cbk3ng7n3i46uzyxzyqj2xjonzllnv0v8",
        "f01551220c3c4733ec8affd06cf9e9ff50ffc6bcd2ec85a6170004bb709669c31de94391a",
    ] {
        assert!(
            Cid::parse(cid).is_ok(),
            "expected a real IPFS CID form to be accepted: {cid}"
        );
    }
}

proptest! {
    /// Any string containing a byte outside `[A-Za-z0-9_-]` is rejected — the allowlist covers
    /// every disallowed byte, not just the ones named above.
    #[test]
    fn any_string_with_a_disallowed_byte_is_rejected(
        prefix in "[A-Za-z0-9_-]{0,16}",
        bad in prop::char::any().prop_filter(
            "must be outside the allowed set",
            |c| !(c.is_ascii_alphanumeric() || *c == '-' || *c == '_'),
        ),
        suffix in "[A-Za-z0-9_-]{0,16}",
    ) {
        let s = format!("{prefix}{bad}{suffix}");
        prop_assert_eq!(Cid::parse(&s), Err(UriError::InvalidCid));
    }

    /// Any non-empty string built only from the allowed alphabet is accepted and round-trips
    /// byte-for-byte through `Cid::as_str` — the gate neither mangles nor truncates a legitimate
    /// CID.
    #[test]
    fn any_allowed_string_round_trips(s in "[A-Za-z0-9_-]{1,64}") {
        let cid = Cid::parse(&s).expect("every byte is allowed");
        prop_assert_eq!(cid.as_str(), s);
    }
}

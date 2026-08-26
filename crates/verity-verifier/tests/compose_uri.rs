//! URI parsing. No network, no feature flag — this is pure logic and should be testable without
//! either.

#![allow(clippy::expect_used, clippy::panic)]

use proptest::prelude::*;
use verity_verifier::compose::{Cid, ComposeUri, ComposeUrl, UriError};

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

// — VA-3 follow-up: `ComposeUri::Http` closes the same asymmetry `Cid` closed for `Ipfs` —
//
// Seen-to-fail evidence (verified against `529deda`, before `ComposeUrl` existed): the enum's own
// docs claim a caller "cannot accidentally hand a gateway an arbitrary URL", but
// `ComposeUri::Http("file:///etc/passwd".into())` compiled and ran clean — confirmed empirically as
// a scratch test against the unpatched tree (`1 passed; 0 failed`), with nothing anywhere in the
// path rejecting it. That is RED against the invariant the type claims for itself.
//
// No `compile_fail`/trybuild test asserts the fix, for the same reason none exists for `Cid`
// above: Rust has no per-field visibility on an enum tuple variant, so wrapping the field in a
// newtype whose only public constructor is `ComposeUrl::parse` is not one enforcement mechanism
// among several — it is the only one, and it holds at the module boundary for the whole crate, not
// just for a test file. `ComposeUri::Http(ComposeUrl)` no longer compiles from anything but
// `ComposeUri::parse` (or `ComposeUrl::parse(..).map(ComposeUri::Http)`), because `ComposeUrl`'s
// inner `String` is private and it derives no `From`/`FromStr`/serde impl. The tests below pin the
// constructor's behavior, which is the only place left to test.

#[test]
fn refuses_a_bad_http_scheme() {
    assert_eq!(
        ComposeUrl::parse("file:///etc/passwd"),
        Err(UriError::UnsupportedScheme("file".to_owned()))
    );
}

#[test]
fn refuses_a_bare_http_string() {
    assert_eq!(
        ComposeUrl::parse("app-compose.json"),
        Err(UriError::NoScheme)
    );
}

#[test]
fn accepts_both_http_schemes_verbatim() {
    for s in [
        "http://example.invalid/c.json",
        "https://example.invalid/c.json",
    ] {
        let url = ComposeUrl::parse(s).expect("valid");
        assert_eq!(
            url.as_str(),
            s,
            "the URL is fetched verbatim, not normalized"
        );
    }
}

#[test]
fn compose_uri_parse_and_compose_url_parse_never_disagree() {
    // The VA-3 finding-2 no-drift lesson made testable: `ComposeUri::parse`'s http(s) branch does
    // nothing but hand the trimmed string to `ComposeUrl::parse` and wrap the result, so the two
    // must agree on the scheme-validity verdict for every input — there is exactly one definition of
    // "a valid Http URL scheme", not two that could quietly diverge.
    //
    // Trimming itself is NOT part of what is shared: `ComposeUri::parse` trims before calling
    // `ComposeUrl::parse` (see the latter's docs), so this comparison mirrors that by trimming on
    // both sides (`s.trim()` below) rather than asserting `ComposeUrl::parse(s)` directly equals
    // `ComposeUri::parse(s)`'s result — those two *do* diverge for a padded string
    // (`ComposeUrl::parse(" http://x ")` rejects it as `UnsupportedScheme(" http")`, since it does no
    // trimming of its own). The whitespace-padded vector below still agrees once the shared trim is
    // applied on both sides, which is the property this test actually pins.
    for s in [
        "http://example.invalid/c.json",
        "https://example.invalid/c.json",
        "file:///etc/passwd",
        "app-compose.json",
        "",
        "ftp://example.invalid/c.json",
        "  http://example.invalid/c.json  ",
    ] {
        let wrapped_in_http_variant = ComposeUri::parse(s).ok().and_then(|uri| match uri {
            ComposeUri::Http(url) => Some(url),
            ComposeUri::Ipfs(_) => None,
        });
        let parsed_directly = ComposeUrl::parse(s.trim()).ok();
        assert_eq!(
            wrapped_in_http_variant, parsed_directly,
            "diverged on {s:?}"
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

    /// The universal form of `compose_uri_parse_and_compose_url_parse_never_disagree`: for any
    /// string at all, `ComposeUri::parse`'s http branch and a direct `ComposeUrl::parse` call agree
    /// on the scheme-validity verdict once both are compared post-trim — not just the six fixed
    /// vectors above. As with that test, this is a claim about *scheme validity*, not about
    /// whitespace handling: `ComposeUrl::parse` does no trimming of its own (see its docs), so this
    /// trims on both sides to compare like for like, mirroring what `ComposeUri::parse` actually
    /// hands the constructor.
    #[test]
    fn compose_uri_parse_and_compose_url_parse_never_disagree_for_any_string(s in ".{0,64}") {
        let wrapped_in_http_variant = ComposeUri::parse(&s).ok().and_then(|uri| match uri {
            ComposeUri::Http(url) => Some(url),
            ComposeUri::Ipfs(_) => None,
        });
        let parsed_directly = ComposeUrl::parse(s.trim()).ok();
        prop_assert_eq!(wrapped_in_http_variant, parsed_directly);
    }
}

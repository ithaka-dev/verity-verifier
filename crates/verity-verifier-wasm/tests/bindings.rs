//! The bindings must agree with the core crate, including on version.
//!
//! T-12 extended this from version parity to behaviour. The crate was at 21% coverage — not
//! because it was hard to test, but because CI only ever *built* it for wasm32, and "it compiles
//! for the target" is a different claim from "it does the right thing".
//!
//! Why the gap matters more than the number: ADR 0012 ships three distribution surfaces from one
//! core, and ADR 0014 notes each carries its own version and its own opportunity to lag. A binding
//! that disagrees with the core about what counts as a refusal is invisible from the core's own
//! tests, which all pass — and the agents most likely to embed *this* surface are the JavaScript
//! ones.

#![allow(clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use verity_verifier_wasm as bindings;

const COMPOSE: &[u8] =
    include_bytes!("../../verity-verifier/tests/fixtures/app-compose-0.5.7.json");
const QUOTE_HEX: &str =
    include_str!("../../verity-verifier/tests/fixtures/quote-v4-dstack-0.5.7.hex");
const LICENSED_HASH: &str = "64690ef38b54187da11a41a54905f5f539e948a0414ceb312c8036c82f6529fd";
const LICENSED_IMAGE: &str =
    "sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc";

// — the channel-binding pair, captured together from CVM 9be9f370 on dstack-0.5.9 —
//
// See `crates/verity-verifier/tests/fixtures/PROVENANCE.md`. The quote lives *inside* the
// certificate, so these two are one artifact read two ways rather than two that happen to agree.
const RATLS_LEAF_PEM: &[u8] =
    include_bytes!("../../verity-verifier/tests/fixtures/ratls-leaf-dstack-0.5.9.pem");
const RATLS_QUOTE_HEX: &str =
    include_str!("../../verity-verifier/tests/fixtures/ratls-leaf-dstack-0.5.9.quote.hex");
const GATEWAY_LEAF_PEM: &[u8] =
    include_bytes!("../../verity-verifier/tests/fixtures/gateway-leaf-letsencrypt.pem");

/// The quote the hardware actually signed.
fn quote() -> Vec<u8> {
    hex_bytes(QUOTE_HEX)
}

fn hex_bytes(hex: &str) -> Vec<u8> {
    let hex = hex.trim();
    (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("fixture is hex"))
        .collect()
}

/// Fixtures are stored as PEM because that is the form an operator captures a certificate in; the
/// bindings take DER, exactly as a JavaScript caller would after decoding a handshake certificate.
fn der(pem: &[u8]) -> Box<[u8]> {
    let (label, der) = pem_rfc7468::decode_vec(pem).expect("fixture is PEM");
    assert_eq!(label, "CERTIFICATE");
    der.into_boxed_slice()
}

/// ADR 0012: every distribution surface reports the same version.
///
/// A binding reporting a different version from the code it wraps makes "which verifier produced
/// this verdict?" unanswerable — the question ADR 0014 exists to keep answerable.
#[test]
fn version_matches_the_core_crate() {
    assert_eq!(
        bindings::verifier_version(),
        verity_verifier::verdict::VERIFIER_VERSION
    );
    assert_eq!(
        bindings::reference_data_date(),
        verity_verifier::reference::REFERENCE_DATA_DATE
    );
}

#[test]
fn compose_hash_agrees_with_the_core_crate() {
    assert_eq!(bindings::compose_hash(COMPOSE), LICENSED_HASH);
}

#[test]
fn image_check_agrees_with_the_core_crate() {
    assert!(bindings::check_images(COMPOSE, LICENSED_IMAGE).is_none());
    let wrong = format!("sha256:{}", "0".repeat(64));
    assert!(bindings::check_images(COMPOSE, &wrong).is_some());
}

/// A tagged image must be refused through the bindings exactly as through Rust. A binding laxer
/// than the core would be the easiest way to obtain a weakened verifier.
#[test]
fn bindings_are_not_laxer_than_the_core() {
    let tagged = serde_json::to_vec(&serde_json::json!({
        "manifest_version": 2,
        "runner": "docker-compose",
        "docker_compose_file": "services:\n  app:\n    image: alpine:latest\n",
    }))
    .expect("json");
    assert!(bindings::check_images(&tagged, LICENSED_IMAGE).is_some());
}

#[test]
fn malformed_quote_yields_no_measurement() {
    assert!(bindings::quote_mrconfigid(&[0u8; 16]).is_none());
}

#[test]
fn mrconfigid_check_refuses_a_malformed_hash() {
    assert!(bindings::check_mrconfigid(&[0u8; 700], "not-a-hash").is_some());
}

// — T-12: against the quote the hardware signed —

#[test]
fn compose_hash_is_sensitive_to_a_single_appended_byte() {
    let mut tampered = COMPOSE.to_vec();
    tampered.push(b' ');
    assert_ne!(bindings::compose_hash(&tampered), LICENSED_HASH);
}

#[test]
fn a_malformed_digest_refuses_rather_than_passing_through_as_no_problem() {
    // `null` means "no problem", so unparseable input reading as null would invert the answer.
    assert!(bindings::check_images(COMPOSE, "not-a-digest").is_some());
    assert!(bindings::check_images(COMPOSE, "").is_some());
}

#[test]
fn mrconfigid_is_read_from_a_real_quote() {
    let measured = bindings::quote_mrconfigid(&quote()).expect("the fixture quote parses");
    assert!(
        measured.starts_with(&format!("01{LICENSED_HASH}")),
        "V1 is 0x01 followed by the compose hash; got {measured}"
    );
}

/// `null` here means the quote could not be parsed — "a refusal, not an absence", as the binding's
/// own documentation puts it. A caller reading it as "this quote carries no MR-CONFIG-ID" would
/// draw the opposite conclusion from the intended one.
#[test]
fn anything_that_is_not_a_quote_yields_no_measurement() {
    assert!(bindings::quote_mrconfigid(&[]).is_none());
    assert!(bindings::quote_mrconfigid(b"this is not a quote").is_none());
}

/// **No prefix of a quote may trap.** A panic compiled to wasm is an unrecoverable trap for the
/// JavaScript caller — not an exception it can catch — so "refuses" and "crashes the host" are very
/// different outcomes for the same bad input. Every prefix is tried, one byte at a time.
///
/// It also pins where the parser's appetite ends. Prefixes shorter than the header plus the TD
/// report are refused; longer ones parse even though the trailing signature data is missing, and
/// that is correct: this function *extracts* a measurement and makes no claim about authenticity.
/// The signature is verified by the Rust API, which these bindings cannot reach and which reports
/// itself as skipped. Worth stating explicitly, because "it parsed" is exactly the kind of thing a
/// caller might mistake for "it checked out".
#[test]
fn no_prefix_of_a_quote_traps_and_short_ones_are_refused() {
    // Established by probing the parser: below this, there is not enough for a TD report.
    const NEEDS: usize = 4940;

    let full = quote();
    for len in 0..full.len() {
        let parsed = bindings::quote_mrconfigid(&full[..len]);
        if len < NEEDS {
            assert!(parsed.is_none(), "a {len}-byte prefix must not parse");
        }
    }

    assert!(
        bindings::quote_mrconfigid(&full[..NEEDS - 1]).is_none(),
        "one byte below the boundary"
    );
    assert!(
        bindings::quote_mrconfigid(&full[..NEEDS]).is_some(),
        "and exactly at it — an off-by-one here would refuse genuine quotes"
    );
}

#[test]
fn the_genuine_pairing_is_accepted() {
    assert!(
        bindings::check_mrconfigid(&quote(), LICENSED_HASH).is_none(),
        "the real compose and the real quote must verify against each other"
    );
}

/// **The refusal the crate exists for**, at the binding layer: one nibble of the licensed hash
/// changed, and the deployment is refused. This is `licensed_composeHash == attested_composeHash`.
#[test]
fn a_one_nibble_difference_is_refused() {
    let mut altered: Vec<char> = LICENSED_HASH.chars().collect();
    altered[0] = if altered[0] == '6' { '7' } else { '6' };
    let altered: String = altered.into_iter().collect();
    assert!(bindings::check_mrconfigid(&quote(), &altered).is_some());
}

#[test]
fn an_unreadable_hash_and_an_unreadable_quote_are_different_problems() {
    let bad_hash = bindings::check_mrconfigid(&quote(), "zzzz").expect("malformed hex refuses");
    let bad_quote =
        bindings::check_mrconfigid(b"not a quote", LICENSED_HASH).expect("bad quote refuses");
    assert_ne!(
        bad_hash, bad_quote,
        "a caller cannot act on a refusal that does not say which"
    );
}

#[test]
fn a_hash_of_the_wrong_length_is_refused() {
    let too_long = format!("{LICENSED_HASH}00");
    for candidate in ["", "00", &LICENSED_HASH[..62], &too_long] {
        assert!(
            bindings::check_mrconfigid(&quote(), candidate).is_some(),
            "{candidate:?} is not a 32-byte hash"
        );
    }
}

// — CR-1: channel binding through the bindings —

/// The *not-laxer-than-the-core* property, extended to the check CR-1 is about.
///
/// A JavaScript agent that could be talked out of channel binding — by omission, by a laxer
/// comparison, by an error mapped to `null` — is a weakened verifier obtained without touching the
/// Rust crate at all, and the agents most likely to embed this surface are the JavaScript ones.
///
/// All three directions are asserted against the core, not merely against expectations: the
/// bindings must agree with `ChannelBinding::check` on the genuine pair, on a genuine certificate
/// from a different enclave, and on the gateway's publicly trusted certificate.
#[test]
fn the_bindings_perform_channel_binding_exactly_as_the_core_does() {
    use verity_verifier::channel::ChannelBinding;
    use verity_verifier::quote::Quote;

    let ratls_quote = hex_bytes(RATLS_QUOTE_HEX);
    let ratls_leaf = der(RATLS_LEAF_PEM);
    let gateway_leaf = der(GATEWAY_LEAF_PEM);
    let parsed = Quote::parse(&ratls_quote).expect("the 0.5.9 fixture parses");

    // `null` means "no problem", so the pair the hardware produced must read as null — otherwise a
    // caller doing the right thing sees a refusal and starts loosening things.
    assert!(
        bindings::check_channel_binding(&ratls_quote, &ratls_leaf).is_none(),
        "the certificate and the quote it carries must bind"
    );
    assert!(ChannelBinding::check(&ratls_leaf, &parsed).is_ok());

    // A genuine quote from a *different*, destroyed CVM: CR-1's replay, through the bindings.
    let relayed = bindings::check_channel_binding(&quote(), &ratls_leaf)
        .expect("a quote from another enclave must not bind");
    assert!(relayed.contains("channel binding failed"), "{relayed}");

    // The dangerous negative: ordinary TLS verification *succeeds* against this certificate.
    let terminated = bindings::check_channel_binding(&ratls_quote, &gateway_leaf)
        .expect("the gateway's certificate must not bind");
    assert!(
        terminated.contains("channel binding failed"),
        "{terminated}"
    );
    assert!(ChannelBinding::check(&gateway_leaf, &parsed).is_err());
}

/// A quote that cannot be parsed is a refusal, not an absence — the same reading `quoteMrConfigId`
/// documents. Anything else would let malformed input read as "no problem here".
#[test]
fn channel_binding_refuses_rather_than_returning_no_problem_on_bad_input() {
    let ratls_leaf = der(RATLS_LEAF_PEM);
    assert!(bindings::check_channel_binding(b"not a quote", &ratls_leaf).is_some());
    assert!(bindings::check_channel_binding(&[], &ratls_leaf).is_some());

    let not_a_certificate = bindings::check_channel_binding(&hex_bytes(RATLS_QUOTE_HEX), b"nope")
        .expect("bytes that are not a certificate must refuse");
    assert!(
        not_a_certificate.contains("could not be parsed"),
        "a caller cannot act on a refusal that does not say which: {not_a_certificate}"
    );
}

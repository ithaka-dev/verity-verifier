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

/// The quote the hardware actually signed.
fn quote() -> Vec<u8> {
    let hex = QUOTE_HEX.trim();
    (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("fixture is hex"))
        .collect()
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

//! `connect_verified` against local TLS servers.
//!
//! # What can and cannot be established without a CVM
//!
//! **There is no local trustworthy verdict, and that is a property rather than a gap.** One would
//! need an Intel-signed quote committing to a key we hold, which we cannot produce. Every seam that
//! could manufacture one — a policy that skips signature verification, a test-mode collateral, a
//! "trust this quote" flag — would be a seam an attacker could reach for, which is the same
//! reasoning that keeps `dcap-qvl`'s `danger-allow-tcb-override` off. The positive lives on
//! hardware, in `verity-foundation/closed-loop/08-gateway-tls-termination.sh` steps 10 and 11.
//!
//! **What *is* locally provable is more than refusals**, and the distinction matters: a body of
//! evidence made only of refusals cannot tell "the check works" from "the check refuses
//! everything", which is the trap `closed-loop/04` step 3 exists to avoid.
//! `a_locally_keyed_certificate_carrying_a_tampered_quote_binds_and_is_still_refused` is the
//! positive control — over a real handshake it exercises proof of possession *succeeding*, quote
//! extraction from a live `peer_certificates()[0]`, and `ChannelBound` **passing** — while the
//! verdict as a whole is still untrustworthy and no client is produced.
//!
//! # Two things about the fixtures
//!
//! The tampered quote is derived **at runtime and never committed**. `fixtures/PROVENANCE.md`
//! opens with "every artifact here was measured on real hardware, never synthesised", and a
//! synthetic quote filed beside the captures would eventually be read as one.
//!
//! Servers bind and are dialled on `127.0.0.1`, never `localhost`. On macOS `localhost` resolves to
//! `::1` first while `TcpListener::bind("127.0.0.1:0")` binds IPv4, so a `localhost` dial gets
//! `ECONNREFUSED` — and a test expecting a refusal then passes without a connection ever happening.

// Whole-file feature guard: this suite drives `connect_verified` and uses `connect`/`attest`/
// `verify` APIs cfg-gated away when `connect` is off, so without it the file breaks
// `--no-default-features` and `--features fetch`-only builds. `connect` implies `attest`. Mirrors
// the guard on compose_{fetch,http}.rs. Under `--all-features` it still compiles and runs.
#![cfg(feature = "connect")]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::io::Write as _;
use std::net::TcpListener;
use std::sync::Arc;

use rustls::server::ResolvesServerCert;
use rustls::sign::CertifiedKey;
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use sha2::{Digest as _, Sha512};

use verity_verifier::attest::Collateral;
use verity_verifier::binding::ComposeHash;
use verity_verifier::connect::{
    connect_verified, CollateralSource, CollateralUnavailable, ConnectOptions, ConnectRequest,
    Refusal, RefusalKind,
};
use verity_verifier::endpoint::Endpoint;
use verity_verifier::ratls::extension_value_for_quote;
use verity_verifier::verdict::{Check, Disposition, Outcome, Unestablished, Verdict};
use verity_verifier::verify::LicensedVersion;

const RATLS_LEAF_PEM: &[u8] = include_bytes!("fixtures/ratls-leaf-dstack-0.5.9.pem");
const RATLS_QUOTE_HEX: &str = include_str!("fixtures/ratls-leaf-dstack-0.5.9.quote.hex");

/// Absolute offset of `report_data` in a TDX v4 quote: 48-byte header + 520 into the report body.
///
/// Pinned here rather than exported from the library: `quote.rs` keeps its offsets private on
/// purpose, and a *test* helper that rewrites a quote has no business being reachable from
/// production code. `the_tamper_lands_on_report_data_and_nothing_else` is what keeps this honest.
const REPORT_DATA_OFFSET: usize = 48 + 520;
const REPORT_DATA_LEN: usize = 64;

// ---------------------------------------------------------------------------------------------
// Fixtures and helpers
// ---------------------------------------------------------------------------------------------

fn fixture_leaf_der() -> Vec<u8> {
    let (label, der) = pem_rfc7468::decode_vec(RATLS_LEAF_PEM).expect("fixture is PEM");
    assert_eq!(label, "CERTIFICATE");
    der
}

fn fixture_quote() -> Vec<u8> {
    let hex = RATLS_QUOTE_HEX.trim();
    (0..hex.len() / 2)
        .map(|i| {
            u8::from_str_radix(hex.get(i * 2..i * 2 + 2).expect("in range"), 16)
                .expect("fixture is hex")
        })
        .collect()
}

/// What dStack's guest agent commits to: `sha512("ratls-cert:" ‖ SPKI DER)`.
///
/// Recomputed here rather than imported: the library keeps the tag and the computation private so
/// that the compute-it-yourself-then-compare path does not exist, and a test that borrowed the
/// library's own function would be comparing it against itself. This is the independent side.
fn ratls_commitment(spki_der: &[u8]) -> [u8; REPORT_DATA_LEN] {
    let mut h = Sha512::new();
    h.update(b"ratls-cert:");
    h.update(spki_der);
    h.finalize().into()
}

/// A copy of the fixture quote whose `report_data` commits to `spki_der`.
///
/// **Derived at runtime, never written to `fixtures/`.** It is not a measurement and must never sit
/// where measurements live.
fn quote_committing_to(spki_der: &[u8]) -> Vec<u8> {
    let mut quote = fixture_quote();
    let commitment = ratls_commitment(spki_der);
    quote
        .get_mut(REPORT_DATA_OFFSET..REPORT_DATA_OFFSET + REPORT_DATA_LEN)
        .expect("a v4 quote is long enough to contain report_data")
        .copy_from_slice(&commitment);
    quote
}

/// A locally generated P-256 certificate, optionally carrying an attestation extension.
///
/// P-256 because that is what dStack's RA-TLS certificates use (`openssl x509` on the fixture:
/// `id-ecPublicKey`, 256 bit). Matching the algorithm matters for the replay tests: with a
/// different one the handshake would fail on scheme negotiation rather than on the signature, and
/// the test would be establishing the wrong thing.
struct LocalCert {
    der: Vec<u8>,
    key_der: Vec<u8>,
}

/// Generate a certificate, optionally carrying `attestation` as a raw quote.
///
/// `attestation` is the **quote**, not the encoded extension value: encoding goes through the
/// library's [`extension_value_for_quote`] so the test serves the encoding the hardware emits
/// rather than one it invented. `tests/ratls_extraction.rs` pins that equivalence against a
/// captured certificate.
fn local_cert(attestation: Option<&[u8]>) -> LocalCert {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("key");
    cert_with(&key, attestation)
}

/// A certificate whose attestation quote commits to **its own** key.
///
/// The one arrangement a local test can build that makes channel binding pass over a real
/// handshake: the server holds the key, and `report_data` names it.
fn local_cert_committing_to_itself() -> LocalCert {
    use rcgen::PublicKeyData as _;

    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("key");
    let quote = quote_committing_to(&key.subject_public_key_info());
    cert_with(&key, Some(&quote))
}

fn cert_with(key: &rcgen::KeyPair, attestation: Option<&[u8]>) -> LocalCert {
    let mut params =
        rcgen::CertificateParams::new(vec!["127.0.0.1".to_owned()]).expect("certificate params");
    if let Some(raw_quote) = attestation {
        params.custom_extensions = vec![rcgen::CustomExtension::from_oid_content(
            // 1.3.6.1.4.1.62397.1.1 — the same arc `verity_verifier::ratls` searches for.
            &[1, 3, 6, 1, 4, 1, 62397, 1, 1],
            extension_value_for_quote(raw_quote).expect("encodes"),
        )];
    }
    let cert = params.self_signed(key).expect("self-signed");
    LocalCert {
        der: cert.der().to_vec(),
        key_der: key.serialize_der(),
    }
}

fn ring_provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// A server config serving `cert` with `key`, over the given protocol versions.
fn server_with(
    cert: &LocalCert,
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> ServerConfig {
    ServerConfig::builder_with_provider(ring_provider())
        .with_protocol_versions(versions)
        .expect("protocol versions")
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert.der.clone())],
            PrivateKeyDer::try_from(cert.key_der.clone()).expect("a private key"),
        )
        .expect("the key matches its own certificate")
}

/// Serve `chain` with a key that does **not** belong to it.
///
/// `with_single_cert` refuses this: it runs `CertifiedKey::keys_match` and returns
/// `Error::InconsistentKeys(KeyMismatch)`. A custom resolver bypasses that check — **which is
/// exactly the point.** An attacker replaying the enclave's public certificate has no such guard
/// either; the only thing standing in their way is the client verifying the handshake signature.
#[derive(Debug)]
struct ServesSomeoneElsesCertificate(Arc<CertifiedKey>);

impl ResolvesServerCert for ServesSomeoneElsesCertificate {
    fn resolve(&self, _hello: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(Arc::clone(&self.0))
    }
}

fn server_replaying(
    chain_der: Vec<u8>,
    foreign_key_der: &[u8],
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> ServerConfig {
    let signing_key = rustls::crypto::ring::sign::any_ecdsa_type(
        &PrivateKeyDer::try_from(foreign_key_der.to_vec()).expect("a private key"),
    )
    .expect("a P-256 signing key");
    // `CertifiedKey::new` performs no consistency check; `CertifiedKey::from_der` would.
    let certified = CertifiedKey::new(vec![CertificateDer::from(chain_der)], signing_key);
    ServerConfig::builder_with_provider(ring_provider())
        .with_protocol_versions(versions)
        .expect("protocol versions")
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(ServesSomeoneElsesCertificate(Arc::new(certified))))
}

/// Accept one connection, complete the handshake, and answer any request with `body`.
///
/// Returns the bound port. Bound on `127.0.0.1` — see the module docs.
fn serve_once(config: ServerConfig, body: &'static str) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    std::thread::spawn(move || {
        let Ok((sock, _)) = listener.accept() else {
            return;
        };
        let Ok(conn) = ServerConnection::new(Arc::new(config)) else {
            return;
        };
        let mut stream = StreamOwned::new(conn, sock);
        let mut seen = Vec::new();
        let mut byte = [0u8; 1];
        while !seen.ends_with(b"\r\n\r\n") {
            match std::io::Read::read(&mut stream, &mut byte) {
                Ok(0) | Err(_) => return,
                Ok(_) => seen.push(byte[0]),
            }
        }
        let _ = write!(
            stream,
            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{body}",
            body.len()
        );
        let _ = stream.flush();
    });
    port
}

fn endpoint_for(port: u16) -> Endpoint {
    Endpoint::parse(&format!("https://127.0.0.1:{port}")).expect("endpoint")
}

/// Structurally valid, cryptographically useless collateral.
///
/// The pattern `tests/attest.rs` established. It makes `QuoteSignature` fail, which is correct and
/// unavoidable locally: verifying an Intel signature needs Intel's answer for the platform the
/// quote came from, and there is no committed collateral fixture.
fn minimal_collateral() -> Collateral {
    Collateral {
        pck_crl_issuer_chain: String::new(),
        root_ca_crl: Vec::new(),
        pck_crl: Vec::new(),
        tcb_info_issuer_chain: String::new(),
        tcb_info: "{}".to_owned(),
        tcb_info_signature: Vec::new(),
        qe_identity_issuer_chain: String::new(),
        qe_identity: "{}".to_owned(),
        qe_identity_signature: Vec::new(),
        pck_certificate_chain: None,
    }
}

struct Minimal;
impl CollateralSource for Minimal {
    fn collateral_for(&self, _raw_quote: &[u8]) -> Result<Collateral, CollateralUnavailable> {
        Ok(minimal_collateral())
    }
}

struct Unavailable;
impl CollateralSource for Unavailable {
    fn collateral_for(&self, _raw_quote: &[u8]) -> Result<Collateral, CollateralUnavailable> {
        Err(CollateralUnavailable::new("the PCCS did not answer"))
    }
}

/// A record naming a compose document that no local server serves.
fn licensed() -> LicensedVersion {
    LicensedVersion {
        compose_hash: ComposeHash::of(b"{}"),
        image_digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            .to_owned(),
    }
}

/// Dial `port` and return the refusal, asserting no client was produced.
fn refusal_from(port: u16, source: &dyn CollateralSource) -> Refusal {
    let endpoint = endpoint_for(port);
    let licensed = licensed();
    let request = ConnectRequest::new(&endpoint, &licensed, b"{}".to_vec());
    connect_verified(&request, source, &ConnectOptions::default())
        .map(|_| ())
        .expect_err("no local endpoint can produce a trustworthy verdict")
}

// ---------------------------------------------------------------------------------------------
// The tests
// ---------------------------------------------------------------------------------------------

/// **Refused before a socket is opened**, and the port proves it.
///
/// Nothing listens on port 1 and the host does not resolve, so a `connect_verified` that dialled
/// first would return `NotReached`. Getting `TerminatingEndpoint` is what establishes the ordering.
#[test]
fn a_terminating_endpoint_is_refused_before_any_socket_is_opened() {
    let endpoint = Endpoint::parse(
        "https://38817d24b2e3bd9cdeae1acc60aaec7ea0957d18-8443.dstack-pha-prod5.phala.network:1",
    )
    .expect("endpoint");
    let licensed = licensed();
    let request = ConnectRequest::new(&endpoint, &licensed, b"{}".to_vec());

    let refusal = connect_verified(&request, &Minimal, &ConnectOptions::default())
        .map(|_| ())
        .expect_err("the terminating form can never be channel bound");

    match &refusal {
        Refusal::TerminatingEndpoint { host, passthrough } => {
            assert!(host.contains("-8443."), "{host}");
            assert!(
                passthrough.contains("-8443s."),
                "the refusal must name the host that would work: {passthrough}"
            );
        }
        other => panic!("dialled before classifying, or classified wrongly: {other:?}"),
    }
    assert_eq!(refusal.kind(), RefusalKind::EndpointUnusable);
    assert!(
        refusal.verdict().is_none(),
        "nothing was verified, so there is no verdict to report"
    );
}

/// An ordinary TLS server is refused for carrying no attestation.
///
/// The shape a gateway's Let's Encrypt certificate has, and any web server.
#[test]
fn a_server_with_an_ordinary_certificate_is_refused_for_having_no_attestation() {
    let cert = local_cert(None);
    let port = serve_once(server_with(&cert, rustls::ALL_VERSIONS), "hello");

    let refusal = refusal_from(port, &Minimal);
    assert!(
        matches!(refusal, Refusal::NoAttestation),
        "expected NoAttestation, got {refusal:?}"
    );
    assert_eq!(refusal.kind(), RefusalKind::GuaranteeViolated);
}

/// **CR-1's scenario, end to end through `connect_verified`, with no CVM.**
///
/// A genuine quote from a real (now destroyed) CVM, served beside an endpoint whose key we hold.
/// Every configuration check is about recorded values and could pass; `channel_bound` is the one
/// that cannot, because `report_data` commits to the enclave's key and not to this server's.
#[test]
fn a_relayed_quote_beside_a_local_endpoint_yields_a_refusal_and_never_a_client() {
    // The committed quote, unmodified: this is a relay presenting real evidence about a machine it
    // is not.
    let cert = local_cert(Some(&fixture_quote()));
    let port = serve_once(server_with(&cert, rustls::ALL_VERSIONS), "hello");

    let refusal = refusal_from(port, &Minimal);
    let Refusal::NotTrustworthy { verdict } = &refusal else {
        panic!("expected a verdict-bearing refusal, got {refusal:?}");
    };
    assert!(
        matches!(
            verdict.outcome(Check::ChannelBound),
            Some(Outcome::Failed(_))
        ),
        "channel binding must fail for a relayed quote: {verdict}"
    );
    assert_eq!(refusal.kind(), RefusalKind::GuaranteeViolated);
}

/// **The positive control: possession, extraction and binding all succeed, and it is still
/// refused.**
///
/// A locally generated P-256 key, whose certificate carries a copy of the fixture quote with only
/// `report_data` rewritten to commit to *this* key. Over a genuine handshake that exercises
/// `verify_tls13_signature` **succeeding** — the server really does hold the key — plus quote
/// extraction from a live `peer_certificates()[0]`, plus `ChannelBound` passing.
///
/// It is still untrustworthy, and both halves are asserted in the same verdict so this can never
/// drift into looking like a success: rewriting `report_data` invalidates Intel's signature, and
/// `minimal_collateral()` would fail `QuoteSignature` regardless.
#[test]
fn a_locally_keyed_certificate_carrying_a_tampered_quote_binds_and_is_still_refused() {
    let local = local_cert_committing_to_itself();
    let port = serve_once(server_with(&local, rustls::ALL_VERSIONS), "hello");

    let refusal = refusal_from(port, &Minimal);
    let Refusal::NotTrustworthy { verdict } = &refusal else {
        panic!("expected a verdict-bearing refusal, got {refusal:?}");
    };

    assert_eq!(
        verdict.outcome(Check::ChannelBound),
        Some(&Outcome::Passed),
        "the quote in this certificate commits to this certificate's key, over a handshake the \
         server proved it could sign — channel binding must pass: {verdict}"
    );
    assert!(
        matches!(
            verdict.outcome(Check::QuoteSignature),
            Some(Outcome::Failed(_))
        ),
        "the quote was tampered with and the collateral is useless — Intel's signature must not \
         verify. If this ever passes, something is manufacturing a trustworthy verdict locally, \
         which is the one thing this suite must never be able to do: {verdict}"
    );
    assert!(
        !verdict.is_trustworthy(),
        "no local endpoint may produce a trustworthy verdict"
    );
}

/// The tamper touches `report_data` and nothing else.
///
/// Keeps `REPORT_DATA_OFFSET` honest: an offset that drifted would silently corrupt a measurement
/// register instead, and the test above would then be asserting `ChannelBound` over a quote whose
/// `MR-CONFIG-ID` had been rewritten too.
#[test]
fn the_tamper_lands_on_report_data_and_nothing_else() {
    let original = fixture_quote();
    let tampered = quote_committing_to(b"any spki");
    assert_eq!(original.len(), tampered.len());

    let differing: Vec<usize> = original
        .iter()
        .zip(&tampered)
        .enumerate()
        .filter_map(|(i, (a, b))| (a != b).then_some(i))
        .collect();
    assert!(
        differing
            .iter()
            .all(|i| (REPORT_DATA_OFFSET..REPORT_DATA_OFFSET + REPORT_DATA_LEN).contains(i)),
        "the tamper reached outside report_data: {differing:?}"
    );
    assert!(!differing.is_empty(), "the tamper changed nothing at all");
}

/// **Proof of possession, as a refusal: the enclave's real certificate served without its key.**
///
/// The strongest local negative available. The certificate is genuine — captured from a live CVM —
/// and its quote genuinely commits to it, so `ChannelBinding::check` *would* pass. What the attacker
/// does not have is the private key, and `verify_tls13_signature` is the only place that is tested.
///
/// **Asserted on the variant, never on `is_err()`.** With `verify_tls13_signature` stubbed to
/// `assertion()` the run still errors — later, on collateral — so an `is_err()` assertion would
/// leave the most important mutant in `script/mutate.sh` alive.
#[test]
fn a_peer_that_replays_the_enclaves_certificate_without_its_key_fails_the_handshake() {
    let foreign = local_cert(None);
    let port = serve_once(
        server_replaying(fixture_leaf_der(), &foreign.key_der, rustls::ALL_VERSIONS),
        "hello",
    );

    let refusal = refusal_from(port, &Minimal);
    assert!(
        matches!(refusal, Refusal::HandshakeFailed { .. }),
        "a peer that cannot sign for the certificate it presented must fail the handshake, not \
         reach verification: {refusal:?}"
    );
    assert_eq!(refusal.kind(), RefusalKind::GuaranteeViolated);
}

/// The same replay over TLS 1.2.
///
/// A local client and server negotiate TLS 1.3, so without pinning the version here
/// `verify_tls12_signature` is never called and mutating it to `assertion()` changes nothing
/// observable. Same certificate, same foreign key, different handshake shape — in 1.2 the
/// certificate's key signs `ServerKeyExchange` rather than `CertificateVerify`, and rustls offers no
/// static-RSA suite, so the key is still the only thing being proved.
#[test]
fn the_same_replay_over_tls12_also_fails_the_handshake() {
    let foreign = local_cert(None);
    let port = serve_once(
        server_replaying(
            fixture_leaf_der(),
            &foreign.key_der,
            &[&rustls::version::TLS12],
        ),
        "hello",
    );

    let refusal = refusal_from(port, &Minimal);
    assert!(
        matches!(refusal, Refusal::HandshakeFailed { .. }),
        "expected a TLS 1.2 handshake failure, got {refusal:?}"
    );
    assert_eq!(refusal.kind(), RefusalKind::GuaranteeViolated);
}

/// A well-formed, genuinely-keyed endpoint over TLS 1.2 still reaches verification.
///
/// The control for the test above: without it, "TLS 1.2 refuses a replay" and "TLS 1.2 refuses
/// everything" look identical. Here the server holds its own key, the handshake succeeds over 1.2,
/// and the refusal comes from the verdict rather than from the handshake.
#[test]
fn a_correctly_keyed_tls12_endpoint_reaches_verification_rather_than_failing_the_handshake() {
    let cert = local_cert(Some(&fixture_quote()));
    let port = serve_once(server_with(&cert, &[&rustls::version::TLS12]), "hello");

    let refusal = refusal_from(port, &Minimal);
    assert!(
        matches!(refusal, Refusal::NotTrustworthy { .. }),
        "TLS 1.2 with a matching key must complete the handshake and be refused on the verdict, \
         not on the signature: {refusal:?}"
    );
}

/// **Criterion 5, both sides: an outage is not an attack.**
///
/// Same endpoint, same certificate, same quote. The only difference is that collateral could not be
/// obtained — and the kind must change, because a caller retries one and alerts on the other.
#[test]
fn a_collateral_source_that_fails_yields_could_not_establish_not_guarantee_violated() {
    let cert = local_cert(Some(&fixture_quote()));
    let port = serve_once(server_with(&cert, rustls::ALL_VERSIONS), "hello");

    let refusal = refusal_from(port, &Unavailable);
    assert!(
        matches!(refusal, Refusal::CollateralUnavailable(_)),
        "expected a collateral refusal, got {refusal:?}"
    );
    assert_eq!(
        refusal.kind(),
        RefusalKind::CouldNotEstablish,
        "an outage in the caller's collateral source must not be reported as a violated guarantee"
    );
}

/// The kind mapping is total, and a new variant cannot inherit a default.
///
/// The `match` in `Refusal::kind` has no wildcard, so adding a variant is a compile error until
/// somebody chooses. This asserts the other half: that each kind is actually reachable, so the
/// three-way split is not two buckets and a dead one.
#[test]
fn every_refusal_variant_maps_to_exactly_one_kind() {
    let cases: Vec<(Refusal, RefusalKind)> = vec![
        (
            Refusal::TerminatingEndpoint {
                host: "a".to_owned(),
                passthrough: "b".to_owned(),
            },
            RefusalKind::EndpointUnusable,
        ),
        (
            Refusal::NotReached {
                host: "a".to_owned(),
                port: 443,
                detail: "refused".to_owned(),
            },
            RefusalKind::CouldNotEstablish,
        ),
        (
            Refusal::CollateralUnavailable(CollateralUnavailable::new("no answer")),
            RefusalKind::CouldNotEstablish,
        ),
        (
            Refusal::HandshakeFailed {
                host: "a".to_owned(),
                detail: "bad signature".to_owned(),
            },
            RefusalKind::GuaranteeViolated,
        ),
        (Refusal::NoPeerCertificate, RefusalKind::GuaranteeViolated),
        (Refusal::NoAttestation, RefusalKind::GuaranteeViolated),
        (
            Refusal::UnreadableAttestation {
                detail: "envelope".to_owned(),
            },
            RefusalKind::GuaranteeViolated,
        ),
        (
            Refusal::NotTrustworthy {
                verdict: Box::new(verity_verifier::verdict::Verdict::new()),
            },
            RefusalKind::GuaranteeViolated,
        ),
    ];

    for (refusal, expected) in &cases {
        assert_eq!(refusal.kind(), *expected, "{refusal:?}");
        assert!(
            !refusal.to_string().is_empty(),
            "every refusal must say something an operator can act on: {refusal:?}"
        );
    }

    // All three kinds reachable, and their names stable — `closed-loop/08` step 11 greps them.
    let kinds: std::collections::BTreeSet<&str> =
        cases.iter().map(|(r, _)| r.kind().name()).collect();
    assert_eq!(
        kinds,
        [
            "could_not_establish",
            "endpoint_unusable",
            "guarantee_violated"
        ]
        .into_iter()
        .collect()
    );

    // `Display` is what `examples/connect-verified.rs` prints and what `08` step 11 greps, so it
    // must agree with `name()` rather than being a second, prettier rendering that can drift.
    for (refusal, _) in &cases {
        assert_eq!(refusal.kind().to_string(), refusal.kind().name());
    }
}

// — MA-6: `Refusal::disposition()` and the `kind()` refinement —

/// `Refusal::disposition()` is coarse, like `kind()`: only the two retrieval-shaped refusals
/// disposition to `RetryRetrieval`, and every other variant — including `NotTrustworthy`, whatever
/// its verdict's own per-check dispositions say — is `Refuse`. Not a fold over the verdict: a
/// `NotTrustworthy` refusal here always reads `Refuse` even when every non-passing essential inside
/// it is `Indeterminate`, because this answers "should the caller retry the whole connection", a
/// coarser question than any one check's remedy — read `Verdict::dispositions` via `Refusal::verdict`
/// for that.
#[test]
fn refusal_disposition_is_retry_only_for_the_two_retrieval_shaped_variants() {
    let retryable = [
        Refusal::NotReached {
            host: "a".to_owned(),
            port: 443,
            detail: "refused".to_owned(),
        },
        Refusal::CollateralUnavailable(CollateralUnavailable::new("no answer")),
    ];
    for refusal in &retryable {
        assert_eq!(
            refusal.disposition(),
            Disposition::RetryRetrieval,
            "{refusal:?}"
        );
    }

    let not_retryable = [
        Refusal::TerminatingEndpoint {
            host: "a".to_owned(),
            passthrough: "b".to_owned(),
        },
        Refusal::NoPeerCertificate,
        Refusal::NotTrustworthy {
            verdict: Box::new(Verdict::new().record(
                Check::MrConfigId,
                Outcome::unestablished(Unestablished::VerifierCannotJudge, "V2"),
            )),
        },
    ];
    for refusal in &not_retryable {
        assert_eq!(refusal.disposition(), Disposition::Refuse, "{refusal:?}");
    }
}

/// `kind()`'s refinement: a `NotTrustworthy` verdict whose only non-passing essentials are
/// `Indeterminate` is `CouldNotEstablish`, not `GuaranteeViolated` — nothing was violated, only
/// unestablished.
#[test]
fn kind_reports_could_not_establish_when_every_non_passing_essential_is_indeterminate() {
    let mut verdict = Verdict::new();
    for check in Check::essential() {
        let outcome = if *check == Check::MrConfigId {
            Outcome::unestablished(Unestablished::VerifierCannotJudge, "V2")
        } else {
            Outcome::Passed
        };
        verdict = verdict.record(*check, outcome);
    }
    let refusal = Refusal::NotTrustworthy {
        verdict: Box::new(verdict),
    };
    assert_eq!(refusal.kind(), RefusalKind::CouldNotEstablish);
}

/// The same shape, but one essential reached a refusal instead of merely being unestablished — this
/// must stay `GuaranteeViolated`, because *something* was violated, not only unestablished.
#[test]
fn kind_stays_guarantee_violated_when_any_non_passing_essential_is_failed_or_skipped() {
    for bad in [
        Outcome::Failed("mismatch".to_owned()),
        Outcome::Skipped("declined".to_owned()),
    ] {
        let mut verdict = Verdict::new();
        for check in Check::essential() {
            let outcome = if *check == Check::MrConfigId {
                bad.clone()
            } else {
                Outcome::Passed
            };
            verdict = verdict.record(*check, outcome);
        }
        let refusal = Refusal::NotTrustworthy {
            verdict: Box::new(verdict),
        };
        assert_eq!(refusal.kind(), RefusalKind::GuaranteeViolated, "{bad:?}");
    }
}

/// A refusal that carries no verdict says so, rather than inventing an empty one.
///
/// `Refusal::verdict` returning `Some(Verdict::new())` for an endpoint that was never dialled would
/// read as "every check was considered and none ran" — a different and much worse claim than
/// "verification never started".
#[test]
fn only_a_verdict_bearing_refusal_reports_one() {
    let unusable = Refusal::TerminatingEndpoint {
        host: "a".to_owned(),
        passthrough: "b".to_owned(),
    };
    assert!(unusable.verdict().is_none());

    let judged = Refusal::NotTrustworthy {
        verdict: Box::new(
            verity_verifier::verdict::Verdict::new().record(Check::ChannelBound, Outcome::Passed),
        ),
    };
    assert_eq!(
        judged
            .verdict()
            .and_then(|v| v.outcome(Check::ChannelBound)),
        Some(&Outcome::Passed)
    );
}

/// **No untrustworthy verdict produced a client, in any test above.**
///
/// Every case in this file asserts `expect_err`, which is the same claim from the other direction.
/// This one states it once, explicitly, over the closest thing to a success the local suite can
/// build — the tampered-quote endpoint, whose `ChannelBound` passes.
#[test]
fn an_untrustworthy_verdict_cannot_produce_a_client() {
    let local = local_cert_committing_to_itself();
    let port = serve_once(server_with(&local, rustls::ALL_VERSIONS), "hello");

    let endpoint = endpoint_for(port);
    let licensed = licensed();
    let request = ConnectRequest::new(&endpoint, &licensed, b"{}".to_vec());

    let outcome = connect_verified(&request, &Minimal, &ConnectOptions::default());
    assert!(
        outcome.is_err(),
        "a client was produced from a verdict that is not trustworthy — `TrustworthyVerdict::check` \
         is the only thing standing between a caller and this, and it did not"
    );
}

/// A `ConnectRequest` built by hand carries a boot reference through unchanged.
///
/// `new` defaults `boot` to `None`; the field is public so a caller who has captured one can set it.
/// Exercising both keeps the struct's two construction paths honest with each other.
#[test]
fn a_boot_reference_can_be_supplied_after_construction() {
    let endpoint = endpoint_for(1);
    let licensed = licensed();
    let boot = verity_verifier::reference::BootReference::default();

    let mut request = ConnectRequest::new(&endpoint, &licensed, b"{}".to_vec());
    assert!(request.boot.is_none());
    request.boot = Some(&boot);
    assert_eq!(request.boot, Some(&boot));
}

/// An endpoint nothing is listening on is an outage, not an attack.
#[test]
fn an_endpoint_that_refuses_the_connection_is_not_reached_rather_than_refused() {
    // Bind and immediately drop, so the port is almost certainly free and definitely unserved.
    let port = {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.local_addr().expect("addr").port()
    };

    let refusal = refusal_from(port, &Minimal);
    assert!(
        matches!(refusal, Refusal::NotReached { .. }),
        "expected NotReached, got {refusal:?}"
    );
    assert_eq!(refusal.kind(), RefusalKind::CouldNotEstablish);
}

/// The default bounds are the ones documented, and they are not zero.
///
/// A `ConnectOptions` whose defaults drifted to "no timeout" would be a verification that can hang
/// forever — a denial of service that needs no exploit, only patience.
#[test]
fn the_default_options_bound_every_phase() {
    let options = ConnectOptions::default();
    assert_eq!(options.connect_timeout.as_secs(), 10);
    assert_eq!(options.handshake_timeout.as_secs(), 10);
    assert_eq!(options.request_timeout.as_secs(), 30);
    assert_eq!(options.response_limit, 16 * 1024 * 1024);
}

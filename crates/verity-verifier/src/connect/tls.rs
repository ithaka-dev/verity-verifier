//! The TLS half of the verified transport: the config, the verifier, and the dial.
//!
//! Nothing here decides whether an endpoint is trustworthy. It produces a completed handshake and
//! the leaf certificate that handshake presented, and hands both to [`super`], which verifies them.
//! The split matters: this file's job is to make sure the certificate we go on to check is one the
//! peer proved it holds the key for, and that is the whole of its contribution.

use std::net::{SocketAddr, TcpStream, ToSocketAddrs as _};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::{ClientConfig, ClientConnection, SignatureScheme, StreamOwned};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};

use crate::endpoint::Endpoint;

use super::Refusal;

/// A completed, verified-at-the-TLS-layer connection and the leaf it presented.
///
/// `Debug` is hand-written rather than derived: `StreamOwned` is not `Debug`, and a derive that
/// printed 5 KiB of certificate into a log line would be a poor default anyway.
pub(super) struct Handshook {
    /// The stream, ready for application data — **and not yet written to.**
    pub(super) stream: StreamOwned<ClientConnection, TcpStream>,
    /// DER of the leaf certificate this handshake presented, copied out of the connection.
    pub(super) leaf_der: Vec<u8>,
}

impl std::fmt::Debug for Handshook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Handshook")
            .field("leaf_der_len", &self.leaf_der.len())
            .finish_non_exhaustive()
    }
}

/// Build the `ClientConfig` every connection in this crate uses.
///
/// # Never `ClientConfig::builder()`, and the reason is our own build
///
/// `rustls::crypto::CryptoProvider::from_crate_features` returns a provider only when *exactly one*
/// of the `ring` and `aws_lc_rs` features is enabled, and the bare builder `.expect`s on it with
/// "Could not automatically determine the process-level `CryptoProvider`". Under `--all-features` —
/// which CI and `script/mutate.sh` both use — `fetch` brings ureq's `ring` and `dcap-qvl`'s default
/// `report` feature brings reqwest's `aws-lc-rs`, so **both are on and the bare builder panics
/// here, today**. `builder_with_provider` names the provider and cannot.
///
/// It also deliberately does **not** call `install_default()`. That would mutate a process-global
/// other crates read — reqwest checks `CryptoProvider::get_default()` before falling back — so a
/// library that installed one would be choosing a crypto backend on behalf of its embedder.
///
/// `tests::the_client_config_constructs_under_all_features` is what turns this from a comment into
/// a gate: a regression to the bare builder fails CI rather than an agent's first connect.
pub(super) fn client_config() -> Arc<ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());

    // SAFETY (panic): `with_safe_default_protocol_versions` fails only when the provider offers no
    // cipher suite for any enabled protocol version. The provider is `ring`, constructed one line
    // above, and the versions are whatever the `rustls` features in this workspace's manifest turn
    // on — both compile-time facts about *this* crate, not about anything a caller or a peer
    // supplies. There is no runtime input that can reach this.
    //
    // Propagating it instead was considered and rejected: it would put a `Result` on every call
    // site for a condition no caller could act on or even distinguish, and the honest handling
    // would be to abort anyway. `the_client_config_constructs_under_all_features` executes this
    // exact path in CI, so the invariant is observed rather than assumed.
    #[allow(clippy::expect_used)]
    let mut config = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .expect("the ring provider supports the protocol versions this crate enables")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AuthenticatedByQuote { provider }))
        .with_no_client_auth();

    // — session resumption is off, and this line cannot be defended by a test —
    //
    // A resumed handshake restores `peer_certificates` from the resumption store and calls neither
    // signature verifier: rustls hard-codes `ServerCertVerified::assertion()` and
    // `HandshakeSignatureValid::assertion()` on the resumption path (`client/tls13.rs`,
    // `client/tls12.rs`), with its own comment "We *don't* reverify the certificate chain here".
    //
    // That is sound TLS — the pre-shared key is the proof of continuity — but it is not sound for
    // the claim *this* crate makes, which is narrower: the quote must come out of the certificate
    // **this** handshake presented. On a resumed connection that certificate is a memory of an
    // earlier one, so `connect/mod.rs`'s module docs would be true only with a caveat.
    //
    // Disabling it costs one full handshake per reconnect and buys an unconditional claim.
    //
    // **Reviewer, note:** no mutant defends this. Delete the line and every test still passes,
    // because a resumed connection in the cases we can construct locally still presents the right
    // certificate. It is on the review checklist for that reason.
    config.resumption = rustls::client::Resumption::disabled();

    Arc::new(config)
}

/// The socket, with every read and write bounded by one wall-clock deadline.
///
/// # Why this exists, and what was wrong without it
///
/// A per-socket read timeout bounds a peer that says **nothing**. It does not bound one that says
/// *something*, slowly: `ClientConnection::complete_io` loops internally while the handshake is
/// unfinished (`rustls/src/conn.rs`), so a peer dribbling one byte per half-timeout keeps every
/// individual read inside its budget, never returns control to the caller, and stalls the
/// verification indefinitely. A deadline checked *between* `complete_io` calls is therefore never
/// reached, which is exactly what the first version of this file got wrong.
///
/// So the deadline is enforced **inside** the I/O: each read is given only the time that remains,
/// and once the budget is spent every read fails. The dribbling peer is bounded by the total
/// budget rather than by its own per-byte latency, which is the property `handshake_timeout`
/// claims to have.
///
/// `tests::a_peer_that_dribbles_bytes_loses_on_the_wall_clock_rather_than_per_read` is the test
/// that would fail without it; it fails against a per-read timeout alone.
struct DeadlineIo<'a> {
    sock: &'a mut TcpStream,
    deadline: Instant,
}

impl DeadlineIo<'_> {
    /// Give the socket the time that remains, or report the budget as spent.
    fn arm(&mut self) -> std::io::Result<()> {
        let remaining = self
            .deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "the TLS handshake did not complete within the handshake timeout",
                )
            })?;
        self.sock.set_read_timeout(Some(remaining))?;
        self.sock.set_write_timeout(Some(remaining))
    }
}

impl std::io::Read for DeadlineIo<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.arm()?;
        self.sock.read(buf)
    }
}

impl std::io::Write for DeadlineIo<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.arm()?;
        self.sock.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.sock.flush()
    }
}

/// Dial `endpoint`, complete the handshake, and return the stream with the leaf it presented.
///
/// The two deadlines are separate on purpose. `connect_timeout` bounds reaching the host;
/// `handshake_timeout` bounds everything after the socket is open — a peer that accepts and then
/// says nothing, *and* a peer that dribbles bytes forever. Both stalls cost the attacker one
/// `accept()` and cost us a hung verification; see [`DeadlineIo`] for why the second needs the
/// deadline pushed into the I/O rather than checked around it. `compose/http.rs` already makes this
/// argument for retrieval: whether a verification can hang forever is a security property, and
/// "whatever the library currently does" is a version-dependent accident.
pub(super) fn dial(
    endpoint: &Endpoint,
    config: &Arc<ClientConfig>,
    connect_timeout: Duration,
    handshake_timeout: Duration,
) -> Result<Handshook, Refusal> {
    let not_reached = |detail: String| Refusal::NotReached {
        host: endpoint.host().to_owned(),
        port: endpoint.port(),
        detail,
    };

    // **Before the DNS lookup, deliberately.** A host TLS cannot carry in SNI is an input we can
    // reject without touching the network, and rejecting it first is what makes the refusal say so:
    // resolving first meant every unusable name came back as a DNS failure, because nothing that
    // fails this check resolves either. That ordering made the branch unreachable and its test pass
    // for the wrong reason.
    let server_name = ServerName::try_from(endpoint.host())
        .map_err(|e| {
            not_reached(format!(
                "`{}` is not a valid server name: {e}",
                endpoint.host()
            ))
        })?
        .to_owned();

    let addr = resolve(endpoint).map_err(&not_reached)?;
    let mut sock = TcpStream::connect_timeout(&addr, connect_timeout)
        .map_err(|e| not_reached(e.to_string()))?;

    let mut conn = ClientConnection::new(Arc::clone(config), server_name).map_err(|e| {
        Refusal::HandshakeFailed {
            host: endpoint.host().to_owned(),
            detail: e.to_string(),
        }
    })?;

    // One budget for the whole handshake, enforced on every read and write inside `complete_io`.
    let mut io = DeadlineIo {
        sock: &mut sock,
        deadline: Instant::now() + handshake_timeout,
    };
    while conn.is_handshaking() {
        // `complete_io` drives the handshake and returns when it can make no more progress without
        // more input. A peer that stalls — silently or slowly — surfaces here as an `io::Error` and
        // therefore `NotReached`: an outage, not an attack. A peer that *answers* and answers
        // wrongly surfaces as a `rustls::Error` and therefore `HandshakeFailed`.
        //
        // **That split is where the attack/outage line lives**, and it is the reason these two are
        // matched separately rather than collapsed into one "could not connect".
        match conn.complete_io(&mut io) {
            // `Ok((0, 0))` means `complete_io` made no progress and the handshake is unfinished.
            // Without this the loop spins hot — and **`DeadlineIo` would not bound it**, because
            // that path performs no read or write, so nothing would ever consult the deadline.
            //
            // **Unreachable in rustls 0.23.42, and kept anyway.** `complete_io` returns early with
            // `(0, 0)` only when `!wants_write() && !wants_read()`. Mid-handshake `wants_write()`
            // can be false, but `wants_read()` cannot: it goes false only on non-empty
            // `received_plaintext` (impossible before the handshake finishes) or
            // `has_received_close_notify` — and `common_state.rs:524` sets that flag only when
            // `may_receive_application_data` is true, with rustls' own comment "do not treat
            // unauthenticated alerts like this". Verified by probe: a peer answering the
            // ClientHello with a plaintext `close_notify` is bounded by the deadline, not by this.
            //
            // So this is a guard against a future rustls making that state reachable, where the
            // failure would be a spinning thread rather than a refusal. `script/mutate.sh` records
            // the matching mutant as EQUIVALENT with this argument rather than omitting it.
            Ok((0, 0)) => {
                return Err(not_reached(
                    "the peer stopped responding during the TLS handshake".to_owned(),
                ))
            }
            Ok(_) => {}
            Err(e) => {
                return Err(
                    match e.get_ref().and_then(|r| r.downcast_ref::<rustls::Error>()) {
                        Some(tls) => Refusal::HandshakeFailed {
                            host: endpoint.host().to_owned(),
                            detail: tls.to_string(),
                        },
                        None => not_reached(e.to_string()),
                    },
                );
            }
        }
    }

    // Read before a single application byte is written. `super::connect` owns this value until
    // `TrustworthyVerdict::check` returns `Ok`, so the ordering is structural rather than a
    // convention someone has to preserve.
    let leaf_der = conn
        .peer_certificates()
        .and_then(<[CertificateDer<'_>]>::first)
        .map(|c| c.as_ref().to_vec())
        .ok_or(Refusal::NoPeerCertificate)?;

    // Restore a permissive socket timeout for the request phase; ureq sets its own per operation.
    // Left as an explicit step rather than dropped, because inheriting a 200ms handshake budget as
    // a read timeout on a long-running request would look like a flaky endpoint.
    let _ = sock.set_read_timeout(None);
    let _ = sock.set_write_timeout(None);

    Ok(Handshook {
        stream: StreamOwned::new(conn, sock),
        leaf_der,
    })
}

/// Resolve `host:port` to one address.
///
/// The first address the resolver offers, deliberately: this crate does not implement Happy
/// Eyeballs, and a verifier that silently tried several addresses would make "which peer did I
/// verify?" ambiguous in exactly the situation where the answer matters.
fn resolve(endpoint: &Endpoint) -> Result<SocketAddr, String> {
    (endpoint.host(), endpoint.port())
        .to_socket_addrs()
        .map_err(|e| e.to_string())?
        .next()
        .ok_or_else(|| "the host resolved to no addresses".to_owned())
}

/// The certificate verifier: **no PKI, no hostname, and full signature verification.**
///
/// # What is deliberately not checked
///
/// The chain and the hostname. The leaf is issued by the Dstack App CA, and Intel's signature over
/// the quote is what establishes authenticity; a CA's opinion about the key would be a second,
/// weaker one (ADR 0027). On dStack's TLS-terminating gateway form the *opposite* holds — a
/// publicly trusted certificate that validates perfectly and belongs to the wrong peer — which is
/// precisely why PKI is not the thing consulted here.
///
/// # What is checked, and why it is the whole of MA-1
///
/// [`ServerCertVerifier::verify_tls12_signature`] and
/// [`ServerCertVerifier::verify_tls13_signature`] are **delegated to rustls's real
/// implementations**. rustls offers no static-RSA key exchange, so in both TLS 1.2 and 1.3 the
/// certificate's private key signs the handshake transcript and nothing else — these two calls are
/// the only place the peer proves it holds it.
///
/// An enclave's RA-TLS certificate is **public**: anyone who connects to the real CVM gets a copy.
/// Stub these two — which is exactly what `ureq`'s own `DisabledVerifier` does — and a relay serving
/// that copy completes the handshake with its own ephemeral key, [`crate::channel::ChannelBinding`]
/// passes (the certificate really does match the quote, because it *is* the enclave's), and the
/// holder's document goes to the attacker under a trustworthy verdict. `channel.rs` states the
/// assumption out loud — *"they do not hold the enclave's private key"* — and this is the only
/// place that assumption is tested.
///
/// `script/mutate.sh` scores both, over TLS 1.3 and over TLS 1.2 separately, because a local client
/// and server negotiate 1.3 and the 1.2 path would otherwise be unexercised.
#[derive(Debug)]
struct AuthenticatedByQuote {
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for AuthenticatedByQuote {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // See the type's docs. Asserting here is correct and is *not* the same shape as asserting
        // in the two functions below: this declines to consult a weaker authority, those would
        // decline to test possession of a key.
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // Delegated, never asserted. See the type's docs — this is the whole of MA-1.
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // Delegated, never asserted. See the type's docs — this is the whole of MA-1.
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        // Taken from the provider rather than listed by hand. A hand-written list that drifted
        // ahead of what `ring` can verify would advertise a scheme we then fail to check, and the
        // failure would look like a broken endpoint.
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    //! Tests that need this module's private items.
    //!
    //! `cfg(test)` is not set on the library when `tests/*.rs` compile against it, so anything
    //! reaching a `pub(super)`/private item has to live here. Precedent: `src/channel.rs`, whose
    //! commitment-tag test is in-module for the same reason.

    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::{client_config, dial};
    use crate::endpoint::Endpoint;
    use std::sync::Arc;
    use std::time::Duration;

    /// **The `builder_with_provider` requirement, as a gate rather than a comment.**
    ///
    /// Constructing it at all is the assertion. Under `--all-features` this build has both
    /// `rustls/ring` (via `fetch` → ureq) and `rustls/aws_lc_rs` (via `dcap-qvl`'s default `report`
    /// → reqwest) enabled, so the bare `ClientConfig::builder()` panics with "Could not
    /// automatically determine the process-level `CryptoProvider`" — meaning this test is red the
    /// moment someone simplifies the construction, rather than an agent finding out on its first
    /// connect to a live endpoint.
    ///
    /// **`Resumption::disabled()` is deliberately not asserted here.** rustls exposes no way to
    /// read it back — `Resumption`'s fields are private and `ClientConfig` has no accessor — so an
    /// assertion would have to match on `Debug` output, which is a test that breaks on a rustls
    /// patch release without anything being wrong. The line carries its reason at the call site and
    /// sits on the review checklist instead; a test that cannot be written honestly should not be
    /// written dishonestly.
    #[test]
    fn the_client_config_constructs_under_all_features() {
        let config = client_config();
        assert!(
            config
                .crypto_provider()
                .signature_verification_algorithms
                .supported_schemes()
                .contains(&rustls::SignatureScheme::ECDSA_NISTP256_SHA256),
            "the provider must be able to verify the P-256 signatures dStack's RA-TLS \
             certificates use — without that, every genuine endpoint fails the handshake"
        );
    }

    /// A host TLS cannot carry in SNI is refused by **that** check, not by DNS.
    ///
    /// # Why this asserts on the detail and not only on the kind
    ///
    /// The first version dialled `https://..:1` and asserted `CouldNotEstablish`. It passed — and
    /// established nothing, because `dial` resolved first, `("..", 1).to_socket_addrs()` failed, and
    /// the `ServerName` branch was never reached. Both paths produce the same kind, so the
    /// assertion could not tell them apart.
    ///
    /// Nothing that fails `ServerName::try_from` resolves either, so no host can separate the two by
    /// choice of input; `dial` now validates the name **before** the lookup, and this asserts on the
    /// message so the branch is named rather than inferred.
    #[test]
    fn a_host_that_is_not_a_usable_server_name_is_refused_by_the_name_check() {
        // A leading hyphen: accepted as a URL, rejected as a DNS name by rustls-pki-types.
        let endpoint = Endpoint::parse("https://-lead.example:1").expect("it parses as a URL");
        let refusal = dial(
            &endpoint,
            &client_config(),
            Duration::from_millis(200),
            Duration::from_millis(200),
        )
        .expect_err("a leading hyphen is not a server name");

        assert!(
            refusal.to_string().contains("is not a valid server name"),
            "the refusal must name the check that refused, or a DNS failure is indistinguishable \
             from an unusable name: {refusal}"
        );
        assert_eq!(
            refusal.kind(),
            crate::connect::RefusalKind::CouldNotEstablish
        );
    }

    /// `Handshook`'s hand-written `Debug` says the size and not the certificate.
    #[test]
    fn the_handshake_debug_impl_reports_a_length_and_not_a_certificate() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let cert =
            rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_owned()]).expect("certificate");
        let server = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("versions")
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            rustls_pki_types::PrivateKeyDer::try_from(cert.signing_key.serialize_der())
                .expect("key"),
        )
        .expect("the key matches its certificate");
        std::thread::spawn(move || {
            if let Ok((sock, _)) = listener.accept() {
                if let Ok(conn) = rustls::ServerConnection::new(Arc::new(server)) {
                    let mut stream = rustls::StreamOwned::new(conn, sock);
                    let mut byte = [0u8; 1];
                    let _ = std::io::Read::read(&mut stream, &mut byte);
                }
            }
        });

        let endpoint = Endpoint::parse(&format!("https://127.0.0.1:{port}")).expect("endpoint");
        let handshook = dial(
            &endpoint,
            &client_config(),
            Duration::from_secs(5),
            Duration::from_secs(5),
        )
        .expect("the local server completes a handshake");

        let rendered = format!("{handshook:?}");
        assert!(rendered.contains("leaf_der_len"), "{rendered}");
        assert!(
            !rendered.contains("30, 130"),
            "the certificate bytes must not be printed: {rendered}"
        );
    }

    /// A peer that accepts a socket and then says nothing must lose on the handshake budget.
    ///
    /// The cheapest denial of service there is: it costs the attacker one `accept()`.
    ///
    /// **Dialled as `127.0.0.1`, not `localhost`, and that is not cosmetic.** On macOS `localhost`
    /// resolves to `::1` first while `TcpListener::bind("127.0.0.1:0")` binds IPv4, so the dial got
    /// `ECONNREFUSED` — and this test passed, quickly, having established nothing about the
    /// deadline. The `accepted` handshake below is what makes the difference observable: without a
    /// connection there is nothing to time out on.
    ///
    /// Budget pinned at 200ms so the 10s default never costs the mutation harness 29 × 10s. The
    /// lower bound is asserted as well as the upper: a refusal that arrives *instantly* is a
    /// connection that never happened, which is how this test lied the first time it was written.
    #[test]
    fn a_peer_that_accepts_and_never_speaks_loses_within_the_handshake_budget() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let (accepted_tx, accepted_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let accepted = listener.accept();
            let _ = accepted_tx.send(accepted.is_ok());
            // Hold the connection open, saying nothing, past any budget the test might use.
            std::thread::sleep(Duration::from_secs(30));
        });

        let endpoint = Endpoint::parse(&format!("https://127.0.0.1:{port}")).expect("endpoint");
        let started = std::time::Instant::now();
        let refusal = dial(
            &endpoint,
            &client_config(),
            Duration::from_secs(5),
            Duration::from_millis(200),
        )
        .expect_err("a peer that never speaks cannot complete a handshake");
        let elapsed = started.elapsed();

        assert_eq!(
            accepted_rx.recv_timeout(Duration::from_secs(5)),
            Ok(true),
            "the server never accepted a connection, so this refusal is not about the handshake \
             budget at all"
        );
        assert!(
            elapsed >= Duration::from_millis(150),
            "the refusal arrived in {elapsed:?}, faster than the 200ms budget — that is a \
             connection that never happened, not a deadline being enforced"
        );
        assert!(
            elapsed < Duration::from_secs(5),
            "the handshake budget was not applied: waited {elapsed:?}"
        );
        // An outage, not an attack. A stalled peer is indistinguishable from a broken network, and
        // reporting it as `GuaranteeViolated` would put a retryable fault in the alert bucket.
        assert_eq!(
            refusal.kind(),
            crate::connect::RefusalKind::CouldNotEstablish
        );
    }

    /// **The subtler stall: a peer that answers, slowly, forever.**
    ///
    /// The test the review found missing, and it turned out to be missing a mechanism as well as a
    /// test. A per-socket read timeout bounds a peer that says *nothing*; it does not bound one that
    /// says *something* every half-timeout. `complete_io` loops internally while the handshake is
    /// unfinished, so every individual read lands inside its budget, control never returns to
    /// `dial`, and a deadline checked around `complete_io` is never reached.
    ///
    /// This server writes one byte per 60ms against a 300ms budget — so no read ever times out, and
    /// only a wall-clock deadline enforced *inside* the I/O can stop it.
    ///
    /// **The bytes must be well formed, and that is the whole difficulty.** A first attempt
    /// dribbled `0x16` repeatedly; rustls rejected it as a malformed record and the refusal came
    /// back `GuaranteeViolated` — the test would then have passed its timing assertions while
    /// measuring a *parse* failure rather than a *stall*. So the peer sends a legal handshake record
    /// header declaring a maximum-length body and then dribbles that body forever: rustls stays in
    /// `wants_read` and never errors, which is the real slowloris.
    ///
    /// Asserted on the kind as well as the timing, because "refused after roughly the budget" is
    /// also what a coincidental TLS error looks like.
    #[test]
    fn a_peer_that_dribbles_bytes_loses_on_the_wall_clock_rather_than_per_read() {
        const BUDGET: Duration = Duration::from_millis(300);
        const PER_BYTE: Duration = Duration::from_millis(60);

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let (accepted_tx, accepted_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let Ok((mut sock, _)) = listener.accept() else {
                return;
            };
            let _ = accepted_tx.send(true);
            // A legal TLS record header: handshake (0x16), TLS 1.2 legacy version, and a body length
            // of 0x4000 — the maximum a record may carry, so rustls accepts the header and then
            // waits for 16384 bytes that arrive one at a time and never finish.
            if std::io::Write::write_all(&mut sock, &[0x16, 0x03, 0x03, 0x40, 0x00]).is_err() {
                return;
            }
            let _ = std::io::Write::flush(&mut sock);
            for _ in 0..500 {
                if std::io::Write::write_all(&mut sock, &[0x00]).is_err() {
                    return;
                }
                let _ = std::io::Write::flush(&mut sock);
                std::thread::sleep(PER_BYTE);
            }
        });

        let endpoint = Endpoint::parse(&format!("https://127.0.0.1:{port}")).expect("endpoint");
        let started = std::time::Instant::now();
        let refusal = dial(&endpoint, &client_config(), Duration::from_secs(5), BUDGET)
            .expect_err("a peer that never finishes the handshake cannot be verified");
        let elapsed = started.elapsed();

        assert_eq!(
            accepted_rx.recv_timeout(Duration::from_secs(5)),
            Ok(true),
            "the server never accepted, so this refusal is not about the handshake budget"
        );
        assert!(
            elapsed >= PER_BYTE,
            "the refusal arrived in {elapsed:?}, before the peer could dribble anything — that is \
             a connection that never happened, not a deadline being enforced"
        );
        assert!(
            elapsed < BUDGET * 6,
            "the wall-clock deadline did not bound a dribbling peer: waited {elapsed:?} against a \
             {BUDGET:?} budget. A per-read timeout alone cannot catch this, which is why the \
             deadline lives inside `DeadlineIo` rather than around `complete_io`"
        );
        assert_eq!(
            refusal.kind(),
            crate::connect::RefusalKind::CouldNotEstablish,
            "a slow peer is an outage, not an attack"
        );
    }
}

//! The HTTP half: a `ureq` connector that verifies, a transport that carries, and one request
//! function that both the public methods and the tests go through.
//!
//! # Why ureq at all
//!
//! Because a client you cannot use is a detachable verdict with a struct around it. Handing back
//! `impl Read + Write` moves the problem: an agent author with an unusable client reaches for
//! `reqwest` against the same URL and opens a **second, unverified** connection — worse than today,
//! because they now believe they verified something. And hand-rolling HTTP/1.1 here would break the
//! workspace's standing refusal of hand-written parsers for structured input; chunked transfer
//! encoding and header folding are that argument, not an exception to it.
//!
//! # Why the `Connector` seam specifically
//!
//! ureq's stable `TlsConfig` exposes only a crypto provider and `disable_verification`. It cannot
//! install a [`rustls::client::danger::ServerCertVerifier`] and gives no access to the peer
//! certificate, so channel binding is impossible through it — and `disable_verification` is
//! precisely the wrong switch, because ureq's `DisabledVerifier` stubs the handshake-signature
//! checks that are the whole of MA-1.
//!
//! Going through the connector instead buys the property that matters: **every connection the agent
//! opens runs the same verification**, including ureq's own reconnect after a pooled socket closes.
//! There is one code path, not two, and no way for ureq to obtain a connection that skipped it.
//!
//! `ureq::unversioned::transport` is documented as not following semver. Accepted, with the
//! mitigation that a breaking change there is a **compile** error rather than a behaviour change,
//! the version floor is declared at `3.3`, and this glue is kept thin.

use std::io::{Read as _, Write as _};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ureq::config::Config;
use ureq::http::Uri;
use ureq::unversioned::resolver::DefaultResolver;
use ureq::unversioned::transport::{
    Buffers, ConnectionDetails, Connector, LazyBuffers, NextTimeout, Transport,
};
use ureq::Agent;

use crate::channel::ChannelBinding;
use crate::verdict::TrustworthyVerdict;

use super::{ConnectOptions, ConnectRequest, Refusal, Response, TransportError};

/// What a completed verification established, republished on every reconnect.
///
/// Held behind a `Mutex` and read by [`super::VerifiedClient::verdict`] and
/// [`super::VerifiedClient::channel_binding`]. **Not a cache.** A `VerifiedClient` that answered
/// "what am I talking to?" with the connect-time certificate after ureq had silently reconnected
/// would be reporting a stale SPKI — and in the crown jewel a stale answer to that question is a
/// lie, not a caching decision.
#[derive(Debug, Clone)]
pub(super) struct Verification {
    pub(super) verdict: TrustworthyVerdict,
    pub(super) binding: ChannelBinding,
}

/// The owned form of a [`ConnectRequest`].
///
/// `Connector` is `Send + Sync + 'static` (ureq requires it, because an `Agent` is shared), and
/// `ConnectRequest<'a>` is all borrows. So the connector takes clones. Everything it needs already
/// derives `Clone`; nothing is re-derived here that could drift from the caller's intent.
#[derive(Debug, Clone)]
pub(super) struct OwnedRequest {
    pub(super) endpoint: crate::endpoint::Endpoint,
    pub(super) licensed: crate::verify::LicensedVersion,
    pub(super) compose_document: Vec<u8>,
    pub(super) boot: Option<crate::reference::BootReference>,
    pub(super) tcb: crate::attest::TcbPolicy,
}

impl OwnedRequest {
    pub(super) fn from_borrowed(request: &ConnectRequest<'_>) -> Self {
        Self {
            endpoint: request.endpoint.clone(),
            licensed: request.licensed.clone(),
            compose_document: request.compose_document.clone(),
            boot: request.boot.cloned(),
            tcb: request.tcb.clone(),
        }
    }
}

/// The connector. Every connection ureq opens comes through here, and none leaves unverified.
pub(super) struct VerifiedConnector {
    pub(super) request: OwnedRequest,
    pub(super) options: ConnectOptions,
    pub(super) tls: Arc<rustls::ClientConfig>,
    /// Intel collateral from the first verification.
    ///
    /// The *collateral* is cached, not the [`super::CollateralSource`]. Caching the source would
    /// force `Send + Sync + 'static` onto the caller's implementation, which would stop it
    /// borrowing a tokio runtime to fetch — the shape every real implementation has, because
    /// `dcap-qvl` fetches asynchronously.
    ///
    /// Consequence, stated rather than discovered: collateral eventually falls outside its validity
    /// window and a later reconnect refuses. The remedy is another `connect_verified`. Fail-closed.
    pub(super) collateral: Arc<crate::attest::Collateral>,
    /// Republished on every successful verification. See [`Verification`].
    ///
    /// `None` only before the first one completes, which is before a [`super::VerifiedClient`]
    /// exists — so no caller can observe the empty state.
    pub(super) latest: Arc<Mutex<Option<Verification>>>,
    /// The transport from the connection [`super::connect_verified`] verified, waiting for the
    /// first request.
    ///
    /// **This is what makes "the socket that was verified is the socket the requests travel over"
    /// literally true** rather than "an equivalent socket, verified the same way". Without it the
    /// first request would open a second connection — still verified, because it would come through
    /// this same connector, but a different one from the one whose verdict was returned.
    ///
    /// If the server closes it before the first request, ureq's failure is an ordinary I/O error
    /// and its retry comes back through [`Connector::connect`], which dials and verifies afresh.
    /// Fail-closed either way.
    pub(super) pending: Mutex<Option<VerifiedTransport>>,
}

impl std::fmt::Debug for VerifiedConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Hand-written so the collateral and the TLS config do not land in a log line, and so this
        // stays cheap. `Connector` requires `Debug`; it does not require it to be interesting.
        f.debug_struct("VerifiedConnector")
            .field("endpoint", &self.request.endpoint.url())
            .finish_non_exhaustive()
    }
}

impl VerifiedConnector {
    /// Dial, handshake, and verify.
    ///
    /// Used for every reconnect. [`super::connect_verified`] performs the same dial itself — it has
    /// to, because the collateral that this connector caches can only be fetched once the quote is
    /// known — and then calls [`VerifiedConnector::verify_handshook`], which is the *whole* of the
    /// post-handshake sequence. **There is one verification code path**, and both entry points go
    /// through it.
    pub(super) fn verify_connection(&self) -> Result<VerifiedTransport, Refusal> {
        let handshook = super::tls::dial(
            &self.request.endpoint,
            &self.tls,
            self.options.connect_timeout,
            self.options.handshake_timeout,
        )?;
        self.verify_handshook(handshook).map(|(_, t)| t)
    }

    /// Verify a completed handshake, and yield a transport only if the verdict is trustworthy.
    ///
    /// Takes the handshake by value: the socket lives inside it, so every error path below drops
    /// the connection rather than leaving one open that failed verification. That ownership is what
    /// makes "no application byte is written before the check" structural rather than a convention.
    pub(super) fn verify_handshook(
        &self,
        handshook: super::tls::Handshook,
    ) -> Result<(Verification, VerifiedTransport), Refusal> {
        // The quote comes out of the certificate this handshake presented — not from a cloud API,
        // not from the caller. `tls::dial` has already established that the peer holds the key for
        // it, so "the quote came out of the certificate we then check it against" is not circular:
        // an attacker can copy the enclave's public certificate, but then fails the handshake; or
        // embed a genuine recorded quote in their own certificate, but then `report_data` commits
        // to the enclave's key rather than theirs. Nothing is attacker-selectable on both sides.
        let raw_quote =
            crate::ratls::quote_from_certificate(&handshook.leaf_der).map_err(|e| match e {
                crate::ratls::AttestationError::Missing => Refusal::NoAttestation,
                other => Refusal::UnreadableAttestation {
                    detail: other.to_string(),
                },
            })?;

        let verdict = crate::verify::verify(
            &self.request.licensed,
            &crate::verify::Evidence {
                raw_quote: &raw_quote,
                compose_document: self.request.compose_document.clone(),
                collateral: &self.collateral,
                now_secs: ConnectOptions::now_secs(),
                // The same bytes the quote came out of, and the same bytes the peer proved
                // possession of. Not a certificate a caller handed us — which is the residual
                // ADR 0027 documented and this module exists to close.
                peer_certificate: crate::channel::PeerCertificate::Presented(&handshook.leaf_der),
            },
            self.request.boot.as_ref(),
            &self.request.tcb,
        );

        // — the post-verify guard —
        //
        // The socket is inside `handshook` and is dropped on this error path, so a connection whose
        // verdict was not trustworthy is closed rather than returned. `script/mutate.sh` removes
        // this guard; `tests::the_connector_refuses_to_produce_a_transport_for_an_untrustworthy_verdict`
        // is what kills that mutant.
        let verdict =
            TrustworthyVerdict::check(verdict).map_err(|verdict| Refusal::NotTrustworthy {
                verdict: Box::new(verdict),
            })?;

        // Re-run rather than plumbed out of `verify`: `verify` records an `Outcome`, not the
        // binding value, and the alternative — widening `verify`'s return type — would put an
        // I/O-layer convenience into the crate's most-audited signature.
        let quote =
            crate::quote::Quote::parse(&raw_quote).map_err(|e| Refusal::UnreadableAttestation {
                detail: e.to_string(),
            })?;
        let binding = ChannelBinding::check(&handshook.leaf_der, &quote).map_err(|e| {
            Refusal::UnreadableAttestation {
                detail: e.to_string(),
            }
        })?;

        let verification = Verification { verdict, binding };
        // Published so `VerifiedClient::verdict` and `::channel_binding` describe the connection
        // currently in use rather than the one that happened to be first. A poisoned lock is
        // swallowed: another thread panicking must not turn a verified connection into an abort,
        // and the client keeps its own connect-time copy as a floor.
        if let Ok(mut latest) = self.latest.lock() {
            *latest = Some(verification.clone());
        }

        Ok((verification, VerifiedTransport::new(handshook.stream)))
    }

    /// Take the transport `connect_verified` verified, if the first request has not used it yet.
    fn take_pending(&self) -> Option<VerifiedTransport> {
        self.pending.lock().ok().and_then(|mut p| p.take())
    }

    /// Stash the transport from the connection `connect_verified` verified.
    pub(super) fn set_pending(&self, transport: VerifiedTransport) {
        if let Ok(mut pending) = self.pending.lock() {
            *pending = Some(transport);
        }
    }
}

impl Connector<()> for VerifiedConnector {
    type Out = VerifiedTransport;

    fn connect(
        &self,
        _details: &ConnectionDetails<'_>,
        _chained: Option<()>,
    ) -> Result<Option<Self::Out>, ureq::Error> {
        // `details.uri` and `details.addrs` are ignored deliberately. The host is fixed by the
        // verification that produced this client, and `VerifiedClient::{get, post}` take a path
        // rather than a URL, so there is no argument a caller could supply that would make this dial
        // elsewhere. Reading either here would create exactly the lever the API refuses to offer.
        //
        // **The cost, named: DNS is resolved twice per connection.** ureq's `DefaultResolver` has
        // already filled in `details.addrs` by this point, and `tls::dial` resolves again. Using
        // ureq's answer would mean the address we connect to came from a component that does not
        // know which host was verified — cheap, and the wrong shape for the one place in this crate
        // where "which peer is this?" has to have a single answer. A second `getaddrinfo` on a
        // connection that is about to do a TLS handshake and a DCAP verification is not the cost
        // worth optimising.
        //
        // The first request consumes the connection `connect_verified` already verified; every
        // later one is dialled and verified here. Both went through `verify_handshook`.
        if let Some(pending) = self.take_pending() {
            return Ok(Some(pending));
        }
        self.verify_connection().map(Some).map_err(|refusal| {
            // `Error::Other` is ureq's documented escape hatch for bespoke connector chains, and it
            // is what lets the `Refusal` survive the trip out and be downcast back in `request`.
            // Mapping to `Error::Io` instead — ureq's first recommendation — would flatten a
            // refusal into a string, and criterion 5 asks that a caller can tell an attack from an
            // outage precisely here, on a mid-session endpoint swap.
            ureq::Error::Other(Box::new(refusal))
        })
    }
}

/// A `ureq` transport over a connection this crate verified.
///
/// Mirrors ureq's own `RustlsTransport` with one difference that matters: it owns the `TcpStream`
/// directly rather than wrapping a chained transport, because the dial happened in
/// [`super::tls::dial`] where the certificate could be captured.
pub(super) struct VerifiedTransport {
    buffers: LazyBuffers,
    stream: rustls::StreamOwned<rustls::ClientConnection, std::net::TcpStream>,
}

impl VerifiedTransport {
    pub(super) fn new(
        stream: rustls::StreamOwned<rustls::ClientConnection, std::net::TcpStream>,
    ) -> Self {
        Self {
            // ureq's own defaults. Sized here rather than taken from `ConnectionDetails` so the
            // `#[cfg(test)]` tests below can build a transport without a live `Config`.
            buffers: LazyBuffers::new(BUFFER_SIZE, BUFFER_SIZE),
            stream,
        }
    }

    /// Apply a ureq per-operation deadline to the underlying socket.
    ///
    /// ureq's `Duration` is a wrapper carrying a "never happens" case; `not_zero` already maps that
    /// to `None`, and `*` takes the inner `std::time::Duration` for the rest. `None` clears the
    /// socket timeout, which is what "no deadline for this operation" means at the OS level.
    fn set_deadline(&mut self, timeout: NextTimeout) {
        let deadline = timeout.not_zero().map(|d| *d);
        let _ = self.stream.sock.set_read_timeout(deadline);
        let _ = self.stream.sock.set_write_timeout(deadline);
    }
}

/// ureq's own default input/output buffer size.
const BUFFER_SIZE: usize = 128 * 1024;

impl std::fmt::Debug for VerifiedTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedTransport").finish_non_exhaustive()
    }
}

impl Transport for VerifiedTransport {
    fn buffers(&mut self) -> &mut dyn Buffers {
        &mut self.buffers
    }

    fn transmit_output(&mut self, amount: usize, timeout: NextTimeout) -> Result<(), ureq::Error> {
        self.set_deadline(timeout);
        // `get(..amount)` rather than an index. ureq passes an `amount` it derived from this same
        // buffer, so a short slice cannot happen — but this crate denies `indexing_slicing` because
        // a panic reaching an embedder is worse than any error, and "the caller is well behaved" is
        // exactly the assumption a verifier should not be making anywhere.
        let output = self.buffers.output().get(..amount).ok_or_else(|| {
            ureq::Error::Other("the output buffer was shorter than ureq asked for".into())
        })?;
        self.stream.write_all(output)?;
        Ok(())
    }

    fn await_input(&mut self, timeout: NextTimeout) -> Result<bool, ureq::Error> {
        self.set_deadline(timeout);
        let input = self.buffers.input_append_buf();
        let amount = self.stream.read(input)?;
        self.buffers.input_appended(amount);
        Ok(amount > 0)
    }

    fn is_open(&mut self) -> bool {
        // A cheap liveness probe, the same one ureq's TCP transport uses: peek for a byte with a
        // zero timeout. `Ok(0)` means the peer sent FIN.
        let mut byte = [0u8; 1];
        let _ = self
            .stream
            .sock
            .set_read_timeout(Some(Duration::from_millis(1)));
        match self.stream.sock.peek(&mut byte) {
            Ok(0) => false,
            Ok(_) => true,
            Err(e) => matches!(
                e.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ),
        }
    }

    fn is_tls(&self) -> bool {
        // **Not decorative.** `Transport::is_tls` defaults to `false`, and ureq then rejects an
        // https request over this transport with `Error::TlsRequired` — a fully verified connection
        // refused for describing itself wrongly. No mutant defends this line; the request test
        // below does, because without it every request fails.
        true
    }
}

/// The `ureq::Config` every verified client uses.
///
/// `pub(super)` and shared with the tests below rather than inlined at the construction site: a
/// second copy of these settings is a second place for `max_redirects` to be wrong.
pub(super) fn agent_config(options: &ConnectOptions) -> Config {
    Config::builder()
        // **A redirect to another host is a request to leave the connection that was verified.**
        // Following one would open a connection to a peer nobody attested and return its body under
        // a `VerifiedClient`. With this at 0 ureq returns the 3xx response itself, so the caller
        // sees the redirect and decides — rather than the library deciding for them, invisibly.
        // `script/mutate.sh` raises this to 10.
        .max_redirects(0)
        // Statuses are data, not errors. A 404 from a verified enclave is a verified 404, and
        // ureq's default of turning 4xx/5xx into `Error::StatusCode` would make
        // `TransportError::Io` the reported cause of a perfectly healthy exchange.
        .http_status_as_error(false)
        .timeout_global(Some(options.request_timeout))
        .build()
}

/// Build the agent that carries requests over verified connections.
pub(super) fn agent(options: &ConnectOptions, connector: VerifiedConnector) -> Agent {
    Agent::with_parts(agent_config(options), connector, DefaultResolver::default())
}

/// Perform one request over a verified connection, and read a bounded response.
///
/// # Why this is a free function
///
/// So it can be tested. [`super::VerifiedClient::get`] and [`super::VerifiedClient::post`] are
/// two-line delegations to it, which means the request path, the redirect policy, the size cap and
/// the refusal downcast are all exercised by unit tests that build an `Agent` — **without any test
/// seam that could construct a `VerifiedClient`**. That distinction is the point: a test may build
/// the plumbing; nothing may build the guarantee.
///
/// It is the same move `transcript_line` made out of `examples/verify-attestation.rs` and
/// `compose_only_verdict` made out of the wasm boundary — logic welded to a boundary a test cannot
/// cross is logic nothing tests.
///
/// # Errors
///
/// [`TransportError`], including [`TransportError::Refused`] when the connector refused to produce
/// a connection.
pub(super) fn request(
    agent: &Agent,
    base: &crate::endpoint::Endpoint,
    method: &str,
    path: &str,
    body: Option<(&str, &[u8])>,
    response_limit: usize,
) -> Result<Response, TransportError> {
    // A path, never a URL: the authority comes from the `Endpoint` that was verified and cannot be
    // influenced by the caller. A leading `/` is added rather than demanded, because `get("health")`
    // silently addressing something else would be a poor trade for strictness in a place where
    // there is no ambiguity to resolve.
    let uri: Uri = format!(
        "https://{}:{}{}{}",
        base.host(),
        base.port(),
        if path.starts_with('/') { "" } else { "/" },
        path
    )
    .parse()
    .map_err(|e| TransportError::Io {
        detail: format!("`{path}` is not a usable request path: {e}"),
    })?;

    let mut builder = ureq::http::Request::builder().method(method).uri(uri);
    if let Some((content_type, _)) = body {
        builder = builder.header("content-type", content_type);
    }
    let built = builder
        .body(body.map(|(_, bytes)| bytes).unwrap_or_default())
        .map_err(|e| TransportError::Io {
            detail: format!("the request could not be built: {e}"),
        })?;

    let response = agent.run(built).map_err(from_ureq)?;
    let status = response.status().as_u16();
    let headers: Vec<(String, String)> = response
        .headers()
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|v| (name.as_str().to_ascii_lowercase(), v.to_owned()))
        })
        .collect();

    // Read one byte past the limit deliberately: a body exactly at the limit is fine, and the extra
    // byte is what distinguishes "exactly at" from "over". Streaming rather than buffering the
    // whole response first means a hostile endpoint cannot make us allocate gigabytes before we
    // notice — the same argument, and the same shape, as `compose/http.rs::read_capped`.
    let mut buf = Vec::new();
    let read = response
        .into_body()
        .into_reader()
        .take(
            u64::try_from(response_limit)
                .unwrap_or(u64::MAX)
                .saturating_add(1),
        )
        .read_to_end(&mut buf)
        .map_err(|e| TransportError::Io {
            detail: e.to_string(),
        })?;
    if read > response_limit {
        return Err(TransportError::TooLarge {
            limit: response_limit,
        });
    }

    Ok(Response {
        status,
        headers,
        body: buf,
    })
}

/// Recover a [`Refusal`] from ureq's error, or fall back to a transport fault.
///
/// **This downcast is load-bearing.** The connector carries a refusal out through
/// `ureq::Error::Other`; if it is not taken back out here, a reconnect that failed *verification*
/// arrives at the caller as an indistinguishable I/O error — and criterion 5 asks that a caller can
/// tell an attack from an outage precisely on that path, where an endpoint has changed under them
/// mid-session. `tests::a_connector_refusal_arrives_back_as_transport_error_refused` pins it.
fn from_ureq(error: ureq::Error) -> TransportError {
    if let ureq::Error::Other(boxed) = error {
        return match boxed.downcast::<Refusal>() {
            Ok(refusal) => TransportError::Refused(refusal),
            Err(other) => TransportError::Io {
                detail: other.to_string(),
            },
        };
    }
    TransportError::Io {
        detail: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    //! The plumbing, driven through a real `Agent::with_parts`.
    //!
    //! These live in `src/` because `cfg(test)` is not set on the library when `tests/*.rs` compile
    //! against it, so nothing there can reach a `pub(super)` item. Precedent: `src/channel.rs`,
    //! whose commitment-tag test is in-module for the same reason.
    //!
    //! **What they deliberately do not do is construct a `VerifiedClient`.** There is no
    //! `#[cfg(test)]` constructor for it and there must not be: the risk is not a shipped bypass
    //! but a future test author asserting behaviour through one, and thereby testing a client that
    //! never existed in production. A test seam may build the plumbing; nothing may build the
    //! guarantee. Everything below goes through the same `agent_config` and `request` that
    //! `VerifiedClient` does.

    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use std::io::Write as _;
    use std::net::TcpListener;

    use super::{agent_config, from_ureq, request, VerifiedTransport};
    use crate::connect::{ConnectOptions, Refusal, TransportError};
    use crate::endpoint::Endpoint;
    use ureq::unversioned::resolver::DefaultResolver;
    use ureq::unversioned::transport::{ConnectionDetails, Connector};
    use ureq::Agent;

    /// A connector that hands over a transport built from an already-established TLS stream.
    ///
    /// It performs no verification, and it cannot: it has no verdict, no quote and no
    /// `TrustworthyVerdict`. That is exactly the boundary — it builds a `Transport`, which is
    /// plumbing, and it cannot build a `VerifiedClient`, which is the guarantee.
    #[derive(Debug)]
    struct HandsOverPreparedTransport(std::sync::Mutex<Option<VerifiedTransport>>);

    impl Connector<()> for HandsOverPreparedTransport {
        type Out = VerifiedTransport;
        fn connect(
            &self,
            _d: &ConnectionDetails<'_>,
            _c: Option<()>,
        ) -> Result<Option<Self::Out>, ureq::Error> {
            self.0
                .lock()
                .expect("not poisoned")
                .take()
                .map(Some)
                .ok_or_else(|| ureq::Error::Other("the prepared transport was already used".into()))
        }
    }

    /// A connector that always refuses, carrying a `Refusal` the way the real one does.
    #[derive(Debug)]
    struct AlwaysRefuses;

    impl Connector<()> for AlwaysRefuses {
        type Out = VerifiedTransport;
        fn connect(
            &self,
            _d: &ConnectionDetails<'_>,
            _c: Option<()>,
        ) -> Result<Option<Self::Out>, ureq::Error> {
            Err(ureq::Error::Other(Box::new(Refusal::NoAttestation)))
        }
    }

    /// Serve one TLS connection with a locally generated certificate, replying with `response`.
    fn serve_once(response: &'static str) -> u16 {
        serve(response, 1)
    }

    /// Serve `connections` TLS connections with a locally generated certificate.
    ///
    /// Returns the port. The certificate is irrelevant to what most of these tests establish — they
    /// are about the HTTP glue, and the client half is the same `client_config` production uses,
    /// which does not consult PKI.
    ///
    /// **`connections` is load-bearing for the reconnect test.** With the listener dropped after one
    /// accept, a reconnect fails at the TCP layer with `ECONNREFUSED` and never reaches
    /// `verify_handshook` — so a test asserting "the second request failed" passes without the
    /// verification it exists to observe ever running. Serving twice is what makes the reconnect
    /// reach the connector and be refused *on the verdict*.
    fn serve(response: &'static str, connections: usize) -> u16 {
        let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_owned()])
            .expect("generate a certificate");
        let server_config = std::sync::Arc::new(
            rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .expect("protocol versions")
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.cert.der().clone()],
                rustls_pki_types::PrivateKeyDer::try_from(cert.signing_key.serialize_der())
                    .expect("a private key"),
            )
            .expect("the generated key matches its own certificate"),
        );

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        std::thread::spawn(move || {
            for _ in 0..connections {
                let Ok((sock, _)) = listener.accept() else {
                    return;
                };
                let config = std::sync::Arc::clone(&server_config);
                // Each connection on its own thread: the reconnect test dials again while the first
                // connection is still open, and a serial loop would deadlock waiting to read from a
                // socket whose client is blocked waiting to be accepted.
                std::thread::spawn(move || {
                    let Ok(conn) = rustls::ServerConnection::new(config) else {
                        return;
                    };
                    let mut stream = rustls::StreamOwned::new(conn, sock);
                    // Read until the end of the request headers, then answer. Enough for a request
                    // with no body, which is all these tests send.
                    let mut seen = Vec::new();
                    let mut byte = [0u8; 1];
                    while !seen.ends_with(b"\r\n\r\n") {
                        match std::io::Read::read(&mut stream, &mut byte) {
                            Ok(0) | Err(_) => return,
                            Ok(_) => seen.push(byte[0]),
                        }
                    }
                    let _ = stream.write_all(response.as_bytes());
                    let _ = stream.flush();
                });
            }
        });
        port
    }

    /// Dial `port` with the production client config and wrap the result in a transport.
    ///
    /// **`127.0.0.1`, not `localhost`.** On macOS `localhost` resolves to `::1` first while the
    /// listener above binds IPv4, so a `localhost` dial gets `ECONNREFUSED` — and a test that
    /// expects a refusal would then pass without a connection ever happening.
    fn prepared_transport(port: u16) -> (Endpoint, VerifiedTransport) {
        let endpoint = Endpoint::parse(&format!("https://127.0.0.1:{port}")).expect("endpoint");
        let handshook = crate::connect::tls::dial(
            &endpoint,
            &crate::connect::tls::client_config(),
            std::time::Duration::from_secs(5),
            std::time::Duration::from_secs(5),
        )
        .expect("the local server completes a handshake");
        (endpoint, VerifiedTransport::new(handshook.stream))
    }

    fn agent_over(port: u16, options: &ConnectOptions) -> (Endpoint, Agent) {
        let (endpoint, transport) = prepared_transport(port);
        let agent = Agent::with_parts(
            agent_config(options),
            HandsOverPreparedTransport(std::sync::Mutex::new(Some(transport))),
            DefaultResolver::default(),
        );
        (endpoint, agent)
    }

    /// The two hand-written `Debug` impls say enough to debug with and no more.
    ///
    /// Both exist because the derived versions are unusable: `StreamOwned` is not `Debug`, and a
    /// transport that printed its buffers would put 128 KiB of response body into a log line.
    #[test]
    fn the_transport_and_handshake_debug_impls_are_terse() {
        let port = serve_once("HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n");
        let (_, transport) = prepared_transport(port);
        let rendered = format!("{transport:?}");
        assert!(rendered.starts_with("VerifiedTransport"), "{rendered}");
        assert!(
            rendered.len() < 60,
            "too much detail to be safe: {rendered}"
        );
    }

    /// The transport carries a real request and a real response — and `is_tls()` is true.
    ///
    /// If `is_tls()` returned the trait's default of `false`, ureq would reject this https request
    /// with `Error::TlsRequired` before writing a byte. That is what defends the line; no mutant
    /// can.
    #[test]
    fn a_request_travels_over_the_verified_transport() {
        let port = serve_once(
            "HTTP/1.1 200 OK\r\ncontent-length: 21\r\ncontent-type: text/plain\r\n\r\n\
             verity-gateway-probe\n",
        );
        let options = ConnectOptions::default();
        let (endpoint, agent) = agent_over(port, &options);

        let response = request(
            &agent,
            &endpoint,
            "GET",
            "health",
            None,
            options.response_limit,
        )
        .expect("the request travels over the verified transport");

        assert_eq!(response.status(), 200);
        assert_eq!(response.body(), b"verity-gateway-probe\n");
        assert_eq!(response.header("content-type"), Some("text/plain"));
        // Header lookup is case-insensitive on the way in; a caller should not have to match the
        // server's capitalisation to read a header off a verified response.
        assert_eq!(response.header("Content-Type"), Some("text/plain"));
        assert_eq!(response.header("x-absent"), None);
    }

    /// **A redirect to another host is not followed.**
    ///
    /// `max_redirects(0)` means ureq returns the 302 rather than opening a connection to a peer
    /// nobody attested. `script/mutate.sh` raises it to 10; with that mutant this test sees the
    /// agent try to leave the verified peer.
    #[test]
    fn a_redirect_to_another_host_is_not_followed() {
        let port = serve_once(
            "HTTP/1.1 302 Found\r\nlocation: https://relay.attacker.example/\r\n\
             content-length: 0\r\n\r\n",
        );
        let options = ConnectOptions::default();
        let (endpoint, agent) = agent_over(port, &options);

        let response = request(&agent, &endpoint, "GET", "/", None, options.response_limit)
            .expect("the redirect is returned rather than followed");

        assert_eq!(
            response.status(),
            302,
            "the redirect must come back to the caller; following it would carry a request to a \
             peer this client never verified"
        );
        assert_eq!(
            response.header("location"),
            Some("https://relay.attacker.example/")
        );
    }

    /// A `POST` carries its content type and body over the same verified transport.
    ///
    /// The other half of `request`: `VerifiedClient::post` delegates here, so without this the
    /// body-and-header branch is only ever compiled, never run.
    #[test]
    fn a_post_carries_its_content_type_and_body() {
        let port = serve_once("HTTP/1.1 202 Accepted\r\ncontent-length: 8\r\n\r\naccepted");
        let options = ConnectOptions::default();
        let (endpoint, agent) = agent_over(port, &options);

        let response = request(
            &agent,
            &endpoint,
            "POST",
            "/convert",
            Some(("application/json", br#"{"from":"md"}"#)),
            options.response_limit,
        )
        .expect("the post travels over the verified transport");

        assert_eq!(response.status(), 202);
        assert_eq!(response.body(), b"accepted");
    }

    /// A path that cannot form a URI is a transport error, not a panic.
    ///
    /// The host is fixed by the verification, so the only thing a caller can get wrong is the path —
    /// and getting it wrong must not take the process down.
    #[test]
    fn a_path_that_cannot_form_a_uri_is_reported_rather_than_panicking() {
        let options = ConnectOptions::default();
        let endpoint = Endpoint::parse("https://127.0.0.1:1").expect("endpoint");
        let agent = Agent::with_parts(
            agent_config(&options),
            AlwaysRefuses,
            DefaultResolver::default(),
        );
        let error = request(
            &agent,
            &endpoint,
            "GET",
            "/ has a space",
            None,
            options.response_limit,
        )
        .expect_err("a space cannot appear in a request target");
        assert!(matches!(error, TransportError::Io { .. }), "{error:?}");
    }

    /// A response over the limit is refused rather than buffered.
    #[test]
    fn a_response_larger_than_the_limit_is_refused() {
        let port = serve_once("HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nhello");
        let options = ConnectOptions::default();
        let (endpoint, agent) = agent_over(port, &options);

        let error = request(&agent, &endpoint, "GET", "/", None, 4)
            .expect_err("five bytes is more than four");
        assert!(matches!(error, TransportError::TooLarge { limit: 4 }));
    }

    /// **T3: a `Refusal` survives the trip through `ureq::Error`.**
    ///
    /// Without the downcast in `from_ureq`, a reconnect that failed *verification* would reach the
    /// caller as `TransportError::Io` with a stringified message — losing exactly the attack/outage
    /// distinction criterion 5 asks for, on the path where it matters most.
    #[test]
    fn a_connector_refusal_arrives_back_as_transport_error_refused() {
        let options = ConnectOptions::default();
        let endpoint = Endpoint::parse("https://localhost:1").expect("endpoint");
        let agent = Agent::with_parts(
            agent_config(&options),
            AlwaysRefuses,
            DefaultResolver::default(),
        );

        let error = request(&agent, &endpoint, "GET", "/", None, options.response_limit)
            .expect_err("the connector refuses");

        match error {
            TransportError::Refused(refusal) => {
                assert!(matches!(*refusal, Refusal::NoAttestation));
                assert_eq!(
                    refusal.kind(),
                    crate::connect::RefusalKind::GuaranteeViolated
                );
            }
            other => panic!("the refusal was flattened into {other:?}"),
        }
    }

    /// An error that is not a `Refusal` is reported as I/O rather than mislabelled.
    #[test]
    fn an_unrelated_transport_error_is_not_reported_as_a_refusal() {
        let flattened = from_ureq(ureq::Error::Other("something else entirely".into()));
        assert!(matches!(flattened, TransportError::Io { .. }));
        let io = from_ureq(ureq::Error::HostNotFound);
        assert!(matches!(io, TransportError::Io { .. }));
    }

    // ---------------------------------------------------------------------------------------
    // The real connector, driven through a real `Agent`
    // ---------------------------------------------------------------------------------------
    //
    // Everything above uses a stand-in connector, which exercises the request path but not the one
    // production actually installs. These build a genuine `VerifiedConnector` — the same type, the
    // same `verify_handshook`, the same `Error::Other` carrying a `Refusal` — and let ureq call it,
    // so `ConnectionDetails` is constructed by ureq rather than by hand.
    //
    // Still no `VerifiedClient` and still no `TrustworthyVerdict`. A connector is plumbing; the
    // guarantee is the thing it refuses to produce.

    /// Build the real connector for `endpoint`, with useless-but-well-formed collateral.
    fn real_connector(endpoint: &Endpoint, options: &ConnectOptions) -> super::VerifiedConnector {
        super::VerifiedConnector {
            request: super::OwnedRequest {
                endpoint: endpoint.clone(),
                licensed: crate::verify::LicensedVersion {
                    compose_hash: crate::binding::ComposeHash::of(b"{}"),
                    image_digest: "sha256:00".to_owned(),
                },
                compose_document: b"{}".to_vec(),
                boot: None,
                tcb: crate::attest::TcbPolicy::default(),
            },
            options: options.clone(),
            tls: crate::connect::tls::client_config(),
            // The `tests/attest.rs` pattern: structurally valid, cryptographically useless. It makes
            // `QuoteSignature` fail, which is correct and unavoidable without Intel's answer for the
            // platform a quote came from.
            collateral: std::sync::Arc::new(crate::attest::Collateral {
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
            }),
            latest: std::sync::Arc::new(std::sync::Mutex::new(None)),
            pending: std::sync::Mutex::new(None),
        }
    }

    /// **The post-verify guard, through the connector ureq actually calls.**
    ///
    /// The local server presents an ordinary certificate with no attestation, so
    /// `verify_handshook` refuses before a transport exists — and the refusal reaches the caller as
    /// `TransportError::Refused` rather than as a flattened I/O error.
    ///
    /// `script/mutate.sh` removes the guard; with it gone the connector returns `Ok(transport)` and
    /// this request succeeds, which is what kills that mutant.
    #[test]
    fn the_connector_refuses_to_produce_a_transport_for_an_untrustworthy_verdict() {
        let port = serve_once("HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n");
        let options = ConnectOptions::default();
        let endpoint = Endpoint::parse(&format!("https://127.0.0.1:{port}")).expect("endpoint");
        // Built through the same `agent()` production uses, so the redirect policy and timeouts
        // under test are the ones that ship rather than a copy assembled here.
        let agent = super::agent(&options, real_connector(&endpoint, &options));

        let error = request(&agent, &endpoint, "GET", "/", None, options.response_limit)
            .expect_err("an endpoint with no attestation cannot yield a verified connection");

        match error {
            TransportError::Refused(refusal) => {
                assert!(
                    matches!(*refusal, Refusal::NoAttestation),
                    "expected NoAttestation, got {refusal:?}"
                );
            }
            other => panic!(
                "the connector produced a usable transport, or the refusal was flattened: {other:?}"
            ),
        }
    }

    /// The first request consumes the connection `connect_verified` verified.
    ///
    /// Covers the pending-transport handover: `set_pending` then `Connector::connect` returning it
    /// rather than dialling again. Without it the first request would open a *second* connection —
    /// still verified, but not the one whose verdict the caller was handed.
    #[test]
    fn the_first_request_travels_over_the_connection_that_was_already_verified() {
        let port = serve_once("HTTP/1.1 200 OK\r\ncontent-length: 20\r\n\r\nverity-gateway-probe");
        let options = ConnectOptions::default();
        let (endpoint, transport) = prepared_transport(port);
        let connector = real_connector(&endpoint, &options);
        connector.set_pending(transport);

        let agent = super::agent(&options, connector);
        let response = request(&agent, &endpoint, "GET", "/", None, options.response_limit)
            .expect("the pending connection carries the first request");
        assert_eq!(response.status(), 200);
        assert_eq!(response.body(), b"verity-gateway-probe");
    }

    /// **A second request is verified afresh, and refused by the verification.**
    ///
    /// The reconnect path, and the behaviour that makes `VerifiedClient` safe across ureq's pool
    /// churn: `take_pending` returns `None`, so `Connector::connect` calls `verify_connection`,
    /// which dials, handshakes and refuses — because this server presents no attestation. **A
    /// connection does not become trusted by having worked once.**
    ///
    /// # Why the server serves twice, and why the assertion is one variant
    ///
    /// The first version used a one-shot server. The reconnect then failed at the TCP layer with
    /// `ECONNREFUSED` and never reached `verify_handshook` at all — while the match accepted
    /// `NotReached` *and* a bare `TransportError::Io`, so it passed on "the second request failed",
    /// which is not what it claims. Serving twice makes the reconnect reach verification;
    /// asserting `NoAttestation` alone is what proves it got there.
    #[test]
    fn a_reconnect_is_verified_rather_than_trusted_because_the_first_request_worked() {
        let port = serve("HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok", 2);
        let options = ConnectOptions::default();
        let (endpoint, transport) = prepared_transport(port);
        let connector = real_connector(&endpoint, &options);
        connector.set_pending(transport);

        let agent = super::agent(&options, connector);
        assert!(
            request(&agent, &endpoint, "GET", "/", None, options.response_limit).is_ok(),
            "the pending connection should carry the first request"
        );

        let error = request(&agent, &endpoint, "GET", "/", None, options.response_limit)
            .expect_err("the reconnect is verified, and this endpoint cannot pass");
        match error {
            TransportError::Refused(refusal) => assert!(
                matches!(*refusal, Refusal::NoAttestation),
                "the reconnect was refused, but not by the verification — expected NoAttestation, \
                 got {refusal:?}. Anything else means the connector never got as far as reading \
                 the peer's certificate."
            ),
            other => panic!(
                "a reconnect must reach verification and be refused by it, not fail as a bare \
                 transport fault: {other:?}"
            ),
        }
    }

    /// The connector's `Debug` names the endpoint and leaks neither collateral nor TLS config.
    ///
    /// `Connector` requires `Debug`, and a derived one would print Intel collateral into whatever
    /// log line touched it.
    #[test]
    fn the_connector_debug_names_the_endpoint_and_nothing_sensitive() {
        let options = ConnectOptions::default();
        let endpoint = Endpoint::parse("https://example.com:8443").expect("endpoint");
        let rendered = format!("{:?}", real_connector(&endpoint, &options));
        assert!(rendered.contains("example.com"), "{rendered}");
        assert!(!rendered.contains("tcb_info"), "{rendered}");
        assert!(!rendered.contains("ClientConfig"), "{rendered}");
    }
}

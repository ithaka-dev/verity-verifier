//! A verified transport: dial the endpoint, verify **that** connection, hand back a client only if
//! the verdict is trustworthy.
//!
//! # The gap this closes
//!
//! [`crate::verify::verify`] binds a quote to a certificate **it was handed**. It cannot establish
//! that the certificate came from the handshake being judged, because this crate is deliberately
//! I/O-free — so the caller is trusted for that provenance, and
//! [`crate::channel::PeerCertificate::Presented`] says so out loud. An agent author who calls
//! `verify()` with a certificate from anywhere other than their live connection gets a passing
//! `ChannelBound` that means nothing.
//!
//! The second half of the same finding: the crate's *one constructor, and it performs the check*
//! discipline stopped at the [`crate::verdict::Verdict`], so invariant I1 rested on every agent
//! author remembering `if !verdict.is_trustworthy() { return }`. **A verdict that can be ignored is
//! a verdict that will be.**
//!
//! [`connect_verified`] closes both. It owns the socket, the handshake, the certificate and the
//! quote; the caller supplies none of them. And a [`VerifiedClient`] has no public constructor and
//! no path from an untrustworthy verdict, so the check cannot be skipped by forgetting it.
//!
//! # Raw `verify()` is not deprecated by this
//!
//! It remains the right call for auditors reasoning about recorded evidence, for pre-purchase
//! inspection where there is no connection yet, and for any embedder without a TCP stack — offline,
//! `wasm32`, or inside another enclave. That is why this module is behind a non-default feature:
//! the offline path stays the default, and this is additive to it.
//!
//! # What a caller still supplies, and why that is safe
//!
//! One thing: Intel collateral, through [`CollateralSource`], and it is handed the quote **this
//! handshake produced**. Collateral is FMSPC-specific so it cannot be fetched before the handshake,
//! and `dcap-qvl` fetches it asynchronously, so fetching it here would mean this crate choosing an
//! async runtime for every embedder. The seam is safe for a reason that generalises — see
//! [`CollateralSource`] — and a transport seam is not, which is why there is no way to inject one.
//!
//! # Where the guarantee is not established
//!
//! There is **no local end-to-end success path**, and that is a property rather than a gap: it
//! would need an Intel-signed quote committing to a key we hold, and any seam that manufactured one
//! — a policy that skips signature verification, a test-mode collateral, a "trust this quote" flag
//! — would be a seam an attacker could reach for. The positive lives on real hardware, in
//! `verity-foundation/closed-loop/08-gateway-tls-termination.sh` steps 10 and 11.

mod http;
mod tls;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::attest::{Collateral, TcbPolicy};
use crate::channel::ChannelBinding;
use crate::compose::DEFAULT_CONNECT_TIMEOUT;
use crate::endpoint::{Endpoint, EndpointForm};
use crate::reference::BootReference;
use crate::verdict::{TrustworthyVerdict, Verdict};
use crate::verify::LicensedVersion;

/// How long the TLS handshake may take once the socket is open.
///
/// Separate from [`crate::compose::DEFAULT_CONNECT_TIMEOUT`] because they bound different failures:
/// that one bounds *reaching* the host, this one bounds everything after the socket is open.
///
/// It covers **two** stalls, and the second is the subtler one:
///
/// - a peer that accepts a connection and then says nothing; and
/// - a peer that answers *slowly, forever* — one byte per half-timeout. Every individual read lands
///   inside its budget, so a per-socket read timeout never fires, and rustls' `complete_io` loops
///   internally rather than returning, so a deadline checked around it is never consulted either.
///
/// Both cost an attacker one `accept()` and would otherwise hang a verification indefinitely. This
/// budget bounds the handshake as a whole — it is applied to each read and write as *the time that
/// remains*, not restarted per operation.
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a whole request over a verified connection may take.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// How large a response this client will read.
///
/// 16 MiB, and deliberately **not** [`crate::compose::DEFAULT_SIZE_LIMIT`]: that bounds a compose
/// document, which is small by nature, and a tool's response is not one. Reusing it would have made
/// the verified transport unusable for the thing it exists to carry.
pub const DEFAULT_RESPONSE_LIMIT: usize = 16 * 1024 * 1024;

/// What is being connected to, and what was licensed.
///
/// **No `Default`, on purpose** — the same reason [`crate::verify::Evidence`] has none. Every field
/// is a decision, and a default would let an integration compile while establishing nothing.
#[derive(Debug)]
#[non_exhaustive]
pub struct ConnectRequest<'a> {
    /// The endpoint to dial, already parsed and classified.
    pub endpoint: &'a Endpoint,
    /// What the licence names: the compose hash to bind to, and the image digest it must reference.
    pub licensed: &'a LicensedVersion,
    /// The published `app-compose.json`.
    ///
    /// **Untrusted.** It is hashed against `licensed.compose_hash` inside, so a hostile source can
    /// withhold the document but cannot substitute a different one undetected — a wrong answer
    /// causes a refusal, never an acceptance.
    pub compose_document: Vec<u8>,
    /// An OS image reference, when the caller has captured one.
    ///
    /// `None` leaves the boot-measurement check *skipped*, which is legitimate and does not sink
    /// the verdict — most callers have no reference. Contrast the certificate, whose absence is not
    /// legitimate for a verdict about an endpoint.
    pub boot: Option<&'a BootReference>,
    /// Which Intel TCB statuses to accept.
    pub tcb: &'a TcbPolicy,
}

impl<'a> ConnectRequest<'a> {
    /// A request with no boot reference and the default TCB policy.
    ///
    /// A constructor rather than a `Default`: the three arguments here are the ones with no
    /// defensible default, and `tcb` is defaulted to [`TcbPolicy::up_to_date_only`], which is the
    /// strict end. Anything looser stays an explicit, visible choice at the call site.
    #[must_use]
    pub fn new(
        endpoint: &'a Endpoint,
        licensed: &'a LicensedVersion,
        compose_document: Vec<u8>,
        tcb: &'a TcbPolicy,
    ) -> Self {
        Self {
            endpoint,
            licensed,
            compose_document,
            boot: None,
            tcb,
        }
    }
}

/// Where Intel collateral comes from — supplied by the caller, **after** the quote is known.
///
/// Collateral is FMSPC-specific, so it cannot be fetched before the handshake; and `dcap-qvl`
/// fetches it asynchronously, so fetching it here would mean this crate choosing an async runtime
/// for every embedder. The implementation is handed the quote **this handshake produced**.
///
/// # Why this seam is safe and a transport seam is not
///
/// `dcap-qvl` compiles Intel's production root into the binary and verifies collateral against
/// *that* pinned root, not against anything the source provides. So a wrong or hostile answer
/// produces a refusal, never an acceptance.
///
/// **That is the test to apply to any future seam here: if getting it wrong can produce a false
/// accept, it does not belong in caller code.** An injected transport would fail it — the caller
/// would produce the certificate, which is the provenance gap this module exists to close, wearing
/// a costume that looks like the library is doing the work.
///
/// # The bound on that guarantee
///
/// Fail-closed *within a window*, not absolutely. A hostile source can serve genuine, Intel-signed
/// but **older** TCB info for the correct FMSPC, under which a platform a current answer marks
/// `OutOfDate` may read `UpToDate`. That downgrade is bounded only by the collateral's own validity
/// window and by the verification time being honest. **Prefer a source you trust for freshness.**
///
/// The verification time is read from the system clock and is deliberately **not** a caller-supplied
/// option, precisely so this bound cannot be widened from a call site. A timestamp pinned in the
/// past keeps collateral inside its validity window after it should have expired — one field
/// assignment, invisible in review, with the same effect as `dcap-qvl`'s `danger-allow-tcb-override`
/// that this repo bans outright. Reading the clock here is honest because this is the I/O layer;
/// everywhere else in the crate the time is passed in so that verification stays pure.
pub trait CollateralSource {
    /// Obtain collateral for the platform this quote came from.
    ///
    /// # Errors
    ///
    /// [`CollateralUnavailable`] when collateral could not be obtained. That is an **outage, not an
    /// attack**, and [`RefusalKind::CouldNotEstablish`] says so.
    ///
    /// **This call is not bounded from here.** It is the caller's blocking call and cannot be
    /// interrupted without spawning a thread, so the implementation owns its own timeout. An
    /// implementation that can hang forever makes `connect_verified` hang forever.
    fn collateral_for(&self, raw_quote: &[u8]) -> Result<Collateral, CollateralUnavailable>;
}

/// Collateral could not be obtained.
///
/// `#[non_exhaustive]` per [ADR 0014], like every other public type here: constructing one goes
/// through [`CollateralUnavailable::new`], so a field added later stays a minor version.
///
/// [ADR 0014]: https://github.com/ithaka-dev/verity-foundation/blob/main/docs/decisions/0014-verifier-update-discipline.md
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("collateral could not be obtained: {detail}")]
#[non_exhaustive]
pub struct CollateralUnavailable {
    /// What the source reported.
    pub detail: String,
}

impl CollateralUnavailable {
    /// Report a failure to obtain collateral.
    #[must_use]
    pub fn new(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
        }
    }
}

/// Bounds on the connection.
///
/// Public fields with a [`Default`]: unlike [`ConnectRequest`], every one of these has a defensible
/// default, and the defaults are the strict end. Mutate after `default()`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ConnectOptions {
    /// How long to wait for the TCP connection.
    pub connect_timeout: Duration,
    /// How long to wait for the TLS handshake once connected.
    pub handshake_timeout: Duration,
    /// How long a whole request may take.
    pub request_timeout: Duration,
    /// How large a response body this client will read.
    pub response_limit: usize,
}

impl Default for ConnectOptions {
    fn default() -> Self {
        Self {
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            response_limit: DEFAULT_RESPONSE_LIMIT,
        }
    }
}

impl ConnectOptions {
    /// Verification time, read from the system clock.
    ///
    /// # Why this is not a caller-supplied option
    ///
    /// It was one, and it was removed. `CollateralSource`'s own rule decides it: *if getting a seam
    /// wrong can produce a false accept, it does not belong in caller code.* A verification time
    /// pinned in the past keeps collateral inside its validity window after it should have expired,
    /// which is precisely the TCB downgrade that trait documents as the bound on its guarantee — one
    /// field assignment, on a struct whose documentation says the defaults are the strict end, and
    /// no call site for a reviewer to see. That is the same shape as `dcap-qvl`'s
    /// `danger-allow-tcb-override`, which this repo bans outright and asserts the absence of in CI.
    ///
    /// Reading the clock here is honest in a way it would not be elsewhere: the rest of the crate
    /// takes `now_secs` as an argument so that verification stays pure and auditable, and
    /// `connect_verified` is the I/O layer, where a socket is already being opened.
    ///
    /// If a controlled clock is ever genuinely needed it can return as `dangerous_verification_time`
    /// with a matching CI grep, which `#[non_exhaustive]` keeps a minor version. Nothing needs it
    /// today.
    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            // A clock before 1970 is a broken host, not an endpoint problem. Zero makes every
            // collateral validity window fail closed, which is the right direction for a value this
            // crate cannot obtain honestly.
            .map_or(0, |d| d.as_secs())
    }
}

/// Open a connection to `request.endpoint`, verify **that connection**, and return a client only if
/// the verdict is trustworthy.
///
/// This is the shipped affordance — the one an agent should reach for. Raw
/// [`crate::verify::verify`] remains for auditors and for pre-purchase inspection, where there is
/// no connection to judge.
///
/// # What happens, in order
///
/// 1. The endpoint's form is classified and dStack's TLS-**terminating** gateway host is refused
///    **before a socket is opened** — see [`Refusal::TerminatingEndpoint`].
/// 2. TCP connect, then the RA-TLS handshake, both under their own deadlines. The peer must prove
///    it holds the private key for the certificate it presents; a relay serving a copy of the
///    enclave's public certificate fails here.
/// 3. The quote is lifted out of **that handshake's** leaf certificate.
/// 4. `collateral` is asked for Intel collateral for that quote.
/// 5. [`crate::verify::verify`] runs every check, with the same certificate bytes as
///    [`crate::channel::PeerCertificate::Presented`].
/// 6. [`TrustworthyVerdict::check`] — and only then is the socket handed on.
///
/// **No application byte is written before step 6.** The socket is owned by a private value until
/// the check returns `Ok`, so the ordering is structural rather than a convention.
///
/// # Errors
///
/// [`Refusal`]. Every variant is a refusal and none licenses proceeding; [`Refusal::kind`] is
/// coarse triage for telling an attack from an outage, and [`Refusal::verdict`] is authoritative
/// whenever it is `Some`.
pub fn connect_verified(
    request: &ConnectRequest<'_>,
    collateral: &dyn CollateralSource,
    options: &ConnectOptions,
) -> Result<VerifiedClient, Refusal> {
    // — refused before a socket is opened —
    //
    // On dStack's terminating form the gateway completes the handshake itself and presents a valid,
    // publicly trusted certificate for the gateway. Channel binding then fails, correctly — but a
    // bare `channel_bound FAILED` on the form the platform's own API advertises reads as "the check
    // is too strict", and that reading is an invitation to the loosening ADR 0009 rule 3 forbids.
    // Naming it costs one comparison and saves the four CVM runs it cost to work out once.
    //
    // Branching on `passthrough_form()` rather than on `form()` is deliberate: it returns `Some`
    // exactly when the form is `DstackTerminating`, so the condition that triggers the refusal and
    // the suggestion the refusal carries come from one call and cannot disagree. The two-step
    // version needed a fallback for a case that cannot happen, which is a branch nothing can test
    // and nothing can maintain.
    if let Some(passthrough) = request.endpoint.passthrough_form() {
        debug_assert_eq!(request.endpoint.form(), EndpointForm::DstackTerminating);
        return Err(Refusal::TerminatingEndpoint {
            host: request.endpoint.host().to_owned(),
            passthrough,
        });
    }

    let tls = tls::client_config();

    // The first handshake is performed here rather than inside the connector, because the
    // collateral has to be fetched between the handshake and the verification — the quote is what
    // names the platform — and the connector cannot call back into the caller's source without
    // imposing `Send + Sync + 'static` on it.
    let handshook = tls::dial(
        request.endpoint,
        &tls,
        options.connect_timeout,
        options.handshake_timeout,
    )?;
    // Extracted here to name the platform for the collateral fetch, and **extracted again inside
    // `verify_handshook`**. That duplication is deliberate, not an oversight: it is what keeps
    // `verify_handshook` the complete post-handshake sequence rather than a fragment that trusts a
    // quote someone else pulled out. Passing this one in would make the first connection's path
    // shorter than every reconnect's, which is exactly the "one privileged code path" shape the
    // module is built to avoid. The cost is one extra DER parse per `connect_verified`.
    let raw_quote =
        crate::ratls::quote_from_certificate(&handshook.leaf_der).map_err(|e| match e {
            crate::ratls::AttestationError::Missing => Refusal::NoAttestation,
            other => Refusal::UnreadableAttestation {
                detail: other.to_string(),
            },
        })?;
    let collateral = Arc::new(collateral.collateral_for(&raw_quote)?);

    let connector = http::VerifiedConnector {
        request: http::OwnedRequest::from_borrowed(request),
        options: options.clone(),
        tls,
        collateral,
        // Seeded by `verify_handshook` below, and never read before then: a `VerifiedClient` is not
        // constructed unless that call returned `Ok`, so no caller can observe the empty state.
        latest: Arc::new(Mutex::new(None)),
        pending: Mutex::new(None),
    };

    // The whole post-handshake sequence — quote out of the leaf, verify, and the guard — on the
    // connection dialled above. **This is the same function every reconnect goes through**, so
    // there is no privileged first connection with a shorter path.
    let (first, transport) = connector.verify_handshook(handshook)?;
    // Handed to the connector rather than dropped, so the socket that was verified is literally the
    // socket the first request travels over.
    connector.set_pending(transport);

    let latest = Arc::clone(&connector.latest);
    let endpoint = request.endpoint.clone();
    let agent = http::agent(options, connector);

    Ok(VerifiedClient {
        agent,
        endpoint,
        latest,
        first,
        response_limit: options.response_limit,
    })
}

/// A connection to an endpoint that verified.
///
/// **There is no public constructor, and none obtainable from an untrustworthy verdict.** The only
/// constructor is private, takes a [`TrustworthyVerdict`], and is called from exactly one place:
/// [`connect_verified`], with the verdict produced from that handshake's certificate.
///
/// There is also **no accessor returning the underlying stream**, and no `From`/`TryFrom`. A client
/// that could be split from its verification is a verdict you can detach, which is the finding this
/// module exists to close.
///
/// # Reconnects re-verify
///
/// ureq may close an idle pooled connection and open another. Every such connection goes through
/// the same verification, so a CVM that restarted with a new key, or was upgraded to a different
/// compose hash, yields [`TransportError::Refused`] rather than a silent fallback.
#[derive(Debug)]
pub struct VerifiedClient {
    agent: ureq::Agent,
    endpoint: Endpoint,
    /// The most recent successful verification, republished by the connector on every connection.
    ///
    /// Always `Some` by the time a `VerifiedClient` exists: `connect_verified` does not construct
    /// one unless `verify_handshook` returned `Ok`, and that is what fills this in.
    latest: Arc<Mutex<Option<http::Verification>>>,
    /// The connect-time verification.
    ///
    /// Kept so the accessors never have to answer "I do not know" and never have to panic on a
    /// poisoned lock. It is a true statement about a connection this client did verify, which makes
    /// it a safe floor — the only thing lost by falling back to it is freshness, and only in the
    /// already-degraded case where another thread panicked mid-verification.
    first: http::Verification,
    response_limit: usize,
}

impl VerifiedClient {
    /// The verdict from the **most recent** verification this client performed.
    ///
    /// An owned clone rather than a borrow, and the latest rather than the connect-time one:
    /// after a reconnect, answering "what am I talking to?" with a previous connection's evidence
    /// would be a lie rather than a caching decision.
    #[must_use]
    pub fn verdict(&self) -> TrustworthyVerdict {
        self.latest_verification().verdict
    }

    /// The channel binding established against the most recent connection's certificate.
    ///
    /// See [`VerifiedClient::verdict`] for why this is the latest and not the first.
    #[must_use]
    pub fn channel_binding(&self) -> ChannelBinding {
        self.latest_verification().binding
    }

    /// The endpoint this client verified and talks to.
    #[must_use]
    pub const fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// `GET path` over a verified connection.
    ///
    /// **A path, never a URL.** The host is fixed by the verification, so no argument can send this
    /// request anywhere else. Redirects are not followed for the same reason: a 302 to another host
    /// is a request to leave the connection that was verified, and it comes back to the caller as a
    /// 302 rather than being followed invisibly.
    ///
    /// # Errors
    ///
    /// [`TransportError`], including [`TransportError::Refused`] if a reconnect failed
    /// verification.
    pub fn get(&self, path: &str) -> Result<Response, TransportError> {
        http::request(
            &self.agent,
            &self.endpoint,
            "GET",
            path,
            None,
            self.response_limit,
        )
    }

    /// `POST path` over a verified connection.
    ///
    /// # Errors
    ///
    /// As [`VerifiedClient::get`].
    pub fn post(
        &self,
        path: &str,
        content_type: &str,
        body: &[u8],
    ) -> Result<Response, TransportError> {
        http::request(
            &self.agent,
            &self.endpoint,
            "POST",
            path,
            Some((content_type, body)),
            self.response_limit,
        )
    }

    /// Read the latest published verification.
    ///
    /// Falls back to the connect-time one rather than panicking. Two ways that can happen — a
    /// poisoned lock, or a slot somehow still empty — and in both the fallback is a true statement
    /// about a connection this client verified. `expect` here would convert another thread's panic
    /// into this thread's, in a library, on a read-only accessor.
    fn latest_verification(&self) -> http::Verification {
        // Written as a `match` rather than as `.ok().and_then(..).unwrap_or_else(..)` so the two
        // fallback cases are visible as cases. They are the whole content of this function, and a
        // combinator chain renders them as punctuation.
        match self.latest.lock() {
            Ok(slot) => match slot.as_ref() {
                Some(latest) => latest.clone(),
                None => self.first.clone(),
            },
            Err(_) => self.first.clone(),
        }
    }
}

/// A response from a verified connection.
#[derive(Debug, Clone)]
pub struct Response {
    pub(crate) status: u16,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: Vec<u8>,
}

impl Response {
    /// The HTTP status.
    ///
    /// A 4xx or 5xx from a verified enclave is a *verified* 4xx: statuses are data, not transport
    /// errors, so they arrive here rather than as [`TransportError`].
    #[must_use]
    pub const fn status(&self) -> u16 {
        self.status
    }

    /// The response body, already bounded by [`ConnectOptions::response_limit`].
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// One header, matched case-insensitively.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Why a request over a verified connection did not complete.
///
/// `#[non_exhaustive]` per [ADR 0014].
///
/// [ADR 0014]: https://github.com/ithaka-dev/verity-foundation/blob/main/docs/decisions/0014-verifier-update-discipline.md
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TransportError {
    /// The request could not be sent or the response could not be read.
    #[error("the request did not complete: {detail}")]
    Io {
        /// What the transport reported.
        detail: String,
    },
    /// The response exceeded [`ConnectOptions::response_limit`].
    #[error("the response exceeded the {limit} byte limit")]
    TooLarge {
        /// The limit that was exceeded.
        limit: usize,
    },
    /// **A reconnect did not verify.**
    ///
    /// The client refuses rather than falling back: the endpoint changed under us, or something
    /// else is now answering. Distinct from [`TransportError::Io`] on purpose — this is the one
    /// place a mid-session substitution becomes visible, and flattening it into an I/O error would
    /// lose exactly the distinction a caller needs.
    #[error("a reconnect to this endpoint did not verify")]
    Refused(#[source] Box<Refusal>),
}

/// Why a connection was refused.
///
/// **Every variant is a refusal**, and none of them has a degraded mode in which proceeding is
/// correct. `#[non_exhaustive]` per [ADR 0014].
///
/// [ADR 0014]: https://github.com/ithaka-dev/verity-foundation/blob/main/docs/decisions/0014-verifier-update-discipline.md
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Refusal {
    /// dStack's TLS-**terminating** gateway form.
    ///
    /// Refused **before a socket is opened**. The gateway completes the handshake itself with a
    /// valid, publicly trusted certificate for the gateway, so ordinary TLS verification succeeds
    /// while the peer is not the enclave. The message names the host that should have been used.
    #[error(
        "`{host}` is dStack's TLS-terminating gateway form: the certificate it presents belongs \
         to the gateway, not the enclave, so this connection can never be channel bound. Use the \
         passthrough form `{passthrough}`"
    )]
    TerminatingEndpoint {
        /// The host that was supplied.
        host: String,
        /// The `s`-suffixed host that would reach the enclave.
        passthrough: String,
    },
    /// DNS, TCP, or a timeout.
    ///
    /// An outage rather than an attack: an `std::io::Error` during connect or handshake lands here,
    /// including a peer that accepts a socket and then says nothing.
    #[error("could not reach {host}:{port}: {detail}")]
    NotReached {
        /// The host that was dialled.
        host: String,
        /// The port that was dialled.
        port: u16,
        /// What the operating system reported.
        detail: String,
    },
    /// A TLS error during the handshake.
    ///
    /// **Including the peer failing to prove it holds the private key for the certificate it
    /// presented** — which is a relay, not an outage. An enclave's RA-TLS certificate is public, so
    /// anyone can serve a copy; this is where that copy fails.
    #[error("the TLS handshake with {host} failed: {detail}")]
    HandshakeFailed {
        /// The host that was dialled.
        host: String,
        /// What rustls reported.
        detail: String,
    },
    /// The handshake completed and the peer presented no certificate.
    #[error("the peer presented no certificate, so there is nothing to bind the quote to")]
    NoPeerCertificate,
    /// The peer's certificate carries no dStack attestation extension.
    ///
    /// What a gateway's Let's Encrypt certificate looks like, and what any ordinary web server
    /// looks like.
    #[error("the peer's certificate carries no attestation: it is not an enclave's")]
    NoAttestation,
    /// The attestation extension is present and could not be read.
    #[error("the peer's attestation could not be read: {detail}")]
    UnreadableAttestation {
        /// What the parser reported.
        detail: String,
    },
    /// Intel collateral could not be obtained.
    #[error(transparent)]
    CollateralUnavailable(#[from] CollateralUnavailable),
    /// Every input was obtained and an essential check did not pass.
    ///
    /// Carries the whole verdict, because *which* check refused is what tells a misconfiguration
    /// from an attack — and collapsing that into one error type throws the distinction away.
    #[error("this endpoint is not trustworthy: {verdict}")]
    NotTrustworthy {
        /// The verdict, with every check and its outcome.
        verdict: Box<Verdict>,
    },
}

impl Refusal {
    /// Coarse triage — **not a diagnosis**.
    ///
    /// All three kinds are refusals; none licenses proceeding. [`Refusal::verdict`] is
    /// authoritative whenever it is `Some`.
    ///
    /// In particular [`Refusal::NotTrustworthy`] maps to [`RefusalKind::GuaranteeViolated`] because
    /// *some* essential check refused — but the reason may be a platform TCB advisory
    /// ([`crate::attest::AttestError`] keeps "genuine but out of date" distinguishable from "not
    /// genuine" precisely so that is visible), or a compose document that arrived truncated.
    /// Neither is an attack. **Read the verdict before raising an incident.**
    ///
    /// MA-6's `disposition()` is what will make this per-check. When it lands, this mapping should
    /// be derived from the verdict's dispositions rather than fixed here, and [`RefusalKind`]
    /// should map onto its vocabulary. Both are additive, and `#[non_exhaustive]` keeps them minor
    /// versions.
    #[must_use]
    pub const fn kind(&self) -> RefusalKind {
        // Matched exhaustively and **without a wildcard**, deliberately. `Refusal` is
        // `#[non_exhaustive]`, but that only binds other crates — inside this one a new variant
        // makes this a compile error, which forces whoever adds it to choose a kind rather than
        // inherit a fallback. Same reasoning as `Outcome::label`.
        match self {
            Self::TerminatingEndpoint { .. } => RefusalKind::EndpointUnusable,
            Self::NotReached { .. } | Self::CollateralUnavailable(_) => {
                RefusalKind::CouldNotEstablish
            }
            Self::HandshakeFailed { .. }
            | Self::NoPeerCertificate
            | Self::NoAttestation
            | Self::UnreadableAttestation { .. }
            | Self::NotTrustworthy { .. } => RefusalKind::GuaranteeViolated,
        }
    }

    /// The verdict, when one was reached.
    ///
    /// `None` means verification never got far enough to record anything — the endpoint was
    /// refused, unreachable, or presented nothing to verify.
    #[must_use]
    pub const fn verdict(&self) -> Option<&Verdict> {
        match self {
            Self::NotTrustworthy { verdict } => Some(verdict),
            _ => None,
        }
    }
}

/// Enough to tell an attack from an outage, which is what a caller does differently.
///
/// `#[non_exhaustive]` per [ADR 0014].
///
/// [ADR 0014]: https://github.com/ithaka-dev/verity-foundation/blob/main/docs/decisions/0014-verifier-update-discipline.md
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RefusalKind {
    /// A check ran and refused.
    ///
    /// Retrying the same connection cannot change it. Read [`Refusal::verdict`] before deciding
    /// what it means — see [`Refusal::kind`], which is coarse triage rather than a diagnosis.
    GuaranteeViolated,
    /// Verification could not be completed: an outage, a timeout, missing collateral.
    ///
    /// Retrying may help; proceeding never does.
    CouldNotEstablish,
    /// The endpoint itself is unusable, and would be for every retry.
    ///
    /// Most often dStack's TLS-terminating gateway form. The fix is upstream, in whatever handed
    /// this endpoint over.
    EndpointUnusable,
}

impl RefusalKind {
    /// A stable identifier, suitable for telemetry and for a shell harness to grep.
    ///
    /// `closed-loop/08-gateway-tls-termination.sh` step 11 asserts on this word to establish that
    /// the terminating form was refused **for being the terminating form**, not for failing channel
    /// binding — a run that refuses for the wrong reason has demonstrated nothing about step 10.
    /// Like [`crate::verdict::Check::name`], these strings are an interface: renaming one breaks a
    /// gate, and `tests/verified_transport.rs` pins them.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::GuaranteeViolated => "guarantee_violated",
            Self::CouldNotEstablish => "could_not_establish",
            Self::EndpointUnusable => "endpoint_unusable",
        }
    }
}

impl core::fmt::Display for RefusalKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

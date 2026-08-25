//! Dial a live dStack CVM, verify **that connection**, and use the client it yields.
//!
//! The runner for `verity-foundation/closed-loop/08-gateway-tls-termination.sh` steps 10 and 11 —
//! the only place the end-to-end *positive* can be demonstrated, because a trustworthy verdict needs
//! an Intel-signed quote committing to a key the endpoint actually holds, and no local test can
//! produce one.
//!
//! ```text
//! connect-verified --endpoint https://<app-id>-<port>s.<domain>
//!                  --compose app-compose.json
//!                  --image-digest sha256:…
//!                  --licensed-compose-hash <64 hex>
//!                  [--path /] [--os-image dstack-0.5.9] [--boot-reference boot.json]
//! ```
//!
//! # `--os-image` hard-fails on a revoked image, before dialling
//!
//! [ADR 0014] point 3 makes revocation a fact that hard-fails rather than a check a caller may
//! weigh. This runner is the one `closed-loop/08` steps 10-11 call and the one the README points
//! agents at, so it performs that refusal rather than leaving it to the older
//! `verify-attestation` path — a blessed runner that silently skipped it would be weaker than the
//! thing it replaced, on precisely the point the ADR is about.
//!
//! Naming an image establishes **identity and revocation only**. `KNOWN_OS_IMAGES` carries a name,
//! an `os_image_hash` and a revocation flag — no MRTD, no RTMRs — so it never supplies boot
//! measurements. Those come from `--boot-reference`, which is JSON an operator captured from a
//! deployment they satisfied themselves about; without it, check 7 is *skipped* rather than
//! silently passed.
//!
//! [ADR 0014]: https://github.com/ithaka-dev/verity-foundation/blob/main/docs/decisions/0014-verifier-update-discipline.md
//!
//! # How this differs from `verify-attestation`
//!
//! `verify-attestation` takes a certificate the *caller* captured and reasons about it. That is a
//! supported path — it is what an auditor does with recorded evidence — but it means the library is
//! trusting the caller for provenance, which ADR 0027 records as the residual MA-1 exists to close.
//!
//! Here nothing about the connection comes from the command line except the URL. The socket, the
//! handshake, the certificate and the quote are all obtained inside the library, and a
//! `VerifiedClient` is returned only when every essential check passed against *that* handshake.
//!
//! # Exit codes are a shell contract
//!
//! - **0** — connected. A client exists, so the verdict was trustworthy.
//! - **1** — refused. Step 11 asserts this *and* the refusal kind, because a run that refuses for
//!   the wrong reason has demonstrated nothing about step 10.
//! - **2** — the run could not be performed: a file was unreadable, or collateral could not be
//!   fetched. Distinct from 1 on purpose; conflating them would let an outage read as a refusal.

// A CLI, not library code. `expect` on a missing argument *is* the correct behaviour here — the
// caller gets a clear message and a non-zero exit — and the library's blanket denial exists to stop
// panics reaching an embedder, which an example has none of.
#![allow(clippy::expect_used)]

use std::process::ExitCode;

use verity_verifier::attest::Collateral;
use verity_verifier::binding::ComposeHash;
use verity_verifier::connect::{
    connect_verified, CollateralSource, CollateralUnavailable, ConnectOptions, ConnectRequest,
};
use verity_verifier::endpoint::Endpoint;
use verity_verifier::quote::Measurement;
use verity_verifier::reference::BootReference;
use verity_verifier::verdict::transcript_line;
use verity_verifier::verify::LicensedVersion;

fn arg(name: &str) -> Option<String> {
    let mut args = std::env::args();
    while let Some(a) = args.next() {
        if a == name {
            return args.next();
        }
    }
    None
}

/// Fetch Intel collateral through Phala's PCCS.
///
/// **The I/O the library refuses to do.** `dcap-qvl` fetches asynchronously, so wrapping it inside
/// the crate would mean choosing an async runtime for every embedder; the trait exists so that
/// choice stays here, in the caller. It is handed the quote *this handshake produced*, and its
/// answer is checked against the Intel root compiled into `dcap-qvl` — so a wrong answer causes a
/// refusal, never an acceptance.
struct PhalaPccs {
    runtime: tokio::runtime::Runtime,
}

impl CollateralSource for PhalaPccs {
    fn collateral_for(&self, raw_quote: &[u8]) -> Result<Collateral, CollateralUnavailable> {
        let client = dcap_qvl::collateral::CollateralClient::with_default_http(
            verity_verifier::attest::PHALA_PCCS_URL,
        )
        .map_err(|e| CollateralUnavailable::new(format!("could not build a client: {e:?}")))?;
        // The trait's rustdoc says the implementation owns its own timeout, because the library
        // cannot interrupt a blocking call without spawning a thread. This is that timeout.
        self.runtime.block_on(async {
            tokio::time::timeout(std::time::Duration::from_secs(30), client.fetch(raw_quote))
                .await
                .map_err(|_| CollateralUnavailable::new("the PCCS did not answer within 30s"))?
                .map_err(|e| CollateralUnavailable::new(format!("{e:?}")))
        })
    }
}

fn main() -> ExitCode {
    let endpoint_arg = arg("--endpoint").expect("--endpoint https://…");
    let compose_path = arg("--compose").expect("--compose <file>");
    let image_digest = arg("--image-digest").expect("--image-digest sha256:…");
    let licensed_compose_hash =
        arg("--licensed-compose-hash").expect("--licensed-compose-hash <64 hex>");
    // What to fetch once connected. Step 10 asserts on the body, because a client that connects and
    // is never used has not demonstrated that the transport works.
    let path = arg("--path").unwrap_or_else(|| "/".to_owned());
    // Optional, and independent. `--os-image` establishes identity and revocation;
    // `--boot-reference` is the only source of register values. Neither is inferred from the other.
    let os_image = arg("--os-image");
    let boot_reference_path = arg("--boot-reference");

    // Parsed here so a malformed URL is a *setup* failure (exit 2) rather than a refusal (exit 1).
    // `connect_verified` would refuse it too, but the two mean different things to the harness.
    let endpoint = match Endpoint::parse(&endpoint_arg) {
        Ok(endpoint) => endpoint,
        Err(why) => {
            eprintln!("--endpoint is not usable: {why}");
            return ExitCode::from(2);
        }
    };
    let compose_document = match std::fs::read(&compose_path) {
        Ok(bytes) => bytes,
        Err(why) => {
            eprintln!("could not read --compose: {compose_path}: {why}");
            return ExitCode::from(2);
        }
    };
    let compose_hash = match ComposeHash::parse_hex(&licensed_compose_hash) {
        Ok(hash) => hash,
        Err(why) => {
            eprintln!("could not read --licensed-compose-hash: {why}");
            return ExitCode::from(2);
        }
    };

    // Before anything is dialled. A revoked OS image is a refusal ADR 0014 makes unconditional, and
    // spending a handshake to arrive at it would only make the refusal later, never different.
    if !report_os_image(os_image.as_deref()) {
        return ExitCode::FAILURE;
    }
    let boot = match boot_reference_path.as_deref().map(load_boot_reference) {
        None => None,
        Some(Ok(reference)) => Some(reference),
        Some(Err(why)) => {
            eprintln!("could not read --boot-reference: {why}");
            return ExitCode::from(2);
        }
    };

    let licensed = LicensedVersion {
        compose_hash,
        image_digest,
    };
    let mut request = ConnectRequest::new(&endpoint, &licensed, compose_document);
    request.boot = boot.as_ref();

    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(why) => {
            eprintln!("could not start a runtime for collateral fetching: {why}");
            return ExitCode::from(2);
        }
    };
    let source = PhalaPccs { runtime };

    println!("endpoint:       {endpoint}");
    println!("endpoint form:  {:?}", endpoint.form());
    println!("licensed hash:  {}", licensed.compose_hash);

    match connect_verified(&request, &source, &ConnectOptions::default()) {
        Ok(client) => report_connected(&client, &path),
        Err(refusal) => {
            println!("\nrefusal kind:   {}", refusal.kind());
            println!("refusal:        {refusal}");
            if let Some(verdict) = refusal.verdict() {
                println!("\nchecks performed:");
                for (check, outcome) in verdict.results() {
                    println!("{}", transcript_line(*check, outcome));
                }
                for unrun in verdict.unrun_essentials() {
                    println!("  {:<22} NOT RUN (essential)", unrun.name());
                }
            }
            println!("\nREFUSED");
            ExitCode::FAILURE
        }
    }
}

/// Report what a named OS image is, and refuse a revoked one. Returns false to abort.
///
/// **This does not supply boot measurements.** `KNOWN_OS_IMAGES` carries a name, an
/// `os_image_hash` and a revocation flag — no MRTD, no RTMRs — so naming an image establishes
/// *identity and revocation*, never what the registers should contain. [ADR 0014] point 3 makes
/// revocation a fact that hard-fails, and that is the part this checks.
///
/// Deliberately the same shape as `verify-attestation.rs`'s: two runners that refuse a revoked
/// image differently would make "was this image revoked?" depend on which one an operator reached
/// for.
///
/// [ADR 0014]: https://github.com/ithaka-dev/verity-foundation/blob/main/docs/decisions/0014-verifier-update-discipline.md
fn report_os_image(name: Option<&str>) -> bool {
    let Some(name) = name else { return true };
    match verity_verifier::reference::KNOWN_OS_IMAGES
        .iter()
        .find(|i| i.name == name)
    {
        Some(image) if image.revoked => {
            eprintln!("REFUSED before connecting: OS image `{name}` is revoked");
            false
        }
        Some(image) => {
            println!("os image:       {name} (hash {})", image.os_image_hash);
            if !verity_verifier::reference::meets_minimum_version(name) {
                eprintln!("warning: {name} is below the minimum version this verifier accepts");
            }
            true
        }
        None => {
            eprintln!("warning: `{name}` is not a known OS image; boot measurements unaffected");
            true
        }
    }
}

/// Load a caller-supplied boot reference.
///
/// There is nowhere to get one automatically — nothing bundled holds register values — so this is
/// JSON the caller captured from a deployment they independently satisfied themselves about. Its
/// absence leaves check 7 *skipped* rather than silently passing, which is why every field is
/// `Option`.
///
/// Returns the reason as a string rather than exiting, so the caller can exit 2 with it: a file
/// problem is "the run could not be performed", never "the endpoint was refused".
fn load_boot_reference(path: &str) -> Result<BootReference, String> {
    let raw: serde_json::Value =
        serde_json::from_slice(&std::fs::read(path).map_err(|e| format!("{path}: {e}"))?)
            .map_err(|e| format!("{path} is not JSON: {e}"))?;

    let measurement = |key: &str| -> Result<Option<Measurement>, String> {
        let Some(hex) = raw.get(key).and_then(serde_json::Value::as_str) else {
            return Ok(None);
        };
        let bytes = hex_decode(hex).ok_or_else(|| format!("{key} is not hex"))?;
        let sized: [u8; verity_verifier::quote::MEASUREMENT_LEN] = bytes
            .try_into()
            .map_err(|_| format!("{key} is not exactly 48 bytes"))?;
        Ok(Some(Measurement::from_bytes(sized)))
    };

    Ok(BootReference {
        mrtd: measurement("mrtd")?,
        rtmr0: measurement("rtmr0")?,
        rtmr1: measurement("rtmr1")?,
        rtmr2: measurement("rtmr2")?,
    })
}

#[must_use]
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

/// Print what a verified connection established, then use it.
///
/// Split out of `main` so the success path reads as one thing. The order matters to
/// `closed-loop/08` step 10: the transcript, then the binding, then a request whose body the script
/// asserts on — because a client that connects and is never exercised has not demonstrated that the
/// verified socket carries anything.
fn report_connected(client: &verity_verifier::connect::VerifiedClient, path: &str) -> ExitCode {
    // The transcript, in the same shape `verify-attestation` prints and `04`/`06`/`08` grep.
    // Rendered by the library rather than formatted here, so a crate test can pin the bytes.
    let verdict = client.verdict();
    println!("\nchecks performed:");
    for (check, outcome) in verdict.verdict().results() {
        println!("{}", transcript_line(*check, outcome));
    }
    println!(
        "\nchannel binding established over SPKI ({} bytes)",
        client.channel_binding().spki_der().len()
    );

    match client.get(path) {
        Ok(response) => {
            println!("GET {path} -> {}", response.status());
            println!(
                "body: {}",
                String::from_utf8_lossy(response.body()).trim_end()
            );
            println!("\nCONNECTED");
            ExitCode::SUCCESS
        }
        Err(why) => {
            // The verdict was trustworthy and the request failed, which is a different situation
            // from a refusal — exit 2, so a harness does not read a transport fault as a
            // verification result.
            eprintln!("connected, but the request failed: {why}");
            ExitCode::from(2)
        }
    }
}

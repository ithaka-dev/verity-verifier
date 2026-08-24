//! Verify a live dStack CVM against a compose document you claim was licensed.
//!
//! This is the runner for `closed-loop/04-refuses-on-mismatch.sh`. It exists as an *example* rather
//! than as part of the library on purpose: it performs I/O — fetching Intel collateral — and the
//! library deliberately performs none, so that verification can run offline, in `wasm32`, or inside
//! another enclave. The division is the point.
//!
//! ```text
//! verify-attestation --attestation att.json --compose app-compose.json --image-digest sha256:…
//!                    [--licensed-compose-hash <64 hex>]
//!                    [--os-image dstack-0.5.9] [--boot-reference boot.json]
//!                    [--endpoint https://…] [--leaf-cert leaf.pem]
//! ```
//!
//! # `--licensed-compose-hash` decides whether check 1 means anything
//!
//! ADR 0009 step 2 compares the served document against the hash **the licence names**. Without this
//! argument the runner has no licence to consult, so it derives the reference from the document it
//! was just handed — comparing `sha256(doc)` with `sha256(doc)`, which passes for every input
//! including a tampered one and would keep passing with `VerifiedCompose::check` deleted. The
//! transcript says so out loud when that happens, because two closed-loop scripts grep
//! `compose_hash passed` as a positive control and it was worth nothing to them.
//!
//! Exits 0 when the verdict is accepted and 1 when it is refused, so a shell harness can assert
//! **both** directions. A run that only ever sees the good case cannot tell "the check passed" from
//! "the check did not run". Exit 2 means the run could not be performed at all — collateral could
//! not be fetched, or a file named on the command line could not be read.
//!
//! # `--leaf-cert` decides whether this run means anything about an endpoint
//!
//! Without it, `channel_bound` is *skipped* and the verdict is untrustworthy however well the
//! configuration checks go, because a quote read from a file establishes what ran somewhere and not
//! what you are talking to. With it, the certificate must be the one the TLS handshake with
//! `--endpoint` actually returned; this runner cannot check that and neither can the library.
//!
//! **The transcript format is a shell contract.** `closed-loop/04-refuses-on-mismatch.sh` and
//! `06-refuses-relayed-endpoint.sh` grep the per-check lines below. They are rendered by
//! `verity_verifier::verdict::transcript_line` rather than formatted here, so a crate test can pin
//! the bytes — while the format lived in this file no test could reach it.

// A CLI, not library code. `expect` on a missing argument *is* the correct behaviour here — the
// caller gets a clear message and a non-zero exit — and the library's blanket denial of it exists
// to stop panics reaching an embedder, which an example has none of.
#![allow(clippy::expect_used, clippy::indexing_slicing)]

use std::process::ExitCode;

use verity_verifier::attest::{Collateral, TcbPolicy};
use verity_verifier::binding::ComposeHash;
use verity_verifier::channel::PeerCertificate;
use verity_verifier::endpoint::{Endpoint, EndpointForm};
use verity_verifier::quote::Measurement;
use verity_verifier::reference::BootReference;
use verity_verifier::verdict::transcript_line;
use verity_verifier::verify::{verify, Evidence, LicensedVersion};

fn arg(name: &str) -> Option<String> {
    let mut args = std::env::args();
    while let Some(a) = args.next() {
        if a == name {
            return args.next();
        }
    }
    None
}

#[tokio::main]
async fn main() -> ExitCode {
    let attestation_path = arg("--attestation").expect("--attestation <file>");
    let compose_path = arg("--compose").expect("--compose <file>");
    let image_digest = arg("--image-digest").expect("--image-digest sha256:…");
    // Optional. Absent means the boot check is *indeterminate* — a remedy exists (supply a
    // reference and run this again) and the verdict says so — which is not the same as passing, and
    // is why `BootReference` uses `Option` per field rather than defaults.
    let os_image = arg("--os-image");
    let boot_reference_path = arg("--boot-reference");
    // Optional, and the two are independent. `--endpoint` is provenance the library never sees;
    // `--leaf-cert` is the only thing that makes this run a statement about a connection.
    let endpoint = arg("--endpoint");
    let leaf_cert_path = arg("--leaf-cert");
    // Optional, and its absence is why check 1 can be vacuous. See `licensed_compose_hash`.
    let licensed_compose_hash = arg("--licensed-compose-hash");

    // — the quote, raw, out of the RA-TLS leaf certificate —
    //
    // Not the provider's parsed `tcb_info`. That trusts Phala's rendering of the hardware's
    // statement; this trusts Intel's signature over the statement itself.
    let attestation: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&attestation_path).expect("attestation file"))
            .expect("attestation is JSON");
    let quote_hex = attestation["app_certificates"][0]["quote"]
        .as_str()
        .expect("app_certificates[0].quote");
    let raw_quote = hex_decode(quote_hex).expect("quote is hex");

    // — the document we claim was licensed, and what we claim was licensed —
    let compose_document = std::fs::read(&compose_path).expect("compose file");
    let (compose_hash, compose_hash_is_self_referential) =
        match licensed_hash(licensed_compose_hash.as_deref(), &compose_document) {
            Ok(pair) => pair,
            Err(why) => {
                eprintln!("could not read --licensed-compose-hash: {why}");
                return ExitCode::from(2);
            }
        };
    let licensed = LicensedVersion {
        compose_hash,
        image_digest: image_digest.clone(),
    };

    // — the certificate the connection presented, if there was a connection —
    //
    // Read before anything expensive happens. A file-level problem must never fall through to
    // `NotConnected`: that would silently turn "I could not read your certificate" into "channel
    // binding was not attempted", and `06` would then fail with *refused, but not because of
    // channel binding* — sending an operator after the wrong defect. Certificate **semantics** stay
    // the library's: bytes that decode but are not a certificate go in and come back as
    // `channel_bound FAILED`.
    let leaf_cert_der = match leaf_cert_path.as_deref().map(load_leaf_certificate) {
        None => None,
        Some(Ok(der)) => Some(der),
        Some(Err(why)) => {
            eprintln!("could not read --leaf-cert: {why}");
            return ExitCode::from(2);
        }
    };

    println!("quote:          {} bytes", raw_quote.len());
    println!("compose:        {} bytes", compose_document.len());
    println!("licensed hash:  {}", licensed.compose_hash);
    if compose_hash_is_self_referential {
        // Said in the transcript rather than only in a comment, because two closed-loop scripts
        // grep `compose_hash passed` as a positive control and both were doing it against a check
        // that cannot fail. A reader of that transcript has to be able to see it.
        //
        // **`CANNOT FAIL` is a shell contract**, like the check names. `04` and `06` both grep for
        // that exact string at their step 3 to catch `--licensed-compose-hash` being dropped or
        // renamed — without it their positive control is decoration and they cannot tell. Changing
        // these words means changing both scripts in the same commit.
        println!(
            "                ^ derived from the document itself — no --licensed-compose-hash was \
             supplied, so check 1 compares sha256(doc) against sha256(doc) and CANNOT FAIL. It is \
             not evidence. mr_config_id is what catches a tampered configuration in this run."
        );
    }
    if let Some(endpoint) = endpoint.as_deref() {
        println!("endpoint:       {endpoint}");
        warn_if_tls_terminating(endpoint);
    }

    // — collateral, fetched here so the library stays free of I/O —
    let client = dcap_qvl::collateral::CollateralClient::with_default_http(
        verity_verifier::attest::PHALA_PCCS_URL,
    )
    .expect("collateral client");
    let collateral: Collateral = match client.fetch(&raw_quote).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("could not fetch collateral: {e:?}");
            return ExitCode::from(2);
        }
    };

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs();

    // — the OS image, if the caller named one —
    //
    // **This does not supply boot measurements.** `KNOWN_OS_IMAGES` carries a name, an
    // `os_image_hash` and a revocation flag — no MRTD, no RTMRs — so naming an image establishes
    // *identity and revocation*, never what the registers should contain. ADR 0014 point 3 makes
    // revocation a fact that hard-fails, and that is the part this can check.
    if !report_os_image(os_image.as_deref()) {
        return ExitCode::FAILURE;
    }

    // — boot measurements, only when a reference was supplied —
    //
    // There is nowhere to get one automatically: nothing bundled holds register values. So this is
    // caller-supplied JSON, and its absence leaves check 7 indeterminate rather than silently
    // passing.
    let boot = boot_reference_path.as_deref().map(load_boot_reference);

    // Absent means `PeerCertificate::NotConnected`, which is honest and which makes the verdict
    // untrustworthy however well everything else goes. Said loudly and *before* the check list,
    // because a reader who skims a wall of `passed` and stops at the bottom line should still have
    // met the sentence that explains why the bottom line says REFUSED.
    let peer_certificate = if let Some(der) = leaf_cert_der.as_deref() {
        PeerCertificate::Presented(der)
    } else {
        println!(
            "\nchannel binding: NOT ATTEMPTED — no --leaf-cert supplied; \
             this run cannot establish what you are talking to."
        );
        PeerCertificate::NotConnected
    };

    let verdict = verify(
        &licensed,
        &Evidence {
            raw_quote: &raw_quote,
            compose_document,
            collateral: &collateral,
            now_secs,
            peer_certificate,
        },
        boot.as_ref(),
        &TcbPolicy::default(),
    );

    report_transcript(&verdict);
    report_measured_registers(&raw_quote);

    if verdict.is_trustworthy() {
        println!("\nACCEPTED");
        ExitCode::SUCCESS
    } else {
        println!("\nREFUSED");
        ExitCode::FAILURE
    }
}

/// Report what a named OS image is, and refuse a revoked one. Returns false to abort.
///
/// **This does not supply boot measurements.** `KNOWN_OS_IMAGES` carries a name, an
/// `os_image_hash` and a revocation flag — no MRTD, no RTMRs — so naming an image establishes
/// *identity and revocation*, never what the registers should contain. ADR 0014 point 3 makes
/// revocation a fact that hard-fails, and that is the part this checks.
fn report_os_image(name: Option<&str>) -> bool {
    let Some(name) = name else { return true };
    match verity_verifier::reference::KNOWN_OS_IMAGES
        .iter()
        .find(|i| i.name == name)
    {
        Some(image) if image.revoked => {
            eprintln!("REFUSED before verifying: OS image `{name}` is revoked");
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

/// Print which comparisons actually ran, not only what they concluded.
///
/// A verifier that quietly stops performing one still reports success; this list is the only place
/// that shows. The per-check lines are rendered by the **library** rather than here: passed,
/// skipped, failed and indeterminate are four different things and must render as four — an
/// earlier version of this example printed anything not-passed as FAILED, reporting a *skipped*
/// boot-measurement check as a failure. That logic now lives in `transcript_line`, where
/// `tests/transcript_contract.rs` pins the exact bytes, because two closed-loop gates parse these
/// lines and nothing could reach them while they were formatted in an example binary.
fn report_transcript(verdict: &verity_verifier::verdict::Verdict) {
    println!("\nchecks performed:");
    for (check, outcome) in verdict.results() {
        println!("{}", transcript_line(*check, outcome));
    }
    // Only checks that genuinely never ran. `missing_essentials` also includes ones that ran and
    // failed, so printing that here labelled a *failed* check as "NOT RUN" — the two are opposite
    // situations and this is the display that has to keep them apart.
    for unrun in verdict.unrun_essentials() {
        println!("  {:<22} NOT RUN (essential)", unrun.name());
    }
}

/// Print the boot registers this deployment measured.
///
/// Always, because there is no bundled source for these. Capturing them from a deployment you have
/// independently satisfied yourself about is the only way a `--boot-reference` ever comes to exist.
/// `RTMR3` is deliberately not printed: it varies per boot, so showing it beside the others would
/// invite someone to capture it as a reference.
fn report_measured_registers(raw_quote: &[u8]) {
    let Ok(quote) = verity_verifier::quote::Quote::parse(raw_quote) else {
        return;
    };
    println!("\nmeasured boot registers (a reference is captured, never derived):");
    println!("  mrtd   {}", quote.mrtd());
    for (index, rtmr) in quote.rtmrs().iter().enumerate().take(3) {
        println!("  rtmr{index}  {rtmr}");
    }
}

/// Resolve the hash check 1 compares against, and say whether it is real evidence.
///
/// **The reference and the document are two different things, and conflating them is how check 1
/// becomes decoration.** ADR 0009 step 2 compares the *served document* against the hash **the
/// licence names**, which comes from an `AppManifest` version record — somewhere else entirely.
/// Derive the reference from the document instead and you have compared `sha256(doc)` against
/// `sha256(doc)`: a check that passes for every input including a tampered one, and that would keep
/// passing with `VerifiedCompose::check` deleted outright.
///
/// That is the same defect as supplying both sides of the channel-binding comparison, one check
/// earlier, and it is why `--licensed-compose-hash` exists.
///
/// Returns the hash and whether it was self-referential. This runner has no `AppManifest` to consult,
/// so it cannot refuse to run without one — but it can, and does, say so in the transcript.
fn licensed_hash(
    supplied: Option<&str>,
    compose_document: &[u8],
) -> Result<(ComposeHash, bool), String> {
    match supplied {
        Some(hex) => ComposeHash::parse_hex(hex)
            .map(|h| (h, false))
            .map_err(|e| e.to_string()),
        None => Ok((ComposeHash::of(compose_document), true)),
    }
}

/// Read a leaf certificate as DER, accepting either PEM or DER on disk.
///
/// PEM is a container format and therefore belongs on this side of the I/O boundary: the library
/// takes DER only. Decoding happens through `pem-rfc7468` rather than twenty lines of hand-rolled
/// base64 — the workspace already refuses hand-rolled scanners for JSON and YAML, and that argument
/// does not weaken because the format is smaller, least of all in the file that feeds the
/// crown-jewel check its input.
///
/// Returns the reason as a string rather than exiting, so the caller can exit 2 with it. Every
/// failure here is a *file* problem; certificate semantics are the library's to judge.
fn load_leaf_certificate(path: &str) -> Result<Vec<u8>, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;

    // Sniffed, not guessed from the extension: operators name these files `.pem`, `.crt`, `.cer`
    // and `.der` more or less at random, and the first bytes are unambiguous.
    if !bytes.starts_with(b"-----BEGIN") {
        return Ok(bytes);
    }

    let (label, der) =
        pem_rfc7468::decode_vec(&bytes).map_err(|e| format!("{path} is not valid PEM: {e}"))?;
    // A private key or a CSR in this argument is a mistake worth naming here. Passing its DER on
    // would produce `channel_bound FAILED`, which is the correct verdict for the wrong reason and
    // reads exactly like an attack.
    if label != "CERTIFICATE" {
        return Err(format!(
            "{path} is a PEM `{label}` block, not a CERTIFICATE — \
             --leaf-cert wants the leaf from the TLS handshake"
        ));
    }
    Ok(der)
}

/// Warn when an endpoint uses dStack's TLS-*terminating* gateway form.
///
/// The rule itself now lives in [`verity_verifier::endpoint`], where tests can reach it — while it
/// lived here nothing could, which is the same defect `transcript_line` was moved out of this file
/// to fix. What stays here is the *policy*: one classifier, two call sites, and they behave
/// differently on purpose.
///
/// **Advisory only, and that includes an unparseable endpoint.** It touches neither the verdict nor
/// the exit code. This runner's `verify()` path takes a caller-supplied certificate and must not
/// refuse — the refusal is already produced by consequence, when the gateway's certificate fails to
/// match the quote — whereas `connect_verified` owns the connection and refuses outright.
///
/// **The exit code is load-bearing here.** `04` and `06` distinguish exit 1 (*refused*) from exit 2
/// (*could not run*), so a typo in a diagnostic argument must not turn a refusal into an
/// inconclusive result. Hence a warning and a return, never `ExitCode::from(2)`.
///
/// Warns only on a positive match. Unrecognised hosts say nothing, or `06`'s
/// `relay.attacker.example` would generate noise on every run.
fn warn_if_tls_terminating(endpoint: &str) {
    let parsed = match Endpoint::parse(endpoint) {
        Ok(parsed) => parsed,
        Err(why) => {
            // Said, not swallowed — and still not fatal. See the doc comment.
            eprintln!("warning: --endpoint could not be classified ({why}); it is advisory here");
            return;
        }
    };
    if parsed.form() != EndpointForm::DstackTerminating {
        return;
    }
    let passthrough = parsed
        .passthrough_form()
        .unwrap_or_else(|| parsed.host().to_owned());
    eprintln!(
        "warning: `{}` is dStack's TLS-TERMINATING gateway form. The certificate you get from it \
         belongs to the gateway, not the enclave, so channel binding cannot succeed. The \
         passthrough form appends `s` to the port label: `{passthrough}`",
        parsed.host()
    );
}

/// Load a caller-supplied boot reference.
///
/// There is nowhere to get one automatically — nothing bundled holds register values — so this is
/// JSON the caller captured from a deployment they independently satisfied themselves about. Its
/// absence leaves check 7 *indeterminate* rather than silently passing, which is why every field is
/// `Option`.
fn load_boot_reference(path: &str) -> BootReference {
    let raw: serde_json::Value =
        serde_json::from_slice(&std::fs::read(path).expect("boot reference file"))
            .expect("boot reference is JSON");
    let measurement = |key: &str| -> Option<Measurement> {
        raw.get(key).and_then(serde_json::Value::as_str).map(|hex| {
            let bytes = hex_decode(hex).expect("measurement is hex");
            let sized: [u8; verity_verifier::quote::MEASUREMENT_LEN] =
                bytes.try_into().expect("a measurement is exactly 48 bytes");
            Measurement::from_bytes(sized)
        })
    };
    BootReference {
        mrtd: measurement("mrtd"),
        rtmr0: measurement("rtmr0"),
        rtmr1: measurement("rtmr1"),
        rtmr2: measurement("rtmr2"),
    }
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

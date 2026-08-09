//! Verify a live dStack CVM against a compose document you claim was licensed.
//!
//! This is the runner for `closed-loop/04-refuses-on-mismatch.sh`. It exists as an *example* rather
//! than as part of the library on purpose: it performs I/O — fetching Intel collateral — and the
//! library deliberately performs none, so that verification can run offline, in `wasm32`, or inside
//! another enclave. The division is the point.
//!
//! ```text
//! verify-attestation --attestation att.json --compose app-compose.json --image-digest sha256:…
//! ```
//!
//! Exits 0 when the verdict is accepted and 1 when it is refused, so a shell harness can assert
//! **both** directions. A run that only ever sees the good case cannot tell "the check passed" from
//! "the check did not run".

// A CLI, not library code. `expect` on a missing argument *is* the correct behaviour here — the
// caller gets a clear message and a non-zero exit — and the library's blanket denial of it exists
// to stop panics reaching an embedder, which an example has none of.
#![allow(clippy::expect_used, clippy::indexing_slicing)]

use std::process::ExitCode;

use verity_verifier::attest::{Collateral, TcbPolicy};
use verity_verifier::binding::ComposeHash;
use verity_verifier::quote::Measurement;
use verity_verifier::reference::BootReference;
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
    // Optional. Absent means the boot check is *skipped*, and the verdict says so — which is not
    // the same as passing, and is why `BootReference` uses `Option` per field rather than defaults.
    let os_image = arg("--os-image");
    let boot_reference_path = arg("--boot-reference");

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

    // — the document we claim was licensed —
    let compose_document = std::fs::read(&compose_path).expect("compose file");
    let licensed = LicensedVersion {
        compose_hash: ComposeHash::of(&compose_document),
        image_digest: image_digest.clone(),
    };

    println!("quote:          {} bytes", raw_quote.len());
    println!("compose:        {} bytes", compose_document.len());
    println!("licensed hash:  {}", licensed.compose_hash);

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
    // caller-supplied JSON, and its absence leaves check 7 skipped rather than silently passing.
    let boot = boot_reference_path.as_deref().map(load_boot_reference);

    let verdict = verify(
        &licensed,
        &Evidence {
            raw_quote: &raw_quote,
            compose_document,
            collateral: &collateral,
            now_secs,
        },
        boot.as_ref(),
        &TcbPolicy::default(),
    );

    // Which comparisons actually ran, not only what they concluded. A verifier that quietly stops
    // performing one still reports success; the list is the only place that shows.
    println!("\nchecks performed:");
    for (check, outcome) in verdict.results() {
        // Passed, skipped and failed are three different things and must render as three. An
        // earlier version of this example printed anything not-passed as FAILED, which reported a
        // *skipped* boot-measurement check as a failure — collapsing exactly the distinction the
        // library refuses to collapse, and the one F-09's alert is built on.
        let rendered = match outcome {
            verity_verifier::verdict::Outcome::Passed => "passed".to_owned(),
            verity_verifier::verdict::Outcome::Skipped(why) => format!("skipped ({why})"),
            verity_verifier::verdict::Outcome::Failed(why) => format!("FAILED ({why})"),
            // `Outcome` is `#[non_exhaustive]`, so a future variant lands here rather than silently
            // rendering as one of the three above.
            other => format!("unrecognised outcome: {other:?}"),
        };
        println!("  {:<22} {rendered}", check.name());
    }
    // Only checks that genuinely never ran. `missing_essentials` also includes ones that ran and
    // failed, so printing it here labelled a *failed* check as "NOT RUN" — the two are opposite
    // situations and this is the display that has to keep them apart.
    for unrun in verdict.unrun_essentials() {
        println!("  {:<22} NOT RUN (essential)", unrun.name());
    }

    // Printed always, because there is no bundled source for these. Capturing them from a
    // deployment you have independently satisfied yourself about is the only way a `--boot-reference`
    // ever comes to exist.
    if let Ok(quote) = verity_verifier::quote::Quote::parse(&raw_quote) {
        println!("\nmeasured boot registers (a reference is captured, never derived):");
        println!("  mrtd   {}", quote.mrtd());
        for (index, rtmr) in quote.rtmrs().iter().enumerate().take(3) {
            println!("  rtmr{index}  {rtmr}");
        }
    }

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

/// Load a caller-supplied boot reference.
///
/// There is nowhere to get one automatically — nothing bundled holds register values — so this is
/// JSON the caller captured from a deployment they independently satisfied themselves about. Its
/// absence leaves check 7 *skipped* rather than silently passing, which is why every field is
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

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

use std::process::ExitCode;

use verity_verifier::attest::{Collateral, TcbPolicy};
use verity_verifier::binding::ComposeHash;
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

    let verdict = verify(
        &licensed,
        &Evidence {
            raw_quote: &raw_quote,
            compose_document,
            collateral: &collateral,
            now_secs,
        },
        None,
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

    if verdict.is_trustworthy() {
        println!("\nACCEPTED");
        ExitCode::SUCCESS
    } else {
        println!("\nREFUSED");
        ExitCode::FAILURE
    }
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

//! The public verdict: what was checked, what was found, and by which verifier.
//!
//! # Never a bare boolean
//!
//! [ADR 0014] requires a verdict to carry provenance — the verifier version, the reference-data
//! date, and **which checks actually ran**. That last field is what makes a weakened verifier
//! detectable: one that quietly stopped comparing `MR-CONFIG-ID` still returns "verified", but it
//! can no longer *claim* to have compared it.
//!
//! Enforcement is impossible here — this code runs on the agent's side and nobody can compel an
//! update. So the design goal is not prevention but **visibility**: a stale or loosened verifier
//! must not be able to be either invisibly.
//!
//! A caller wanting a boolean derives one with [`Verdict::is_trustworthy`]. The library never
//! offers only that shape.
//!
//! [ADR 0014]: https://github.com/ithaka-dev/verity-foundation/blob/main/docs/decisions/0014-verifier-update-discipline.md

use core::fmt;

/// This verifier's version, from the crate manifest.
pub const VERIFIER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// A check this verifier can perform.
///
/// Named individually so a verdict can report exactly which ran — a count would not distinguish
/// "all six passed" from "six of the cheap ones passed".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Check {
    /// The served compose hashed to the licensed `composeHash`.
    ComposeHash,
    /// Every image in the compose is digest-pinned (I8).
    ImagesPinned,
    /// The compose references the licensed `imageDigest`.
    LicensedImagePresent,
    /// The quote's signature chain verified against Intel.
    QuoteSignature,
    /// The platform's TCB status was acceptable.
    TcbStatus,
    /// `MR-CONFIG-ID` matched the licensed configuration.
    MrConfigId,
    /// Boot measurements matched the expected OS image.
    BootMeasurements,
}

impl Check {
    /// A stable identifier, suitable for telemetry.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::ComposeHash => "compose_hash",
            Self::ImagesPinned => "images_pinned",
            Self::LicensedImagePresent => "licensed_image_present",
            Self::QuoteSignature => "quote_signature",
            Self::TcbStatus => "tcb_status",
            Self::MrConfigId => "mr_config_id",
            Self::BootMeasurements => "boot_measurements",
        }
    }

    /// Checks without which a verdict means nothing.
    ///
    /// A verifier reporting success while having skipped any of these has not verified anything,
    /// whatever it says.
    #[must_use]
    pub const fn essential() -> &'static [Self] {
        &[
            Self::ComposeHash,
            Self::ImagesPinned,
            Self::LicensedImagePresent,
            Self::QuoteSignature,
            Self::MrConfigId,
        ]
    }
}

impl fmt::Display for Check {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// What a single check concluded.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Outcome {
    /// Performed, and passed.
    Passed,
    /// Performed, and failed. The string says how.
    Failed(String),
    /// Not performed, and why not.
    ///
    /// Skipping is visible rather than silent: a check nobody ran is not a check that passed.
    Skipped(String),
}

impl Outcome {
    /// Whether this outcome is a pass.
    #[must_use]
    pub const fn passed(&self) -> bool {
        matches!(self, Self::Passed)
    }
}

/// The result of verifying an endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    verifier_version: &'static str,
    reference_data_date: &'static str,
    results: Vec<(Check, Outcome)>,
}

impl Verdict {
    /// Start an empty verdict.
    #[must_use]
    pub fn new() -> Self {
        Self {
            verifier_version: VERIFIER_VERSION,
            reference_data_date: crate::reference::REFERENCE_DATA_DATE,
            results: Vec::new(),
        }
    }

    /// Record a check's outcome.
    #[must_use]
    pub fn record(mut self, check: Check, outcome: Outcome) -> Self {
        self.results.push((check, outcome));
        self
    }

    /// Which verifier produced this.
    #[must_use]
    pub const fn verifier_version(&self) -> &'static str {
        self.verifier_version
    }

    /// How old this verifier's reference data is.
    #[must_use]
    pub const fn reference_data_date(&self) -> &'static str {
        self.reference_data_date
    }

    /// Every check and its outcome, in the order performed.
    #[must_use]
    pub fn results(&self) -> &[(Check, Outcome)] {
        &self.results
    }

    /// The outcome of one check, if it was considered at all.
    #[must_use]
    pub fn outcome(&self, check: Check) -> Option<&Outcome> {
        self.results
            .iter()
            .find(|(c, _)| *c == check)
            .map(|(_, o)| o)
    }

    /// Checks that failed.
    #[must_use]
    pub fn failures(&self) -> Vec<(Check, &str)> {
        self.results
            .iter()
            .filter_map(|(c, o)| match o {
                Outcome::Failed(why) => Some((*c, why.as_str())),
                _ => None,
            })
            .collect()
    }

    /// Essential checks that did not pass — whether they failed or were never run.
    ///
    /// The two are grouped on purpose. From the position of someone deciding whether to trust an
    /// endpoint, "this check failed" and "nobody ran this check" are the same answer: **you do not
    /// know.**
    #[must_use]
    /// Essential checks that **never ran at all** — no outcome was recorded for them.
    ///
    /// Distinct from [`Verdict::missing_essentials`], which also includes checks that ran and
    /// failed. The difference is the whole of F-09's alert: a check that failed is the system
    /// working, and a check that silently stopped running is the failure mode §4.5 cannot otherwise
    /// see. Collapsing them would make "the verifier stopped checking" indistinguishable from "the
    /// verifier refused something", which are opposite situations.
    #[must_use]
    pub fn unrun_essentials(&self) -> Vec<Check> {
        Check::essential()
            .iter()
            .copied()
            .filter(|c| self.outcome(*c).is_none())
            .collect()
    }

    /// Essential checks that did not pass — whether they failed or never ran.
    ///
    /// This is the **trust** question, and for it the two cases are equivalent: neither establishes
    /// what the check was there to establish. For the *diagnostic* question, which tells a
    /// regression from a refusal, use [`Verdict::unrun_essentials`].
    pub fn missing_essentials(&self) -> Vec<Check> {
        Check::essential()
            .iter()
            .copied()
            .filter(|c| !self.outcome(*c).is_some_and(Outcome::passed))
            .collect()
    }

    /// Whether every essential check ran and passed.
    ///
    /// This is the boolean, derived rather than offered directly — so a caller reaching for it has
    /// at least walked past the reasons it might be wrong.
    #[must_use]
    pub fn is_trustworthy(&self) -> bool {
        self.missing_essentials().is_empty()
    }
}

impl Default for Verdict {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "verity-verifier {} (reference data {})",
            self.verifier_version, self.reference_data_date
        )?;
        for (check, outcome) in &self.results {
            match outcome {
                Outcome::Passed => writeln!(f, "  pass    {check}")?,
                Outcome::Failed(why) => writeln!(f, "  FAIL    {check}: {why}")?,
                Outcome::Skipped(why) => writeln!(f, "  skipped {check}: {why}")?,
            }
        }
        let missing = self.missing_essentials();
        if missing.is_empty() {
            write!(f, "  => trustworthy")
        } else {
            let names: Vec<&str> = missing.iter().map(|c| c.name()).collect();
            write!(f, "  => NOT trustworthy (missing: {})", names.join(", "))
        }
    }
}

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
    /// The quote commits to the certificate presented on the connection in use.
    ///
    /// The check that stops a genuine quote from being replayed beside an endpoint it never
    /// attested. Every other check here can be satisfied by evidence recorded from a machine that
    /// no longer exists; this one cannot.
    ChannelBound,
}

impl Check {
    /// A stable identifier, suitable for telemetry.
    ///
    /// **These names are an interface twice over.** They are what F-09's alert groups by, and — via
    /// [`transcript_line`] — they are what `closed-loop/04-refuses-on-mismatch.sh` and
    /// `closed-loop/06-refuses-relayed-endpoint.sh` grep for. Renaming one breaks a dashboard and a
    /// gate, and neither failure shows up in this crate's own tests unless a test pins the string.
    /// `tests/verdict_semantics.rs` does.
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
            Self::ChannelBound => "channel_bound",
        }
    }

    /// Checks without which a verdict means nothing.
    ///
    /// A verifier reporting success while having skipped any of these has not verified anything,
    /// whatever it says.
    ///
    /// **`TcbStatus` belongs here and was missing.** ADR 0014 decision 2 makes TCB enforcement
    /// mandatory and not configurable — "no option, no override, no strict mode that can be left
    /// off" — and `verify` does record the refusal. But recording it outside this list meant the
    /// refusal never reached `is_trustworthy`, so a genuine quote from a platform with a known
    /// TCB weakness returned `true`. The enforcement was honest in the transcript and absent from
    /// the answer, which is the precise shape ADR 0014 exists to prevent.
    ///
    /// **`BootMeasurements` is deliberately not here.** It compares against a reference the caller
    /// supplies and most callers have none, so its absence is a legitimate configuration rather
    /// than a gap. That is the line, and `TcbStatus` was on the wrong side of it: TCB status always
    /// has an answer whenever a signature verified.
    ///
    /// **`ChannelBound` is here, on the same line of reasoning.** It sits where `BootMeasurements`
    /// does not because every caller who opened a connection has a certificate to supply, and a
    /// caller who opened none has not verified an endpoint at all — they have established what is
    /// running somewhere. There is no configuration in which its absence is legitimate *and* the
    /// verdict is about an endpoint, so "the caller had no reference for this" never applies.
    ///
    /// Without it in this list, every other check can be satisfied by a genuine quote recorded from
    /// a CVM that has since been destroyed, presented beside an endpoint an attacker controls. That
    /// is review finding CR-1, and this line is where it is refused.
    #[must_use]
    pub const fn essential() -> &'static [Self] {
        &[
            Self::ComposeHash,
            Self::ImagesPinned,
            Self::LicensedImagePresent,
            Self::QuoteSignature,
            Self::TcbStatus,
            Self::MrConfigId,
            Self::ChannelBound,
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

    /// The one-word transcript label: `passed`, `skipped` or `FAILED`.
    ///
    /// **This is a shell contract, not a display preference.**
    /// `verity-foundation/closed-loop/04-refuses-on-mismatch.sh` and
    /// `06-refuses-relayed-endpoint.sh` grep these exact words out of the runner's stdout. They are
    /// the only end-to-end gates over this crate, and until this function existed the words lived in
    /// an example binary where no test could reach them.
    ///
    /// `FAILED` is shouted and the other two are not, because a human skimming a transcript should
    /// see a refusal without reading.
    ///
    /// Matched exhaustively and **without a wildcard**, deliberately. `Outcome` is
    /// `#[non_exhaustive]`, but that only binds other crates — inside this one a new variant makes
    /// this match a compile error, which forces whoever adds it to choose a word rather than
    /// inherit a fallback. That is stronger than a wildcard, and the wildcard is what a downstream
    /// renderer such as the WASM bindings has to write instead.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Skipped(_) => "skipped",
            Self::Failed(_) => "FAILED",
        }
    }
}

/// One line of the runner's transcript, byte-identical to what `verify-attestation` prints.
///
/// # Why this is in the library
///
/// `verity-foundation/closed-loop/04-refuses-on-mismatch.sh` and `06-refuses-relayed-endpoint.sh`
/// are the only end-to-end gates over this crate, and both decide pass or fail by grepping this
/// exact layout out of the runner's stdout — `^  channel_bound +FAILED`, `^  compose_hash +FAILED`,
/// `^  <name> +passed`, `^  channel_bound +skipped`.
///
/// While the format lived inside `examples/verify-attestation.rs` no test could reach it, so the
/// two gates rested on an unasserted `println!`. This is the same split the WASM crate already made
/// when `compose_only_verdict` came out of `verify_compose_only`: logic welded to a boundary a test
/// cannot cross is logic nothing tests.
///
/// # Why it is not unified with `Verdict`'s `Display`
///
/// They render the same three outcomes differently, and that is on purpose.
/// [`Verdict`]'s `Display` is for a human reading a refusal; this one is parsed by shell. The
/// obvious future tidy-up — "why are there two renderers? unify them" — is green in every Rust test
/// and silently breaks both gates. `tests/transcript_contract.rs` asserts that they differ, so that
/// cleanup fails a test instead of passing a review.
///
/// # Format
///
/// ```
/// use verity_verifier::verdict::{transcript_line, Check, Outcome};
///
/// assert_eq!(
///     transcript_line(Check::ChannelBound, &Outcome::Passed),
///     "  channel_bound          passed",
/// );
/// ```
#[must_use]
pub fn transcript_line(check: Check, outcome: &Outcome) -> String {
    let label = outcome.label();
    // A pass has nothing to explain; the other two carry the reason in parentheses. Rendering all
    // three identically would report a *skipped* check as though it had concluded something — the
    // collapse this crate refuses everywhere else, and the one F-09's alert is built on.
    let rendered = match outcome {
        Outcome::Passed => label.to_owned(),
        Outcome::Failed(why) | Outcome::Skipped(why) => format!("{label} ({why})"),
    };
    // The literal space after `{:<22}` is what guarantees the scripts' `+` always has something to
    // match, including for `licensed_image_present`, which is exactly 22 characters and so consumes
    // the whole padding. The padding itself is alignment for a human reader — do not remove either
    // and assume the other covers it.
    format!("  {:<22} {rendered}", check.name())
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
    #[must_use]
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

/// A verdict in which every essential check ran and passed.
///
/// # Why this type exists
///
/// [`Verdict::is_trustworthy`] is a method a caller has to remember to call, and then remember to
/// act on. The 2026-08-09 review's finding was that the crate's `VerifiedCompose` /
/// `ChannelBinding` discipline — *one constructor, and it performs the check* — stopped at the
/// verdict, so invariant I1 rested on every agent author writing
/// `if !verdict.is_trustworthy() { return }`. **A verdict that can be ignored is a verdict that
/// will be.**
///
/// So this applies the same discipline one layer out. The only constructor is
/// [`TrustworthyVerdict::check`]; holding one is evidence the verdict was judged, and
/// [`crate::connect::VerifiedClient`] cannot be built without one.
///
/// # Ungated on purpose
///
/// It sits here rather than in `connect` so that callers of raw [`crate::verify::verify`] get the
/// same affordance without a TCP stack, and so the WASM bindings can adopt it later without a
/// feature. It adds no dependency.
///
/// # What it does not establish
///
/// That the evidence came from the connection you are using. Every essential check passing is a
/// statement about the inputs it was given; [`crate::connect::connect_verified`] is what makes
/// those inputs come from a handshake it performed itself.
#[derive(Debug, Clone)]
pub struct TrustworthyVerdict(Verdict);

impl TrustworthyVerdict {
    /// Judge a verdict, and return it wrapped only if every essential check ran and passed.
    ///
    /// # Errors
    ///
    /// Returns the verdict **back, unchanged**, when any essential check did not pass. Returned
    /// rather than discarded because a refusal a caller cannot explain is a refusal they will
    /// eventually route around: [`Verdict::failures`] and [`Verdict::unrun_essentials`] are how
    /// they tell a misconfiguration from an attack, and `Display` renders the whole transcript.
    ///
    /// # Examples
    ///
    /// ```
    /// use verity_verifier::verdict::{Check, Outcome, TrustworthyVerdict, Verdict};
    ///
    /// let empty = Verdict::new();
    /// // Nothing ran, so nothing passed — and the verdict comes back for rendering.
    /// let returned = TrustworthyVerdict::check(empty).expect_err("no check ran");
    /// assert_eq!(returned.unrun_essentials(), Check::essential());
    /// # let _ = Outcome::Passed;
    /// ```
    pub fn check(verdict: Verdict) -> Result<Self, Verdict> {
        // `is_trustworthy` rather than a re-implementation, so there is exactly one definition of
        // "every essential check ran and passed" in the crate. A second one here would be a place
        // for the two to drift, and the drift would be invisible: both would keep returning a
        // boolean that looks right.
        if verdict.is_trustworthy() {
            Ok(Self(verdict))
        } else {
            Err(verdict)
        }
    }

    /// The verdict, which by construction is trustworthy.
    ///
    /// Still the full transcript rather than a boolean: ADR 0014 requires a verdict to carry which
    /// checks ran, and that obligation does not lapse because the answer was yes.
    #[must_use]
    pub const fn verdict(&self) -> &Verdict {
        &self.0
    }

    /// Unwrap to the underlying verdict.
    ///
    /// The one-way door: a `Verdict` can be turned into a `TrustworthyVerdict` only through
    /// [`TrustworthyVerdict::check`], while going the other way is free. That asymmetry is the
    /// point — it is what makes holding the wrapper mean something.
    #[must_use]
    pub fn into_verdict(self) -> Verdict {
        self.0
    }
}

impl fmt::Display for TrustworthyVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
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

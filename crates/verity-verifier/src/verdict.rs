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
    ///
    /// **This is also why `ChannelBound` never becomes [`Outcome::Indeterminate`].** MA-6 adds a
    /// remedy-bearing outcome for "a named action would let this same call conclude" — but no such
    /// action exists for `ChannelBound` on a call with no connection: the paragraph above already
    /// says its absence is never legitimate for a verdict about an endpoint, so it stays `Skipped`,
    /// cited here as the one exception to the rule at [`crate::verify`]'s module doc.
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

    /// Every check this verifier can perform, in a stable order.
    ///
    /// Hand-maintained rather than derived — `Check` is `#[non_exhaustive]`, so a downstream caller
    /// genuinely cannot enumerate it any other way, and Rust has no dependency-free way to do this
    /// for them. Staleness here weakens *test coverage* (a new variant untested by anything that
    /// loops over `ALL`), never the crate's own correctness: [`disposition`]'s private `Weight`
    /// match has no wildcard, so a new variant is a compile error there regardless of whether this
    /// list was updated.
    ///
    /// **Do not refactor `tests/verdict_semantics.rs`'s hand-enumerated check names onto this.**
    /// That test's whole point is that a rename has to confront string literals; looping over `ALL`
    /// and calling [`Check::name`] would assert `name() == name()`.
    pub const ALL: &'static [Self] = &[
        Self::ComposeHash,
        Self::ImagesPinned,
        Self::LicensedImagePresent,
        Self::QuoteSignature,
        Self::TcbStatus,
        Self::MrConfigId,
        Self::BootMeasurements,
        Self::ChannelBound,
    ];
}

impl fmt::Display for Check {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Why a check could not be established, as a class the caller can act on.
///
/// The remedy in typed form. The `detail` string beside it on [`Outcome::Indeterminate`] is for
/// humans; **this** is what [`disposition`] reads, so a caller never has to parse prose to decide
/// what to do.
///
/// # The rule that decides which cause applies, and when a check is `Indeterminate` at all
///
/// A check is `Indeterminate` when it did not conclude, and a named action available to whoever
/// operates the caller would let **this same call** conclude it on a later attempt: retrieve the
/// document again, supply a reference, or run a verifier version that supports this construction.
/// Contrast [`Outcome::Skipped`], which is what remains once no such action applies to *this*
/// verdict — moot because a prior check already refused, or this construction structurally cannot
/// perform it, or (the one cited exception, [`Check::essential`]'s doc on `ChannelBound`) the
/// caller declined for a reason with no remedy in this verdict at all.
///
/// "This same call" is load-bearing rather than a version/build-target guess: it is what keeps a
/// browser binding's collateral-less checks `Skipped` (no later call of that function, with no
/// collateral parameter, concludes them — reaching the Rust API is a *different* call) while
/// keeping a missing boot reference or an unsupported `MR-CONFIG-ID` construction `Indeterminate`
/// (the same function, given the missing input or an updated build, does conclude).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Unestablished {
    /// Evidence could not be retrieved. A later attempt, possibly from another source, may
    /// succeed.
    RetrievalFailed,
    /// No reference was available to compare against.
    ReferenceUnavailable,
    /// This build cannot judge it — a recognised construction, format, or signature this verifier
    /// does not yet handle. A build that can exists or can be made; running it is the action
    /// available here. Not "an unrecognised input could not be accounted for" — that has no remedy
    /// to name and stays [`Outcome::Failed`].
    VerifierCannotJudge,
}

/// What a single check concluded.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Outcome {
    /// Performed, and passed.
    Passed,
    /// Performed, and failed. The string says how.
    ///
    /// **Reached a refusal** — same inputs, same refusal. This is the discriminator against
    /// [`Outcome::Indeterminate`]: nothing about a later attempt of this call would change the
    /// answer.
    Failed(String),
    /// Not performed, and there is nothing to tell the caller to do about it.
    ///
    /// A prior check already refused and made this one moot, or this construction structurally
    /// cannot perform it, or (one cited exception: `ChannelBound`, see [`Check::essential`]'s doc)
    /// the caller declined for a reason no remedy in this verdict addresses. Distinct from
    /// [`Outcome::Indeterminate`], which names a remedy — `Skipped` is what remains once none
    /// applies to *this* verdict.
    ///
    /// Skipping is visible rather than silent: a check nobody ran is not a check that passed.
    Skipped(String),
    /// Attempted, and could not conclude.
    ///
    /// Distinct from both [`Outcome::Failed`] (a refusal — same inputs, same answer) and
    /// [`Outcome::Skipped`] (nothing to do). A named action available to whoever operates the
    /// caller — see [`Unestablished`] — would let this same call conclude on a later attempt.
    ///
    /// **This changes what the caller does about a refusal, never whether they may proceed.**
    /// Proceeding is governed by [`TrustworthyVerdict`] and nothing else; `Indeterminate` on an
    /// essential check makes a verdict untrustworthy exactly as `Failed` or `Skipped` would, by
    /// construction — a property that was not established is a property this verdict cannot claim.
    Indeterminate {
        /// The remedy class, in typed form — what [`disposition`] reads. Match this, never the
        /// detail string.
        cause: Unestablished,
        /// For humans. A caller matching on this string's content is the failure this outcome
        /// exists to prevent — branch on `cause` instead.
        detail: String,
    },
}

impl Outcome {
    /// Attempted, and could not conclude. See [`Outcome::Indeterminate`] and [`Unestablished`].
    #[must_use]
    pub fn unestablished(cause: Unestablished, detail: impl Into<String>) -> Self {
        Self::Indeterminate {
            cause,
            detail: detail.into(),
        }
    }

    /// The remedy class, when this outcome is [`Outcome::Indeterminate`]. `None` otherwise.
    #[must_use]
    pub const fn cause(&self) -> Option<Unestablished> {
        match self {
            Self::Indeterminate { cause, .. } => Some(*cause),
            Self::Passed | Self::Failed(_) | Self::Skipped(_) => None,
        }
    }

    /// Whether this outcome is a pass.
    ///
    /// **`Indeterminate` is not a pass** — deliberately, and this is where that is decided: `matches!`
    /// answers `false` for every variant but `Passed`, so a check that could not conclude never
    /// reads as having concluded successfully. `tests/verdict_semantics.rs` pins it.
    #[must_use]
    pub const fn passed(&self) -> bool {
        matches!(self, Self::Passed)
    }

    /// The one-word transcript label: `passed`, `skipped`, `FAILED` or `indeterminate`.
    ///
    /// **This is a shell contract, not a display preference.**
    /// `verity-foundation/closed-loop/04-refuses-on-mismatch.sh` and
    /// `06-refuses-relayed-endpoint.sh` grep these exact words out of the runner's stdout. They are
    /// the only end-to-end gates over this crate, and until this function existed the words lived in
    /// an example binary where no test could reach them.
    ///
    /// `FAILED` is shouted and the others are not. `indeterminate` is lower case *deliberately*: it
    /// usually means an outage, and shouting it would train an operator to read infrastructure
    /// faults as attacks — the sensitisation this outcome exists to prevent.
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
            Self::Indeterminate { .. } => "indeterminate",
        }
    }
}

/// What a caller should do about one check.
///
/// **This is advice about a check, never permission to proceed.** Whether an endpoint may be used
/// is answered by [`TrustworthyVerdict`] and by nothing else — including this. A `RetryRetrieval`
/// on an essential check means "retry, and until it succeeds you still have no verdict".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Disposition {
    /// The check ran and passed. Nothing to do.
    Satisfied,
    /// Refuse. Retrying cannot change it and no remedy applies.
    ///
    /// **Can appear on a verdict that is still trustworthy.** `(BootMeasurements, Failed)` still
    /// dispositions to `Refuse` — `BootMeasurements` is advisory, so the mismatch does not sink
    /// `is_trustworthy()`, but a measured discrepancy is a refusal whatever else passed. This is
    /// deliberate asymmetry, not a bug: dispositions never override [`TrustworthyVerdict`] and never
    /// substitute for it. Read the trust boolean for "may I proceed" and dispositions for "what do I
    /// do about a refusal I already have" — folding a `Refuse` here into "therefore do not proceed"
    /// reintroduces the single actionable value this type deliberately does not offer (see
    /// [`disposition`]'s rejection of an aggregate).
    Refuse,
    /// Evidence could not be retrieved. Try again, or try another source.
    RetryRetrieval,
    /// This build cannot judge it. Use one that can.
    UpdateVerifier,
    /// No reference was available to compare against. Obtain one.
    UpdateReference,
    /// Not established, and the verdict does not depend on it.
    ProceedNonEssential,
}

impl Disposition {
    /// A stable identifier, for telemetry and the JavaScript surface.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Satisfied => "satisfied",
            Self::Refuse => "refuse",
            Self::RetryRetrieval => "retry_retrieval",
            Self::UpdateVerifier => "update_verifier",
            Self::UpdateReference => "update_reference",
            Self::ProceedNonEssential => "proceed_non_essential",
        }
    }
}

impl fmt::Display for Disposition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// How much a check's outcome matters to the verdict.
///
/// Private: this is the *only* thing [`disposition`] needs from a [`Check`], and exposing it would
/// create a second public spelling of [`Check::essential`] — two definitions of "essential" that
/// can drift apart, which is the defect [`TrustworthyVerdict::check`] avoids by calling
/// [`Verdict::is_trustworthy`] rather than re-implementing it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Weight {
    Essential,
    Advisory,
}

/// Deliberately **not** derived from `Check::essential().contains(check)`: a `contains` lookup
/// would silently classify a *new* `Check` variant as advisory, the fail-open default. Matched
/// exhaustively and without a wildcard instead, for the same reason [`Outcome::label`] is — a new
/// variant is a compile error here, forcing whoever adds it to choose. `tests/verdict_semantics.rs`
/// asserts this agrees with [`Check::essential`] for every check, so the duplication cannot drift
/// unnoticed.
const fn weight(check: Check) -> Weight {
    match check {
        Check::ComposeHash
        | Check::ImagesPinned
        | Check::LicensedImagePresent
        | Check::QuoteSignature
        | Check::TcbStatus
        | Check::MrConfigId
        | Check::ChannelBound => Weight::Essential,
        Check::BootMeasurements => Weight::Advisory,
    }
}

/// What to do about one check's outcome.
///
/// A property of the *pair*, like [`transcript_line`]: the same [`Outcome`] means something
/// different on an essential check than on an advisory one — `(BootMeasurements, Skipped)` is
/// `ProceedNonEssential`, but the identical outcome on any other check is `Refuse` — so neither
/// [`Check`] nor [`Outcome`] alone can answer it. Free rather than a method on either type, for the
/// same reason.
///
/// The mapping is exhaustive and total over every `(Check, Outcome)` shape; `tests/verdict_semantics.rs`
/// asserts every cell against a literal, not a re-derivation, so a change to the mapping has to
/// change the test too rather than pass silently.
///
/// **Rejected: a single aggregate over a whole verdict.** Remedies are a set, not a lattice — a
/// verdict can need a verifier update *and* a retrieval retry, and folding them into one value picks
/// one and hides the other. A single actionable value on `Verdict` is also one rename away from
/// becoming the thing callers branch on instead of [`TrustworthyVerdict`], reintroducing the
/// ignorable verdict that type exists to close.
#[must_use]
pub fn disposition(check: Check, outcome: &Outcome) -> Disposition {
    match outcome {
        Outcome::Passed => Disposition::Satisfied,
        Outcome::Failed(_) => Disposition::Refuse,
        Outcome::Skipped(_) => match weight(check) {
            Weight::Essential => Disposition::Refuse,
            Weight::Advisory => Disposition::ProceedNonEssential,
        },
        Outcome::Indeterminate { cause, .. } => match cause {
            Unestablished::RetrievalFailed => Disposition::RetryRetrieval,
            Unestablished::ReferenceUnavailable => Disposition::UpdateReference,
            Unestablished::VerifierCannotJudge => Disposition::UpdateVerifier,
        },
    }
}

impl Unestablished {
    /// The remedy this cause calls for, independent of any check.
    ///
    /// Lets a caller whose retrieval failed report a refusal **with a typed disposition** and no
    /// verdict at all — the shape [`crate::connect::Refusal`] already uses for
    /// [`crate::connect::CollateralUnavailable`]. Defined here, in the ungated `verdict` module
    /// rather than beside `verify`, so a `default-features = false` embedder building for `wasm32`
    /// — the embedder most likely to be hand-implementing [`crate::compose::Source`] — can reach it
    /// without the `attest` feature that gates `verify`.
    #[must_use]
    pub const fn disposition(self) -> Disposition {
        match self {
            Self::RetrievalFailed => Disposition::RetryRetrieval,
            Self::ReferenceUnavailable => Disposition::UpdateReference,
            Self::VerifierCannotJudge => Disposition::UpdateVerifier,
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
        Outcome::Failed(why)
        | Outcome::Skipped(why)
        | Outcome::Indeterminate { detail: why, .. } => {
            format!("{label} ({why})")
        }
    };
    // The literal space after `{:<22}` is what guarantees the scripts' `+` always has something to
    // match, including for `licensed_image_present`, which is exactly 22 characters and so consumes
    // the whole padding. The padding itself is alignment for a human reader — do not remove either
    // and assume the other covers it.
    format!("  {:<22} {rendered}", check.name())
}

/// Intel's TCB statement about the platform a verdict is about.
///
/// Verdict-level provenance, like [`Verdict::verifier_version`] and
/// [`Verdict::reference_data_date`] — *not* a check outcome. It is present whenever a signature
/// verified, on a passing `UpToDate` as well as on a refused degraded status, so a reader can
/// always see which status was judged and any advisories Intel published. It is descriptive:
/// [`Verdict::is_trustworthy`] never reads it — the enforcement lives in `is_tcb_acceptable`,
/// which runs (via `attest::verify_quote`) before this is ever recorded.
///
/// **No `#[non_exhaustive]`.** Both fields are private with no public constructor but
/// `AttestedTcb::new`, so the attribute would add nothing here: it exists to stop a
/// struct-literal or exhaustive-destructure from another crate, and private fields already do
/// that. Contrast `connect::CollateralUnavailable`, which needs it because it has a public field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestedTcb {
    status: String,
    advisory_ids: Vec<String>,
}

#[cfg(feature = "attest")]
impl AttestedTcb {
    /// Construct from a verified quote's status.
    ///
    /// `pub(crate)` on purpose: this type is *read* by external callers off a [`Verdict`], never
    /// built by them. The only production caller is `verify::record_attestation`, mapping an
    /// `attest::Attested` or `attest::AttestError::TcbUnacceptable` across the module boundary —
    /// `verdict` stays free of the `attest` feature, so it cannot name those types itself and the
    /// conversion happens on the gated side instead. Keeping the constructor crate-internal
    /// preserves "a verdict's TCB statement comes from the verifier, not from a caller", the same
    /// posture as VA-1's removal of the caller-configurable TCB policy type.
    ///
    /// `#[cfg(feature = "attest")]`, unlike the accessors below: nothing can construct an
    /// `AttestedTcb` without a signature to attest in the first place, so without `attest` this
    /// constructor is unreachable dead code rather than a real capability being hidden — `Verdict`
    /// itself, and reading a `None` off `attested_tcb()`, both stay available on every target.
    #[must_use]
    pub(crate) fn new(status: String, advisory_ids: Vec<String>) -> Self {
        Self {
            status,
            advisory_ids,
        }
    }
}

impl AttestedTcb {
    /// Intel's TCB status for this platform, e.g. `UpToDate`.
    #[must_use]
    pub fn status(&self) -> &str {
        &self.status
    }

    /// Advisory identifiers Intel associates with this platform's TCB level.
    #[must_use]
    pub fn advisory_ids(&self) -> &[String] {
        &self.advisory_ids
    }

    /// Whether Intel considers this platform up to date. The property the verifier enforces.
    #[must_use]
    pub fn is_up_to_date(&self) -> bool {
        is_tcb_acceptable(&self.status)
    }
}

/// The one enforced rule: only `UpToDate` is acceptable.
///
/// [ADR 0014] decision 2 makes TCB enforcement mandatory and not a caller's choice — "no option, no
/// override, no strict mode that can be left off" — so there is exactly one definition of the rule
/// in the crate, called from both sides of the `attest`/`verdict` boundary: `attest::verify_quote`
/// enforces it before an `Attested` can exist at all, and `AttestedTcb::is_up_to_date` reports it
/// afterward on whatever was recorded. Defined here, in the ungated module, so `attest` (gated) can
/// depend on it without `verdict` ever depending back on `attest` — the same direction
/// `AttestedTcb::new` already established.
///
/// `pub(crate)`: nothing outside the crate needs the raw predicate, only the two methods that read
/// off it. Case-insensitive: Intel's casing is not something a caller should have to match exactly.
///
/// [ADR 0014]: https://github.com/ithaka-dev/verity-foundation/blob/main/docs/decisions/0014-verifier-update-discipline.md
pub(crate) fn is_tcb_acceptable(status: &str) -> bool {
    status.eq_ignore_ascii_case("UpToDate")
}

#[cfg(test)]
mod tcb_acceptance_tests {
    //! The single definition of TCB acceptance, tested once here rather than once per caller.
    //! `attest.rs` no longer has its own copy to test — see VA-1 review finding 2.

    use super::is_tcb_acceptable;

    #[test]
    fn only_up_to_date_is_acceptable() {
        for accepted in ["UpToDate", "uptodate", "UPTODATE", "uPtOdAtE"] {
            assert!(is_tcb_acceptable(accepted), "{accepted} must be accepted");
        }

        // Every status Intel actually emits other than UpToDate, plus unrecognised input. Each
        // means either a known platform weakness or an unknown answer this crate cannot reason
        // about — and accepting either silently is the outcome ADR 0014 forbids.
        for degraded in [
            "OutOfDate",
            "OutOfDateConfigurationNeeded",
            "SWHardeningNeeded",
            "ConfigurationNeeded",
            "ConfigurationAndSWHardeningNeeded",
            "Revoked",
            "",
            "Fine",
            "UpToDateish",
            "🙂",
        ] {
            assert!(!is_tcb_acceptable(degraded), "{degraded} must be refused");
        }
    }
}

/// The result of verifying an endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    verifier_version: &'static str,
    reference_data_date: &'static str,
    results: Vec<(Check, Outcome)>,
    /// Intel's TCB statement, when a signature verified. `None` on every path that verified none —
    /// including the WASM `compose_only_verdict` path, which has no collateral at all.
    tcb: Option<AttestedTcb>,
}

impl Verdict {
    /// Start an empty verdict.
    #[must_use]
    pub fn new() -> Self {
        Self {
            verifier_version: VERIFIER_VERSION,
            reference_data_date: crate::reference::REFERENCE_DATA_DATE,
            results: Vec::new(),
            tcb: None,
        }
    }

    /// Record a check's outcome.
    #[must_use]
    pub fn record(mut self, check: Check, outcome: Outcome) -> Self {
        self.results.push((check, outcome));
        self
    }

    /// Intel's TCB statement, when a signature verified.
    ///
    /// `None` when it did not, or when this construction cannot verify one at all — the WASM
    /// `compose_only_verdict` path has no collateral and no `attest` feature.
    #[must_use]
    pub fn attested_tcb(&self) -> Option<&AttestedTcb> {
        self.tcb.as_ref()
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
    ///
    /// **Non-pass dominates.** A check recorded more than once reports a non-`Passed` record in
    /// preference to a `Passed` one, so a later `Failed`/`Skipped`/`Indeterminate` can never be
    /// masked by an earlier `Passed`. This is what keeps `is_trustworthy()` coherent with
    /// `failures()` and with an essential `Indeterminate` (ADR 0035 §2): a verdict cannot read
    /// trustworthy while any essential also carries a refusal or an unestablished outcome.
    /// Order-independent for the trust question — any non-pass sinks it regardless of order — and
    /// inert for every single-record path, which is every production and wasm builder. It is
    /// **not** order-independent for the specific value reported when a check carries two or more
    /// *different* non-pass records (e.g. `Indeterminate` then `Skipped` returns the first of the
    /// two); that case is unreachable on any real path — every `Check` is recorded exactly once —
    /// and the trust answer is identical either way.
    #[must_use]
    pub fn outcome(&self, check: Check) -> Option<&Outcome> {
        let mut passed: Option<&Outcome> = None;
        for (c, o) in &self.results {
            if *c != check {
                continue;
            }
            if !o.passed() {
                return Some(o); // first non-pass dominates
            }
            passed.get_or_insert(o); // hold the pass only until a non-pass appears
        }
        passed
    }

    /// Checks that failed.
    ///
    /// **Deliberately excludes `Indeterminate`.** A check that could not conclude did not reach a
    /// refusal, so listing it here would report something that did not happen. That is the correct
    /// reading, but it is not the one the wildcard below enforces — a new variant would fall into
    /// it silently, so `tests/verdict_semantics.rs` pins this behaviour with a test written from the
    /// failure: adding an arm for `Indeterminate` here and watching the assertion go red.
    #[must_use]
    pub fn failures(&self) -> Vec<(Check, &str)> {
        self.results
            .iter()
            .filter_map(|(c, o)| match o {
                Outcome::Failed(why) => Some((*c, why.as_str())),
                Outcome::Passed | Outcome::Skipped(_) | Outcome::Indeterminate { .. } => None,
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

    /// What to do about one check. `None` when it was never recorded.
    #[must_use]
    pub fn disposition(&self, check: Check) -> Option<Disposition> {
        self.outcome(check)
            .map(|outcome| disposition(check, outcome))
    }

    /// Every check and what to do about it, in the order performed.
    ///
    /// Deliberately not folded into one aggregate value: remedies are a *set*, not a lattice — a
    /// verdict can need a verifier update **and** a retrieval retry, and collapsing them would hide
    /// one. See [`disposition`]'s rejection of `Verdict::overall_disposition`.
    #[must_use]
    pub fn dispositions(&self) -> Vec<(Check, Disposition)> {
        self.results
            .iter()
            .map(|(c, o)| (*c, disposition(*c, o)))
            .collect()
    }
}

#[cfg(feature = "attest")]
impl Verdict {
    /// Record the attested TCB statement. Builder-style, like [`Verdict::record`].
    ///
    /// `pub(crate)`, unlike [`Verdict::record`]: `Check`/[`Outcome`] are fully public and
    /// constructible outside the crate (the wasm crate's `compose_only_verdict` calls `record`
    /// cross-crate), so keeping that one `pub` grants nothing new. `AttestedTcb` has no public
    /// constructor at all — only `AttestedTcb::new`, itself `pub(crate)` — so no external caller
    /// could pass a meaningful argument here regardless. Matches the "a verdict's TCB statement
    /// comes from the verifier, not a caller" posture `AttestedTcb::new`'s own doc states.
    ///
    /// `#[cfg(feature = "attest")]`, like `AttestedTcb::new`: the only production caller,
    /// `verify::record_attestation`, is itself gated behind `attest`, so without it this method is
    /// unreachable dead code rather than a real capability being hidden — [`Verdict::attested_tcb`]
    /// stays available on every target, correctly returning `None` where nothing was attested.
    #[must_use]
    pub(crate) fn record_attested_tcb(mut self, tcb: AttestedTcb) -> Self {
        self.tcb = Some(tcb);
        self
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
/// # What holding one proves — and only this
///
/// That the [`Verdict`] it wraps records [`Outcome::Passed`] for every essential check
/// ([`Check::essential`]). It is a judgment about a transcript, nothing more.
///
/// # What it does NOT prove
///
/// - **That any check was actually performed against real evidence.** [`Verdict::new`] and
///   [`Verdict::record`] are public and ungated — deliberately, so the WASM bindings can assemble
///   a `Verdict` check-by-check across the crate boundary. A caller can equally well hand-assemble
///   a `Verdict` of all-`Passed` records and wrap it; the wrapper reports what the transcript says,
///   and the transcript is only as honest as whoever built it.
/// - **That the evidence was genuine even when the transcript is genuine.** [`crate::verify::verify`]
///   performs no I/O and trusts the `Evidence` it is handed, including the caller-supplied
///   `peer_certificate`. A caller who feeds it a recorded quote plus a matching certificate gets a
///   real, honestly-computed, all-`Passed` verdict about a connection they are not using. A
///   `TrustworthyVerdict` minted from that verdict is indistinguishable, by anything this type
///   exposes, from one about a live endpoint — hand-assembly is not the only route to a forged
///   verdict, and this route runs through the crate's own, correctly-functioning checks.
/// - **That the evidence came from a live connection, or from any connection at all.** A verdict
///   about recorded evidence and a verdict about an endpoint you are talking to right now look
///   identical here.
/// - **That the inputs were not chosen by the caller.**
///
/// The only thing that binds a verdict to a connection the caller actually made is
/// [`crate::connect::connect_verified`] / [`crate::connect::VerifiedClient`], whose constructor is
/// private for exactly this reason — see its own doc. Treat a bare `TrustworthyVerdict` from an
/// untrusted source as an unverified claim about a transcript; require a `VerifiedClient` wherever
/// provenance matters.
#[derive(Debug, Clone)]
pub struct TrustworthyVerdict(Verdict);

impl TrustworthyVerdict {
    /// Judge a verdict, and return it wrapped only if every essential check ran and passed.
    ///
    /// **This judges a transcript; it does not authenticate the transcript's origin.** See
    /// [`TrustworthyVerdict`]'s "What it does NOT prove" — a hand-assembled or replayed-evidence
    /// `Verdict` passes this exactly as a genuine one does. Only [`crate::connect::VerifiedClient`]
    /// establishes that the evidence came from a connection the caller made.
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
        // Human `Display` only — not the shell contract `transcript_line` is. Printed once, next to
        // the version/date header rather than inside the per-check loop below, because it is
        // provenance about the platform rather than one more check's outcome.
        if let Some(tcb) = &self.tcb {
            let advisories = if tcb.advisory_ids.is_empty() {
                String::new()
            } else {
                format!(" (advisories: {})", tcb.advisory_ids.join(", "))
            };
            writeln!(f, "  platform TCB: {}{advisories}", tcb.status)?;
        }
        // 14-column label field, widened from 8 to fit `indeterminate` (13 characters) with at
        // least one space of separation — the same guarantee `transcript_line`'s `{:<22}` makes for
        // check names. A shorter word just for `Display` would put a fifth spelling into a
        // vocabulary this change exists to reduce to four, at the one surface a human reads during
        // a refusal.
        for (check, outcome) in &self.results {
            match outcome {
                Outcome::Passed => writeln!(f, "  {:<14}{check}", "pass")?,
                Outcome::Failed(why) => writeln!(f, "  {:<14}{check}: {why}", "FAIL")?,
                Outcome::Skipped(why) => writeln!(f, "  {:<14}{check}: {why}", "skipped")?,
                Outcome::Indeterminate { detail, .. } => {
                    writeln!(f, "  {:<14}{check}: {detail}", "indeterminate")?;
                }
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

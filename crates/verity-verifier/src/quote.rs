//! TDX quote parsing.
//!
//! Parses the structure only — this module extracts measurements and makes no judgement about
//! them, and performs **no signature verification**. A successfully parsed quote is not a
//! trustworthy one. See [`crate`] for where verification happens.

use core::fmt;

/// Length of a TDX measurement register, in bytes.
pub const MEASUREMENT_LEN: usize = 48;

/// Length of the TD report's `report_data` field, in bytes.
pub const REPORT_DATA_LEN: usize = 64;

/// Quote header length, in bytes.
const HEADER_LEN: usize = 48;

/// TD report body length, in bytes.
const REPORT_LEN: usize = 584;

/// Offset of the `signature_data_len` field: immediately after the report body.
const OFF_SIG_LEN: usize = HEADER_LEN + REPORT_LEN;

/// Minimum length to read the structure through `signature_data_len`.
///
/// The measured fields end before this, but a quote whose signature section has been truncated
/// away is malformed and should be refused here rather than deferred to signature verification.
/// Accepting it would mean the parser reports success on input that can never verify.
const MIN_QUOTE_LEN: usize = OFF_SIG_LEN + 4;

/// `tee_type` value identifying Intel TDX.
const TEE_TYPE_TDX: u32 = 0x81;

// Offsets within the TD report body. The report begins at `HEADER_LEN` in the quote.
const OFF_MRTD: usize = 136;
const OFF_MRCONFIGID: usize = 184;
const OFF_MROWNER: usize = 232;
const OFF_MROWNERCONFIG: usize = 280;
const OFF_RTMR0: usize = 328;
const OFF_RTMR1: usize = 376;
const OFF_RTMR2: usize = 424;
const OFF_RTMR3: usize = 472;
const OFF_REPORTDATA: usize = 520;

// The offsets above are one contiguous run, so pin them as a chain rather than as nine independent
// literals. A single mistyped digit then fails to compile instead of silently reading a neighbouring
// register — and a register read at the wrong offset fails *closed*, which is safe but produces a
// mismatch no error message can explain.
const _: () = assert!(OFF_MRTD + MEASUREMENT_LEN == OFF_MRCONFIGID);
const _: () = assert!(OFF_MRCONFIGID + MEASUREMENT_LEN == OFF_MROWNER);
const _: () = assert!(OFF_MROWNER + MEASUREMENT_LEN == OFF_MROWNERCONFIG);
const _: () = assert!(OFF_MROWNERCONFIG + MEASUREMENT_LEN == OFF_RTMR0);
const _: () = assert!(OFF_RTMR0 + MEASUREMENT_LEN == OFF_RTMR1);
const _: () = assert!(OFF_RTMR1 + MEASUREMENT_LEN == OFF_RTMR2);
const _: () = assert!(OFF_RTMR2 + MEASUREMENT_LEN == OFF_RTMR3);
const _: () = assert!(OFF_RTMR3 + MEASUREMENT_LEN == OFF_REPORTDATA);

// `report_data` ends the **v1.0** report body this crate parses, and only that one.
//
// Do not read this as "report_data is the last field of a TD report". In the TDX 1.5 body — 648
// bytes, reached through quote v5 — `report_data` stays at offset 520 and `tee_tcb_svn2` and
// `mrservicetd` are appended *after* it. Whoever adds v5 support will trip this assertion, and the
// right response is to give v5 its own `REPORT_LEN`, not to move `OFF_REPORTDATA`. Quote v5 is
// rejected in `parse` before any of this is reached, so today the narrow reading is the true one.
const _: () = assert!(OFF_REPORTDATA + REPORT_DATA_LEN == REPORT_LEN);

/// A 48-byte TDX measurement.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Measurement([u8; MEASUREMENT_LEN]);

impl Measurement {
    /// From raw bytes.
    ///
    /// Public so that a *reference* measurement can be constructed for comparison. Constructing
    /// one does not assert it came from a quote — only [`Quote::parse`] does that.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; MEASUREMENT_LEN]) -> Self {
        Self(bytes)
    }

    /// The raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; MEASUREMENT_LEN] {
        &self.0
    }

    /// True when every byte is zero.
    ///
    /// Worth checking explicitly: an unpopulated field is all-zero, and treating that as a
    /// legitimate value would compare successfully against a reference someone also left empty.
    ///
    /// `MROWNER` and `MROWNERCONFIG` are unpopulated on dstack 0.5.7, so a comparison against
    /// either is a comparison against nothing.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|b| *b == 0)
    }
}

/// The TD report's 64-byte `report_data` — what the enclave asked the hardware to sign *for it*.
///
/// Every other field in a quote is measured by the platform. This one is supplied by the workload,
/// which is what makes it the only place a quote can be tied to something outside itself. dStack's
/// RA-TLS puts a commitment to the TLS key here, so that a quote proves something about a *live
/// connection* rather than merely about a machine.
///
/// **Parsing this is not checking it.** Reading the field establishes nothing on its own — the
/// comparison against the connection's certificate is what makes the quote non-detachable, and
/// until that check exists a populated `report_data` is decoration. See [`crate`].
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReportData([u8; REPORT_DATA_LEN]);

impl ReportData {
    /// From raw bytes.
    ///
    /// Public so an *expected* commitment can be constructed for comparison. Constructing one does
    /// not assert it came from a quote — only [`Quote::parse`] does that.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; REPORT_DATA_LEN]) -> Self {
        Self(bytes)
    }

    /// The raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; REPORT_DATA_LEN] {
        &self.0
    }

    /// True when every byte is zero.
    ///
    /// Worth checking explicitly, and more so here than for a measurement. A workload is free to
    /// leave `report_data` empty — a quote requested for some purpose other than RA-TLS carries
    /// exactly this — and an all-zero field would compare equal to an expected value someone also
    /// left empty. A channel-binding check must treat "the enclave committed to nothing" as a
    /// refusal to establish the binding, never as a binding to nothing.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|b| *b == 0)
    }
}

impl fmt::Debug for ReportData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Display for ReportData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl fmt::Debug for Measurement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Display for Measurement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// Why a quote could not be parsed.
///
/// Parsing refuses rather than guessing. A quote that is too short, or that claims a TEE type
/// this crate does not understand, produces an error — never a partially populated result.
/// New variants will be added as verification grows — tag validation, signature-chain failures —
/// so this enum is `#[non_exhaustive]`. Downstream `match` arms need a wildcard, and adding a
/// variant stays a minor version rather than a breaking one. That matters more here than usual:
/// [ADR 0014] makes version discipline a first-class concern for a crate embedded in agents that
/// cannot easily be updated.
///
/// [ADR 0014]: https://github.com/ithaka-dev/verity-foundation/blob/main/docs/decisions/0014-verifier-update-discipline.md
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ParseError {
    /// The input is shorter than a header plus report body.
    #[error("quote too short: {got} bytes, need at least {need}")]
    TooShort {
        /// Bytes supplied.
        got: usize,
        /// Bytes required.
        need: usize,
    },
    /// The quote structure version is not one this crate parses.
    #[error("unsupported quote version {0}")]
    UnsupportedVersion(u16),
    /// The `tee_type` field is not TDX.
    #[error("tee_type 0x{0:x} is not TDX (0x81)")]
    NotTdx(u32),
    /// The signature section is shorter than the quote's own `signature_data_len` declares.
    ///
    /// Such a quote can never verify, so it is refused at parse time rather than reported as a
    /// successful parse that fails later.
    #[error("signature section truncated: {got} bytes, quote declares {declared}")]
    SignatureTruncated {
        /// Bytes supplied.
        got: usize,
        /// Bytes the quote declares it should have.
        declared: usize,
    },
    /// The quote declares a signature section too large to be real.
    ///
    /// Separate from [`Self::SignatureTruncated`] because the defect is different: the length
    /// field itself is implausible rather than the buffer being short. Reachable on 32-bit
    /// targets — `wasm32` among them, which this crate ships bindings for — where an
    /// attacker-supplied length near `u32::MAX` overflows a `usize`.
    #[error("declared signature length {declared} is implausible")]
    SignatureLengthImplausible {
        /// The length the quote declared.
        declared: u32,
    },
    /// The input was not valid hexadecimal.
    #[error("input is not valid hexadecimal")]
    InvalidHex,
}

/// The measured fields of a TDX quote.
///
/// `RTMR3` is parsed and exposed for diagnostics, but **must not be compared against a
/// reference** — it accumulates `app-id`, `instance-id` and `mr-kms`, and the last varies per
/// boot, so no stable reference value exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Quote {
    version: u16,
    mrtd: Measurement,
    mrconfigid: Measurement,
    mrowner: Measurement,
    mrownerconfig: Measurement,
    rtmr: [Measurement; 4],
    report_data: ReportData,
}

impl Quote {
    /// Parse a quote from raw bytes.
    ///
    /// # Examples
    ///
    /// A buffer too short to contain a header and report body is refused, and the error says how
    /// much was needed:
    ///
    /// ```
    /// use verity_verifier::quote::{ParseError, Quote};
    ///
    /// match Quote::parse(&[0u8; 16]) {
    ///     Err(ParseError::TooShort { got, need }) => {
    ///         assert_eq!(got, 16);
    ///         assert!(need > got);
    ///     }
    ///     other => panic!("expected TooShort, got {other:?}"),
    /// }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when the input is too short, has an unsupported structure version,
    /// or is not a TDX quote.
    pub fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        // Every read below goes through a fallible accessor. Nothing in this function may panic
        // on malformed input — a verifier that panics gets wrapped in catch-and-continue by
        // whoever embeds it, which reaches the same place as loosening a check.
        let too_short = |need: usize| ParseError::TooShort {
            got: bytes.len(),
            need,
        };

        let le_u16 = |off: usize| -> Result<u16, ParseError> {
            let s: [u8; 2] = bytes
                .get(off..off + 2)
                .ok_or_else(|| too_short(off + 2))?
                .try_into()
                .map_err(|_| too_short(off + 2))?;
            Ok(u16::from_le_bytes(s))
        };
        let le_u32 = |off: usize| -> Result<u32, ParseError> {
            let s: [u8; 4] = bytes
                .get(off..off + 4)
                .ok_or_else(|| too_short(off + 4))?
                .try_into()
                .map_err(|_| too_short(off + 4))?;
            Ok(u32::from_le_bytes(s))
        };

        // Length is checked before any field is interpreted. Reading a version out of a buffer
        // that is not a quote produces a confident, wrong answer — a caller handed 16 stray bytes
        // should be told the input is too short, not that it is "version 0".
        if bytes.len() < MIN_QUOTE_LEN {
            return Err(too_short(MIN_QUOTE_LEN));
        }

        // Header: version (2) | att_key_type (2) | tee_type (4) | ...
        let version = le_u16(0)?;
        if version != 4 {
            return Err(ParseError::UnsupportedVersion(version));
        }
        let tee_type = le_u32(4)?;
        if tee_type != TEE_TYPE_TDX {
            return Err(ParseError::NotTdx(tee_type));
        }

        // A quote missing its signature section can never verify, so refuse it here rather than
        // reporting a successful parse on input that is structurally incomplete.
        let sig_len_raw = le_u32(OFF_SIG_LEN)?;
        // usize is 32-bit on wasm32, so this addition genuinely can overflow there. Reporting it
        // as "too short, you need usize::MAX bytes" would be nonsense; the defect is that the
        // declared length is implausible, so say that.
        let declared = usize::try_from(sig_len_raw)
            .ok()
            .and_then(|n| MIN_QUOTE_LEN.checked_add(n))
            .ok_or(ParseError::SignatureLengthImplausible {
                declared: sig_len_raw,
            })?;
        if bytes.len() < declared {
            return Err(ParseError::SignatureTruncated {
                got: bytes.len(),
                declared,
            });
        }

        let measurement = |off: usize| -> Result<Measurement, ParseError> {
            let abs = HEADER_LEN + off;
            let s: [u8; MEASUREMENT_LEN] = bytes
                .get(abs..abs + MEASUREMENT_LEN)
                .ok_or_else(|| too_short(abs + MEASUREMENT_LEN))?
                .try_into()
                .map_err(|_| too_short(abs + MEASUREMENT_LEN))?;
            Ok(Measurement(s))
        };

        // Read inline rather than through `measurement`, which is fixed at 48 bytes. A const-generic
        // `measurement::<N>` would unify the two with the same call-site safety, but at one extra
        // caller the indirection costs more than the duplication saves.
        let report_data = {
            let abs = HEADER_LEN + OFF_REPORTDATA;
            let s: [u8; REPORT_DATA_LEN] = bytes
                .get(abs..abs + REPORT_DATA_LEN)
                .ok_or_else(|| too_short(abs + REPORT_DATA_LEN))?
                .try_into()
                .map_err(|_| too_short(abs + REPORT_DATA_LEN))?;
            ReportData(s)
        };

        Ok(Self {
            version,
            mrtd: measurement(OFF_MRTD)?,
            mrconfigid: measurement(OFF_MRCONFIGID)?,
            mrowner: measurement(OFF_MROWNER)?,
            mrownerconfig: measurement(OFF_MROWNERCONFIG)?,
            rtmr: [
                measurement(OFF_RTMR0)?,
                measurement(OFF_RTMR1)?,
                measurement(OFF_RTMR2)?,
                measurement(OFF_RTMR3)?,
            ],
            report_data,
        })
    }

    /// Parse a quote from a hexadecimal string, with or without a `0x` prefix.
    ///
    /// # Examples
    ///
    /// Malformed input is refused rather than partially parsed:
    ///
    /// ```
    /// use verity_verifier::quote::{ParseError, Quote};
    ///
    /// assert_eq!(Quote::parse_hex("not hex"), Err(ParseError::InvalidHex));
    /// assert_eq!(Quote::parse_hex("abc"), Err(ParseError::InvalidHex));
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::InvalidHex`] for malformed input, or any error from [`Self::parse`].
    pub fn parse_hex(hex: &str) -> Result<Self, ParseError> {
        let s = hex.trim();
        let s = s.strip_prefix("0x").unwrap_or(s);
        if !s.len().is_multiple_of(2) || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(ParseError::InvalidHex);
        }
        let mut bytes = Vec::with_capacity(s.len() / 2);
        for chunk in s.as_bytes().chunks_exact(2) {
            let (hi, lo) = match chunk {
                [h, l] => (*h, *l),
                _ => return Err(ParseError::InvalidHex),
            };
            let hi = char::from(hi).to_digit(16).ok_or(ParseError::InvalidHex)?;
            let lo = char::from(lo).to_digit(16).ok_or(ParseError::InvalidHex)?;
            let byte = u8::try_from((hi << 4) | lo).map_err(|_| ParseError::InvalidHex)?;
            bytes.push(byte);
        }
        Self::parse(&bytes)
    }

    /// Quote structure version.
    #[must_use]
    pub const fn version(&self) -> u16 {
        self.version
    }

    /// `MRTD` — the initial measurement of the trust domain.
    #[must_use]
    pub const fn mrtd(&self) -> &Measurement {
        &self.mrtd
    }

    /// `MR-CONFIG-ID` — carries the configuration identity this crate compares against.
    #[must_use]
    pub const fn mrconfigid(&self) -> &Measurement {
        &self.mrconfigid
    }

    /// `MROWNER`.
    #[must_use]
    pub const fn mrowner(&self) -> &Measurement {
        &self.mrowner
    }

    /// `MROWNERCONFIG`.
    #[must_use]
    pub const fn mrownerconfig(&self) -> &Measurement {
        &self.mrownerconfig
    }

    /// Runtime measurement register `n`, for `n` in `0..=3`.
    #[must_use]
    pub fn rtmr(&self, n: usize) -> Option<&Measurement> {
        self.rtmr.get(n)
    }

    /// `report_data` — the workload-supplied field RA-TLS commits the TLS key into.
    ///
    /// Exposed so a channel-binding check can compare it against the certificate presented on the
    /// connection actually in use. **A quote read from a file says nothing about a connection**: it
    /// is this comparison, and only this comparison, that stops a genuine quote from being replayed
    /// beside an endpoint it never attested.
    #[must_use]
    pub const fn report_data(&self) -> &ReportData {
        &self.report_data
    }

    /// All four runtime measurement registers.
    ///
    /// Index 3 is `RTMR3`, which must not be compared against a reference — see [`Quote`].
    #[must_use]
    pub const fn rtmrs(&self) -> &[Measurement; 4] {
        &self.rtmr
    }
}

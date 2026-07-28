//! TDX quote parsing.
//!
//! Parses the structure only — this module extracts measurements and makes no judgement about
//! them, and performs **no signature verification**. A successfully parsed quote is not a
//! trustworthy one. See [`crate`] for where verification happens.

use core::fmt;

/// Length of a TDX measurement register, in bytes.
pub const MEASUREMENT_LEN: usize = 48;

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

/// A 48-byte TDX measurement.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Measurement([u8; MEASUREMENT_LEN]);

impl Measurement {
    /// The raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; MEASUREMENT_LEN] {
        &self.0
    }

    /// True when every byte is zero.
    ///
    /// Worth checking explicitly: an unpopulated field is all-zero, and treating that as a
    /// legitimate value would compare successfully against a reference someone also left empty.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|b| *b == 0)
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// The input is shorter than a header plus report body.
    TooShort {
        /// Bytes supplied.
        got: usize,
        /// Bytes required.
        need: usize,
    },
    /// The quote structure version is not one this crate parses.
    UnsupportedVersion(u16),
    /// The `tee_type` field is not TDX.
    NotTdx(u32),
    /// The signature section is shorter than the quote's own `signature_data_len` declares.
    ///
    /// Such a quote can never verify, so it is refused at parse time rather than reported as a
    /// successful parse that fails later.
    SignatureTruncated {
        /// Bytes supplied.
        got: usize,
        /// Bytes the quote declares it should have.
        declared: usize,
    },
    /// The input was not valid hexadecimal.
    InvalidHex,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort { got, need } => {
                write!(f, "quote too short: {got} bytes, need at least {need}")
            }
            Self::UnsupportedVersion(v) => write!(f, "unsupported quote version {v}"),
            Self::NotTdx(t) => write!(f, "tee_type 0x{t:x} is not TDX (0x{TEE_TYPE_TDX:x})"),
            Self::SignatureTruncated { got, declared } => write!(
                f,
                "signature section truncated: {got} bytes, quote declares {declared}"
            ),
            Self::InvalidHex => f.write_str("input is not valid hexadecimal"),
        }
    }
}

impl core::error::Error for ParseError {}

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
}

impl Quote {
    /// Parse a quote from raw bytes.
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
        let sig_len = le_u32(OFF_SIG_LEN)? as usize;
        let declared = MIN_QUOTE_LEN
            .checked_add(sig_len)
            .ok_or_else(|| too_short(usize::MAX))?;
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
        })
    }

    /// Parse a quote from a hexadecimal string, with or without a `0x` prefix.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::InvalidHex`] for malformed input, or any error from [`Self::parse`].
    pub fn parse_hex(hex: &str) -> Result<Self, ParseError> {
        let s = hex.trim();
        let s = s.strip_prefix("0x").unwrap_or(s);
        if s.len() % 2 != 0 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
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

    /// All four runtime measurement registers.
    ///
    /// Index 3 is `RTMR3`, which must not be compared against a reference — see [`Quote`].
    #[must_use]
    pub const fn rtmrs(&self) -> &[Measurement; 4] {
        &self.rtmr
    }
}

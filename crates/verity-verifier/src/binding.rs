//! The binding between what was licensed and what was measured.
//!
//! A licence names a `composeHash`. A CVM measures the configuration it booted into
//! `MR-CONFIG-ID`. This module is where those two meet.
//!
//! # Unverified bytes are not usable
//!
//! [`VerifiedCompose`] has one constructor, and it checks the hash. There is no way to hold a
//! `VerifiedCompose` that was not compared against a licensed [`ComposeHash`] — so a caller cannot
//! forget the check, and a reviewer does not have to search for whether it happened.
//!
//! That is the difference between offering a check and requiring one. The check that gets skipped
//! is the one it was possible to skip.

use core::fmt;

use sha2::{Digest as _, Sha256};

use crate::quote::{Measurement, MEASUREMENT_LEN};

/// Length of a SHA-256 digest, in bytes.
pub const COMPOSE_HASH_LEN: usize = 32;

/// The SHA-256 of an `app-compose.json`.
///
/// This is what a licence binds to (ADR 0006). Not the image digest: the image is pinned
/// *transitively*, inside a compose whose hash this is, because the platform measures the whole
/// configuration rather than the image alone.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ComposeHash([u8; COMPOSE_HASH_LEN]);

impl ComposeHash {
    /// From raw digest bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; COMPOSE_HASH_LEN]) -> Self {
        Self(bytes)
    }

    /// Compute the hash of a compose document.
    #[must_use]
    pub fn of(document: &[u8]) -> Self {
        let mut h = Sha256::new();
        h.update(document);
        let out = h.finalize();
        let mut bytes = [0u8; COMPOSE_HASH_LEN];
        bytes.copy_from_slice(&out);
        Self(bytes)
    }

    /// Parse from a 64-character hex string.
    ///
    /// # Examples
    ///
    /// ```
    /// use verity_verifier::binding::ComposeHash;
    ///
    /// let h = ComposeHash::parse_hex(
    ///     "64690ef38b54187da11a41a54905f5f539e948a0414ceb312c8036c82f6529fd",
    /// )?;
    /// assert_eq!(h.to_string().len(), 64);
    /// # Ok::<(), verity_verifier::binding::HashParseError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`HashParseError`] if the input is not exactly 64 hex characters.
    pub fn parse_hex(s: &str) -> Result<Self, HashParseError> {
        let s = s.trim().strip_prefix("0x").unwrap_or(s.trim());
        if s.len() != COMPOSE_HASH_LEN * 2 {
            return Err(HashParseError::WrongLength { got: s.len() });
        }
        let mut bytes = [0u8; COMPOSE_HASH_LEN];
        // `as_chunks` rather than `chunks_exact` (clippy 1.98's `chunks_exact_to_as_chunks`): the
        // length check above guarantees an even byte count, so the ignored remainder is always
        // empty either way — but the array pattern is irrefutable, where the slice match needed a
        // defensive arm for a length that cannot occur.
        for (i, chunk) in s.as_bytes().as_chunks::<2>().0.iter().enumerate() {
            let [hi, lo] = *chunk;
            let hi = char::from(hi).to_digit(16).ok_or(HashParseError::NotHex)?;
            let lo = char::from(lo).to_digit(16).ok_or(HashParseError::NotHex)?;
            let byte = u8::try_from((hi << 4) | lo).map_err(|_| HashParseError::NotHex)?;
            match bytes.get_mut(i) {
                Some(slot) => *slot = byte,
                None => return Err(HashParseError::WrongLength { got: s.len() }),
            }
        }
        Ok(Self(bytes))
    }

    /// The raw digest.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; COMPOSE_HASH_LEN] {
        &self.0
    }
}

impl fmt::Debug for ComposeHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Display for ComposeHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// Why a hex digest could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum HashParseError {
    /// Not 64 hex characters.
    #[error("expected 64 hex characters, got {got}")]
    WrongLength {
        /// How many characters were supplied.
        got: usize,
    },
    /// Contains a non-hexadecimal character.
    #[error("digest contains a non-hexadecimal character")]
    NotHex,
}

/// A compose document whose hash matched the licensed one.
///
/// The only way to construct this is [`VerifiedCompose::check`], which performs the comparison.
/// Holding one is therefore evidence the check passed — it cannot be fabricated by a caller who
/// skipped it.
#[derive(Debug, Clone)]
pub struct VerifiedCompose {
    document: Vec<u8>,
    hash: ComposeHash,
}

impl VerifiedCompose {
    /// Check `document` against the licensed hash.
    ///
    /// # Errors
    ///
    /// Returns [`HashMismatch`] when the document is not the one the licence names. **This is a
    /// refusal, not a warning.** A mismatch means the document served is not the document
    /// licensed, and there is no degraded mode in which proceeding is correct.
    pub fn check(document: Vec<u8>, licensed: &ComposeHash) -> Result<Self, HashMismatch> {
        let actual = ComposeHash::of(&document);
        if actual == *licensed {
            Ok(Self {
                document,
                hash: actual,
            })
        } else {
            Err(HashMismatch {
                expected: *licensed,
                actual,
            })
        }
    }

    /// The document bytes.
    #[must_use]
    pub fn document(&self) -> &[u8] {
        &self.document
    }

    /// Its hash, which by construction equals the licensed hash.
    #[must_use]
    pub const fn hash(&self) -> &ComposeHash {
        &self.hash
    }
}

/// The document served is not the document licensed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("compose hash mismatch: licensed {expected}, served {actual}")]
pub struct HashMismatch {
    /// What the licence named.
    pub expected: ComposeHash,
    /// What arrived.
    pub actual: ComposeHash,
}

/// Which `MR-CONFIG-ID` construction a platform uses.
///
/// **Branch on this; never assume.** V1 and V2 are different formats, and which applies is a
/// property of the platform version rather than of this crate. Hard-coding `0x01` would fail
/// silently against a V2 platform — returning a mismatch that looks like an attack and is actually
/// a format change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MrConfigIdVersion {
    /// `0x01 ‖ SHA-256(app-compose.json) ‖ 0x00 × 15`.
    ///
    /// Measured in use on dstack 0.5.7, including where KMS is enabled.
    V1,
    /// `0x02 ‖ Keccak256(compose_hash ‖ app_id ‖ kp_type ‖ kp_id) ‖ padding`.
    ///
    /// Documented but not observed in our measurements. Recognised so that encountering it
    /// produces a clear "unsupported" rather than a silent mismatch.
    V2,
}

impl MrConfigIdVersion {
    /// The version a measurement's prefix byte declares.
    ///
    /// Returns `None` for a prefix this crate does not recognise — including all-zero, which is
    /// what an unpopulated field looks like.
    #[must_use]
    pub fn from_measurement(m: &Measurement) -> Option<Self> {
        match m.as_bytes().first() {
            Some(0x01) => Some(Self::V1),
            Some(0x02) => Some(Self::V2),
            _ => None,
        }
    }
}

/// Build the `MR-CONFIG-ID` a licensed configuration should produce, for V1.
///
/// `0x01 ‖ composeHash ‖ 0x00 × 15`.
///
/// Nothing per-deployment enters this, which is what makes the expected measurement computable
/// from the published compose **before anything is deployed** — verification becomes a
/// pre-commitment rather than only a post-hoc check.
///
/// # Examples
///
/// ```
/// use verity_verifier::binding::{expected_mrconfigid_v1, ComposeHash};
///
/// let licensed = ComposeHash::parse_hex(
///     "64690ef38b54187da11a41a54905f5f539e948a0414ceb312c8036c82f6529fd",
/// )?;
/// let expected = expected_mrconfigid_v1(&licensed);
/// assert_eq!(expected.as_bytes()[0], 0x01);
/// # Ok::<(), verity_verifier::binding::HashParseError>(())
/// ```
#[must_use]
pub fn expected_mrconfigid_v1(licensed: &ComposeHash) -> Measurement {
    let mut out = [0u8; MEASUREMENT_LEN];
    out[0] = 0x01;
    // 1 + 32 = 33 <= 48, so this range is always in bounds.
    if let Some(slot) = out.get_mut(1..1 + COMPOSE_HASH_LEN) {
        slot.copy_from_slice(licensed.as_bytes());
    }
    Measurement::from_bytes(out)
}

/// Why a measurement did not match the licensed configuration.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum MrConfigIdError {
    /// The prefix byte is not a construction this crate understands.
    ///
    /// Distinct from a mismatch on purpose: an unrecognised format is a platform-version problem,
    /// and reporting it as "wrong configuration" would send someone hunting an attack that is not
    /// there.
    #[error("unrecognised MR-CONFIG-ID version prefix 0x{prefix:02x}")]
    UnknownVersion {
        /// The prefix byte found.
        prefix: u8,
    },
    /// A construction this crate recognises but cannot yet compute a reference for.
    #[error("MR-CONFIG-ID {version:?} is not supported by this version of the verifier")]
    UnsupportedVersion {
        /// Which construction.
        version: MrConfigIdVersion,
    },
    /// The measurement does not match the licensed configuration.
    #[error("MR-CONFIG-ID mismatch: expected {expected}, measured {measured}")]
    Mismatch {
        /// What the licensed configuration should produce.
        expected: Measurement,
        /// What the quote carried.
        measured: Measurement,
    },
}

/// Compare a quote's `MR-CONFIG-ID` against a licensed configuration.
///
/// Branches on the measurement's own prefix byte rather than assuming a construction.
///
/// # Errors
///
/// Returns [`MrConfigIdError`] when the prefix is unrecognised, the construction is not yet
/// supported, or the measurement does not match.
pub fn check_mrconfigid(
    measured: &Measurement,
    licensed: &ComposeHash,
) -> Result<(), MrConfigIdError> {
    match MrConfigIdVersion::from_measurement(measured) {
        Some(MrConfigIdVersion::V1) => {
            let expected = expected_mrconfigid_v1(licensed);
            if expected == *measured {
                Ok(())
            } else {
                Err(MrConfigIdError::Mismatch {
                    expected,
                    measured: *measured,
                })
            }
        }
        // Recognised, but computing a V2 reference needs app_id, kp_type and kp_id, which are not
        // available here. Refusing explicitly is the honest answer; guessing would be worse than
        // useless in a component whose job is to not be fooled.
        Some(version @ MrConfigIdVersion::V2) => {
            Err(MrConfigIdError::UnsupportedVersion { version })
        }
        None => Err(MrConfigIdError::UnknownVersion {
            prefix: measured.as_bytes().first().copied().unwrap_or(0),
        }),
    }
}

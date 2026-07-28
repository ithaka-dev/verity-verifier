//! Reference measurements for known dstack OS images.
//!
//! `MRTD` and `RTMR0-2` identify the guest OS a CVM booted. They were measured stable across
//! deployments, so unlike `RTMR3` they can be compared against a known value.
//!
//! # Bundled, dated, and updatable — not fetched
//!
//! References compile in, so verification works with no network at all. The bundle carries a date
//! that appears in every verdict, which makes staleness *legible* without making it *fatal*
//! ([ADR 0014]).
//!
//! **Refuse on known-bad; warn on merely old.** A revoked image is a fact and hard-fails. An old
//! bundle is a proxy and only informs. There is deliberately no expiry: a verifier that refuses to
//! run after N months is a remote kill switch on the component everything else depends on, and it
//! turns a wrong clock into a total outage.
//!
//! [ADR 0014]: https://github.com/ithaka-dev/verity-foundation/blob/main/docs/decisions/0014-verifier-update-discipline.md

use crate::quote::Measurement;

/// When the bundled reference data was assembled, as `YYYY-MM-DD`.
///
/// Surfaced in every verdict so a caller can see how old the verifier's world-view is.
pub const REFERENCE_DATA_DATE: &str = "2026-07-28";

/// A known dstack OS image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OsImage {
    /// Image name, e.g. `dstack-0.5.7`.
    pub name: &'static str,
    /// The `os-image-hash` dstack publishes for it.
    pub os_image_hash: &'static str,
    /// Whether this image is revoked and must be refused outright.
    pub revoked: bool,
}

/// dstack OS images this verifier knows about.
///
/// Sourced from Phala's published image list. `dstack-0.5.7` is the one our measurements came
/// from; the others are recorded so an unexpected-but-known image is reported as such rather than
/// as an unknown.
pub const KNOWN_OS_IMAGES: &[OsImage] = &[
    OsImage {
        name: "dstack-0.5.6",
        os_image_hash: "1a4fb372957b76a81a8938029616d02bed7b0f7af4486ea8defd65efcd435d95",
        revoked: false,
    },
    OsImage {
        name: "dstack-0.5.7",
        os_image_hash: "761c05d282c81abeae2d1a8f6d5b1e039c8ce14cc95a6da020b9ed2ff1056816",
        revoked: false,
    },
    OsImage {
        name: "dstack-0.5.8",
        os_image_hash: "6427f4f5ded88b72d326bd973e581c1689c5080c6444a0cf90fec7d9e4c8b92a",
        revoked: false,
    },
    OsImage {
        name: "dstack-0.5.9",
        os_image_hash: "bd369a8c2f9edb2b52dad48ac8e0b32dde5f1337c423a506b48d07403a7d8033",
        revoked: false,
    },
    OsImage {
        name: "dstack-0.5.10",
        os_image_hash: "4c9bd0249cf8a1f79f7b558867b0791d628d7a89dcba84a963338fc5539255fc",
        revoked: false,
    },
];

/// Look up an OS image by its published hash.
#[must_use]
pub fn os_image_by_hash(hash: &str) -> Option<&'static OsImage> {
    KNOWN_OS_IMAGES.iter().find(|i| i.os_image_hash == hash)
}

/// Whether spec §2.5's minimum dstack version is satisfied.
///
/// Below 0.5.6 the attestation pipeline predates the Jan–Feb 2026 hardening.
#[must_use]
pub fn meets_minimum_version(name: &str) -> bool {
    // Names are `dstack-<major>.<minor>.<patch>`; anything unparseable is not vouched for.
    let Some(rest) = name.strip_prefix("dstack-") else {
        return false;
    };
    let mut parts = rest.split('.').filter_map(|p| p.parse::<u32>().ok());
    match (parts.next(), parts.next(), parts.next()) {
        (Some(0), Some(5), Some(patch)) => patch >= 6,
        (Some(major), _, _) => major > 0,
        _ => false,
    }
}

/// Boot measurements a caller expects, when they know which OS image should be running.
///
/// Absent means "do not compare" rather than "compare against nothing" — the distinction matters,
/// because a comparison against an empty reference silently succeeds.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BootReference {
    /// Expected `MRTD`.
    pub mrtd: Option<Measurement>,
    /// Expected `RTMR0`.
    pub rtmr0: Option<Measurement>,
    /// Expected `RTMR1`.
    pub rtmr1: Option<Measurement>,
    /// Expected `RTMR2`.
    pub rtmr2: Option<Measurement>,
}

/// Why boot measurements did not match.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum BootError {
    /// A measurement differs from the reference.
    #[error("{register} mismatch: expected {expected}, measured {measured}")]
    Mismatch {
        /// Which register.
        register: &'static str,
        /// The reference value.
        expected: Measurement,
        /// What the quote carried.
        measured: Measurement,
    },
    /// The OS image is known and revoked.
    ///
    /// A fact, so it hard-fails — distinct from the bundle merely being old.
    #[error("OS image `{name}` is revoked")]
    RevokedImage {
        /// Which image.
        name: &'static str,
    },
}

/// Compare a quote's boot measurements against a reference.
///
/// **`RTMR3` is not compared and cannot be**, by construction: it is absent from [`BootReference`].
/// It accumulates `app-id`, `instance-id` and `mr-kms`, the last varying per boot, so no stable
/// reference exists. Leaving it out of the type is stronger than documenting that it should be
/// skipped.
///
/// # Errors
///
/// Returns [`BootError`] on the first mismatch.
pub fn check_boot_measurements(
    quote: &crate::quote::Quote,
    reference: &BootReference,
) -> Result<(), BootError> {
    let pairs: [(&'static str, Option<Measurement>, Measurement); 4] = [
        ("MRTD", reference.mrtd, *quote.mrtd()),
        ("RTMR0", reference.rtmr0, quote.rtmrs()[0]),
        ("RTMR1", reference.rtmr1, quote.rtmrs()[1]),
        ("RTMR2", reference.rtmr2, quote.rtmrs()[2]),
    ];
    for (register, expected, measured) in pairs {
        if let Some(expected) = expected {
            if expected != measured {
                return Err(BootError::Mismatch {
                    register,
                    expected,
                    measured,
                });
            }
        }
    }
    Ok(())
}

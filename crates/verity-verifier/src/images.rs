//! Image references inside a compose document.
//!
//! Two checks live here, and they are the reason `composeHash` is a meaningful binding at all.
//!
//! # Why hashing the compose is not enough on its own
//!
//! A licence binds to `composeHash`, and the image is supposed to be pinned *transitively* because
//! the compose names it. That reasoning holds **only if the compose names the image by digest.**
//!
//! With a tag — `image: myapp:latest` — the compose text never changes, so `composeHash` stays
//! stable, `MR-CONFIG-ID` stays stable, attestation passes, and the code actually executing is
//! whatever the registry currently serves. Every check succeeds and the guarantee is gone.
//!
//! dStack's own reference compose uses a bare tag, so this cannot be treated as a thing that
//! happens rarely.
//!
//! # Fail closed
//!
//! Where this module cannot be confident — a compose it cannot parse, a shape it does not
//! recognise, an image reference it cannot classify — it **refuses**. Passing something
//! unrecognised would mean the one check an attacker cannot route around is also the one that
//! shrugs at input it does not understand.

use core::fmt;

use yaml_rust2::{Yaml, YamlLoader};

/// A digest-pinned image reference, e.g. `alpine@sha256:d9e8…`.
///
/// Constructing one asserts the reference is digest-pinned. A tag cannot become an `ImageRef`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ImageRef {
    reference: String,
    digest: String,
}

impl ImageRef {
    /// The full reference as it appears in the compose.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.reference
    }

    /// The `sha256:…` portion.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }
}

impl fmt::Display for ImageRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.reference)
    }
}

/// Why a compose document was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ImageError {
    /// The outer document is not valid JSON.
    #[error("compose is not valid JSON: {detail}")]
    NotJson {
        /// What the parser said.
        detail: String,
    },
    /// No `docker_compose_file` field.
    #[error("compose has no `docker_compose_file` field")]
    MissingComposeFile,
    /// The embedded compose is not valid YAML.
    #[error("embedded docker-compose is not valid YAML: {detail}")]
    NotYaml {
        /// What the parser said.
        detail: String,
    },
    /// An image reference is not digest-pinned.
    ///
    /// The finding this module exists for.
    #[error("service `{service}` references image `{reference}` by tag, not digest")]
    NotPinned {
        /// Which service.
        service: String,
        /// The offending reference.
        reference: String,
    },
    /// A service has no `image` field, and none of the shapes that legitimately replace one.
    #[error("service `{service}` has no image reference")]
    NoImage {
        /// Which service.
        service: String,
    },
    /// The compose declares no services.
    ///
    /// Refused rather than vacuously passed: a document with nothing to check is not a document
    /// that passed the check.
    #[error("compose declares no services")]
    NoServices,
    /// The licensed image digest does not appear among the compose's images.
    #[error("compose does not reference the licensed image digest `{licensed}`")]
    LicensedDigestAbsent {
        /// The digest the manifest record names.
        licensed: String,
    },
}

/// Is this reference digest-pinned?
///
/// Accepts `repo@sha256:<64 hex>` and rejects everything else, including `repo@sha256:` with a
/// short or malformed digest — a truncated digest is not a weaker pin, it is not a pin.
fn classify(reference: &str) -> Option<ImageRef> {
    let (_, digest) = reference.split_once('@')?;
    let (algorithm, hex) = digest.split_once(':')?;
    if algorithm != "sha256" || hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(ImageRef {
        reference: reference.to_owned(),
        digest: digest.to_owned(),
    })
}

/// Extract every digest-pinned image from a compose document, refusing if any is not pinned.
///
/// # Errors
///
/// Returns [`ImageError`] if the document cannot be parsed, declares no services, or contains any
/// image reference that is not digest-pinned.
pub fn pinned_images(compose: &[u8]) -> Result<Vec<ImageRef>, ImageError> {
    let outer: serde_json::Value =
        serde_json::from_slice(compose).map_err(|e| ImageError::NotJson {
            detail: e.to_string(),
        })?;

    let inner = outer
        .get("docker_compose_file")
        .and_then(serde_json::Value::as_str)
        .ok_or(ImageError::MissingComposeFile)?;

    let docs = YamlLoader::load_from_str(inner).map_err(|e| ImageError::NotYaml {
        detail: e.to_string(),
    })?;

    let services = docs
        .first()
        .and_then(|d| d["services"].as_hash())
        .ok_or(ImageError::NoServices)?;

    if services.is_empty() {
        return Err(ImageError::NoServices);
    }

    let mut found = Vec::new();
    for (name, body) in services {
        let service = name.as_str().unwrap_or("<unnamed>").to_owned();
        match &body["image"] {
            Yaml::String(reference) => match classify(reference) {
                Some(image) => found.push(image),
                None => {
                    return Err(ImageError::NotPinned {
                        service,
                        reference: reference.clone(),
                    })
                }
            },
            // A service with no `image` is refused rather than skipped. A `build:` service is
            // legitimate in ordinary compose usage, but not here: what it produces is not
            // content-addressed, so nothing pins what would actually run.
            _ => return Err(ImageError::NoImage { service }),
        }
    }

    Ok(found)
}

/// Check the compose actually references the licensed image digest.
///
/// **This is the enforcement an attacker cannot route around** (ADR 0007). The publishing tool and
/// the on-chain write path can both be bypassed by a determined publisher; this cannot, because it
/// runs on the verifying side against the document the licence itself names.
///
/// It also gives `imageDigest` a job beyond human readability: it becomes the value the compose is
/// checked *against*, closing the loop between the two fields of a manifest record.
///
/// # Errors
///
/// Returns [`ImageError`] if the compose is unparseable, any image is unpinned, or none of its
/// images match `licensed_digest`.
pub fn check_references_licensed_digest(
    compose: &[u8],
    licensed_digest: &str,
) -> Result<(), ImageError> {
    let images = pinned_images(compose)?;
    if images.iter().any(|i| i.digest() == licensed_digest) {
        Ok(())
    } else {
        Err(ImageError::LicensedDigestAbsent {
            licensed: licensed_digest.to_owned(),
        })
    }
}

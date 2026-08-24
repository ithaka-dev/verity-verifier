//! T-11: `FetchError -> Unestablished -> Disposition`, at the layer where it is actually true.
//!
//! The acceptance criterion "a gateway/collateral retrieval failure yields `Indeterminate`, not a
//! mismatch" is not satisfiable inside `verify()` — neither it nor `connect_verified` fetches the
//! compose document (see the design record). What *is* true, and provably so without a live IPFS
//! daemon, is the chain a caller's own `compose::Source` implementation goes through: a
//! `FetchError` converts to an `Unestablished` cause, and that cause has one typed remedy.
//!
//! **Deliberately not in `tests/compose_fetch.rs`.** That file is `#![cfg(feature = "fetch")]` and
//! its own header says its tests skip when no IPFS daemon is reachable. `FetchError` and
//! `Unestablished` are both ungated, so putting an acceptance-criterion test behind a feature flag
//! *and* a live daemon would mean it does not run on a plain `cargo test` — an acceptance criterion
//! guarded by a test most runs skip.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use verity_verifier::compose::FetchError;
use verity_verifier::verdict::{Disposition, Unestablished};

fn cases() -> Vec<FetchError> {
    vec![
        FetchError::Transport {
            uri: "ipfs://x".to_owned(),
            detail: "connection refused".to_owned(),
        },
        FetchError::Status {
            uri: "http://x".to_owned(),
            status: 503,
        },
        FetchError::TooLarge {
            uri: "http://x".to_owned(),
            limit: 1024,
        },
        FetchError::Unsupported {
            source_kind: "Gateway",
            uri: "kubo://x".to_owned(),
        },
    ]
}

/// Every `FetchError` variant becomes `Unestablished::RetrievalFailed` — the mapping is total, and
/// (per the `From` impl's own doc) deliberately does not try to distinguish an outage from a hostile
/// oversized response, because the caller's remedy is identical either way and a verdict cannot tell
/// them apart.
#[test]
fn every_fetch_error_variant_maps_to_retrieval_failed() {
    for err in cases() {
        assert_eq!(
            Unestablished::from(&err),
            Unestablished::RetrievalFailed,
            "{err:?}"
        );
    }
}

/// T-11's acceptance criterion, at the layer where it is true: a retrieval failure's cause
/// dispositions to `RetryRetrieval` for every `FetchError` shape, without constructing a `Verdict`
/// or performing any I/O.
#[test]
fn retrieval_failure_dispositions_to_retry_retrieval() {
    for err in cases() {
        let cause = Unestablished::from(&err);
        assert_eq!(cause.disposition(), Disposition::RetryRetrieval, "{err:?}");
    }
}

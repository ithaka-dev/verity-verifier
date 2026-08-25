//! MI-5: multi-gateway fallback. `Fallback<S>` tries sources in order; a miss falls through to the
//! next; only all-down surfaces as a failure.
//!
//! **Deliberately ungated.** `Fallback` is generic over any `Source`, defined in `compose.rs`
//! itself (not `compose/http.rs`), and needs no network — same reasoning as `dispositions.rs` for
//! `FetchError`/`Unestablished`: putting this behind `#![cfg(feature = "fetch")]` would mean the
//! multi-gateway acceptance criteria don't run on a plain `cargo test`.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use verity_verifier::compose::{ComposeUri, Fallback, FetchError, Source};
use verity_verifier::verdict::Unestablished;

/// What a [`Scripted`] source does when fetched.
#[derive(Clone)]
enum Outcome {
    Success(&'static [u8]),
    /// A transport-shaped failure — the ordinary "this source is down" case.
    Failing,
    /// The wrong kind of `ComposeUri` for this source — must fall through like any other miss,
    /// not be treated as special.
    Unsupported,
}

/// A `Source` whose outcome is fixed at construction, and counts how many times it was called — so
/// a test can tell whether a later source in a chain was ever reached.
#[derive(Clone)]
struct Scripted {
    calls: Arc<AtomicUsize>,
    outcome: Outcome,
}

impl Scripted {
    fn succeeding(body: &'static [u8]) -> Self {
        Self {
            calls: Arc::new(AtomicUsize::new(0)),
            outcome: Outcome::Success(body),
        }
    }

    fn failing() -> Self {
        Self {
            calls: Arc::new(AtomicUsize::new(0)),
            outcome: Outcome::Failing,
        }
    }

    fn unsupported() -> Self {
        Self {
            calls: Arc::new(AtomicUsize::new(0)),
            outcome: Outcome::Unsupported,
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl Source for Scripted {
    fn fetch(&self, uri: &ComposeUri) -> Result<Vec<u8>, FetchError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match &self.outcome {
            Outcome::Success(body) => Ok(body.to_vec()),
            Outcome::Failing => Err(FetchError::Transport {
                uri: uri.to_string(),
                detail: "scripted failure".to_owned(),
            }),
            Outcome::Unsupported => Err(FetchError::Unsupported {
                source_kind: "Scripted",
                uri: uri.to_string(),
            }),
        }
    }
}

/// A second, distinct `Source` implementation — exists only so the heterogeneous-`Fallback` test
/// below mixes two genuinely different source *types* under `Box<dyn Source>`, rather than two
/// boxed copies of `Scripted`.
struct Echo(&'static [u8]);

impl Source for Echo {
    fn fetch(&self, _uri: &ComposeUri) -> Result<Vec<u8>, FetchError> {
        Ok(self.0.to_vec())
    }
}

fn cid() -> ComposeUri {
    ComposeUri::parse("ipfs://bafkreiabcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuv")
        .expect("uri")
}

#[test]
fn a_working_first_source_answers_and_the_rest_are_never_touched() {
    let first = Scripted::succeeding(b"from first");
    let second = Scripted::failing();
    let fallback = Fallback::new(first.clone(), vec![second.clone()]);

    let body = fallback.fetch(&cid()).expect("first source answers");

    assert_eq!(body, b"from first");
    assert_eq!(first.calls(), 1, "the first source must be tried");
    assert_eq!(
        second.calls(),
        0,
        "a working first source means the rest are never touched"
    );
}

#[test]
fn a_dead_first_source_falls_through_to_a_live_second() {
    let first = Scripted::failing();
    let second = Scripted::succeeding(b"from second");
    let fallback = Fallback::new(first.clone(), vec![second.clone()]);

    let body = fallback
        .fetch(&cid())
        .expect("the live second source must answer");

    assert_eq!(body, b"from second");
    assert_eq!(first.calls(), 1);
    assert_eq!(
        second.calls(),
        1,
        "a miss must fall through to the next source"
    );
}

#[test]
fn several_dead_sources_fall_through_in_order_before_a_live_one() {
    let first = Scripted::failing();
    let dead_second = Scripted::failing();
    let live_third = Scripted::succeeding(b"from third");
    let fallback = Fallback::new(first.clone(), vec![dead_second.clone(), live_third.clone()]);

    let body = fallback
        .fetch(&cid())
        .expect("the third source must answer");

    assert_eq!(body, b"from third");
    assert_eq!(first.calls(), 1);
    assert_eq!(dead_second.calls(), 1);
    assert_eq!(live_third.calls(), 1);
}

/// All-down: the fetch itself fails, and — the load-bearing property — that failure maps to
/// `Indeterminate` through the *existing* `From<&FetchError> for Unestablished` (pinned exhaustively
/// in `dispositions.rs`), not a fork of it. A `Fallback` with every source down is, at the verdict
/// level, indistinguishable from any single source being down.
#[test]
fn when_every_source_is_down_the_failure_maps_to_retrieval_failed() {
    let first = Scripted::failing();
    let second = Scripted::failing();
    let third = Scripted::failing();
    let fallback = Fallback::new(first.clone(), vec![second.clone(), third.clone()]);

    let err = fallback.fetch(&cid()).expect_err("every source is down");

    assert_eq!(first.calls(), 1);
    assert_eq!(second.calls(), 1);
    assert_eq!(
        third.calls(),
        1,
        "every source must be tried before giving up"
    );
    assert_eq!(
        Unestablished::from(&err),
        Unestablished::RetrievalFailed,
        "reuses the existing mapping rather than forking a new failure path"
    );
}

/// A single source is a degenerate but legal fallback chain — `Fallback::new` takes a guaranteed
/// first source rather than a fallible `Vec`, so there is no empty case to test for: it cannot be
/// constructed.
#[test]
fn a_single_source_fallback_behaves_like_the_source_alone() {
    let only = Scripted::succeeding(b"solo");
    let fallback = Fallback::new(only.clone(), vec![]);

    assert_eq!(
        fallback.fetch(&cid()).expect("solo source answers"),
        b"solo"
    );
    assert_eq!(only.calls(), 1);
}

/// `Unsupported` — the wrong kind of `ComposeUri` for a given source — is not special-cased: it
/// falls through to the next source exactly like a transport failure would. This is what makes a
/// heterogeneous chain (sources that each only handle one URI kind) work through `Fallback` at all.
#[test]
fn an_unsupported_first_source_falls_through_like_any_other_miss() {
    let first = Scripted::unsupported();
    let second = Scripted::succeeding(b"from second");
    let fallback = Fallback::new(first.clone(), vec![second.clone()]);

    let body = fallback
        .fetch(&cid())
        .expect("the second source must still answer");

    assert_eq!(body, b"from second");
    assert_eq!(first.calls(), 1);
    assert_eq!(
        second.calls(),
        1,
        "Unsupported must fall through like any other miss"
    );
}

/// The `impl<S: Source + ?Sized> Source for Box<S>` blanket impl exists to let
/// `Fallback<Box<dyn Source>>` mix source *kinds* — proven here by actually constructing one from
/// two different concrete types, not just exercising it implicitly through a homogeneous chain.
#[test]
fn a_heterogeneous_fallback_over_boxed_sources_mixes_source_kinds() {
    let dead: Box<dyn Source> = Box::new(Scripted::failing());
    let live: Box<dyn Source> = Box::new(Echo(b"from echo"));
    let fallback = Fallback::new(dead, vec![live]);

    let body = fallback
        .fetch(&cid())
        .expect("the live boxed source must answer");

    assert_eq!(body, b"from echo");
}

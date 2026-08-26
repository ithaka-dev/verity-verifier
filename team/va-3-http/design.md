# Design — VA-3 follow-up: close the `ComposeUri::Http` asymmetry with a validated newtype

**Repo:** `verity-verifier` @ `529deda` · **Cycle:** rust-team (ADR 0026) · **Author:** vahttp-architect
**Status:** consensus (Phase 2) — developer AGREE on (a), the `ComposeUrl` name, and the newtype
shape; one AMEND on the test approach, conceded and folded in below. For reviewer sign-off (ADR 0018).

---

## Decision

**Take (a): close the asymmetry.** Introduce a `HttpUrl` **value newtype** — private inner `String`,
sole constructor `HttpUrl::parse` that validates the `http(s)://` scheme allowlist **and nothing
more** — and change the variant to `ComposeUri::Http(HttpUrl)`. `ComposeUri::parse` routes its
existing scheme check *through* that one constructor, so there is a single definition of "valid Http
URL" and it cannot drift. No host, port, path, or SSRF policy is added or reconsidered; VA-3 §3
settled that and this design does not reopen it.

> **Naming collision to resolve during implementation.** `HttpUrl` is already the name of the
> `Source` impl in `compose/http.rs` (the thing that GETs arbitrary URLs). The *value* newtype and
> the *Source* are different concepts and must not share a name. Recommendation: name the value type
> **`ComposeUrl`** and leave the `Source` as `HttpUrl`. That reads correctly at every use site
> (`ComposeUri::Http(ComposeUrl)`, "a `ComposeUrl` is a parsed http(s) URL") and avoids a rename of
> the public `HttpUrl` source, which is a larger and unrelated blast radius. The rest of this
> document uses **`ComposeUrl`** for the newtype. This is the one naming decision I hand to the
> developer to confirm; the shape below is independent of which name wins.
>
> **Confirmed in Phase 2:** `ComposeUrl` is not a preference but forced. `compose/http.rs` already
> declares `pub struct HttpUrl` and it is re-exported into the same `compose` namespace, so reusing
> `HttpUrl` for the value type is a straight name collision, not just a readability smell. The name
> question the least-certain note raised is therefore settled: `ComposeUrl`.

### The newtype is the sole mechanism (not one of two)

The brief floated "a newtype *or* making the variant's field private" as two options. There is only
one: **Rust has no per-field visibility on an enum tuple variant.** `Http(String)` cannot become
`Http(/* private */ String)` — the inner value of a tuple variant is as visible as the variant, which
is as visible as the enum. The only way to make it unconstructable-when-invalid is to wrap it in a
struct with a private field, i.e. a newtype. So "field private" and "newtype" name the same change.
This also closes the seen-to-fail question below: because the module boundary plus the private field
are the *entire* enforcement, there is no residual bypass a compiled negative test could catch that a
structural argument does not already prove.

### Why (a) over (b)

The brief is right that the security stakes are lower than the `Cid` case: the value is fetched
**verbatim** (`get(url, …)`, never interpolated into a larger URL), `ureq` rejects non-`http(s)`
schemes at call time, redirects are off, and the bytes are hash-checked so a wrong URL yields a
spurious *refusal*, never a spurious success. So the newtype buys **no new security property** — the
injection/traversal vectors that justified `Cid` genuinely do not exist here.

What it buys is the enum keeping its own stated invariant. `ComposeUri`'s doc says values are
"*parsed rather than passed around as a string so that a caller cannot accidentally hand a gateway an
arbitrary URL*". Today that is true for `Ipfs` and false for `Http`: `ComposeUri::Http("file:///…")`
compiles and constructs, bypassing `ComposeUri::parse`'s `http(s)://` check. That is a real,
demonstrable hole in an invariant the type advertises — an embedder building a `ComposeUri` by hand,
or a future deserialization/`From` path, inherits no check. (a) is chosen for four concrete reasons,
none of which is "more validation is better":

1. **No legitimate caller is broken.** Every construction of the variant in the tree today goes
   through `ComposeUri::parse` (verified: `tests/compose_uri.rs:25-33` and every `compose_http.rs`
   site call `parse`, never the raw variant; there is no `From`, `FromStr`, or serde impl on
   `ComposeUri`). The public surface a caller can reach is `ComposeUri::parse` — which is unchanged
   in behavior — so this is source-compatible for the intended usage and only removes the
   raw-tuple-literal escape hatch, which nothing uses.
2. **No false confidence.** The one risk that would favor (b) is a validator that manufactures a
   guarantee it does not deliver. A scheme-only check does not: it validates exactly what its
   docstring claims (the scheme is `http`/`https`) and no more, and the type's docs will state plainly
   that it carries **no** content-addressing or host guarantee — the hash check remains authoritative.
   It does not pretend to prevent SSRF, validate the host, or make retrieval trusted.
3. **The operator asked for all three follow-ups resolved.** (a) resolves it; (b) leaves the
   asymmetry standing and asks the operator to accept it. (b) is only correct if (a) were actively
   worse, and it is not.
4. **Symmetry is itself the maintainability property.** After this change, *both* arms of
   `ComposeUri` hold a private-inner, single-constructor newtype whose only way in validates. A
   reviewer reasoning about "can an unvalidated compose target exist" gets one answer for the whole
   enum instead of two. That is worth a ~30-line newtype.

(b) is not adopted. It remains a coherent position — the residual is genuinely near-zero — but its
only advantage is avoiding ceremony, and the ceremony here is small, breaks nothing, and removes a
stated-invariant violation rather than papering over it.

---

## Shape (signatures / skeleton only — no implementation)

### The newtype, in `compose.rs`, mirroring `Cid`

```rust
/// A parsed `http`/`https` compose URL.
///
/// The invariant is **scheme-validity, and only that**: the inner string begins with `http://` or
/// `https://`. It is deliberately *not* a claim about the host, port, path, or reachability, and
/// carries **no** content-addressing guarantee — unlike [`Cid`], the value is fetched verbatim
/// (never interpolated into a larger URL), so there is no injection surface to defend and no host
/// policy to enforce here. Whether an embedder should point retrieval at a given URL, and any
/// private-range concern, is the embedder's decision (see [`HttpUrl`]'s retrieval-policy docs);
/// retrieval is outside the trust model and the hash check against the licensed `composeHash` is
/// authoritative regardless of what comes back.
///
/// The only constructor is [`ComposeUrl::parse`]; the inner field is private so that no caller can
/// build a [`ComposeUri::Http`] holding a string that did not pass the scheme check — the same
/// "parsed, not a raw string" guarantee [`Cid`] gives the `Ipfs` arm.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ComposeUrl(String);

impl ComposeUrl {
    /// Parse an `http`/`https` URL, accepting only the two schemes this crate retrieves.
    ///
    /// Performs **no** host, port, path, or private-range validation — see the type docs for why
    /// that is deliberate, not an oversight.
    ///
    /// # Errors
    ///
    /// Returns [`UriError::UnsupportedScheme`] if `s` carries a scheme other than `http`/`https`,
    /// or [`UriError::NoScheme`] if it carries none. (Shares its verdict vocabulary with
    /// [`ComposeUri::parse`] so the two cannot disagree about what a valid Http URL is.)
    pub fn parse(s: &str) -> Result<Self, UriError> { /* scheme check, then Ok(Self(s.to_owned())) */ }

    /// The URL's string form.
    #[must_use]
    pub fn as_str(&self) -> &str { &self.0 }
}

impl fmt::Display for ComposeUrl { /* write_str(&self.0) */ }
```

### The variant and the shared check

```rust
pub enum ComposeUri {
    Ipfs(Cid),
    Http(ComposeUrl),   // was Http(String)
}

impl ComposeUri {
    pub fn parse(s: &str) -> Result<Self, UriError> {
        let s = s.trim();
        if let Some(cid) = s.strip_prefix("ipfs://") {
            return Cid::parse(cid).map(Self::Ipfs);
        }
        // The http(s):// decision now lives in ONE place. `ComposeUri::parse` no longer branches on
        // the prefix itself — it hands the string to `ComposeUrl::parse` and lets the single
        // definition decide. This is the VA-3 finding-2 no-drift lesson applied: two copies of
        // "what is a valid http URL" cannot disagree because there is only one.
        ComposeUrl::parse(s).map(Self::Http)
    }

    pub fn cid(&self) -> Option<&str> {
        match self {
            Self::Ipfs(cid) => Some(cid.as_str()),
            Self::Http(_) => None,
        }
    }
}
```

**One subtlety the developer must preserve — the error mapping for a non-http, non-ipfs scheme.**
Today `ComposeUri::parse` returns `UnsupportedScheme("file")` for `file:///…` and `NoScheme` for a
bare string, and `tests/compose_uri.rs:46-63` pin both. `ComposeUrl::parse` must reproduce that exact
split so those tests keep passing unchanged: when the string is neither `http://` nor `https://`,
distinguish "has a `scheme://`" (→ `UnsupportedScheme(scheme)`) from "has no scheme at all"
(→ `NoScheme`), i.e. the existing `split_once("://")` logic moves *into* `ComposeUrl::parse` rather
than staying in `ComposeUri::parse`. This is the whole point of the shared definition — the error
behavior travels with the check.

### Display, and the three fetch sites

`ComposeUri`'s `Display` arm becomes `Self::Http(url) => f.write_str(url.as_str())` (was
`f.write_str(url)`). The three `compose/http.rs` sites that match `ComposeUri::Http(url)` change how
they read the value, not what they do:

- `HttpUrl::fetch` (`http.rs:259`): `get(url.as_str(), self.limit)` — was `get(url, …)`.
- `Gateway::fetch` `Unsupported` arm (`http.rs:149`): `uri: url.to_string()` (or `url.as_str().to_owned()`) — was `url.clone()`.
- `KuboRpc::fetch` `Unsupported` arm (`http.rs:197`): same.

No behavioral change: the verbatim URL still reaches `get` unchanged, and the `Unsupported` error
still carries the URL string.

---

## Blast radius (exact sites, verified at `529deda`)

Production (`crates/verity-verifier/src/`):

| Site | File:line | Change |
|---|---|---|
| Variant definition | `compose.rs:111` | `Http(String)` → `Http(ComposeUrl)` |
| `ComposeUri::parse` http branch | `compose.rs:136-142` | route through `ComposeUrl::parse`; move the `split_once` error split into it |
| `Display` | `compose.rs:159` | `f.write_str(url)` → `f.write_str(url.as_str())` |
| `cid()` http arm | `compose.rs:150` | none (already `Self::Http(_) => None`) |
| New newtype | `compose.rs` (near `Cid`, ~:60-94) | add `ComposeUrl` + `parse` + `as_str` + `Display` |
| `HttpUrl::fetch` | `compose/http.rs:259` | `get(url.as_str(), …)` |
| `Gateway::fetch` Unsupported | `compose/http.rs:149` | `url.to_string()` |
| `KuboRpc::fetch` Unsupported | `compose/http.rs:197` | `url.to_string()` |

Export: `ComposeUrl` is `pub struct ComposeUrl` inside `pub mod compose`, matching `Cid` exactly.
Confirmed in Phase 2: `Cid` is **not** re-exported at the crate root — it lives as `pub` inside the
`compose` module and callers name it `compose::Cid`. `ComposeUrl` gets the same treatment and nothing
extra; no crate-root re-export is added.

Tests: no test constructs `ComposeUri::Http` directly (grep-confirmed — all go through
`ComposeUri::parse`), so **no existing test needs editing to keep compiling**. `tests/compose_uri.rs`
and `tests/compose_http.rs` keep their intent unchanged. New tests are added (below).

**No public-behavior regression:** `ComposeUri::parse` accepts and rejects exactly what it did
before, `Display` round-trips exactly as before (`compose_uri.rs:32` `uri.to_string() == s` still
holds), and every fetch path sends the same bytes.

---

## Test plan (seen-to-fail first — CLAUDE.md)

**Test approach follows `Cid`'s actual precedent, not trybuild** (AMEND conceded in Phase 2). My
first draft proposed a `trybuild`/`compile_fail` test for the "cannot construct an invalid value"
property. That is wrong for this repo, for four reasons the developer surfaced and I accept:

1. **This repo explicitly rejected trybuild.** `tests/tcb_enforcement.rs` documents choosing a
   structural/regex guard *because* it is "toolchain-robust and does not rot the way a trybuild
   `.stderr` snapshot would across the pinned 1.97.1 / local 1.98 split." A `.stderr` snapshot test
   is a known-bad pattern here.
2. **The `Cid` precedent this design claims to mirror did not use trybuild.** `tests/compose_uri.rs`
   proves `Cid`'s unconstructability with a prose RED-artifact comment + runtime parse-rejection
   tests + a structural argument in prose. Mirroring `Cid` means mirroring *that*, not adding a
   mechanism `Cid` never used.
3. **No trybuild dependency exists in the workspace,** and adding one cuts against the same
   minimal-deps posture VA-3 used to reject pulling in a CID crate.
4. **The structural proof is airtight without a compiled artifact.** Per the "sole mechanism"
   section above, a private field on the newtype is the *only* way in, and Rust's module boundary
   already guarantees it at compile time for the whole crate. There is no bypass gap for a
   `compile_fail` test to catch that the type system does not already close — so the compiled
   negative would assert a property the language already enforces, buying nothing.

The seen-to-fail obligation is still honored — it is discharged **empirically, the way the developer
already did it**: on the pre-fix tree at `529deda`, `ComposeUri::Http("file:///…".to_owned())`
compiles and passes (the RED artifact — the bug demonstrated, not asserted from belief); after the
change that expression cannot be written because `Http` no longer takes a `String` and `ComposeUrl`
has no public constructor or field. That transition is recorded in prose as a RED-artifact comment on
the new tests, exactly as `Cid` records its own.

1. **Seen-to-fail — the raw-construction escape hatch is gone (structural + RED artifact).**
   Record, as a prose comment mirroring `Cid`'s in `compose_uri.rs`, that `ComposeUri::Http(String)`
   was constructible with an arbitrary string on `529deda` (verified: it compiles and passes
   pre-fix), and that after the newtype the inner field is private so no such value can exist — the
   private field being the sole and complete mechanism (see above). No `compile_fail`/trybuild test;
   the module boundary is the proof, and the runtime rejection tests below pin the constructor's
   behavior.

2. **Constructor rejects a bad scheme (runtime).**
   `assert_eq!(ComposeUrl::parse("file:///etc/passwd"), Err(UriError::UnsupportedScheme("file".into())))`
   and `assert_eq!(ComposeUrl::parse("app-compose.json"), Err(UriError::NoScheme))`. This pins that
   the *only* validation the newtype performs is the scheme allowlist, with the same verdicts
   `ComposeUri::parse` already returns — the no-drift property made testable.

3. **Constructor accepts both schemes, verbatim.**
   `ComposeUrl::parse("http://example.invalid/c.json")` and the `https` form both `Ok`, and
   `.as_str()` returns the input unchanged (no normalization — it is fetched verbatim).

4. **No-drift, stated as one assertion.**
   For a representative set of strings, `ComposeUri::parse(s).map(ComposeUrl from the Http arm)` and
   `ComposeUrl::parse(s.trim())` agree on accept/reject and on the resulting string — the mechanical
   proof that the two entry points share one definition. (This is the VA-3 finding-2 lesson turned
   into a guard rather than a comment.)

5. **Regression: existing behavior unchanged.**
   `tests/compose_uri.rs` and `tests/compose_http.rs` pass unedited. Explicitly re-confirm
   `parses_http_and_https` (`compose_uri.rs:24`) and the `HttpUrl` fetch tests
   (`compose_http.rs:209-266`) are green — they exercise the round-trip and the verbatim GET.

**Toolchain (from brief):** build/test `--no-default-features --features fetch` and `--features
connect`; clippy with only `-A clippy::chunks_exact_to_as_chunks`; `wasm32` is CI-only.

---

## What this design does NOT do (guardrails)

- **No host/port/private-range/SSRF policy.** VA-3 §3 settled that retrieval is untrusted, the
  sibling sources legitimately target loopback, and a blocklist is theater against DNS rebinding.
  `ComposeUrl::parse` validates the scheme and stops. This document does not reopen it.
- **No redirect-policy change.** `max_redirects(0)` in `agent()` is untouched.
- **No `Fallback`/`Cached`/MI-5 disturbance.**
- **No rename of the `HttpUrl` `Source`.** Only the new value type is named `ComposeUrl`.
- **No `From`/`FromStr`/serde on `ComposeUri` or `ComposeUrl`** — adding one would reopen the exact
  bypass being closed. If serde is ever wanted, it must deserialize through `parse`, not derive a
  field-wise impl. Flag, do not build.

---

## Rejected alternative — (b), accept and document the asymmetry

Coherent and honestly close to break-even on security, since the residual is a spurious-refusal-only
risk. Rejected because: it leaves a type violating its own advertised invariant; the operator asked
for resolution; and (a)'s cost (a ~30-line newtype mirroring one that already exists, zero broken
callers, zero behavior change) is low enough that the "ceremony without value" argument does not
carry. Recorded here so the operator sees it was weighed, not skipped.

---

## Least-certain point (resolved in Phase 2)

The one thing I flagged as least-certain — the newtype's **name** — is now settled: `ComposeUrl` is
forced, not chosen, because `HttpUrl` is already a `pub struct` re-exported into the same `compose`
namespace and would collide. Nothing else in the design was contested.

---

## Decision log

- **Phase 1 (architect):** Decided (a), close the asymmetry with a validated value newtype;
  recommended the name `ComposeUrl`; flagged the name and the trybuild test approach as open.
- **Phase 2 (developer critique, `team/va-3-http/critique.md`):** AGREE on (a), the `ComposeUrl`
  name, and the newtype shape. No OBJECT. One AMEND on the test approach.
  - **AMEND — drop trybuild/`compile_fail`, follow `Cid`'s actual pattern (runtime
    parse-rejection + prose RED-artifact + structural argument).** **Conceded.** The four reasons
    (repo rejected trybuild in `tcb_enforcement.rs`; `Cid` precedent used no trybuild; no trybuild
    dep exists and adding one fights minimal-deps; the private-field structural proof is airtight so
    a compiled negative catches nothing the type system does not) are correct. Test plan rewritten
    accordingly.
  - **Doc correction (i) — "make the variant's field private" is not a separate option;** enum tuple
    fields have no per-field visibility, so the newtype is the sole mechanism. **Folded in** as its
    own section.
  - **Doc correction (ii) — `Cid` is not re-exported at crate root;** it is `pub` inside
    `pub mod compose`. **Folded in;** `ComposeUrl` gets the same, nothing extra.
- **Outcome:** consensus reached in one round. No open questions for the operator. Ready for
  implementation and reviewer sign-off (ADR 0018).
- **Phase 3 (developer implementation, `vahttp-developer`):** Implemented as designed — `ComposeUrl`
  added to `src/compose.rs` (private inner `String`, sole `parse` constructor, `Display`, `as_str`),
  `ComposeUri::Http(String)` → `Http(ComposeUrl)`, `ComposeUri::parse` routes its http(s) branch
  through `ComposeUrl::parse` (the `split_once("://")` error split moved into it, preserving the
  existing `UnsupportedScheme`/`NoScheme` split), and the three `compose/http.rs` sites updated
  (`get(url.as_str(), ...)`, two `url.to_string()` in the `Unsupported` arms). Test plan implemented
  exactly as the Phase 2 revision specifies: a prose RED-artifact comment in `tests/compose_uri.rs`
  (mirroring `Cid`'s, citing the empirical Phase-2 confirmation that
  `ComposeUri::Http("file:///etc/passwd".into())` compiled and ran clean on `529deda`), plus four new
  runtime tests — bad-scheme rejection, bare-string rejection, both-schemes-accepted-verbatim, and the
  no-drift assertion between `ComposeUri::parse`'s Http arm and `ComposeUrl::parse` called directly.
  No `trybuild`/`compile_fail`, as agreed.
  - **Forced deviation 1 (mechanical):** the no-drift test's two local bindings (`via_uri`/`via_url`
    in the original draft) tripped `clippy::similar_names` (a `pedantic` lint this workspace runs at
    `warn`, promoted to `-D warnings`). Renamed to `wrapped_in_http_variant`/`parsed_directly` —
    no behavior change, purely a naming fix to pass the existing gate.
  - **Forced deviation 2 (mechanical):** the design's skeleton doc-links `HttpUrl` as
    `` [`HttpUrl`](crate::compose::HttpUrl) ``. Under `--all-features`, rustdoc's
    `redundant_explicit_links` lint (warn-by-default) flagged the explicit target as redundant since
    the plain autolink `` [`HttpUrl`] `` resolves to the same item. Simplified to the plain form;
    `cargo doc --no-deps --all-features` is now warning-free. Under default features (`fetch` off),
    the link is unresolved either way — pre-existing pattern in this crate (10 other
    ungated-doc-links-to-gated-item warnings already exist, e.g. `verdict.rs` → `crate::connect::*`;
    confirmed by diffing warning counts before/after: 10 baseline → 11 with this change, +1 as
    expected, no new category introduced).
  - No other deviations. All eight blast-radius sites match the table exactly; zero existing tests
    were edited to keep compiling, confirming the Phase 2 claim.
- **Phase 4 (fresh-eyes reviewer, no design context):** LGTM-with-nits. Confirmed the bypass analysis
  independently (private field, no `From`/`FromStr`/serde, one shared validity definition), the
  rejection tests assert specific error variants, and every call site is correct. Four findings:
  1. **FIX** — `[HttpUrl]` doc-linked from `ComposeUrl`'s type docs is exactly the new
     unresolved-link warning under default features that Forced deviation 2 above already flagged as
     the one new warning this diff adds to any leg. Unlink to plain text, matching how the module
     docs already write `Gateway`/`KuboRpc` (`compose.rs:15-16`).
  2. **FIX** — the docs overstated "the two cannot disagree about what a valid Http URL is":
     `ComposeUri::parse` trims before calling `ComposeUrl::parse`, and `ComposeUrl::parse` does no
     trimming of its own, so `ComposeUrl::parse(" http://x ")` called directly rejects what
     `ComposeUri::parse(" http://x ")` accepts. The *scheme-validity* verdict still agrees in every
     case; only whitespace handling differs, and only because trimming is deliberately the caller's
     step. Doc corrected to say so precisely.
  3. **FIX** — the no-drift test was six fixed vectors in a file that already uses `proptest`.
  4. **Developer's call (nit, not blocking)** — whether to add a bare `compile_fail` doctest as a
     regression guard against a *future* `From<String>`/`FromStr`/`Deserialize` impl reopening the
     bypass, which the current private-field argument describes but does not prevent going forward.

  **Applied:**
  1. `[HttpUrl]` unlinked to plain text.
  2. Added a doc paragraph to `ComposeUrl::parse` stating trimming is the caller's step and giving the
     exact counter-example, and reworded the "cannot disagree" claim to name the scheme-validity
     verdict specifically. Added a whitespace-padded vector
     (`"  http://example.invalid/c.json  "`) to the fixed-vector test with a comment explaining why it
     still agrees (the test trims on both sides to compare like for like, which is the property it
     actually pins — not raw-string equality).
  3. Added `compose_uri_parse_and_compose_url_parse_never_disagree_for_any_string`, a `proptest` over
     `.{0,64}` inside the existing `proptest!` block, pinning the universal form of the fixed-vector
     test (same trim-on-both-sides comparison).
  4. **Decision: added the `compile_fail` doctest.** On reflection this is a different claim than the
     one rejected in Phase 2, and the Phase 2 critique conflated two things that are not alike:
     - Phase 2's objection to `trybuild` was specifically about **`.stderr` snapshot matching** —
       pinning the literal rendered diagnostic text, which is exactly what
       `tests/tcb_enforcement.rs` documents rejecting for being toolchain-version-sensitive (the
       1.97.1/1.98 split). A **bare `compile_fail` doctest with no error-code or message pinned**
       carries none of that: rustdoc checks only whether compilation failed, a boolean outcome
       stable across compiler versions and diagnostic wording changes. It is closer in kind to the
       "regex, toolchain-robust" guard `tests/tcb_enforcement.rs` *chose* than to the snapshot form
       it rejected.
     - It also needs no new dependency — `compile_fail` is a built-in rustdoc doctest attribute, not
       the `trybuild` crate — so Phase 2's dependency objection doesn't apply to this form at all.
     - Most importantly, it closes a real, distinct gap: the structural "private field" argument is a
       true description of *today's* code, not an enforced constraint on *tomorrow's*. A future
       `From<String>` or derived `Deserialize` added to `ComposeUrl` or `ComposeUri` — plausibly by
       someone who never reads this design doc — would silently reopen the exact bypass this whole
       follow-up exists to close, and nothing else in the suite would catch it. The doctest would.
     - `Cid` lacks the equivalent guard, which is an inconsistency, not a reason to skip a genuine
       improvement — it is recorded here as a residual worth a future follow-up (add the same
       `compile_fail` doctest to `Cid`) rather than a reason to withhold it from `ComposeUrl`.
     Added as a `# Examples` section on `ComposeUrl`'s type doc, reproducing the exact expression used
     as evidence throughout this design (`ComposeUri::Http("file:///etc/passwd".to_owned())`), with no
     `.stderr` pinning and no error-code annotation. Confirmed passing (rustdoc reports the expected
     compile failure as `ok`) under both default and `--all-features` doctests.
  **Gate results after this round:** `cargo fmt --all --check` clean; `cargo clippy --all-targets
  --all-features -- -D warnings -A clippy::chunks_exact_to_as_chunks` clean (and clean per feature leg);
  `cargo test -p verity-verifier --all-features` green — `compose_uri` now 17 tests (was 16), 10
  doctests (was 9, +1 for the new `compile_fail`); the fetch leg (compose tests + lib, matching VA-3's
  own scoping — the crate-doctest gap under `fetch`-only is pre-existing and unrelated) and the
  `connect` leg (full suite including doctests) both green; default-features full suite green;
  `cargo build --workspace --all-targets` clean; `cargo doc --no-deps --all-features` 0 warnings;
  `cargo doc --no-deps` (default features) back down to the 10 pre-existing warnings baseline (the
  extra one from finding 1 is gone).

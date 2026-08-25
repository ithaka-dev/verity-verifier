# Design — VA-3 / MI-5: harden compose retrieval; multi-gateway (+ deferred file cache)

**Repo:** `verity-verifier` @ `2ecbedf` · **Module:** `crates/verity-verifier/src/compose.rs`
+ `compose/http.rs`, all behind the `fetch` feature · **Author:** va3-architect (rust-team cycle)
**Status:** draft — for developer consensus (ADR 0026), then reviewer sign-off (ADR 0018).

---

## 0. Decision summary (read this first)

| # | Decision | Choice |
|---|---|---|
| 1 | CID validation | **(B) dependency-free strict-charset**, as the invariant of a new `Cid` newtype, **plus** percent-encoding at every interpolation site. No `cid`/`multibase` crate. |
| 2 | Redirects | **Mirror connect: `.max_redirects(0)`** on the shared compose agent. |
| 3 | `HttpUrl` policy | **Keep, document explicitly, no private-range blocklist**; redirect-0 closes the sharp edge. Recommend a **separable `fetch-http-url` feature gate** as the deliberate answer to "consider removing" — flagged to the team, not built silently. |
| 4 | MI-5 | **Split. Build multi-gateway `Fallback` now** (small, clear liveness win). **Defer the file-backed cache** — its marginal value is low and its questions are answered below so it is specified if a concrete need appears. |
| 5 | Scope | **Two changes.** VA-3 first (security), then MI-5 (multi-gateway). Separate reviewer gates. |

The one I was least certain about is **#1's `Cid` newtype** (a pre-1.0 breaking change to a public
variant) versus keeping `Ipfs(String)` and relying on sink-side encoding alone. Both satisfy the
security property; the newtype costs churn now to make the illegal state unrepresentable. Reasoning
in §1.4.

---

## 1. Decision 1 — CID validation: dependency-free strict-charset (B)

### 1.1 What the security property actually is

The stakes (per brief): retrieval is **outside the trust model**. A wrong or hostile document is
caught by the hash check that runs after every fetch. VA-3 is entirely about **retrieval-side
effects that happen before that check** — SSRF, injection, path traversal, redirect-to-internal.
For the CID specifically the property is exactly:

> No byte of the CID string may alter the structure of the request URL it is interpolated into —
> neither the path (`{base}/ipfs/{cid}`, `http.rs:113`) nor the Kubo query value
> (`{api}/api/v0/cat?arg={cid}`, `http.rs:158`).

That is a **lexical** property of a byte string, not a semantic property of a CID. We do not need to
know the CID's multibase, codec, or multihash — we need to know it contains no URL-significant or
control byte.

### 1.2 Why (B) over (A) — the crate

Chosen: **(B) strict-charset rejection, dependency-free.** Rejected: **(A) a `cid`/`multibase` crate.**

- **Trust surface.** The `cid` crate pulls `multibase` + `multihash` + `unsigned-varint` (and their
  trees) onto the **crown-jewel verifier**, whose entire discipline (workspace manifest, ADRs) is
  deliberate dependency minimalism. Each is now a crate `cargo deny` / `cargo audit` must track (CI
  runs both). Spending that surface to validate something **outside the trust model** is a bad
  trade.
- **It would over-claim.** A CID-crate parse establishes "this is a structurally valid CID." All we
  are entitled to assert, and all the security property needs, is "this is safe to interpolate."
  Naming a validator `is_valid_cid` when its job is interpolation-safety is exactly the kind of
  mislabel the project warns against.
- **It converts hardening into a spurious-refusal path.** A CID-crate rejects valid-but-unusual or
  future CID forms its version does not know. This whole component already tilts toward refusal
  (`Unestablished::RetrievalFailed` → Indeterminate); coupling retrieval **liveness** to a
  CID-spec-tracking dependency, for zero trust benefit, adds a refusal vector we do not need.
- **It does not even save the encoding step.** Some multibase alphabets are *not* URL-safe — base64
  standard (`m` prefix) contains `+ /`. A CID crate would happily accept those, and we would then
  have to percent-encode anyway. So (A) accepts a **broader, less-safe** input surface and still
  needs the sink defense.

### 1.3 Weighing the FI-1 lesson — both ways

FI-1 ("a taxonomy of gates that do not guard", `verity-foundation/records/experiments/2026-08-15-…`)
taught: *a check that must understand its input's **semantics** has to **parse** it, not scan bytes* —
a hand-rolled lexer for chain-ids was bypassed ~18 ways. That lesson applies when the property is
semantic (which chain, which image reference hiding among others).

Here the property is **not** semantic. "No URL-significant byte reaches interpolation" is a
character-set predicate — the one shape where a whitelist is the *correct and exhaustively
verifiable* tool, and a structural parser is the wrong, heavier one. The FI-1 failure was scanning
where parsing was required; doing the reverse (parsing where a charset predicate suffices) would
import the very dependency-and-overclaim risk FI-1's cousin lessons warn about.

**The honest statement of what the check establishes** (goes in the doc comment): *this string
contains only characters that cannot alter URL structure — it is safe to interpolate. It is **not** a
claim that the string is a valid CID; validity is irrelevant because a wrong document is caught by
the hash check.*

### 1.4 Where the invariant lives — a `Cid` newtype (the least-certain call)

`ComposeUri::Ipfs(String)` today has a **public tuple field**. Validating only inside
`ComposeUri::parse` is therefore **insufficient**: any caller can write
`ComposeUri::Ipfs("../admin".into())` and bypass the parse gate. The sink (interpolation in
`http.rs`) is the only point every CID actually funnels through.

Two ways to make the property hold:

- **Chosen — carry the invariant in the type.** Introduce a validated newtype with a **private**
  inner and a validating constructor; the variant holds it. The illegal state becomes
  unrepresentable — a `ComposeUri::Ipfs(_)` *always* holds an interpolation-safe value, whoever
  built it.

  ```rust
  /// A content identifier whose string form is safe to interpolate into a request URL.
  ///
  /// The invariant is **interpolation-safety, not CID validity**: the inner string contains no
  /// URL-significant or control byte (see `UriError::InvalidCid`). It is deliberately *not* a claim
  /// that the value is a structurally valid CID — a wrong document is caught by the hash check, so
  /// CID validity is not this type's job. Retrieval is outside the trust model.
  #[derive(Debug, Clone, PartialEq, Eq, Hash)]
  pub struct Cid(String); // inner PRIVATE — the only constructor validates

  impl Cid {
      /// # Errors
      /// [`UriError::EmptyCid`] if empty; [`UriError::InvalidCid`] if it contains any byte outside
      /// the interpolation-safe set (§1.5).
      pub fn parse(s: &str) -> Result<Self, UriError> { /* charset gate */ }
      #[must_use] pub fn as_str(&self) -> &str { &self.0 }
  }

  // Required — the `ComposeUri::Ipfs(cid)` Display arm and the http.rs interpolation sinks both
  // format the CID; without this the `{cid}` sites do not compile.
  impl fmt::Display for Cid {
      fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(&self.0) }
  }

  pub enum ComposeUri {
      Ipfs(Cid),      // was Ipfs(String)
      Http(String),
  }
  ```

- **Rejected-lighter — keep `Ipfs(String)`, validate at `parse` + encode at the sink.** Simpler, no
  API change. Sink percent-encoding *does* fully neutralize even a directly-constructed bad variant
  (`../admin` → `..%2Fadmin`, `cid&x=y` → `cid%26x%3Dy`), so the security property still holds. But
  the public tuple field then *invites* the bug back — a future `From`, deserialization, or careless
  caller reopens it, and the type tells the reader nothing. For a **pre-1.0** crate (`0.0.0`) the
  newtype is cheap now and expensive after release; that is precisely the versioning commitment this
  role exists to get right.

**Why I flag it:** the newtype touches the public API, `Display`, `cid()`, `http.rs`, and the URI
tests — real churn — while the lighter option is defensible on pure security grounds. I recommend
the newtype; the developer should push back if the churn is judged to outweigh the legibility.

`cid()` becomes `Option<&Cid>` (or keep `Option<&str>` via `Cid::as_str` to avoid rippling the
public accessor — developer's call). `UriError` gains one variant (already `#[non_exhaustive]`):

```rust
/// A CID containing a byte that could alter URL structure (`/ ? # & % : @ [ ] .`, whitespace,
/// or an ASCII control character). Rejected before it can reach a gateway path or a Kubo query.
#[error("ipfs:// CID contains a character unsafe to interpolate")]
InvalidCid,
```

### 1.5 The charset — a conservative safe *subset*, tuned to reject

This is an **allowlist, not a blacklist** — and that is the crux of why FI-1 does not apply. Allowed:
ASCII alphanumeric `[A-Za-z0-9]` plus base64url's `-` and `_`. Everything not on that list is rejected
(`/ ? # & % : @ [ ] .`, all whitespace, all non-ASCII, all ASCII control, and anything else). A
blacklist has to *enumerate the dangerous* and fails on the one it forgot — that is the FI-1 failure
mode. An allowlist over a purely lexical property has **nothing to under-enumerate**: a byte is either
in the safe set or rejected, so there is no "forgotten dangerous character." That is exactly why a scan
is the correct tool *here* and was the wrong tool for FI-1's semantic problem.

This is a **deliberate subset**, not CID-completeness. The IPFS canonical CID string forms used for
addressing — base32 (`b…`, the CIDv1 default), base58btc (`Qm…`), base36 (`k…`), base16 (`f…`) — are
all within `[A-Za-z0-9]`. base64url (`u…`, alphabet exactly `[A-Za-z0-9-_]`) also **passes** the
charset — harmless, because it is still hash-checked, but note the honest limit: **passing the charset
is not the same as being a real CID form.** The gate asserts interpolation-safety only; it is not
claiming the input is a valid or canonical CID (§1.3). We reject base64-standard (`+ /`) forms: those
are not used for `ipfs://` addressing in practice, and if one ever appears the outcome is a **spurious
refusal (fail-closed, safe direction)**, never a bypass. The set is chosen to be provably
interpolation-safe and to *reject* the ambiguous, not to be a CID parser.

```rust
fn is_interpolation_safe(s: &str) -> bool {
    !s.is_empty()
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
```

### 1.6 Defense-in-depth: percent-encode at the sink regardless

Independently of §1.4, percent-encode the CID at both interpolation sites so a *future relaxation of
the charset gate* cannot reopen injection — especially the Kubo `?arg=` **query value**, where `& = #`
are structurally significant.

- Dependency-free: a small total function encoding every byte outside the unreserved set
  (`A-Za-z0-9-._~`) as `%XX`. It is a byte→`%XX` map — exhaustively testable, unlike a parser. For
  the validated subset it is a **no-op on the happy path** (all allowed bytes are unreserved), and a
  hard stop for anything that slips through.
- `percent-encoding` crate is an acceptable alternative if the reviewer prefers a vetted impl; I
  recommend the inline helper to stay consistent with the no-new-deps decision, since the charset
  gate is the real guarantee and this is belt-and-suspenders.

```rust
// http.rs — at the two sinks:
ComposeUri::Ipfs(cid) => get(&format!("{}/ipfs/{}", self.base, encode(cid.as_str())), limit),
ComposeUri::Ipfs(cid) => post(&format!("{}/api/v0/cat?arg={}", self.api, encode(cid.as_str())), limit),
```

### 1.7 wasm

`fetch` is off on `wasm32-unknown-unknown` today, so an added dep under `fetch` would not *by
itself* break the wasm build (assumption in the brief — **confirmed** against
`crates/verity-verifier/Cargo.toml`: `fetch = ["dep:ureq"]`, and `verity-verifier-wasm` does not
enable it). But (B) sidesteps the question entirely: the charset gate and the encoder are
`no_std`-compatible pure functions with zero new crates, so they cannot regress the wasm leg the
crate's discipline protects.

---

## 2. Decision 2 — redirects: mirror connect's `max_redirects(0)`

The compose `agent()` (`http.rs:45`) sets connect + total timeouts but **no redirect policy**; ureq
follows redirects by default, so a fetch can be bounced into loopback/private targets (SSRF) — the
side effect landing *before* the hash check, which is exactly VA-3's class.

The in-crate precedent is `connect/http.rs:369` (`agent_config`), `.max_redirects(0)` with a full
rationale, guarded by `a_redirect_to_another_host_is_not_followed` (`:722`). The compose agent uses
the **same ureq 3.3 `ConfigBuilder`** (`ureq::Agent::config_builder()`), so the method transfers
unchanged:

```rust
fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_connect(Some(DEFAULT_CONNECT_TIMEOUT))
        .timeout_global(Some(DEFAULT_TOTAL_TIMEOUT))
        // A content-addressed gateway has no legitimate reason to bounce us elsewhere. Following a
        // redirect would carry the fetch to a host nobody chose — into loopback/private space — and
        // the harm is the *request*, since it lands before the hash check. With this at 0, ureq
        // returns the 3xx itself; its small body then fails the hash check → refusal. Mirrors
        // `connect::http::agent_config`; `script/mutate.sh` raising it is the mutant the test kills.
        .max_redirects(0)
        .build()
        .into()
}
```

**Implementation note (fixes the mutate.sh claim).** `script/mutate.sh` today only mutates
`connect/http.rs`; the comment above would otherwise reference a mutant that does not exist. **This
change adds the compose-agent mutant** (raise `compose/http.rs`'s `max_redirects(0)` → `10`) to
`mutate.sh` in the same VA-3 commit, so the comment is true *and* the redirect guard is continuously
exercised — fully mirroring the connect precedent (`a_redirect_to_another_host_is_not_followed` is the
test that kills the connect mutant; the new compose redirect test kills this one). Chosen over merely
rewording the comment: the connect precedent pairs the claim with a real mutant, and a comment that
points at a guard should point at one that exists.

**Rejected — a revalidate-each-redirect policy.** More code, and there is no legitimate redirect for
a content-addressed fetch; the caller can point at a working gateway. `0` keeps the policy in one
place and matches precedent. (Note for the developer: the rationale now lives in two agents; a
one-line cross-reference comment keeps them from drifting, but they are different features and should
not be forcibly merged.)

---

## 3. Decision 3 — `HttpUrl` scheme/host policy

`HttpUrl` (`http.rs:201`) GETs any `http(s)://` URL with no scheme/host/port/private-range policy.
The audit recommends an explicit policy and floats *"consider removing arbitrary HTTP retrieval."*

**Decision: keep it, document the policy explicitly, add no private-range blocklist; recommend a
separable `fetch-http-url` feature gate as the deliberate answer to "consider removing."**

Why not a private-range blocklist:

- It would be **security theater** here. The redirect-0 change (§2, shared agent) closes the sharp
  redirect-to-internal edge. A static IP/loopback blocklist is defeated by DNS rebinding, and —
  decisively — the sibling sources are *designed* to hit loopback: `Gateway::new("http://127.0.0.1:8080")`
  and `KuboRpc::new("http://127.0.0.1:5001")` are the intended local-node deployments. A blocklist
  cannot tell the legitimate local gateway from an SSRF probe, because the source does not know
  deployment intent.
- The residual risk is a **pre-hash GET to an operator-relevant URL**. Since retrieval is outside
  the trust model and the hash check is authoritative, the embedder controls this risk by **choosing
  whether to enable `HttpUrl` at all** — which is what the feature gate makes concrete.

The documented policy (goes on `HttpUrl`): *fetches exactly the URL given; follows no redirects
(shared agent); caps size and total time; performs **no** private-range or scheme filtering. Whether
to point it at a manifest you do not trust is the embedder's decision — retrieval is untrusted and
the hash check is authoritative.*

**Recommended follow-up — CONFIRMED (b): documented recommendation, raised-but-deferred, NOT built in
VA-3 (or MI-5).** Gate `HttpUrl` and `ComposeUri::Http` retrieval behind a distinct `fetch-http-url`
feature so an IPFS-only embedder never compiles the arbitrary-URL path — turning the audit's "consider
removing" into a **compile-time opt-out** rather than a deletion, and leaving the product-level
question (should the manifest schema permit `http` compose URIs at all? — a spec/`verity-contracts`
question) where it belongs, not decided unilaterally here. The developer confirmed it composes cleanly
with `fetch`/`connect`/`attest`. It is deliberately **not** implemented in either change: the audit
only *recommends* it, it is a public feature-surface addition, and VA-3 must stay tight to the security
core. Raise it to the team as its own decision; if adopted it is a third, separate change.

---

## 4. Decision 4 — MI-5: multi-gateway now, file cache deferred

### 4.1 Sanity-check: is MI-5 needed now?

- **Gateway-down → Indeterminate already works.** `FetchError` → `Unestablished::RetrievalFailed`
  (`compose.rs:151`) already surfaces an outage as Indeterminate at the verdict level. MI-5 adds
  nothing to *that* half.
- **Multi-gateway fallback** is genuine, low-complexity **liveness** value (public gateways are
  flaky): try the next source before giving up. **Build it now.**
- **File-backed cache**: its marginal value over the existing in-memory `Cached` is *restart
  survival*. That is low against the on-disk-atomicity/tampering/invalidation complexity it adds, and
  the "gateway down → Indeterminate" outcome it partly justified is already delivered. **Defer** —
  but the questions the `Cached` doc named as the reason for deferral are *answered* in §4.3 so it is
  specified, not inherited, if a concrete offline/rate-limited need appears.

### 4.2 Multi-gateway `Fallback` (build now)

A combinator `Source`, same wrapper shape as `Cached`:

```rust
/// Tries each inner source in order; the first success wins, an outage falls through to the next.
///
/// **Only all-down surfaces as a failure**, and it reuses the existing
/// `From<&FetchError> for Unestablished` mapping (→ `RetrievalFailed` → Indeterminate) — it does not
/// fork it. A single reachable source is enough to establish a verdict.
pub struct Fallback<S> {
    first: S,
    rest: Vec<S>,
}

impl<S: Source> Fallback<S> {
    /// At least one source, by construction — no empty list to guard against at fetch time.
    #[must_use]
    pub fn new(first: S, rest: Vec<S>) -> Self { Self { first, rest } }
}

impl<S: Source> Source for Fallback<S> {
    fn fetch(&self, uri: &ComposeUri) -> Result<Vec<u8>, FetchError> {
        // try in order; on Err, remember and continue; return last Err if all fail.
    }
}

// So a heterogeneous list (a Gateway + a KuboRpc) works via Fallback<Box<dyn Source>>:
impl<S: Source + ?Sized> Source for Box<S> { /* delegate */ }
```

Decisions inside `Fallback`:

- **Non-empty by construction (AMEND, conceded).** `new(first, rest)` rather than `new(Vec) -> Result`.
  An empty source list is a *caller mistake*, not a retrieval outcome, so it should be a type-level
  impossibility, not a runtime `Result` the fetch path has to carry — the same "make illegal states
  unrepresentable" argument §1.4 uses for the `Cid` newtype. Applying it to `Cid` but not `Fallback`
  would be inconsistent; the developer was right to call that out.
- **Homogeneous by default** (`Fallback<Gateway>` for a gateway *list*, per the brief), heterogeneous
  via `Fallback<Box<dyn Source>>` enabled by the blanket `impl Source for Box<S>`. `Source::fetch`
  is already object-safe (`&self`, no generics), so this is free.
- **All-down → return the last error**, which maps to `RetrievalFailed`. Any variant maps there, so
  the choice is only about the message; last is fine. Do **not** let an `Unsupported` (wrong URI
  kind) short-circuit the chain — treat it like any other miss and try the next.
- **Bounded duration is additive.** Each inner source already carries connect+total timeouts, so N
  dead sources cost up to N × total_timeout worst-case. Document this and recommend **short lists
  (2–3)** and/or tightened per-source timeouts when used behind `Fallback`. Do **not** parallelize:
  the crate is sync, and fanning out to gateways adds complexity and load for a document that is a
  few kilobytes. This honors the rust-architect "bounded concurrency + bounded duration" discipline
  without importing a runtime.

Layering composes cleanly: `Cached<Fallback<Gateway>>` — cache in front of a fallback list.

### 4.3 File-backed cache (designed, **deferred** — answers, not inheritance)

If a concrete need appears, this is the specification. The **safety argument carries unchanged**: the
hash check reruns every call, so a poisoned/tampered on-disk entry causes only a **spurious refusal,
never a spurious success** — identical to `Cached`. The questions `Cached`'s doc deferred are
answered:

1. **Tampering → no integrity protection, by design.** The cache file is **untrusted**, exactly like
   the network. Bytes are hashed after load; tampering → hash mismatch → refusal. Therefore the
   cache needs **no** HMAC/signature. Adding one would falsely imply the cache is trusted — the kind
   of manufactured confidence the project explicitly refuses. *This is the answer the `Cached` doc
   asked for.*
2. **Key → filename: hash the URI.** Filename = `sha256(uri.to_string())` hex (`sha2` already a dep).
   Uniform across `Ipfs`/`Http`, collision-resistant, and **always path-safe** — never interpolate a
   raw CID or URL into a filesystem path (the §1 traversal concern, in a new sink). This sidesteps
   CID-as-filename entirely.
3. **Invalidation: none needed for correctness.** Content-addressed entries are immutable per CID.
   For `Http` a stale entry causes a *refusal*, not a wrong answer (same envelope). Add a **bounded**
   count/total-bytes cap mirroring `Cached::capacity`, evicting arbitrarily (every entry equally
   cheap to refetch) to cap disk growth.
4. **Atomicity: temp-file + atomic rename** (`fs::rename`, same filesystem) so a reader never sees a
   half-written entry; a torn read would fail the hash check anyway (safe), rename avoids the wasted
   refetch. A crash leaves an inert stray temp file, never a corrupt live entry.
5. **Read tolerance:** a missing/unreadable/corrupt file falls through to the inner source — mirrors
   how `Cached` tolerates a poisoned lock (`compose.rs:276`). Never propagate a cache I/O error into
   the verification path.

Interface mirrors `Cached` so it composes (`FileCached<Cached<Fallback<Gateway>>>`):

```rust
pub struct FileCached<S> { inner: S, dir: PathBuf, /* bound */ }
impl<S: Source> Source for FileCached<S> { /* load-or-fetch-then-atomic-write */ }
```

**Recommendation: do not build this in the MI-5 change.** Build multi-gateway; keep this design as
the record. Revisit when an offline or gateway-rate-limited deployment actually needs restart
survival.

---

## 5. Decision 5 — scope: two changes

**Two changes, VA-3 first.** ADR 0018 is per-issue review; VA-3 is a security fix that the brief
says must not be diluted or delayed by feature work; the two have independent test surfaces. Same
module is not enough to bundle a security fix with a liveness feature.

- **Change 1 — VA-3** (security, lands + is reviewed alone): `Cid` newtype + charset gate
  (§1.4–1.5), sink percent-encoding (§1.6), `max_redirects(0)` on the shared compose agent (§2, also
  covering `HttpUrl`), `HttpUrl` policy doc (§3). Includes the two seen-to-fail reproductions (§6).
- **Change 2 — MI-5** (scoped to multi-gateway `Fallback`, §4.2): reviewed separately. File cache
  **deferred** (§4.3). The `fetch-http-url` gate (§3) is a **third, optional** item to raise with the
  team, not folded into either.

Sequence: **VA-3 → MI-5 (multi-gateway).**

---

## 6. Test plan — seen-to-fail (red on the current tree first)

Per CLAUDE.md: **write the check from the failure** — build the malformed input / redirecting server
and capture it injecting/following *before* asserting the fix, asserting against the recorded
artifact.

### VA-3 (Change 1)

1. **CID injection — Kubo query.** Fake server records the request line. On the **current tree**:
   `KuboRpc::fetch(parse("ipfs://cid&timeout=0"))` sends `.../api/v0/cat?arg=cid&timeout=0` — assert
   the server sees `timeout=0` as a **separate query param** (RED, injection demonstrated). After
   fix: `parse` returns `UriError::InvalidCid` (the `&` is rejected); and even a directly-constructed
   `Cid` cannot exist with `&`, and the sink encoder would render `arg=cid%26timeout%3D0` as one
   value. GREEN.
2. **CID traversal — gateway path.** On the current tree: `Gateway::fetch(parse("ipfs://../admin"))`
   builds `.../ipfs/../admin` — assert the recorded request path **traverses** (RED). After fix:
   rejected at parse (`/` and `.`); sink encodes `%2E%2E%2Fadmin` if reached. GREEN.
3. **Charset proptest** (proptest already a dev-dep): any string containing a byte outside the
   allowed set is rejected by `Cid::parse`; every accepted string survives interpolation byte-for-byte
   unchanged. Strengthens the "exhaustively verifiable" claim §1.3 rests on.
4. **Redirect not followed** (mirror `connect`'s `a_redirect_to_another_host_is_not_followed`).
   Server A `302 → B`; B records that it was hit. On the **current compose agent** (no policy): the
   fetch follows to B — assert B recorded a hit / B's body came back (RED). After `max_redirects(0)`:
   B is never contacted; the fetch returns the 302's body (which then fails the hash check). GREEN.
   Add the same assertion for `HttpUrl` (shares the agent).

### MI-5 (Change 2)

5. **Fallback — first down, second up.** `Fallback` over [dead source, live source] returns the live
   source's body; the live one is the only success. (And first-up ⇒ second untouched.)
6. **Fallback — all down → Indeterminate.** All sources error; assert `fetch` returns `Err`, and that
   `Unestablished::from(&err)` is `RetrievalFailed` — pinning the reuse of the existing mapping, not a
   fork.

### File cache (only if later built)

7. **Tampered on-disk entry → refusal, not acceptance.** Poison the cache file; `FileCached::fetch`
   returns the poisoned bytes (the cache does not hash — hashing is upstream in `verify`), and the
   **pipeline refuses** at the hash check. Assert bytes-returned-but-verdict-refuses — the property
   is that the cache cannot manufacture a spurious success.
8. **Atomic write** — concurrent readers never observe a torn file (or a torn read → refusal).

---

## 7. Constraints honored

- **Feature legs:** all work behind `fetch`; build/test `--no-default-features --features fetch` and
  (for the redirect precedent) `--features connect`. No change to the `attest`/wasm legs (§1.7).
- **No new dependencies** (Decision 1B + inline encoder). `cargo deny` / `cargo audit` stay green with
  nothing added. If the developer prefers the `percent-encoding` crate for the encoder, that is the
  only dependency question and it is a reviewer-policy matter (§1.6).
- **Reuse, don't fork,** the `FetchError` → `Unestablished::RetrievalFailed` seam (§4.2). Do not
  touch `verdict.rs` / `verify.rs` (VA-1/VA-2 surfaces).
- **ADR 0019** commit-to-main with the review record in the commit message; **ADR 0018** reviewer
  sign-off gates each of the two changes; **ADR 0026** this rust-team cycle.
- Public-API note: the `Cid` newtype + `UriError::InvalidCid` are a pre-1.0 (`0.0.0`) surface change;
  `UriError` is already `#[non_exhaustive]`, and `ComposeUri` should stay so.

---

## 8. Decision log — Phase 2 consensus (architect ⇄ developer)

Developer AGREEd with the design (no OBJECT), having verified every claim against the live tree and
ureq 3.4.0 source, and firmly agreed the file-cache deferral. Folded in this round — **consensus
reached**:

- **AMEND conceded — `Fallback::new(first: S, rest: Vec<S>)`, no `Result`.** Empty list is a caller
  mistake, not a retrieval outcome; made unrepresentable, consistent with §1.4's `Cid` argument
  (§4.2).
- **Fix 1 — `impl fmt::Display for Cid`** added to the sketch; the `{cid}` interpolation sites need it
  to compile (§1.4).
- **Fix 2 — allowlist framing made explicit** ("allowlist, not blacklist" — an allowlist over a
  lexical property has nothing to under-enumerate, which is the sharpened reason FI-1 does not apply),
  and the honest limit stated: base64url (`u…`) *passes* the charset, but passing the charset ≠ being
  a real CID form (§1.5).
- **Fix 3 — resolved by ADDING the compose-agent mutant** (`max_redirects(0) → 10`) to
  `script/mutate.sh` in the VA-3 commit, rather than rewording. The comment now points at a mutant
  that exists, mirroring the connect precedent (§2, implementation note).
- **Fix 4 — `fetch-http-url` CONFIRMED (b): raised-but-deferred, NOT built** in VA-3 or MI-5. A
  documented recommendation for a separate future change; the audit only recommends it and it is a
  public feature-surface addition (§3).

No decision from §0 was reversed; the five headline choices stand as designed. Ready for
implementation (Change 1: VA-3, then Change 2: MI-5 multi-gateway), each under its own reviewer gate.

## 9. Implementation deviation — Change 1 (va3-developer)

**Forced fix, not a design change:** `crates/verity-verifier/tests/compose_http.rs` was missing the
`#![cfg(feature = "fetch")]` guard its sibling `compose_fetch.rs` already carries. Confirmed on a
clean checkout of `2ecbedf` (before touching anything, via `git stash`) that this made `cargo test
--no-default-features --features fetch` (default features, no `fetch`) and, more directly,
`cargo test --features connect` — one of the gates this cycle's implementation is checked against —
fail to *compile*, unrelated to VA-3: `Gateway`/`HttpUrl`/`KuboRpc`/`Source` are all
`#[cfg(feature = "fetch")]`, and this file had nothing gating on that.

Fixed by adding the one-line guard, mirroring the existing sibling-file pattern exactly (no test
logic touched). `cargo test --features connect` now compiles the file to zero tests, matching how
`compose_fetch.rs` already behaves under the same feature set, and passes.

**Left alone, flagged for the record:** `cargo test --no-default-features --features fetch` (fully,
across the whole test suite) still fails today — `tests/attest.rs`, `tests/tcb_enforcement.rs`,
`tests/verified_transport.rs`, `tests/verify_negative.rs`, and `tests/reference_and_verdict.rs` all
reference `verity_verifier::attest`/`verify`, which are `#[cfg(feature = "attest")]`, with no
matching guard on the test files — and `default = ["attest"]` means `--no-default-features` turns
`attest` off. Reproduced identically on a clean `git stash` of this change, so it predates VA-3 and
is out of scope here (`compose`-only per the facilitator's instruction; these are VA-1/VA-2/attest
surfaces). `cargo test --no-default-features --features fetch --lib --test compose_uri --test
compose_http` — the slice this change actually touches — is green. Recommend a follow-up issue to add
the missing guards across those five files; not done here.

## 10. Post-VA-3 follow-ups (reviewer findings, not fixed in this change)

Reviewer returned LGTM-with-nits on VA-3. Two findings are real but out of VA-3's injection/
traversal/redirect scope, and are recorded here as follow-ups rather than fixed in this change:

- **`ComposeUri::Http(String)` is still publicly constructible with an arbitrary string.** The
  enum's own doc says URIs are "parsed rather than passed around as a string" — true for `Ipfs`
  (the `Cid` newtype closes it) but not for `Http`, which still has a public tuple field. Low harm
  today: an `Http` URL is fetched verbatim and never interpolated into anything, `ureq` rejects
  non-`http(s)` schemes on its own, redirects are now off on the shared agent, and the architect's
  no-SSRF-blocklist decision (§3) is deliberate — but the asymmetry between the two variants is
  real and worth closing. Follow-up: a validated `Http` newtype (or at minimum a private field with
  a validating constructor), scoped as its own small change rather than folded into VA-3.
- **`script/mutate.sh --quick` silently mis-scores every feature-gated mutant, including the new
  compose one.** `--quick` drops `--all-features` (sets `CARGO_ARGS=()`), so `compose/http.rs` (and
  every `connect`/TLS mutant already in the file) isn't even compiled under `--quick` — the mutant
  can't be observed either way, and `run()` reports it as `SURVIVED` rather than "not exercised".
  Pre-existing pattern, not introduced by VA-3's addition, but VA-3's mutant inherits it. The
  header text ("skips the slow feature-gated suites") doesn't match what actually happens (nothing
  is skipped — mutants run against a binary that never contained the code being mutated), which is
  itself worth naming as a small gate-integrity issue on its own.

Both are being carried to the board by the facilitator rather than actioned here.

## 11. Implementation notes — Change 2 (va3-developer)

No forced deviations. `Fallback<S>` and the `impl<S: Source + ?Sized> Source for Box<S>` blanket
impl landed in `compose.rs` exactly as specified in §4.2, with the AMEND from §8
(`Fallback::new(first: S, rest: Vec<S>)`, no `Result`) as agreed. Scope held: nothing in
`compose/http.rs` was touched (`Fallback` wraps a `Source`, it doesn't change how any `Source`
fetches), and the file cache stays deferred per §4.1/§4.3 — not built.

Tests live in a new, deliberately **ungated** `tests/compose_fallback.rs`, mirroring
`dispositions.rs`'s own reasoning: `Fallback` is generic over any `Source` and needs no network, so
gating its tests behind `fetch` would mean the multi-gateway acceptance criteria don't run on a
plain `cargo test`. A local `Scripted` stub (success/failure + a call counter) stands in for a real
gateway.

Seen-to-fail: wrote `tests/compose_fallback.rs` referencing `Fallback` before it existed in
`compose.rs`; `cargo test -p verity-verifier --test compose_fallback` failed to compile
(`E0432: unresolved import`), confirming there was nothing to accidentally already satisfy the test.
After implementing, the same file is green (5/5): a working first source is used and the rest are
never touched (call-count asserted at 0); a dead first source falls through to a live second (both
call-counts at 1, in order); three sources fall through in order before a live third; all-down
returns an error whose `Unestablished::from(&err)` is `RetrievalFailed` — the *same* mapping
`dispositions.rs` already pins exhaustively, not a new one; and a single-source `Fallback` behaves
like the source alone (the degenerate case the non-`Result` constructor makes trivially
constructible, unlike an empty-`Vec` design would have needed a test for).

No new dependencies (`git diff --stat` on both `Cargo.toml`s and `Cargo.lock` is empty). Gates —
`cargo fmt --check`, workspace `cargo clippy --all-targets --all-features -- -D warnings`,
`cargo doc --no-deps`, `cargo test --all-features`, `cargo test --features connect`, and
`cargo test --no-default-features --features fetch` scoped to the lib plus
`compose_uri`/`compose_http`/`compose_fallback`/`dispositions` (the same pre-existing, out-of-scope
gap named in §9 for the other five integration test files) — all green.

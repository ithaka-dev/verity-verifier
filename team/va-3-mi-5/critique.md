# Critique — VA-3 / MI-5 design (va3-developer, Phase 2)

**Repo:** `verity-verifier` @ `2ecbedf` · Reviewed against the actual code in
`crates/verity-verifier/src/compose.rs`, `crates/verity-verifier/src/compose/http.rs`,
`crates/verity-verifier/src/connect/http.rs`, `crates/verity-verifier/Cargo.toml`, `Cargo.toml`
(workspace), `deny.toml`, and the three `tests/compose_*.rs` files. Every claim below that could be
checked against the live tree was checked, not taken on the architect's word.

Overall verdict: **AGREE with the design as a whole**, with one AMEND (Fallback's constructor
shape) and a handful of small implementation notes that don't change the shape.

---

## 1. `Cid` newtype vs. `Ipfs(String)` + sink-encoding — AGREE (with the newtype)

Checked every call site that would need to change:

```
crates/verity-verifier/src/compose.rs:52     doc example: matches!(uri, ComposeUri::Ipfs(_))
crates/verity-verifier/src/compose.rs:65     construction: Self::Ipfs(cid.to_owned())
crates/verity-verifier/src/compose.rs:80     match in cid()
crates/verity-verifier/src/compose.rs:89     Display: write!(f, "ipfs://{cid}")
crates/verity-verifier/src/compose/http.rs:113   Gateway match arm
crates/verity-verifier/src/compose/http.rs:157   KuboRpc match arm
crates/verity-verifier/src/compose/http.rs:205   HttpUrl match arm
crates/verity-verifier/tests/compose_uri.rs:14,30   asserts on .cid()
```

That's the entire surface — `grep -rn "ComposeUri::Ipfs\|\.cid()"` across `crates/` turns up nothing
else. In particular `verity-verifier-wasm` never touches `ComposeUri` directly, and `verdict.rs` /
`verify.rs` don't either. The architect's own worry ("real churn") overstates it: this is one
constructor, one accessor, one Display arm, and three match arms in a sibling module — a few hours
of mechanical work, not a sprawling API migration.

The substantive argument is right regardless of size: `ComposeUri::Ipfs(String)` has a **public
tuple field**, so validating only in `parse` is provably insufficient — `ComposeUri::Ipfs("../admin".into())`
compiles today and bypasses every gate the design would add at `parse`. A crate at `0.0.0` is exactly
the moment to make that unrepresentable; the cost only grows after anything depends on the shape.
Take the newtype.

One thing to get right that the design's own code sketch would break: `format!("{}/ipfs/{cid}", ...)`
and `write!(f, "ipfs://{cid}")` use `Display` via the `{cid}` shorthand. `Cid` as sketched has no
`Display` impl (only `as_str()`), so those three sites won't compile as-is — implement
`impl fmt::Display for Cid` (or change all three sites to `.as_str()`). Trivial, but call it out so
it isn't discovered mid-implementation as a surprise.

`cid()`: keep it `Option<&str>` via `Cid::as_str()` rather than rippling to `Option<&Cid>`. Nothing
downstream needs to construct a `Cid` from what `cid()` returns, and the narrower public surface is
consistent with the dependency-minimalism instinct running through the rest of this design.

## 2. CID charset — AGREE, and it's stronger than the brief's framing suggests

Verified the mechanism, not just the argument:

- **It's an allowlist, not a blacklist.** `s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')`
  rejects *everything* not explicitly permitted — `/ ? # & % : @ [ ] .`, all whitespace including
  CR/LF, all ASCII control, all non-ASCII (UTF-8 continuation bytes are ≥ 0x80, never
  `ascii_alphanumeric`), backslash, semicolon, quotes, angle/curly brackets — none of these needed to
  be individually enumerated. This is exactly why FI-1 doesn't apply here the way the brief worries
  it might: FI-1's failure was an *incomplete blacklist* trying to catch known-bad patterns in a
  semantic scan. An allowlist over a lexical property has nothing to be incomplete about — there's no
  list to under-enumerate. The design's §1.3 argument is correct; I'd state it even more plainly in
  the code comment than the draft does, because "allowlist, not blacklist" is the one sentence that
  makes the FI-1 comparison land.
- **Both sinks are covered.** Gateway path (`/`, `.` for traversal, `?`/`#` for path termination) and
  Kubo query value (`&`, `=`, `#` for parameter injection) are both closed by the same allowlist — no
  sink-specific reasoning needed, which is the point of a lexical rather than contextual check.
- **Confirmed the "no-op on the happy path" claim.** RFC 3986 unreserved = `ALPHA / DIGIT / "-" / "." / "_" / "~"`.
  The `Cid` charset (`alnum` + `-` + `_`) is a strict subset (missing `.` and `~`, which is fine —
  more conservative, not less). So percent-encoding a validated `Cid` is genuinely a no-op; the
  design's claim checks out.
- **One accuracy nit, not a security gap:** §1.5 says base64-standard forms (`+ /`) are rejected and
  "not used for `ipfs://` addressing in practice." True, but worth noting for the record: multibase
  `u`-prefixed base64url (no padding) uses exactly `A-Za-z0-9-_` — the *same* alphabet this charset
  allows — so a base64url CID would actually pass, not just fail closed. That's harmless (base64url
  is URL-safe by construction, which is why it happens to coincide) but the doc comment should say
  "we don't validate multibase prefix semantics, only interpolation-safety" rather than implying every
  accepted string is base32/base58/base36/base16 — it's a weaker, purely lexical claim and should read
  that way.

**Seen-to-fail reproductions are genuinely red-first.** I confirmed both against the actual code:
- `Gateway::fetch(parse("ipfs://../admin"))` today builds `{base}/ipfs/../admin` via
  `http.rs:113`'s unencoded `format!` — a real path-traversal string reaches the request. RED on
  current tree, no fix needed to observe it.
- `KuboRpc::fetch(parse("ipfs://cid&timeout=0"))` today builds `{api}/api/v0/cat?arg=cid&timeout=0`
  via `http.rs:157` — `&timeout=0` is a genuine second query parameter an HTTP server parses
  independently. RED on current tree.

Both reproductions require nothing hypothetical; `ComposeUri::parse` (`compose.rs:59-74`) has no
validation beyond "non-empty" today, so both malicious strings parse successfully as `Ipfs(_)` and
flow unmodified into the `format!` calls. Confirmed.

## 3. MI-5 file-cache deferral — AGREE, deferring is correct

My position: **defer it**, and the reasoning holds up from the code standpoint, not just the
liveness-vs-complexity framing.

- I verified `FetchError → Unestablished::RetrievalFailed` (`compose.rs:151-166`) is exhaustive and
  matched without a wildcard — so "gateway down → Indeterminate" is already true today for *any*
  fetch failure, with no MI-5 work required. The brief's headline ("file-backed cache + multi-gateway")
  reads as one feature but is actually two independently-motivated additions, and only one of them
  addresses something not already covered.
- The file cache's only real value over the existing in-memory `Cached<S>` (`compose.rs:218-298`,
  already bounded, already has the "poisoned cache → refusal, never a bypass" argument written and
  tested — `tests/compose_fetch.rs:318-413`) is **restart survival**. Nothing in the brief or the
  board describes an actual deployment that needs that today; it's speculative value against concrete
  complexity (atomic rename, a new filesystem sink that must itself avoid the exact CID-as-path-
  traversal problem VA-3 is fixing, a bounded eviction policy to reimplement).
- Building it now would also be scope creep relative to what the operator asked for read narrowly:
  "VA-3/MI-5" names both issues, but MI-5's own text (per the brief's summary) is satisfied at its
  more valuable half by `Fallback` alone. I'd rather ship the liveness win now and let the file cache
  be pulled in by an actual need than build speculative persistence with its own attack surface
  (a new sink that must independently prove it can't be tricked into writing/reading outside its
  cache directory) against no immediate requirement.
- The design's §4.3 spec answers the exact questions `Cached`'s own doc comment (`compose.rs:227-228`)
  named as the reason it stayed in-memory — tampering, keying, invalidation, atomicity — so nothing
  is being hand-waved; it's genuinely ready to build the moment a need appears, which is the right
  place to leave a deferred feature.

This is a defensible recommendation to send back to the operator: build the liveness half now,
keep the persistence half specified-but-unbuilt, and say explicitly that "MI-5" as landed is a subset
of what the board entry names, with the file cache tracked as a follow-up rather than silently
dropped.

## 4. `fetch-http-url` feature gate — AGREE, but note it isn't actually being built here

Checked the feature graph in `crates/verity-verifier/Cargo.toml:14-31`: `fetch = ["dep:ureq"]`,
`connect = ["attest", "dep:ureq", ...]`. A new `fetch-http-url` feature gating `HttpUrl` and
`ComposeUri::Http` would need to layer under `fetch` (implied by it, the way `connect` implies
`attest`) so an IPFS-only embedder can compile out the arbitrary-URL path while keeping IPFS
retrieval. That's a clean, additive gate in the same style as the existing three — no conflict with
the fetch/connect/attest graph, and Cargo feature unification means it composes fine.

The one thing to flag precisely: the design does **not** propose building this gate in either Change
1 or Change 2 — it's raised as a "third, optional item... to raise with the team" (§5). So there's
nothing to critique implementation-wise yet; I'd just confirm with the architect/team-lead that this
stays a recommendation-only line item in the write-up and doesn't quietly turn into an unreviewed
half-feature bolted onto VA-3's diff. As written, it doesn't — VA-3's scope list (§5) is explicit
about what's included, and the gate isn't on it.

## 5. Redirect mirror + Fallback reuse of the FetchError→Unestablished mapping — AGREE, verified against ureq's actual source

I did not take the "mirrors `connect`, transfers unchanged" claim on faith — checked ureq 3.4.0's
source directly (`~/.cargo/registry/.../ureq-3.4.0/src/config.rs`, `src/run.rs`):

- `ureq::Agent::config_builder()` (`agent.rs:123`) returns the identical `ConfigBuilder<AgentScope>`
  type `Config::builder()` does in `connect/http.rs:369-383`, and `.max_redirects(u32)` is defined at
  `config.rs:497` on that same builder — the method transfers to the compose `agent()` with zero
  adaptation.
- `max_redirects(0)`'s documented behavior (`config.rs:270-269`) is "no redirects are followed and
  the response is always returned (never a `TooManyRedirects` error)" — confirmed against `run.rs:122-128`,
  where the only status-based error path is `status.is_client_error() || status.is_server_error()`,
  which is 4xx/5xx only. A 302 is neither, so compose's `get()`/`post()` (`http.rs:53-79`) will see
  `Ok(response)` with status 302, exactly matching the `connect` precedent's own test expectation
  (`connect/http.rs:730-742`, `a_redirect_to_another_host_is_not_followed`). The design's claim that
  the 3xx body then fails the downstream hash check is the correct mechanism, not an assumption.
- Fallback reusing the mapping: confirmed `Unestablished::RetrievalFailed` (`verdict.rs:173-176`) and
  its two exhaustive match sites (`verdict.rs:395,414`) are untouched by anything in this design.
  `Fallback::fetch` returning the last `FetchError` (whatever variant) routes through the *existing*
  `From<&FetchError> for Unestablished` (`compose.rs:151-166`) with no new arm and no fork — the
  match there is already exhaustive without a wildcard, so a fork would be a compile error, not a
  silent option. Good design property: nothing about `Fallback` *can* bypass that mapping by
  construction.

One small copy-paste risk in the design's own code sketch (§2): the proposed comment on the compose
`agent()` says *"`script/mutate.sh` raising it is the mutant the test kills"* — copied near-verbatim
from the `connect` precedent's comment. I checked `script/mutate.sh` (`grep -n "compose\|http.rs"`)
and it currently only exercises `connect/http.rs`, not `compose/http.rs`. If that sentence lands
unchanged, it will be describing a mutation check that doesn't exist yet for this file. Either add
the compose-agent mutant to `script/mutate.sh` in the same change (cheap, and genuinely closes the
loop the sentence claims), or reword the comment to not claim a mutation test that isn't there. I'd
add the mutant — it's a few lines in an existing script and the whole point of this design is
treating this agent's redirect posture with the same rigor as `connect`'s.

## AMEND — Fallback's constructor shape (§4.2)

The design leaves the empty-list case open: `pub fn new(sources: Vec<S>) -> Result<Self, ...>; // or a non-empty constructor`.
I'd resolve this in favor of the non-empty constructor, not a `Result`: `Fallback::new(first: S, rest: Vec<S>)`
(or `impl IntoIterator` for `rest`). An empty `Fallback` is a caller programming error, not a runtime
condition — nothing about *retrieval* made the list empty, the call site did, at compile time. Forcing
a `Result` here means every construction site has to handle or `expect()` an error that a type-level
constraint would have made unreachable, which is exactly the "illegal state unrepresentable" instinct
the design itself argues for in §1.4 for `Cid`. Applying it inconsistently — newtype for `Cid`,
runtime `Result` for `Fallback` — is worth avoiding for its own sake, not just tidiness: a `Fallback`
holding zero sources is not a retrieval failure the `Unestablished`/`Indeterminate` machinery should
ever have to reason about, so it shouldn't be a value that type-checks as a `Fallback` in the first
place.

---

## Summary for the architect

- Decision 1 (`Cid` newtype): **AGREE**. Churn is smaller than flagged — 8 call sites total, all
  local to `compose.rs`/`compose/http.rs`/one test file, nothing downstream. Add `impl Display for Cid`
  or the code sketch won't compile.
- Decision 2 (CID charset, dependency-free): **AGREE, strengthened**. It's an allowlist (complete by
  construction), not a blacklist (the FI-1 failure mode) — say that explicitly in the doc comment. One
  accuracy nit: base64url multibase forms pass too (harmless, but the doc comment's claim about what
  "accepted" implies should stay purely lexical, not imply multibase-form coverage).
- Decision 3 (defer file cache): **AGREE, firmly**. Gateway-down→Indeterminate is already true today
  without MI-5; the file cache's only marginal value (restart survival) is speculative against real
  complexity (a new path-safety sink, atomicity, eviction) and no concrete deployment need is named.
  Ship `Fallback` now, keep §4.3 as the specified-but-unbuilt record, and say explicitly to the
  operator that this is a scoped subset of "MI-5" as named on the board, not silent scope-dropping.
- Decision 4 (`fetch-http-url` gate): **AGREE it composes cleanly** with the existing feature graph
  (verified against `Cargo.toml`), but note it isn't being built in either change — just flag it stays
  that way through implementation.
- Decision 5 (redirect mirror + Fallback reuse): **AGREE, verified against ureq 3.4.0 source directly**
  — `max_redirects(0)` transfers with zero adaptation and behaves as claimed (302 returned as `Ok`,
  never errors), and `Fallback` cannot bypass the existing `FetchError → Unestablished` mapping by
  construction (the match is exhaustive, no wildcard). One loose end: the design's redirect-agent
  comment claims a `script/mutate.sh` mutant that doesn't exist yet for `compose/http.rs` — add it or
  reword.
- One AMEND: `Fallback::new` should take a guaranteed-non-empty shape (`first: S, rest: Vec<S>`)
  instead of returning `Result`, for the same "illegal state unrepresentable" reason the design
  already applies to `Cid`.

No OBJECTs. The design is sound, and the parts I could independently verify against the live code and
the actual `ureq` source held up exactly as claimed.

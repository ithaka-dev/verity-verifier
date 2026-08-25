# Brief — VA-3 / MI-5: harden compose retrieval; file-backed cache + multi-gateway

**Repo:** `verity-verifier` @ `2ecbedf` · **Issues:** VA-3 (audit VV-03, Low–Medium) folded with MI-5
(2026-08-09 review) · **Board:** `verity-foundation/audit-implementation-plan.md`

Two board items, same module (`crates/verity-verifier/src/compose.rs` + `compose/http.rs`, all behind
the `fetch` feature). The architect decides whether to land as **one change or two** (see Scope) — but
**VA-3 is the security-critical half and should not be diluted or delayed by MI-5's feature work.**

## The security boundary (states the stakes precisely)

Retrieval is **not** in the trust model: the compose document is content-addressed and its hash is
committed on chain, so a wrong/hostile answer is caught by the hash check that runs after every fetch
(`compose.rs` module doc). **So none of this is a verification bypass.** What VA-3 is about is
*retrieval-side effects that happen before the hash check* — SSRF, injection, traversal, redirect-to-
internal, DoS — which the hash check does nothing to prevent.

## VA-3 — the hardening (security fix; do this well)

Current defects, all in `compose.rs`/`compose/http.rs`:

1. **`ComposeUri::parse` accepts any non-empty bytes after `ipfs://`** (`compose.rs:61-65`) as a CID —
   no validation. `ipfs://../admin` and `ipfs://cid&timeout=0` both parse as `Ipfs(..)`.
2. **The CID is interpolated UNENCODED** into request URLs: `{base}/ipfs/{cid}` (`http.rs:113`) and
   `{api}/api/v0/cat?arg={cid}` (`http.rs:158`). So `cid&timeout=0` becomes a Kubo **query parameter**
   and `../admin` a **path segment** — injection and traversal.
3. **The compose-fetch `agent()` sets no redirect policy** (`http.rs:45-51`) — only connect/total
   timeouts. ureq follows redirects by default, so a fetch can be redirected into loopback/private
   targets. **There is an in-crate precedent to mirror:** the *connect* agent sets `.max_redirects(0)`
   with a full rationale and a test (`connect/http.rs:376`, `a_redirect_to_another_host_is_not_followed`
   at :722). The compose agent should adopt the same posture, for the same reason.
4. **`HttpUrl` GETs arbitrary `http(s)://` URLs** (`http.rs:204`) — no scheme/host/port/private-range
   policy. The audit lists an explicit retrieval policy as a *recommendation*, and also floats
   "consider removing arbitrary HTTP compose retrieval if the design requires IPFS." Architect's call
   how far to go here — but decide it deliberately, not by omission.

**The CID-validation dependency decision (flag explicitly — this is the main design call).** The audit
recommends "a dedicated CID/multibase implementation" AND, separately, "reject `/`, `?`, `#`, `&`,
control characters, and invalid multibase forms even before semantic CID validation." Two paths:
- **(A) A `cid`/`multibase` crate** — correct and complete, but a new dependency on the **crown-jewel**
  verifier, which vendors deps deliberately, and it **must build for `wasm32-unknown-unknown`** (the
  `fetch` feature is off on wasm today, but the crate's whole discipline is wasm-buildability — confirm
  the dep doesn't pull in something that breaks it, and that it doesn't drag `std`-only code into a
  path that matters). Cross-check the workspace dependency policy the `rust-reviewer` enforces.
- **(B) Strict-charset validation, dependency-free** — reject any CID containing URL-significant or
  control characters (`/ ? # & % : @ [ ] whitespace`, non-ASCII control) so interpolation is provably
  safe, without claiming to parse CID structure. This closes the *security* hole (the injection/
  traversal/query vectors) because it rejects the dangerous bytes, and it is exhaustively verifiable
  (a character whitelist/blacklist, not a structural parser).
  - **Weigh the FI-1 lesson both ways.** FI-1 (`records/experiments/.../a-taxonomy-…`, and the board)
    taught "a check that must understand *source* has to *parse* it, not scan bytes" — a hand-rolled
    lexer got bypassed 18 ways. But that was about understanding *program semantics* (chain ids). Here
    the security property is "no URL-significant byte reaches interpolation," which genuinely *is* a
    byte-level property — so a charset reject is the right tool for it, provided we do not overclaim it
    as "this is a valid CID." State honestly what the check establishes.
  - Defense-in-depth regardless of A/B: percent-encode the CID at the interpolation site (esp. the
    Kubo `?arg=` **query value**), so a future relaxation of parse doesn't reopen injection.

## MI-5 — file-backed cache + multi-gateway (feature; the separable half)

What exists already (do not rebuild):
- `Cached<S>` is an **in-memory** cache (`compose.rs:218`, `HashMap` in a `Mutex`), bounded, with the
  "a poisoned cache can only cause a spurious refusal, never a spurious success" safety argument
  already written. Its doc explicitly says persistence is "a different design with its own invalidation
  and on-disk-tampering questions, and nothing yet needs it."
- `FetchError` → `Unestablished::RetrievalFailed` already exists (`compose.rs:151`), so a fetch outage
  **already surfaces as `Indeterminate`** at the verdict level (MA-6). MI-5's "gateway-down →
  Indeterminate" is therefore partly already true — what's new is *multi-gateway fallback*.

What MI-5 adds:
1. **A file-backed `Source`** (persistent cache). `Source` is a public trait, and the hash check reruns
   every call, so a poisoned on-disk entry causes only a spurious refusal — carry that exact safety
   argument. Address the on-disk-tampering/invalidation questions the `Cached` doc named as the reason
   it was deferred (they must be *answered*, not inherited).
2. **A multi-gateway source**: a gateway **list** with per-source timeouts; a gateway outage falls
   through to the next; **only all-down** surfaces as `Indeterminate` (via the existing `FetchError` →
   `Unestablished` mapping — reuse it, don't fork it).

## Acceptance criteria

VA-3:
- A malformed CID (`../admin`, `cid&timeout=0`, one with `/ ? # &` / control chars / whitespace) is
  **rejected at parse** (or, if the architect keeps parse permissive, is provably neutralized before it
  reaches any request URL) — no such value ever reaches a gateway path or a Kubo query parameter.
- Redirects are **not followed** on the compose-fetch agent (mirror `connect`'s `max_redirects(0)`), or
  every redirect target is revalidated against a stated policy.
- The `HttpUrl` scheme/host policy is an explicit, documented decision (whatever it is).
- **Seen-to-fail:** the two audit reproductions become permanent tests — a malformed CID that WOULD
  inject/traverse under the current code, and a redirect that WOULD be followed under the current agent
  — each demonstrated **red on the current tree first**, then green.

MI-5:
- A tampered on-disk cache entry yields a **refusal**, not an acceptance (the hash check catches it) —
  tested. A gateway outage on one of several yields fallback, and **all-down** yields `Indeterminate`,
  not a mismatch — tested.
- The file-backed cache's invalidation and tampering posture is documented where the code lives.

## Discipline & constraints

- **Seen-to-fail first** (CLAUDE.md): every guard red on the current tree before green. **Write the
  check from the failure** — build the malformed CID / the redirecting server and capture it injecting/
  following before asserting the fix.
- **ADR 0019:** commit directly to `main`, review record in the commit message. **ADR 0018:** reviewer
  sign-off is the gate (twice if landed as two changes). **ADR 0026:** this rust-team cycle.
- **Dependency additions are a reviewer-policy matter** — if the architect chooses a CID crate, it must
  survive the `rust-reviewer`'s dependency scrutiny AND the wasm-buildability constraint, and `cargo
  deny`/`cargo audit` must stay green (CI runs both).
- **Don't disturb** the landed VA-1/VA-2 surfaces (`verdict.rs`, `verify.rs`) — this is compose-only.
  The `Unestablished::RetrievalFailed` mapping is the seam to reuse, not change.
- Toolchain: local clippy needs `-A clippy::chunks_exact_to_as_chunks` (pre-existing, untouched files),
  allow nothing else. `wasm32-unknown-unknown` can't build locally (no rustup); `fetch`/`connect` are
  the relevant feature legs — build/test them explicitly (`--no-default-features --features fetch`,
  `--features connect`). Existing compose tests: `tests/compose_uri.rs`, `tests/compose_http.rs`,
  `tests/compose_fetch.rs`.
- Team artifacts under `team/va-3-mi-5/`; leave `team/`, `team/va-1/`, `team/va-2/` intact.

## Scope decision (architect to recommend)

Land as **one** change or **two** (VA-3 hardening; then MI-5 cache/multigateway)? Arguments for two:
per-issue review (ADR 0018), VA-3 is a security fix that shouldn't wait on a feature, and they have
independent test surfaces. Argument for one: same module, one review pass. **Recommend explicitly**, and
if two, say which lands first (VA-3) and confirm MI-5 is still wanted now vs. worth deferring — the
gateway-down→Indeterminate half is already covered, so MI-5's marginal value is the file cache + the
fallback, which the architect should sanity-check is actually needed rather than built because it's on
a list.

## Assumption (flag if wrong)

- The `fetch` feature being wasm-off today means a CID-crate dependency added under `fetch` does not by
  itself break the wasm build — but confirm against the actual feature graph, because the crate's
  discipline is that `default`/non-`fetch` paths stay wasm-buildable.

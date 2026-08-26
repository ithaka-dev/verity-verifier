# Brief — VA-3 follow-up: the `ComposeUri::Http` arm bypasses the "parsed, not a string" invariant

**Repo:** `verity-verifier` @ `529deda` · **Issue:** VA-3 review finding 1 (a recorded follow-up, not
a new audit finding) · **Board:** `verity-foundation/audit-implementation-plan.md`

## The finding

VA-3 made `ComposeUri::Ipfs` carry a validated `Cid` newtype (private inner, only constructor
`Cid::parse`), so an unvalidated CID cannot exist. But the sibling arm is still `ComposeUri::Http(String)`
(`src/compose.rs:40`) — a **public tuple variant with a public `String`**. So the enum's own doc
("*Parsed rather than passed around as a string so that a caller cannot accidentally hand a gateway an
arbitrary URL…*", `compose.rs:26-28`) is now enforced for one arm and not the other. A caller can write
`ComposeUri::Http("file:///etc/passwd".into())` or any string, bypassing `ComposeUri::parse` (which
does check the `http://`/`https://` prefix at `:67-68`).

## What is and isn't at stake — read this before deciding scope

This is **materially lower-risk than the `Cid` case, and that difference is the whole decision.**
- The `Http` value is fetched **verbatim** as the full request URL (`HttpUrl::fetch` →
  `get(url, …)`, `compose/http.rs:204`). It is **never interpolated** into a larger URL, so the
  injection/traversal/query-splitting vectors that motivated `Cid`'s validation **do not exist here**.
- `ureq` rejects non-`http(s)` schemes at fetch time, and VA-3 already put `max_redirects(0)` on the
  compose agent.
- Retrieval is outside the trust model regardless: the bytes are hash-checked, so a wrong URL can only
  cause a spurious refusal, never a spurious success.
- **The architect deliberately kept `Http(String)` in VA-3** (design.md §3) and did not design a
  newtype for it. This follow-up is reconsidering that call, so the first question is honestly *whether
  to change it at all*, not just how.

## The decision the team must make

Choose and defend ONE:
- **(a) Close the asymmetry** — make the `Http` arm impossible to construct unvalidated, mirroring
  `Cid`. Options the architect should weigh: a `HttpUrl`/`ComposeUrl` newtype (private inner, only
  constructor validates the `http(s)://` scheme), or making the variant's field private with a
  constructor. Decide what validation it performs — almost certainly *just* the scheme allowlist
  (`http`/`https`), since host/port policy was deliberately declined in VA-3 (SSRF blocklist rejected:
  sibling sources target loopback by design; DNS rebinding defeats it). Do **not** re-open that.
- **(b) Accept the asymmetry and document it** — conclude the residual is low enough that a newtype is
  ceremony without security value, and make that an explicit, defended note at the type (why `Ipfs` is
  validated and `Http` is not: one is interpolated, the other is used whole). 

**The operator has asked for all three VA-3 follow-ups to be resolved**, so (a) is the expected default
unless the team finds a concrete reason it is actively worse than (b) (e.g. it breaks a legitimate
caller, or the validation would give false confidence). If you land on (b), it must be a genuine
engineering conclusion with the reasoning written down, not a shrug — and I will bring it back to the
operator as the recommendation rather than treating "documented" as done silently.

## Blast radius (measured 2026-08-25 for the `Cid` change; re-verify)

The `Cid` migration touched 8 sites, all in `compose.rs` + `compose/http.rs` + one test file. The
`Http` arm's construction/match sites are the parallel set: `ComposeUri::parse` (constructs it),
`Display` (`compose.rs:90`), `cid()` (returns `None` for it), `HttpUrl::fetch` (matches it,
`compose/http.rs:204`), the `Gateway`/`KuboRpc` `Unsupported` arms that match `Http(_)`, and the compose
tests (`compose_uri.rs`, `compose_http.rs`). Grep `ComposeUri::Http` to get the exact list.

## Acceptance criteria (if (a))

- `ComposeUri::Http` cannot be constructed with a string that is not a scheme-valid `http(s)` URL — no
  public field, no `From`/`FromStr`/serde bypass (verify the way VA-3 verified `Cid`).
- `ComposeUri::parse`'s existing `http(s)://` check moves into (or is shared with) the new
  constructor, so there is one definition of "valid Http URL", not two that can drift (the VA-3
  finding-2 lesson).
- **Seen-to-fail:** a test that constructs an invalid `Http` value fails to compile (or the
  constructor rejects it) where it compiled before — demonstrated on the pre-fix tree.
- No behavioral change to legitimate fetches; the existing compose tests keep their intent.
- Whatever is decided, the host/port/SSRF policy is **not** changed (VA-3 settled it).

## Discipline & constraints

- **Seen-to-fail first** (CLAUDE.md). **ADR 0019:** commit to `main`, review record in the commit
  message. **ADR 0018:** reviewer sign-off is the gate. **ADR 0026:** this rust-team cycle.
- Don't disturb the `Cid` work, the redirect policy, or the `Fallback` from MI-5.
- Toolchain: local clippy needs `-A clippy::chunks_exact_to_as_chunks`, allow nothing else. Build/test
  the feature legs (`--no-default-features --features fetch`, `--features connect`); `wasm32` is CI-only.
- Team artifacts under `team/va-3-http/`; leave `team/`, `team/va-1/`, `team/va-2/`, `team/va-3-mi-5/`
  intact.

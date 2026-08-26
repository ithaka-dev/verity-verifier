# Critique — VA-3 follow-up: `ComposeUri::Http` newtype

**Reviewer:** vahttp-developer · **Against:** `design.md` @ `529deda` · **Verdict:** AGREE with one AMEND (test approach), no OBJECT.

---

## 1. Decision (a) vs (b) — AGREE

Take (a). The reasoning in design.md §"Why (a) over (b)" holds up against the live tree: every
construction site is `ComposeUri::parse` (grep-confirmed below), there is no `From`/`FromStr`/serde
on `ComposeUri`, and the operator's standing instruction is to resolve all three follow-ups absent a
concrete reason not to. No such reason exists here.

One point worth adding to the record, because it strengthens (a) beyond what the design argues:
**a private field on an enum's own tuple variant is not something Rust lets you express.** Visibility
qualifiers are rejected on individual enum-variant fields — only the whole enum has a visibility, and
every variant and its fields inherit it uniformly. That means the brief's second option under (a)
("making the variant's field private with a constructor") was never actually available as a distinct
alternative to the newtype — the newtype is the *only* mechanism that gets a private inner value here,
exactly as it was for `Cid`. This isn't a new conclusion, just a firmer floor under the one already
reached.

## 2. Name — AGREE, `ComposeUrl`, and it's not just a style call

Confirmed at the use sites: `compose/http.rs` already defines `pub struct HttpUrl` (the `Source`
impl, `http.rs:229`), re-exported at `compose.rs:285` as `pub use http::{Gateway, HttpUrl, KuboRpc};`
— so `HttpUrl` is a name already live in the `compose` module's own public namespace. Naming the new
value type `HttpUrl` wouldn't just be confusing, it's a straight item-name collision inside the same
module once both are `pub` there. `ComposeUrl` is collision-free and reads correctly at every site the
design lists (`ComposeUri::Http(ComposeUrl)`). No amendment needed here.

## 3. Test approach — AMEND: drop the `compile_fail`/`trybuild` framing, follow `Cid`'s actual pattern

This is the one place I depart from the design. Design.md's test plan item 1 says: *"A `trybuild`/
`compile_fail` doctest is the honest form here because the property is 'this does not compile.'"*
I recommend against that, for four reasons:

1. **This repo has already ruled trybuild out, explicitly, for a directly analogous reason.**
   `tests/tcb_enforcement.rs` states its own guard is "a regex [because it] is toolchain-robust and
   does not rot the way a `trybuild` `.stderr` snapshot would across the pinned 1.97.1 / local 1.98
   split this repo straddles." A `compile_fail` doctest carries the identical fragility — its
   diagnostic text (or even whether rustdoc's doctest harness treats it as "failed to compile" vs.
   some other outcome) is tied to compiler version in exactly the way this repo has already decided
   not to depend on.

2. **The actual precedent — `Cid` — did not use trybuild, and this design says it's mirroring `Cid`.**
   I read `tests/compose_uri.rs:65-90` directly. The `Cid` "seen-to-fail" is: a prose comment
   documenting the pre-fix RED (a fake-server transcript showing real traversal/injection, captured
   *before* `Cid` existed), followed by ordinary runtime tests (`refuses_a_traversal_cid`,
   `refuses_a_query_injection_cid`) plus the structural argument stated in the comment itself —
   *"the two tests below are GREEN against this one, and hold before any request is built, because
   `Cid`'s inner field is private — there is no way to construct a `ComposeUri::Ipfs` holding either
   string at all."* No compile_fail artifact exists anywhere in the tree for `Cid`. Adding one for
   `ComposeUrl` would be a first for this codebase, done for a variant the brief itself rates as
   *lower* stakes than `Cid`.

3. **No dependency benefit, only cost.** `trybuild` isn't a dependency of this crate today. VA-3's own
   commit message for `Cid` explicitly credits the change as "No dependency changes... a CID crate
   would add multibase/multihash surface to the crown jewel and still not cover the encoding" — the
   crate's stated posture is to avoid adding deps to the crown jewel where a structural argument
   already suffices. A trybuild dev-dependency for one compile_fail case is the same shape of
   trade-off, on the losing side.

4. **The structural proof here is *stronger* than `Cid`'s, so a compile_fail test would be redundant
   with something already airtight.** Because enum-variant fields can't carry their own visibility
   (point 1 above), `ComposeUri::Http(ComposeUrl)` with `ComposeUrl`'s only public constructor being
   `parse` makes an unvalidated `ComposeUri::Http` *categorically* unconstructible from outside the
   crate — there's no residual "but what if a future refactor exposes a bypass" gap the way a
   behavioral property might have. A compile_fail test would be asserting a fact the module boundary
   already proves by construction; it demonstrates nothing beyond what the doc comment already states.

**Recommendation:** mirror `compose_uri.rs:65-90` exactly.
- A doc comment near `ComposeUrl` (or at the new tests) stating the pre-fix RED, capturing what I
  verified empirically today: on the pre-fix tree, `ComposeUri::Http("file:///etc/passwd".into())`
  compiles and constructs without error (I ran it as a scratch integration test against `529deda` —
  green, zero warnings beyond an unrelated missing-docs lint). State that post-fix, the identical line
  is rejected at compile time (`Http` no longer accepts a bare `String`), verified by hand during
  implementation and not kept as a permanent artifact requiring a pinned toolchain.
- Keep design.md's tests 2–5 as ordinary `#[test]` functions in `tests/compose_uri.rs`: the bad-scheme
  and no-scheme rejection assertions, the both-schemes-accepted-verbatim assertion, the no-drift
  assertion between `ComposeUri::parse`'s http branch and `ComposeUrl::parse` directly, and confirming
  `compose_uri.rs`/`compose_http.rs` pass unedited.

This keeps the "seen-to-fail first" discipline (CLAUDE.md) — RED was reproduced, on this exact
tree, today — without introducing the toolchain fragility this repo has already named and rejected
once.

## 4. Blast radius and "no test needs editing" — CONFIRMED against the tree

Read `src/compose.rs` and `src/compose/http.rs` directly (not from the design's table alone). The
eight sites match:

| Site | Confirmed at | Note |
|---|---|---|
| Variant definition | `compose.rs:111` (`Http(String)`) | matches |
| `ComposeUri::parse` http branch | `compose.rs:136-138` | matches; the `split_once("://")` error split (line 139-142) must move into `ComposeUrl::parse` as design.md says — today it lives entirely in `ComposeUri::parse`, shared by both the http-miss and no-scheme cases |
| `Display` | `compose.rs:159` (`f.write_str(url)`) | matches |
| `cid()` http arm | `compose.rs:150` (`Self::Http(_) => None`) | no change needed, confirmed |
| `HttpUrl::fetch` | `compose/http.rs:259` (`get(url, self.limit)`) | matches; becomes `get(url.as_str(), self.limit)` |
| `Gateway::fetch` Unsupported | `compose/http.rs:149-152` (`uri: url.clone()`) | matches — **and this one will not silently do the wrong thing if missed**: `url` becomes `&ComposeUrl`, so `url.clone()` produces a `ComposeUrl`, not a `String`, and the `uri: String` field won't accept it. This is a hard compile error, not a latent bug, which is the good case. |
| `KuboRpc::fetch` Unsupported | `compose/http.rs:197-200` | same as above |
| New newtype | `compose.rs`, near `Cid` | new |

Grep for `ComposeUri::Http` across the whole tree turns up matches only in `compose.rs` (definition,
`parse`, `Display`, `cid()`) and `compose/http.rs` (the three match arms above) — **zero** hits in any
`tests/*.rs` file constructing the raw tuple. Every test-file use of `ComposeUri` goes through
`ComposeUri::parse` (`compose_fetch.rs`, `compose_http.rs`, `compose_uri.rs`, `compose_fallback.rs`,
all grep-confirmed). Confirmed also: `ComposeUri` derives only `Debug, Clone, PartialEq, Eq, Hash` —
no `From`, `FromStr`, or serde impl anywhere in `compose.rs`. The design's claim that no existing test
needs editing to keep compiling is accurate.

One correction to the design's own text: §"Export" asks to "confirm whether `Cid` is re-exported at
crate root." It is not — `Cid` is simply `pub struct Cid` inside `pub mod compose;` (`lib.rs:140`),
reachable as `verity_verifier::compose::Cid`, which is exactly how the existing tests import it
(`compose_uri.rs:7`). `ComposeUrl` needs nothing beyond being declared `pub` in `compose.rs` the same
way — no additional `pub use` line, no crate-root re-export to add.

## 5. Seen-to-fail reproducibility — CONFIRMED, empirically, today

Ran this as a scratch integration test against the current tree (`529deda`), `cargo test -p
verity-verifier --no-default-features --features fetch`:

```rust
let bad = ComposeUri::Http("file:///etc/passwd".into());
assert!(matches!(bad, ComposeUri::Http(_)));
```

Result: compiles clean and passes — `1 passed; 0 failed`. That is the red-first artifact design.md
asks for, reproduced rather than assumed. The scratch file was removed after the check; it never
touched the tracked tree (`git status --porcelain` shows nothing but the untracked `team/va-3-http/`
directory).

---

## Summary verdict

| Decision | Verdict |
|---|---|
| (a) close the asymmetry | AGREE |
| Name: `ComposeUrl` | AGREE — and it's a forced choice, not a preference, given `HttpUrl` is already a live public name in the same module |
| Shape: newtype, private inner, sole `parse` constructor, `ComposeUri::parse` routes through it | AGREE |
| Test approach: `compile_fail`/trybuild | AMEND → follow `Cid`'s actual pattern (prose seen-to-fail comment + runtime parse-rejection/no-drift tests), no trybuild dependency |
| Blast radius (8 sites, no test edits, no From/FromStr/serde) | CONFIRMED against the live tree |
| Host/port/SSRF policy unchanged | AGREE, not revisited |

No OBJECT on anything. Ready to implement once the test-approach amendment is folded into consensus.

# verity-verifier

> ## 🚧 Not functional — do not adopt
>
> This repository is **scaffolding**. It does not yet do the thing its description says it does.
> Nothing here is ready to depend on, build against, or copy.
>
> **This matters more here than elsewhere.** A verifier that does not yet verify is worse
> than no verifier: it returns answers that look authoritative and are not. Until this banner is
> gone, **no attestation result from this code means anything.** Do not wire it into anything that
> makes a trust decision.
>
> **Readiness is per-repo and will be announced by removing this banner** and tagging a release.
> Until then, treat anything here as subject to change without notice — including its public
> interface, its behaviour, and its existence.
>
> Sequence and current position: [`plan.md`](https://github.com/ithaka-dev/verity-foundation/blob/main/plan.md).

**The crown jewel.** Agent-side attestation verification: given an endpoint, its evidence, and a licensed version record, decide whether what is running is what was licensed — and refuse on mismatch.

**Language:** Rust (+ WASM and Node bindings)
**Phase:** 1a of the [implementation plan](https://github.com/ithaka-dev/verity-foundation/blob/main/plan.md)

---

## Read before contributing

Every constraint that makes Verity work lives in
**[verity-foundation](https://github.com/ithaka-dev/verity-foundation)** — the specification, the
architecture decisions, the invariants, and the measured facts they rest on. This repository holds
an implementation of decisions made there, not the decisions themselves.

- [Specification](https://github.com/ithaka-dev/verity-foundation/blob/main/docs/Verity-spec.md) — start here; §7 holds the invariants
- [Decisions (ADRs)](https://github.com/ithaka-dev/verity-foundation/tree/main/docs/decisions) — why things are the way they are
- [`CLAUDE.md`](CLAUDE.md) — what binds *this* repository specifically

**If a decision seems missing, it probably isn't — go and find it.** If it genuinely is missing,
it belongs in an ADR in `verity-foundation`, not in a pull request here.

## The three rules

Recorded here rather than only in the code, because they are the ones violated under deadline
pressure and a reader who never opens the source should still meet them.

1. **Never compare `RTMR3`.** It accumulates `app-id`, `instance-id` and `mr-kms`, and the last
   varies per boot, so no stable reference exists. Comparing it produces intermittent false
   refusals. The boot-reference type has no field for it — leaving it out of the type is stronger
   than documenting that it should be skipped.
2. **Branch on the `MR-CONFIG-ID` prefix byte; never assume `0x01`.** V1 and V2 are different
   constructions, and which applies is a property of the platform, not of this crate.
3. **Never loosen a check to resolve a mismatch.** Rule 1 guarantees somebody eventually sees a
   spurious failure. Relaxing a comparison until it passes turns this library into decoration while
   everything continues to look like it works. The correct response is to narrow *what* is compared
   to values that are legitimately stable — never to weaken *how strictly*.

## What is checked

Seven essential checks plus one optional. A verdict that did not pass **every** essential is not
trustworthy, whatever else it says.

| # | Check | Essential | Establishes |
|---|---|---|---|
| 1 | `compose_hash` | yes | the served `app-compose.json` is the one the licence names |
| 2 | `images_pinned` | yes | every image in it is digest-pinned, no tags (I8, ADR 0007) |
| 3 | `licensed_image_present` | yes | the compose references the licensed `imageDigest` |
| 4 | `quote_signature` | yes | Intel signed the quote |
| 5 | `tcb_status` | yes | the platform's TCB is acceptable (ADR 0014, not configurable) |
| 6 | `mr_config_id` | yes | the measured configuration is the licensed one |
| 7 | `boot_measurements` | no | `MRTD`/`RTMR0–2` match a caller-supplied OS-image reference |
| 8 | `channel_bound` | yes | **the quote is about the connection you are using** |

Checks 1–6 are all satisfied by a genuine quote recorded from a CVM that no longer exists. Check 8
is the one that is not: dStack's RA-TLS commits the connection's TLS key into the quote's
`report_data`, so a relay presenting somebody else's quote fails it without holding the enclave's
private key. Without it a hostile or buggy orchestrator can return a real `cvm_id`'s quote beside its
own endpoint and every other check passes.

Two consequences worth knowing before you wire this up:

- **A verdict with no certificate behind it cannot be trustworthy.** Reading a quote out of a file
  establishes what ran *somewhere*, never *what you are talking to*, and the verdict says so.
- **dStack's default endpoint form cannot be channel bound.** The gateway terminates TLS on
  `<app_id>-<port>.<domain>` and hands you a valid Let's Encrypt certificate for itself; only the
  `s`-suffixed passthrough form reaches the enclave's own certificate. This crate refuses the
  terminating form rather than falling back.

Check 7 is not essential because it compares against a reference most callers do not have, so its
absence is a legitimate configuration rather than a gap. `RTMR3` is never compared at all — see the
three rules above.

## Using it: `connect_verified` is the one to reach for

```text
use verity_verifier::connect::{connect_verified, ConnectOptions, ConnectRequest};
use verity_verifier::endpoint::Endpoint;

let endpoint = Endpoint::parse("https://<app-id>-8443s.<domain>")?;
let request = ConnectRequest::new(&endpoint, &licensed, compose_document, &tcb_policy);

// Dials, handshakes, lifts the quote out of *that handshake's* certificate, verifies, and
// returns a client only if every essential check passed. There is no way to obtain one otherwise.
let client = connect_verified(&request, &my_collateral_source, &ConnectOptions::default())?;
let response = client.get("/health")?;
```

Behind the non-default `connect` feature, because the crate must stay buildable where there is no
TCP stack — offline audit, another enclave, `wasm32`.

**Why this rather than `verify()`.** `verify()` binds a quote to a certificate it was *handed*. It
performs no I/O, so it cannot establish that the certificate came from the handshake being judged —
a caller who supplies one obtained anywhere else gets a truthful verdict about a connection they are
not using. And its result is a `Verdict` you can ignore, so the guarantee rested on every agent
author remembering `if !verdict.is_trustworthy() { return }`. **A verdict that can be ignored is a
verdict that will be.**

`connect_verified` owns the socket, the handshake, the certificate and the quote; you supply none of
them. A `VerifiedClient` has no public constructor and no path from an untrustworthy verdict, so the
check cannot be skipped by forgetting it. Every reconnect the client makes is verified the same way.

**`verify()` is not deprecated by this.** It remains right for auditors reasoning about recorded
evidence, for pre-purchase inspection where there is no connection yet, and for any embedder without
a TCP stack. That path is the default; this is additive to it.

**What a caller still supplies is Intel collateral**, through `CollateralSource`, and it is handed
the quote *this handshake produced* — collateral is FMSPC-specific, so it cannot be fetched earlier,
and `dcap-qvl` fetches it asynchronously, so doing it inside would mean this crate choosing an async
runtime for every embedder. That seam is safe for a reason worth generalising: `dcap-qvl` compiles
Intel's production root into the binary and checks collateral against *that*, so a wrong or hostile
answer causes a refusal, never an acceptance. **If getting a seam wrong could produce a false
accept, it does not belong in caller code** — which is why there is no way to inject a transport.

### JavaScript callers

`connect_verified` is **not** available from the WASM bindings, and that is deliberate rather than
unfinished: a browser cannot open a raw TLS connection, and `fetch()` does not expose the peer
certificate at all, so a "verified transport" there would verify nothing. In Node, obtain the DER
from your own TLS layer — `socket.getPeerX509Certificate().raw` — and pass it to `verify`. A
Node-native binding that can genuinely own the handshake is a separate piece of work.

## What a verdict tells you

Never a bare boolean. Every verdict carries the verifier version, the reference-data date, and
**which checks actually ran** — which is what makes a weakened verifier detectable. One that quietly
stopped comparing `MR-CONFIG-ID` still returns "verified", but it can no longer claim to have
compared it.

Enforcement is impossible: this runs on the agent's side and nobody can compel an update. So the
goal is not prevention but **visibility** — a stale or loosened verifier must not be able to be
either invisibly.

## Boundary

Verification happens **here or nowhere**. If this step is skipped or weakened, the whole system degrades to "login plus a container spawn" (spec §4.5).

- Parses the **raw TDX quote** from the RA-TLS leaf certificate. **Never** a cloud provider's parsed `tcb_info` — that trusts the provider's rendering of the hardware's statement, where the raw quote trusts Intel's signature over the statement itself ([ADR 0009](https://github.com/ithaka-dev/verity-foundation/blob/main/docs/decisions/0009-verification-model.md)).
- A verdict is **never a bare boolean** — it carries the verifier version, reference-data date, and which checks actually ran ([ADR 0014](https://github.com/ithaka-dev/verity-foundation/blob/main/docs/decisions/0014-verifier-update-discipline.md)).
- **Never loosen a check to resolve a mismatch.** `mr-kms` varies per boot, so spurious mismatches are guaranteed; relaxing the comparison until they pass converts this library into decoration while everything appears to keep working.

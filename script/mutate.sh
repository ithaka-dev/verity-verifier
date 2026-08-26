#!/usr/bin/env bash
#
# Mutation testing: does the suite actually detect the bugs it is supposed to?
#
# ## Why this exists here, and why it matters more than it did next door
#
# Coverage counts lines executed. It cannot tell an assertion from a bystander. `verity-contracts`
# has the receipt — its invariant suite once scored 2 of 12 while coverage looked healthy, and you
# could delete `requireValidSignature` outright with every test still green.
#
# The stakes are higher in this crate. A weakened contract is visible on chain and can be replaced;
# a weakened verifier ships inside every agent and, by ADR 0014's reasoning, is **less patchable
# than the app template**. ADR 0009 rule 3 says never loosen a check to resolve a mismatch, and ADR
# 0014's whole design goal is that a loosened verifier is *visible*. This is the tool that makes it
# visible before release rather than after.
#
# Each mutant below is a loosening someone could plausibly make — several of them are the exact
# shape CLAUDE.md warns about, and two are defects this project has already made once.
#
# ## Reading a result
#
# `killed` is good — the suite caught it. `SURVIVED` means that behaviour has no test behind it and
# can regress silently.
#
# **Do not delete a surviving mutant to make the score green.** Either write the test, or mark it
# EQUIVALENT with a reason — a mutant that cannot change observable behaviour is not a gap.
#
#   ./script/mutate.sh              # the whole suite — this is the score that counts
#   ./script/mutate.sh --quick      # core mutants only; explicitly SKIPS the feature-gated ones
#                                   # (connect/fetch) — run the full suite to score those
set -uo pipefail

cd "$(dirname "$0")/.."

# An array, not a string. Next door, `forge test $QUICK` word-split *and* glob-expanded into two
# paths, forge rejected its own command line, and the non-zero exit was counted as a kill — every
# mutant "died" without a single test running. The same mistake is one interpolation away here.
#
# `--quick` drops `--all-features`, so the crate builds with default features (`attest`) only. The
# consequence is the whole point of the flag — the slow `connect`/`fetch` deps (ring, rustls, ureq)
# are never compiled — but it has a trap: a mutant on a file those features gate away is applied to
# source the compiler never sees, so `cargo test` passes and the mutant reads as SURVIVED. That is a
# *false* gap: the mutant is unscored here, not unguarded. A mutant that needs a non-default feature
# therefore declares it (the 2nd arg to `run`), and under `--quick` it is skipped out loud rather
# than mis-scored — the full run is where it counts. (Before this was fixed, `--quick` could not even
# establish a baseline: the connect/attest test files were unguarded and failed to compile under
# default features. That is the sibling VA-3 follow-up; both had to land together.)
CARGO_ARGS=(--all-features)
QUICK=0
[ "${1:-}" = "--quick" ] && { CARGO_ARGS=(); QUICK=1; }

backup=$(mktemp -d)
cp -R crates "$backup/"
restore() { rm -rf crates && cp -R "$backup/crates" crates; }
trap 'restore; rm -rf "$backup"' EXIT

killed=0
survived=0
equivalent=0
skipped=0
declare -a survivors=()
declare -a skips=()

# A mutant that fails to apply is worse than a missing one: it leaves the score looking complete
# while one behaviour went unchecked. `set -e` is off so results can be tallied, so this exits
# explicitly instead.
mutate() {
  python3 - "$1" "$2" "$3" <<'PY'
import sys, pathlib
path, old, new = sys.argv[1], sys.argv[2], sys.argv[3]
p = pathlib.Path(path)
s = p.read_text()
if old not in s:
    sys.exit(f"PATTERN NOT FOUND in {path}: {old[:70]}")
p.write_text(s.replace(old, new, 1))
PY
  local status=$?
  if [ $status -ne 0 ]; then
    echo "::error::mutant could not be applied — the source moved and this mutant stopped testing" >&2
    exit 2
  fi
}

run() {
  local name="$1"
  # An optional 2nd arg names a cargo feature this mutant needs to be *scored*: it lives on a file
  # gated behind that feature. Under `--quick` (default features only) such a file is not compiled,
  # so the mutation is inert and `cargo test` would pass — reporting SURVIVED for a mutant that was
  # never actually run. Skip it out loud instead, and count it as skipped, not survived, so the
  # score and the exit code both stay honest. The full run (no `--quick`) ignores this and scores it.
  local needs="${2:-}"
  if [ "$QUICK" = 1 ] && [ -n "$needs" ]; then
    printf '  \033[2mskipped\033[0m   %s \033[2m(feature-gated: needs --features %s; scored only in the full run)\033[0m\n' "$name" "$needs"
    skips+=("$name (needs --features $needs)")
    skipped=$((skipped + 1))
    restore
    return
  fi
  # A mutant that does not compile is still killed — the compiler is part of the suite, and a
  # loosening the type system rejects is a loosening that cannot ship. Reported separately so the
  # score is not quietly inflated by mutants that never ran a test.
  if cargo test ${CARGO_ARGS[@]+"${CARGO_ARGS[@]}"} >/tmp/mutate-run.log 2>&1; then
    printf '  \033[31mSURVIVED\033[0m  %s\n' "$name"
    survivors+=("$name")
    survived=$((survived + 1))
  elif grep -q "^error\[E[0-9]" /tmp/mutate-run.log; then
    printf '  killed    %s \033[2m(rejected by the compiler)\033[0m\n' "$name"
    killed=$((killed + 1))
  else
    printf '  killed    %s\n' "$name"
    killed=$((killed + 1))
  fi
  restore
}

note_equivalent() {
  printf '  equivalent %s\n             \033[2m%s\033[0m\n' "$1" "$2"
  equivalent=$((equivalent + 1))
}

echo "Mutation testing verity-verifier${1:+ ($1)}"
echo

# — the check whose absence made the contracts harness lie —
#
# If the *unmutated* source does not pass, every mutant "dies" for free and the score counts
# nothing. That is not hypothetical: it reported 15/15 having run no tests at all.
#
# So: prove the baseline is green before trusting a single kill.
printf 'baseline (unmutated source must pass) ... '
if ! cargo test ${CARGO_ARGS[@]+"${CARGO_ARGS[@]}"} >/tmp/mutate-baseline.log 2>&1; then
  echo "FAILED"
  echo
  echo "The suite does not pass on unmutated source, so every mutant below would be counted as" >&2
  echo "killed without any test running. Fix the baseline first." >&2
  echo >&2
  tail -20 /tmp/mutate-baseline.log >&2
  exit 2
fi
echo "ok"
echo

BINDING=crates/verity-verifier/src/binding.rs
QUOTE=crates/verity-verifier/src/quote.rs
IMAGES=crates/verity-verifier/src/images.rs
VERDICT=crates/verity-verifier/src/verdict.rs
CHANNEL=crates/verity-verifier/src/channel.rs
ENDPOINT=crates/verity-verifier/src/endpoint.rs
RATLS=crates/verity-verifier/src/ratls.rs
TLS=crates/verity-verifier/src/connect/tls.rs
CONNECT_HTTP=crates/verity-verifier/src/connect/http.rs
COMPOSE_HTTP=crates/verity-verifier/src/compose/http.rs

echo "— the binding (C6: licensed_composeHash == attested_composeHash) —"

# The defining property, deleted. If this survives, the crate has no reason to exist.
mutate "$BINDING" \
  'if actual == *licensed {' 'if true {' \
  && run "compose hash mismatch accepted"

# ADR 0009 rule 3, as a one-character edit: compare a prefix instead of the whole thing. This is the
# shape a loosening actually takes — nobody deletes a check, they weaken a comparison.
mutate "$BINDING" \
  'if expected == *measured {' 'if expected.as_bytes()[..16] == measured.as_bytes()[..16] {' \
  && run "MR-CONFIG-ID compared on its first half only"

mutate "$BINDING" \
  'if expected == *measured {' 'if true {' \
  && run "MR-CONFIG-ID mismatch accepted"

# CLAUDE.md: *branch on the prefix byte, never assume it*. Assuming V1 makes a V2 measurement get
# compared against a V1 reference — a mismatch reported as an attack rather than a version problem.
mutate "$BINDING" \
  'Some(0x02) => Some(Self::V2),' 'Some(0x02) => Some(Self::V1),' \
  && run "V2 measurements treated as V1"

mutate "$BINDING" \
  '_ => None,' '_ => Some(Self::V1),' \
  && run "an unrecognised prefix assumed to be V1"

# The reference construction itself. `0x01 ‖ composeHash ‖ 0x00×15` — a wrong prefix byte means
# every genuine deployment is refused, which fails closed but fails.
mutate "$BINDING" \
  'out[0] = 0x01;' 'out[0] = 0x02;' \
  && run "expected MR-CONFIG-ID built with the wrong version prefix"

# Hash parsing: accepting the wrong length is how a padded or truncated hash becomes a valid-looking
# ComposeHash that then compares against something nobody licensed.
mutate "$BINDING" \
  'if s.len() != COMPOSE_HASH_LEN * 2 {' 'if false {' \
  && run "a hash of the wrong length accepted"

echo
echo "— the quote parser (attacker-influenced bytes) —"

mutate "$QUOTE" \
  'if version != 4 {' 'if false {' \
  && run "a quote of any structure version accepted"

mutate "$QUOTE" \
  'if tee_type != TEE_TYPE_TDX {' 'if false {' \
  && run "a quote from a non-TDX TEE accepted"

echo
echo "— image pinning (ADR 0007) —"

# The check dStack's own reference compose gets wrong. A tag keeps composeHash stable while the code
# inside changes freely: every check passes and the guarantee is gone.
mutate "$IMAGES" \
  'if images.iter().any(|i| i.digest() == licensed_digest) {' 'if true {' \
  && run "a compose not referencing the licensed image accepted"

echo
echo "— the verdict (ADR 0014) —"

# Decision 2: TCB enforcement is mandatory and not configurable. This is the defect T-11 found —
# recorded honestly and absent from the boolean an agent branches on.
mutate "$VERDICT" \
  '            Self::TcbStatus,
' '' \
  && run "TCB status dropped from the essential checks"

mutate "$VERDICT" \
  '            Self::MrConfigId,
' '' \
  && run "MR-CONFIG-ID dropped from the essential checks"

# Decision 1: a verdict is never a bare boolean, and "skipped" must not read as success. This is the
# single edit that would make a verifier approve everything it declined to check.
mutate "$VERDICT" \
  'matches!(self, Self::Passed)' 'matches!(self, Self::Passed | Self::Skipped(_))' \
  && run "a skipped check treated as passed"

mutate "$VERDICT" \
  '.filter(|c| !self.outcome(*c).is_some_and(Outcome::passed))' \
  '.filter(|c| self.outcome(*c).is_some_and(|o| matches!(o, Outcome::Failed(_))))' \
  && run "a check that never ran no longer counts as missing"

echo
echo "— channel binding (CR-1) —"
#
# The finding these exist for: the verifier consumed the quote as a *detached artifact*, so a genuine
# quote from a destroyed CVM paired with an attacker's endpoint passed every essential check. Every
# other mutant in this file loosens a comparison between two recorded values; these loosen the only
# comparison that says the recording is about the connection in front of you.

# The comparison itself. If this survives, `ChannelBound` reports `passed` for any certificate and
# CR-1 is back with a green test suite on top of it.
mutate "$CHANNEL" \
  'if commitment.0 == *report_data.as_bytes() {' 'if true {' \
  && run "channel binding accepts any certificate"

# ADR 0009 rule 3 again, in the new module: nobody deletes a check, they weaken a comparison. A
# 32-byte prefix of a SHA-512 still looks like plenty to someone in a hurry.
mutate "$CHANNEL" \
  'if commitment.0 == *report_data.as_bytes() {' \
  'if commitment.0[..32] == report_data.as_bytes()[..32] {' \
  && run "commitment compared on its first 32 bytes only"

# "The enclave committed to nothing" must never match an expectation that is also nothing. Delete
# this guard and an all-zero `report_data` compares against a commitment nobody supplied — which is
# what a quote requested for a non-certificate purpose carries.
mutate "$CHANNEL" \
  'if report_data.is_zero() {' 'if false {' \
  && run "an all-zero report_data no longer refuses"

# The trap dStack sets on genuine certificates: `cert_usage` reads `app:custom`, and a verifier that
# took *that* as the commitment tag would refuse every legitimate application certificate. Observed
# on hardware, so this mutant is a real mistake rather than an invented one.
mutate "$CHANNEL" \
  'const RATLS_TAG: &str = "ratls-cert";' \
  'const RATLS_TAG: &str = "app:custom";' \
  && run "the commitment tag taken from cert_usage instead of being fixed"

mutate "$VERDICT" \
  '            Self::ChannelBound,
' '' \
  && run "channel binding dropped from the essential checks"

# — the two shell gates, which `cargo test` cannot run —
#
# `04-refuses-on-mismatch.sh` and `06-refuses-relayed-endpoint.sh` grep the runner's stdout. Both
# edits below are invisible to every behavioural test in this crate and turn a gate red — or worse,
# green for the wrong reason — so they are scored here.

# The check name is an identifier in two scripts and in F-09's alert, not just a display string.
mutate "$VERDICT" \
  'Self::ChannelBound => "channel_bound",' 'Self::ChannelBound => "channelBound",' \
  && run "the channel_bound identifier renamed under two shell gates"

# The *rendering* version of "a skip read as a pass". The verdict-level mutant above covers the
# semantics — `Outcome::passed` returning true for a skip — and this covers the word printed. They
# have different blast radii: this one leaves `is_trustworthy` correct while making `04` step 3's
# `channel_bound skipped` grep fail and `06`'s `passed` greps succeed spuriously.
mutate "$VERDICT" \
  'Self::Skipped(_) => "skipped",' 'Self::Skipped(_) => "passed",' \
  && run "a skipped check rendered as passed in the runner transcript"

echo
echo "— the verified transport (MA-1) —"
#
# CR-1 closed the mechanism; MA-1 closes the provenance. `verify()` binds a quote to a certificate it
# was *handed*, and could not know it came from the handshake being judged. `connect_verified` owns
# the socket — so the mutants below are about the two new ways that ownership can be given away:
# accepting a peer that cannot prove it holds the key, and handing out a client anyway.

# **The one that matters.** rustls offers no static-RSA suite, so in both TLS 1.2 and 1.3 the
# certificate's private key signs the handshake and nothing else — these two calls are the only place
# the peer proves it holds it. An enclave's RA-TLS certificate is PUBLIC: anyone who connects to the
# real CVM can copy it. Stub these (which is exactly what ureq's own `DisabledVerifier` does) and a
# relay serving that copy passes channel binding, because the certificate really does match the
# quote. MA-1 would be decoration with a green suite on top of it.
mutate "$TLS" \
  '        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )' \
  '        let _ = (message, cert, dss);
        Ok(HandshakeSignatureValid::assertion())' \
  && run "TLS 1.3 handshake signatures asserted instead of verified" connect

# The same edit on the version a local client and server do NOT negotiate by default. Without
# `the_same_replay_over_tls12_also_fails_the_handshake` pinning a TLS 1.2 server, this mutant changes
# nothing any test observes — which is how a whole protocol version goes unchecked.
mutate "$TLS" \
  '        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )' \
  '        let _ = (message, cert, dss);
        Ok(HandshakeSignatureValid::assertion())' \
  && run "TLS 1.2 handshake signatures asserted instead of verified" connect

# The structural gate. `VerifiedClient` has no constructor that does not pass through here, so this
# single edit is what would hand a client out on a verdict that failed an essential check — the
# "verdict you can ignore" the 2026-08-09 review found, moved inside the library.
mutate "$VERDICT" \
  '        if verdict.is_trustworthy() {' '        if true {' \
  && run "a client handed out on an untrustworthy verdict"

# The post-verify guard in the connector. Removing it returns a transport for a connection that did
# not verify — including on a *reconnect*, where nothing else would notice: the first request
# succeeded, so an agent has every reason to believe the second one is talking to the same peer.
mutate "$CONNECT_HTTP" \
  '        let verdict =
            TrustworthyVerdict::check(verdict).map_err(|verdict| Refusal::NotTrustworthy {
                verdict: Box::new(verdict),
            })?;' \
  '        let verdict = TrustworthyVerdict::check(verdict)
            .unwrap_or_else(|v| TrustworthyVerdict::check(v).unwrap_or_else(|_| unreachable!()));' \
  && run "the post-verify guard removed from the connector" connect

# The endpoint form dStack's own API advertises. Classifying the terminating host as passthrough
# means `connect_verified` dials it and reports a bare channel-binding mismatch — the refusal that
# reads as "the check is too strict" and invites the loosening ADR 0009 rule 3 forbids.
mutate "$ENDPOINT" \
  '            EndpointForm::DstackTerminating' '            EndpointForm::DstackPassthrough' \
  && run "a TLS-terminating gateway host classified as passthrough"

# The documented off-by-4. X.509's outer OCTET STRING is stripped by the parser; dStack's value is
# *itself* one, so the quote starts 8 bytes after the OID and not 4. Dropping the nested unwrap
# yields a buffer that still looks quote-shaped and fails later, somewhere less obvious.
mutate "$RATLS" \
  '    let inner = OctetString::from_der(extension.extn_value.as_bytes()).map_err(|e| {
        AttestationError::UnreadableEnvelope {
            reason: e.to_string(),
        }
    })?;
    Ok(inner.into_bytes().into_vec())' \
  '    Ok(extension.extn_value.as_bytes().to_vec())' \
  && run "the nested OCTET STRING left on the quote (strip 4, not 8)"

# A redirect to another host is a request to leave the connection that was verified. Following one
# carries an agent request to a peer nobody attested, and returns its body under a
# `VerifiedClient` — a verdict about one endpoint attached to an answer from another.
mutate "$CONNECT_HTTP" \
  '        .max_redirects(0)' '        .max_redirects(10)' \
  && run "redirects followed away from the verified peer" connect

# **The deadline, which was a defect before it was a test.** A per-socket read timeout bounds a peer
# that says nothing; it does not bound one that says something every half-timeout, because
# `complete_io` loops internally and never returns for a deadline to be checked around it. Give each
# read the full budget instead of what remains and a dribbling peer stalls the verification forever
# — measured at 31s against a 300ms budget. This is the mutant that stops that regression shipping
# 28/28 green, which is precisely how the original got in.
mutate "$TLS" \
  '.checked_duration_since(Instant::now())' \
  '.checked_duration_since(Instant::now() - Duration::from_secs(3600))' \
  && run "the handshake deadline never counts down, so each read gets the whole budget" connect

# Port 0 parses as a `u16` and names nothing to connect to. `Ok(0) | Err(_)` share a source line, so
# per-line coverage cannot tell whether both patterns are exercised — the exact "coverage cannot tell
# an assertion from a bystander" case this file exists for.
mutate "$ENDPOINT" \
  'Ok(0) | Err(_) => return Err(EndpointError::BadPort { port: p.to_owned() }),' \
  'Err(_) => return Err(EndpointError::BadPort { port: p.to_owned() }),' \
  && run "port 0 accepted as a connectable port"

echo
echo "— compose retrieval (VA-3) —"
#
# Retrieval is outside the trust model — a wrong or hostile compose document is caught by the hash
# check that runs after every fetch. This section is about the request-line-level side effects that
# happen *before* that check: SSRF, injection, and traversal, which the hash check does nothing to
# prevent.

# The same reasoning as $CONNECT_HTTP's redirect mutant above, in the sibling agent that had no
# redirect policy at all before VA-3. A content-addressed gateway has no legitimate reason to bounce
# a fetch elsewhere; following one carries a pre-hash-check request into loopback/private space.
mutate "$COMPOSE_HTTP" \
  '        .max_redirects(0)' '        .max_redirects(10)' \
  && run "the compose agent follows redirects away from a content-addressed source" fetch

echo
echo "— known equivalent —"
note_equivalent "ComposeHash::of over a Vec vs a slice" \
  "sha2 hashes the same bytes either way; the signature difference is ergonomic, not observable."

# Recorded rather than omitted. The guard is real and its absence would be a spinning thread that
# `DeadlineIo` cannot bound — that path performs no I/O, so nothing consults the deadline. But the
# state it guards is not reachable in rustls 0.23.42, so removing it changes no observable
# behaviour, which is this file's definition of equivalent.
note_equivalent "connect/tls.rs: the Ok((0, 0)) hot-spin guard" \
  "complete_io returns (0,0) only when !wants_write() && !wants_read(); mid-handshake wants_read()
             goes false only via has_received_close_notify, which common_state.rs:524 sets only when
             may_receive_application_data is true — false during a handshake, with rustls' own
             comment 'do not treat unauthenticated alerts like this'. Probed: a peer answering the
             ClientHello with a plaintext close_notify is bounded by the deadline, not by this guard.
             Kept against a future rustls making the state reachable; re-check on a rustls bump."

echo
echo "— NOT mutable, and said out loud —"
#
# Two lines in the verified transport carry real security weight and cannot be scored here. Listing
# them is the point: a harness that silently omits what it cannot test looks complete while a
# behaviour goes unchecked, which is the failure this file exists to prevent. Both are review
# checklist items instead.
echo "  review    connect/tls.rs: \`config.resumption = Resumption::disabled()\`"
echo "            A resumed handshake calls NEITHER signature verifier — rustls hard-codes both"
echo "            assertions on that path — so the quote would come from a remembered certificate"
echo "            rather than this connection's. Deleting the line leaves every test green, because"
echo "            a resumed connection in the cases we can build locally still presents the right"
echo "            certificate. Nothing here can defend it; a human must."
echo "  review    connect/http.rs: \`Transport::is_tls() -> true\`"
echo "            Defaults to false, and ureq then rejects an https request over a fully verified"
echo "            connection. Behaviourally defended by the request tests rather than by a mutant:"
echo "            remove it and every request fails, which is loud but is not a scored kill."

echo
total=$((killed + survived))
skipnote=""
[ "$skipped" -gt 0 ] && skipnote=", $skipped skipped (feature-gated — run the full suite)"
echo "score: $killed/$total killed, $equivalent equivalent$skipnote"

if [ "$skipped" -gt 0 ]; then
  echo
  echo "skipped here, scored only in the full run (\`./script/mutate.sh\` with no --quick):"
  for s in "${skips[@]}"; do echo "  - $s"; done
fi

if [ "$survived" -gt 0 ]; then
  echo
  echo "these behaviours have no test behind them:"
  for s in "${survivors[@]}"; do echo "  - $s"; done
  echo
  echo "Write the test, or mark the mutant EQUIVALENT with a reason. Do not delete it."
  exit 1
fi

# A skip is not a pass. Under --quick the exit stays 0 (the skipped mutants are covered by the full
# run), but say plainly that this was a partial score so a green --quick is never mistaken for the
# full guarantee.
if [ "$skipped" -gt 0 ]; then
  echo "every mutant that ran was caught; $skipped feature-gated mutant(s) were skipped — the full run scores those."
else
  echo "every mutant was caught."
fi

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
#   ./script/mutate.sh --quick      # skips the slow feature-gated suites
set -uo pipefail

cd "$(dirname "$0")/.."

# An array, not a string. Next door, `forge test $QUICK` word-split *and* glob-expanded into two
# paths, forge rejected its own command line, and the non-zero exit was counted as a kill — every
# mutant "died" without a single test running. The same mistake is one interpolation away here.
CARGO_ARGS=(--all-features)
[ "${1:-}" = "--quick" ] && CARGO_ARGS=()

backup=$(mktemp -d)
cp -R crates "$backup/"
restore() { rm -rf crates && cp -R "$backup/crates" crates; }
trap 'restore; rm -rf "$backup"' EXIT

killed=0
survived=0
equivalent=0
declare -a survivors=()

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
echo "— known equivalent —"
note_equivalent "ComposeHash::of over a Vec vs a slice" \
  "sha2 hashes the same bytes either way; the signature difference is ergonomic, not observable."

echo
total=$((killed + survived))
echo "score: $killed/$total killed, $equivalent equivalent"

if [ "$survived" -gt 0 ]; then
  echo
  echo "these behaviours have no test behind them:"
  for s in "${survivors[@]}"; do echo "  - $s"; done
  echo
  echo "Write the test, or mark the mutant EQUIVALENT with a reason. Do not delete it."
  exit 1
fi

echo "every mutant was caught."

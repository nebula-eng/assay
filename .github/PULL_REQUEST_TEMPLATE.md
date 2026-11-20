<!--
  Thanks for the PR. The four questions below are the ones a reviewer will ask
  anyway; answering them here saves a round trip.
-->

## What changed

<!-- One paragraph. What behaviour is different after this PR? -->

## Why

<!-- The analysis question or bug this addresses. Link the issue if there is one. -->

## Invariants

Tick what applies. See [CONTRIBUTING.md](../CONTRIBUTING.md) for the full list.

- [ ] No new panics on hostile input — parsing code still uses only `bytes::Reader`
- [ ] Every new loop over attacker-controlled data has a named `MAX_*` cap
- [ ] No new parsing dependencies in `assay-core`
- [ ] No network, time or randomness in the analysis path
- [ ] Every new conclusion carries evidence (finding / technique / factor / note)
- [ ] Tests added: a positive case **and** a plausible negative case

## What I deliberately did not do

<!--
  Limits left in place are as important as features added. If this PR stops at
  first-slice Mach-O, or does not decode .NET metadata, or leaves a format
  unsupported, say so — and say why.
-->

## Sample / fixture

<!--
  If this adds or changes a detector: describe the structural feature that
  triggers it, and add it to scripts/make_samples.py so it is reproducible.
  Do not attach real malware.
-->

## Checks

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo test --workspace`
- [ ] `npm --prefix ui run typecheck` (if the UI changed)
- [ ] `python tests/e2e.py --binary target/debug/assay --samples samples` (if CLI output changed)

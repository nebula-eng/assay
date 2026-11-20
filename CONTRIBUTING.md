# Contributing to Assay

Thanks for looking. This document is short because the hard rules are few and
they are not negotiable.

## The invariants

A pull request that breaks any of these will be asked to change, regardless of
how useful the feature is.

### 1. The engine never panics on hostile input

Every parser must be *total*: a malformed file yields a partial result plus a
diagnostic, never an abort. This is not politeness — if a crafted file can crash
the analyser, the attacker has turned detection into denial-of-analysis.

Practically:

- Read bytes only through `bytes::Reader`. It cannot index out of bounds.
- No `unwrap` / `expect` / `panic!` / slice indexing in parsing code. `unwrap` is
  acceptable in tests and in code paths that are provably infallible (e.g. a
  fixed-size array conversion guarded by a length check two lines above).
- `#![forbid(unsafe_code)]` is crate-wide. Do not propose an exception.

### 2. Every loop over attacker-controlled data has a named cap

If you add a `for i in 0..header.some_count`, there must be a `const MAX_…`
next to it with a comment saying why that number. The existing caps are in
[ARCHITECTURE.md §11](docs/ARCHITECTURE.md#11-threading-and-memory).

### 3. Every conclusion points at evidence

A finding, a technique, a score factor or a structural note must carry the
observation that produced it. If you cannot express *why*, the check does not
belong in the engine yet.

The rule engine enforces a weak version of this: a finding with an empty evidence
vector is never emitted.

### 4. No new parsing dependencies

`assay-core` depends on `serde`, `serde_json`, `thiserror`, `regex-lite` and
`rayon`. It does not depend on `goblin`, `object`, `nom`, `binrw`, `sha2`,
`md-5`, `memmem` or anything else that would replace hand-written code. Adding one
requires a written argument in the PR description explaining why the invariant it
would break is worth breaking.

The reason is not NIH. It is that a parser whose every failure mode is known and
reported with an absolute offset is the whole product, and delegating it means
inheriting a failure model optimised for well-formed input.

### 5. No network, no time, no randomness in the analysis path

The same bytes plus the same rules must produce byte-identical JSON on any
machine. Timestamps belong in metadata (the SBOM), never in a verdict.

### 6. Tests come with the change

- A new parser branch: a fixture built by code (`build_minimal_pe` and friends in
  the test modules) plus an assertion on the recovered field.
- A new detector: a positive case and a negative case. "It fires on the bad file"
  is half a test; the other half is "it does not fire on a plausible good file".
- A new rule: it must survive the built-in corpus test (valid grammar, non-empty
  condition set, unique id, evidence on every finding).

## Workflow

```bash
git clone https://github.com/nebula-eng/assay.git
cd assay
cargo build -p assay-cli      # no Node needed for the engine or the CLI
cargo test -p assay-core -p assay-cli
make samples                  # regenerate fixtures
```

`--workspace` also covers the Tauri shell, whose build script requires the
front-end bundle it embeds and refuses to produce a binary that would open an
empty window. If you work on the desktop side, build the UI first:

```bash
npm --prefix ui install
npm --prefix ui run build
cargo test --workspace
```

Before pushing:

```bash
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test
python scripts/linkcheck.py      # if you touched the docs
npm --prefix ui run typecheck    # if you touched the UI
```

All of them must be clean. CI runs the same commands on Linux, macOS and Windows.

If your change touches detection — a rule, a technique, a string predicate, the
packing heuristic — run the calibration too. It is not a gate on other people's
machines because it needs a Windows host, but a change that moves the
distribution without explaining why is a change that has not been measured:

```bash
make calibrate    # python scripts/calibrate.py, prints the distribution
```

The source tree ships with `nebula-eng/assay` as its repository slug. If you are
publishing a fork, `python scripts/set-repo.py <owner>/<repo>` rewrites all 22
occurrences (manifest, badges, issue templates, security policy, changelog
compare links) in one pass.

## Where things live

| Path | Contents | Notes |
|---|---|---|
| `crates/assay-core/src/bytes.rs` | The bounded reader | The most important file in the project |
| `crates/assay-core/src/format/` | PE, ELF, Mach-O, archive parsers | One file per container |
| `crates/assay-core/src/analysis/` | Entropy, strings, IOC, packing, ATT&CK, scoring | Pure functions over the parsed image |
| `crates/assay-core/src/analysis/hygiene.rs` | The five string predicates | Shared by ATT&CK inference and the rule engine; do not fork it |
| `crates/assay-core/src/rules/` | Rule model and engine | Rules are data; the engine is 300 lines |
| `crates/assay-core/src/asn1.rs` | DER walker for Authenticode | Read-only; no verification |
| `crates/assay-cli/` | The `assay` binary | Arg parsing and output formatting only |
| `crates/assay-desktop/` | Tauri shell | Deliberately thin: window, dialog, drag-drop |
| `ui/` | React front end | No UI framework; CSS variables + hand-rolled components |
| `rules/builtin.json` | The shipped corpus | Readable and editable without recompiling |
| `scripts/` | Fixture and icon generators, calibration, link check, repo-slug rewrite | Generators write to `samples/`, which is not committed |

## Style

Comments should explain why. The code already says what it does, so a comment
restating the line is noise, while one explaining why the obvious alternative was
rejected is the most useful thing in the file. `bytes.rs` and `analysis/score.rs`
show the intended density.

Give constants names rather than literals: `MAX_RESOURCE_ENTRIES` beats `8192`,
and the comment beside it should answer the question "why 8192" before anyone has
to ask.

Prefer a boring implementation of a clear idea to a clever implementation of an
unclear one. Someone will read this codebase while deciding whether to trust a
binary with it.

Error messages are read by people, not just by logs. `AssayError::Truncated`
carries `what`, `offset`, `needed` and `available` because "parse error" is
useless when you are staring at a hex editor.

## Commits and PRs

- One logical change per commit. "Fix ELF RPATH parsing and add three rules" is
  two PRs.
- PR description: what changed, why, and what you did *not* do (the limits you
  left in place are as important as the feature).
- If you add a detector, include a sample description in the PR — not a sample
  file. Describe the structural feature; the fixture generator is where it
  becomes reproducible.

## Reporting a bug

A parser crash on a real file is the highest-value bug report this project can
receive. Please include:

1. The trigger — which bytes, at which offset, in which format.
2. The panic message if there was one.
3. The smallest input that reproduces it.

If the file is sensitive, describe the structure rather than attaching it. A
10-line Python snippet that builds the offending header is better than a 4 MB
binary anyway, because it becomes a test.

Security issues: see [`SECURITY.md`](SECURITY.md) instead of opening an issue.

## License

Contributions are accepted under the MIT license (see [`LICENSE`](LICENSE)). By
opening a PR you confirm you have the right to submit the code under those terms.

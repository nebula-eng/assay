# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Pre-1.0, a minor bump may include breaking changes to the JSON report schema.
Those are called out explicitly under **Changed**.

## [Unreleased]

### Planned

- Multi-slice Mach-O analysis (currently the first slice only, reported as a note)
- Managed assembly metadata table decoding (type and method names)
- `.NET` strong-name signature field extraction
- Debian `.deb` control-file parsing
- An opt-in, offline reputation database file — never a network call
- Per-deployment rule severity overrides (see SCORING.md §10 for why this is
  deliberately not in core)

## [0.1.3] — 2026-11-17

Most of this release is about failure modes. Several places where the tool used to
be quietly wrong now report the problem instead, and one rule changed behaviour
because its name did not match what it matched.

### Fixed: exit codes

- Usage errors no longer exit 2. clap's default code for a malformed command
  line is 2, which this tool already uses for "critical risk". A CI job that
  mistyped a subcommand read the failure as a critical finding. Every usage
  error — unknown subcommand, missing argument, invalid enum value, unknown
  flag — now exits 3 like the rest of the setup failures, and `--help` /
  `--version` still exit 0.
- A bare `assay` is an error, not a success. It printed usage and returned 0,
  so `assay && deploy` deployed without analysing anything.

### Fixed: silent truncation

A truncated file used to produce confident negatives. `trunc_elf.so` arrived as
"0 sections, no `PT_GNU_RELRO`, no `PT_GNU_STACK`" — three statements about a
segment table the parser never read.

- Unreadable tables are reported. `BinaryImage` gained
  `unreadable_tables[]`, carried into the report and mirrored as a warning
  diagnostic. ELF records a section or program header table declared past EOF;
  Mach-O records a load-command region larger than the file; gzip records a
  stream shorter than its 10-byte header plus 8-byte trailer.
- Hardening conclusions are gated on readability. When the segment table
  could not be read, the NX and RELRO notes are withheld — "unexamined" is not
  "unhardened".
- An empty archive is still valid. A 22-byte empty zip and a zero-block tar
  stay clean; the truncation checks are per-format and specific, because a
  generic "recognised container with no entries" heuristic flagged both.

### Fixed: the rules engine could be widened by a typo

This was the worst bug in the release. `MatchSpec` accepted unknown fields, so
`"min_entrpy": 7.0` was silently dropped, the condition set became empty, and the
rule then matched every artefact at its stated severity. `rules validate`
reported it as fine.

- `MatchSpec` and `Rule` now use `deny_unknown_fields`; the parse error names the
  offending key and lists the clauses that exist.
- `Rule::validate` rejects a rule with no conditions, so an empty `match` cannot
  be shipped either.
- `archive-ships-executables` now has a condition that matches its name: the new
  `min_executable_entries` clause reads the entry names the archive parser already
  classified. It previously required only "is an archive", and fired on a
  truncated 12-byte gzip with no members at all.

### Fixed: the calibration corpus was a subset, and the number was not reproducible

This section of the previous draft quoted 643 system binaries. The measurement
was real, but the rule that selected those 643 files was never written down, so
re-running the calibration meant re-inventing it — and running the whole
directory instead produced a materially different picture: **nine critical
verdicts and 1,789 files at medium** on the operating system's own libraries.

The corpus is now the directory itself, with no filter: 4,386 files, 2,183 MiB,
38 s on all cores. `scripts/calibrate.py` reproduces the distribution on any
Windows host, and `tests/e2e.py` gates fifteen of those binaries instead of
eight.

| | clean | low | medium | high | critical |
|---|---|---|---|---|---|
| before | 2,188 | 399 | 1,789 | 10 | **9** |
| after | 3,796 | 389 | 199 | **2** | **0** |

Every change below was made because of a specific file in that run.

- T1486 required the noun `payment`. Eight Microsoft components carry a
  cipher API next to strings like "payment required" (`MdmDiagnostics.dll`) or
  "payment app extension data invalid for package" (`Windows.Payments.dll`),
  because a billing stack encrypts and bills. The marker list now contains
  sentence fragments of a demand (`your files have been encrypted`, `pay in
  bitcoin`, `unlock your files`, `.locked`) and no bare nouns.
- T1490 required the tool name `bcdedit`. `ResetEngine.dll` carries "failed
  to wait for bcdedit -set debug on" — a factory reset enabling a debug flag. The
  markers are now the deletion (`vssadmin delete`, `delete shadows`,
  `delete catalog`, `recoveryenabled no`), not the utility.
- `impact-ransomware-shape` fired on T1490 alone, which is the recovery step,
  not the encryption. It now requires T1486; `impact-recovery-inhibition` keeps
  T1490.
- Rule strings bypassed the hygiene predicates. `slmgr.vbs` and `winrm.vbs`
  were high for obfuscation because both define `GetResource = Eval(name)` to
  read a string from a resource DLL. The predicates moved out of the ATT&CK
  module into `analysis::hygiene`, gained a fifth one for the Windows Script Host
  idiom, and the rule engine now applies the same set the technique layer does.
- The packer heuristic charged for compiler output. A `.fothk` section
  (emitted by `/hotpatch`) was a "non-standard section name"; a multi-kilobyte
  INT3 run was a "sled" even though the MSVC linker pads section gaps with
  `0xCC`; TLS callbacks were ten points of packing on top of their own finding,
  although MSVC emits them for `__declspec(thread)`. All three are gone, and only
  a NOP run counts as a sled.
- "No embedded signature" cost eight points. Windows signs most of its own
  binaries through a catalog that this tool does not verify, so the absence of an
  embedded blob says nothing — the code comment said as much while the score
  charged for it anyway. It is now recorded in the evidence and costs zero.
  This is the same rule as "unexamined is not unhardened": a fact the tool cannot
  interpret is not evidence.
- `pe-no-imports` applied to libraries. 426 of the 4,386 files were medium
  for having an empty import table, among them every keyboard-layout DLL — which
  is a data file with a PE header. The rule now applies to executables only.
- Two rules were graded above what they claim. `pe-tls-callbacks` called
  itself "a context signal rather than a verdict" at medium, and
  `pe-unsigned-with-network` asserted "unsigned" about files it could not check.
  Both are `low` now, and the second is renamed for what it actually observes.

The two remaining high findings are kept on purpose and documented in
`docs/SCORING.md` §9: the Settings app's administrative flow, which really does
carry the switches that disable Defender, and `dpapisrv.dll`, which really does
open an LSA policy handle to unwrap master keys. Suppressing either would mean
making a rule unable to fire.

### Fixed: wording

- `plural()` inflects. It appended `s` unconditionally, producing "2
  executable or script entrys". Consonant + `y` → `ies`, sibilants → `es`.
- A directory is named as a directory. `assay analyze <dir>` reported the
  platform's permission error ("access denied"), sending the reader after a
  permissions problem that did not exist. It now says the path is a directory and
  points at `assay batch`.

### Fixed: documentation that described a different program

Each of these was a statement a reader could act on and be wrong.

- The dependency count omitted `serde_json`. The table said four runtime
  dependencies and then listed four names; `assay-core` has five, and the fifth is
  the one that writes the JSON report.
- The JSON schema block disagreed with the serialiser. `image` was missing
  `endian`, `entry_point` and `image_base`, and `entropy` listed `peak_entropy`
  before `peak_offset`. Field order is not a contract, but a schema example that
  omits fields the tool always emits reads as "these fields are optional".
- `rules-regex` gated nothing. `assay-core` declared a Cargo feature whose
  comment claimed it turned on the rule engine's regex operators and was "on by
  default", while `default = []` turned it off and no `cfg(feature = ...)` existed
  anywhere in the crate — there are no regex clauses to gate. Removed, along with
  the comment that promised them.

### Fixed: the README's benchmark table was fabricated

The performance section claimed "Measured on a Ryzen 7 5800X" with three timings.
None of it was measured: the machine was an Intel Core Ultra 5 125H, and every
number was roughly ten times optimistic.

| Claim | Measured |
|---|---|
| 4 KiB → ~1 ms | 2 KiB → **177 ms** |
| 12 MiB → ~45 ms | 7.7 MB → **1.4 s** |
| 180 MiB → ~1.4 s | 227 MB → **18 s** |

The table now carries real figures from three runs each, and the two facts those
figures actually show: a fixed 170 ms of process start dominates small files,
and steady-state throughput is about 12 MB/s because every byte is walked five
times. `docs/ARCHITECTURE.md` had the same machine mislabelled and is corrected
too.

This matters more than a doc typo. A benchmark table is a claim about the
software; inventing one is a claim the author did not make the measurement. If a
reader had pinned a build pipeline on "45 ms per installer", they would have found
out in production.

### Fixed: the two READMEs were not equivalent

`README.zh-CN.md` was 64 lines shorter and missing **Architecture** and
**Performance** entirely — the two sections a reader deciding whether to trust the
project looks for first. Both are now written, and the section order matches the
English file line for line so the two can be read side by side.

The language split is deliberate and now consistent:

| File | Language | Why |
|---|---|---|
| `README.md` | English | GitHub's default surface; the international audience |
| `README.zh-CN.md` | Chinese | The same content, not a summary — different readers, same claims |
| `docs/*.md` | English | Deep reference. Two copies drift; one is maintained |
| Code, comments, CLI output, rules | English | Source is read by toolchains and by contributors worldwide |

Chinese prose appears in exactly one file — the `简体中文` label in the English
file's language switcher aside — and that file is complete.

### Verified

- `python scripts/linkcheck.py`: 50 relative links and heading anchors across the
  twelve Markdown files resolve, including the double-hyphen slug an em dash
  leaves behind.
- `python scripts/calibrate.py`: the distribution quoted above, reproduced from a
  clean build.

The staged tree was exported to an empty directory, built from scratch
(`cargo build --release -p assay-cli`), its fixtures regenerated with
`scripts/make_samples.py`, and the end-to-end suite run against that binary. That
is the only check that proves nothing required is untracked. The desktop crate
is excluded from the export check because it needs the front-end bundle, which
`make desktop` builds first.

- 198 unit tests, 1 doc test, 25 end-to-end assertions.
- Calibration over all 4,386 files in `C:\Windows\System32`: zero critical, two
  high, both explained; distribution reproducible with `scripts/calibrate.py`.
- 11 malformed inputs (truncated PE/ELF/Mach-O/zip/gzip, hostile section counts,
  noise, a single byte, an empty zip and tar): no panic, no hang, worst case
  161 ms.
- Every documented exit code exercised; all six CLI commands plus `help`.
- SBOM validates as CycloneDX 1.5: `bomFormat`, `specVersion`, `urn:uuid`
  serial, typed components, purls.
- `dump-rules` round-trips: 24 rules out, 24 rules in, identical analysis.

## [0.1.2] — 2026-11-17

A calibration release. 0.1.1 fixed the false positives visible on three system
libraries; this one fixes the ones only a real corpus reveals. The corpus was a
643-file subset of `C:\Windows\System32`, every file signed or catalog-signed by
Microsoft, so whatever the analyser says about them is either right or a bug.
(The selection rule for that subset was not recorded; 0.1.3 replaces it with the
whole directory.)

| | clean | low | medium | high | critical |
|---|---|---|---|---|---|
| 0.1.1 | 359 | 89 | 142 | 40 | **13** |
| 0.1.2 | 377 | 85 | 180 | **1** | **0** |

Thirteen critical verdicts on the operating system's own libraries, all from one
cause: a rule matched a noun where it needed an action.

### Fixed: string evidence

- Word boundaries. `payment` matched `pospaymentconnector` and `shadowcopy`
  matched `shadowcopyexcludefile`, both XML schema names in `AppxPackaging.dll`.
  The pair produced a critical ransomware verdict for a signed packing library.
- Locations are not intent. `%programfiles%\windows defender\msmpeng.exe` is
  the path Task Manager reads to draw an icon; `vega.ws.symantec.com` is the CRL
  endpoint certutil queries. Registry keys are exempt — the persistence rule
  needs them.
- Markup is not a message, and a debug path such as `wbadmin.pdb` is not a
  tool name.
- Self-reference. `wbadmin.exe` was reported as deleting the recovery
  catalogue because its usage text contains its own name.
- Enumeration is the discriminator. `T1003` and `T1562.001` are suppressed for
  modules that list processes or services: `Taskmgr.exe` was a credential dumper
  because it displays `lsass.exe`.
- `T1003` requires a named store; `T1562.001` requires the disable switch,
  not the product name.
- Wallet addresses are checksummed. `APMon.dll` carries
  `3dMPXjCZeBMGVAXdgiZNgsKHRj7FE` — the exact shape of a P2SH address — and
  scored high for contacting a ransom wallet. Base58Check turns a
  one-in-a-few-thousand accident into a one-in-2^32 one; confidence for a real
  address rose 0.90 → 0.97.

### Changed: severity calibration

`high` and `critical` set the score floor, so spending them on a capability half
the operating system shares makes the scale unreadable.

| Rule | Was | Now | Why |
|---|---|---|---|
| `capability-injection` | high | medium | also a debugger, a shim, a remote-session helper |
| `persistence-registry-run` | high | medium | every installer and `msconfig` writes Run keys |
| `pe-no-imports` | high | medium | NT-native images import nothing by design |
| `packed-and-networked` | high | medium | a compressed installer with an update URL |
| `defense-tool-tampering` | critical | high | a settings UI and an AV killer are indistinguishable |
| `pe-unsigned-with-network` | high | high | now requires two indicators, not one |

### Fixed: CLI

- `--color auto` now means auto. It emitted ANSI escapes unconditionally, so
  `assay batch > report.txt` wrote `\x1b[31mhigh\x1b[0m` into the file. Stdout is
  now checked for a terminal and `NO_COLOR` is honoured.
- Zero-byte files are skipped, not scored. Reporting `.gitkeep` as "clean,
  score 0" invites the reader to conclude it was analysed and cleared.

### Added

- An OS-binary gate in `tests/e2e.py`: eight signed system binaries that each
  produced a false finding, run on every push. The fixture corpus proves true
  positives fire; it cannot prove false positives are absent.
- Nine unit tests over the string predicates, enumeration suppression and
  Base58Check.
- [SCORING.md §9](docs/SCORING.md#9-calibration-against-signed-system-binaries)
  documents the corpus and the method.

### Notes

`SystemSettingsAdminFlows.exe` still scores 55/high. That is correct: it is the
Settings app's administrative flow and it genuinely carries the switches that
disable real-time protection. Tuning it away would have been overfitting — one
honest finding in that corpus beats zero achieved by making the rule unable to
fire.

## [0.1.1] — 2026-11-17

A correctness release. The headline is a class of false positive that made the
tool unusable on the files analysts encounter most: **Windows system libraries
were being reported as malicious.**

Measured against `C:\Windows\System32`:

| File | 0.1.0 | 0.1.1 |
|---|---|---|
| `kernel32.dll` | 55 / high — injection, rootkit, VM evasion | **6 / clean** |
| `advapi32.dll` | 75 / critical — credential theft, ransomware | **6 / clean** |
| `notepad.exe` | 55 / high — token manipulation, screen capture | **8 / clean** |

### Fixed: detection accuracy

- API forwarders no longer count as users. `advapi32.dll` exports
  `CryptEncrypt` and imports it from `CRYPTSP.dll`. Every exported symbol is now
  removed from the capability evidence set before any rule runs, because a
  module that provides an API is not a module that uses it.
- A provider is not a user. A module that both exports and imports 200+
  symbols is treated as platform infrastructure; capability inference is withheld
  and the report says why in a structural note. Previously the same shape scored
  as a loader.
- Techniques require corroboration. A rule can no longer fire on a single
  matched symbol, however distinctive. Enforced centrally, so no individual rule
  can regress.
- Single-API rules rewritten. `T1055.012` (hollowing) now also requires a
  remote write; `T1055.004` (APC) requires a remote allocation; `T1134` (token
  manipulation) requires two distinct impersonation operations and no longer
  counts `OpenProcessToken`; `T1622` (debugger evasion) requires two checks;
  `T1003` no longer counts `NtQuerySystemInformation`.
- Two techniques removed from the corpus. `T1113` (screen capture) fired on
  every GDI application — no static combination separates a screenshot from
  ordinary drawing. `T1571` (non-standard port) matched port-number strings,
  which is a coin flip. Both are documented in
  [ARCHITECTURE.md §8](docs/ARCHITECTURE.md#8-attck-inference).
- Identifier namespaces are no longer indicators. `schemas.microsoft.com`,
  `w3.org` and certificate-publication paths (`/pki/`, `/certs/`, `.crl`) are
  names, not endpoints. They gave `kernel32.dll` a full 14/14 on the network
  factor.
- Version strings are no longer IPv4 indicators. A trailing `.0` octet is a
  network address or a version component, never a host — which removes
  `5.1.0.0` / `6.0.0.0` and friends.
- The certificate table is no longer an overlay. Authenticode signatures are
  stored outside the mapped image by specification, so every signed binary looked
  like it carried an appended payload. Overlay size now subtracts the certificate
  range and alignment padding.
- Zero runs are no longer a packing signal. Sections are zero-padded by the
  linker, so every binary over a few kilobytes has multi-kilobyte zero runs. Only
  `0x90` (NOP) and `0xCC` (INT3) runs count now.
- Packing heuristics do not apply to scripts or archives. They produced "no
  imports, therefore packed" on every `.sh` file.
- Rule severities recalibrated so `high` and `critical` — which drive the
  score floor — stay rare enough to trust: `pe-unsigned-with-network` is now
  medium and needs two endpoints, `capability-credential-theft` is high,
  `capability-input-capture` is medium, `evasion-debugger-check` is low.
- The two composite rules were removed. They fired *because* another finding
  had raised the floor, so they appeared as findings that explained nothing,
  restating a score the report already prints.

### Fixed: honesty of the report

- "Unsigned" became "no embedded signature (catalog signing is not checked)".
  Windows signs many of its own binaries through a security catalog; asserting
  `unsigned` was wrong about `notepad.exe` in a way a reader could not detect.
- `rules_evaluated` added to the report. Zero means rule checking was
  disabled, which is a materially different result from "no rule matched". The UI
  previously printed a literal `N` placeholder.
- Partial analysis is stated in text output, not only in JSON diagnostics.
- Evidence lines in text output raised from two to three, and truncated lists
  now say how many were omitted. Two lines cut the substantive clause on
  multi-condition rules.

### Fixed: correctness elsewhere

- `format_size` and byte-size rendering no longer round 1023.9 up into a unit
  that no longer applies.
- Pluralisation is centralised in `bytes::plural`; eight `"(s)"` suffixes were
  removed from user-visible strings across the engine and CLI.
- The rule engine's `min_iocs` evidence now reports the count and the threshold
  rather than only the threshold.
- `archive::parse_zip` no longer writes to a dead local (`external`).
- `ElfFile::sections()` / `segments()` now return public types instead of
  leaking private ones.

### Changed: desktop workbench

- The workbench starts empty in the desktop app. Showing a synthetic sample
  as if the user had opened it costs trust on first launch; the demo entry now
  exists only in the browser preview, where there is no filesystem.
- Selection can no longer disagree with the highlight. The previous fallback
  resolved to insertion order while the sidebar rendered grade order, so the
  active row and the displayed report could be different files.
- Re-analysing the same bytes refreshes in place instead of pointing the
  selection at an id that no longer exists.
- Entries can be removed — per row and from the report header.
- Keyboard operation: `Ctrl+O` import, `Ctrl+K` filter, `1`–`7` switch tabs,
  arrow keys move between tabs, `Escape` clears a filter.
- Confidence is no longer painted as risk. Bars encode confidence on a
  neutral scale; severity colours are reserved for severity. A 95%-certain
  low-impact observation no longer renders in critical red.
- Per-factor evidence is reachable by selecting the factor (the engine has always
  produced it; the UI never showed it).
- The entropy legend is derived from the same band table as the bars, so the two
  can no longer disagree — they previously did for the 3.0–5.0 range.
- Chips, offsets and timestamps are formatted consistently; hex offsets are
  zero-padded so a column of them is scannable.
- Unclassed `<div>`s inside `<button>` replaced with phrasing content.
- Rich-header product ids are resolved to tool names.

### Changed: accessibility and layout

- Contrast audited and fixed. Every text token now reaches WCAG AA (4.5:1) on
  `--surface`, `--surface-2` and `--surface-3`; 362 violations were measured and
  eliminated, including the primary button (white on `#7b61ff` was 4.20:1).
- Type floor raised: no readable text below 10px.
- Focus rings on every interactive element, a skip link, `aria-selected` tabs
  with arrow-key navigation, `aria-label` on icon buttons, and `role="status"` on
  toasts.
- `prefers-reduced-motion` disables animation rather than shortening it.
- Prose measure capped at 84–92 characters per line; long empty states centred
  and capped rather than spanning the window.
- The ATT&CK matrix is an auto-fit grid: five tactics share the width instead of
  bunching left with a void, and twelve wrap instead of hiding behind a scrollbar
  nobody discovers. The detail panel is reserved at wide viewports so selecting a
  technique does not reflow the layout.
- Section, import and indicator tables are single scroll containers instead of
  one card per group.

### Added: verification

- `scripts/ui_shots.mjs` — 28 screenshots across four viewports, asserting no
  horizontal overflow, no overlapping panels, no collapsed text, no clipped tabs.
- `scripts/design_audit.mjs` — contrast, type floor, line length, spacing rhythm,
  target size and truncation checks, evaluated in a real browser engine.
- Two e2e assertions locking the accuracy fix: a plain utility must carry no
  techniques and no findings, and the report must state its rule count.

## [0.1.0] — 2026-11-16

First public release.

### Added

**Containers**

- PE parser: DOS/NT headers, sections, imports, delay-load imports, exports with
  forwarders, resource tree (depth 4, 8192-entry budget), debug directory with
  PDB path and GUID, TLS callbacks, Rich header with XOR key recovery, CLR header,
  Authenticode blob, checksum recomputation
- ELF parser: 32/64-bit both endians, section and program headers, `.dynamic`
  (`DT_NEEDED`/`SONAME`/`RPATH`/`RUNPATH`/`BIND_NOW`), `.dynsym` imports and
  exports, `.note.gnu.build-id`, `.comment` compiler strings, NX/RELRO/PIE posture
- Mach-O parser: thin and fat containers, load commands, segments and sections,
  dylibs, `LC_UUID`, `LC_BUILD_VERSION`, `LC_CODE_SIGNATURE`, per-slice inventory
- Archive parsers: zip family with Zip64 (`.zip`, `.jar`, `.apk`, `.whl`,
  `.nupkg`, `.vsix`, `.epub`, OOXML), `ar` (`.a`, `.lib`, `.deb`), tar
  (ustar/GNU/pax), gzip header
- Script detection: shebang dispatch, UTF-16 PowerShell, obfuscation markers

**Analysis**

- Windowed Shannon entropy with peak tracking and longest high-entropy run
- String recovery across ASCII, UTF-16LE and UTF-16BE with per-encoding budgets
- Indicator extraction with per-kind confidence: URL, domain, IPv4, IPv6, email,
  Bitcoin, Ethereum, onion, registry key, UNC path, GUID, user agent
- Packer detection fusing 33 byte signatures with 13 weighted heuristics
- MITRE ATT&CK inference from import combinations: 36 rules across 10 tactics
- CycloneDX 1.5 SBOM synthesis
- CTPH fuzzy hashing with union-find family clustering

**Scoring**

- Five-factor additive model (capability 35, packing 28, signing 15, network 14,
  structure 8) with per-factor evidence
- Severity floor: a critical or high finding pins the score to the corresponding
  band, recorded as its own factor with a stated reason

**Rules**

- Declarative JSON rule engine with 18 clause types
- 24 built-in rules covering delivery shape, packing, managed code, drivers,
  capability, impact, evasion, C2, persistence and platform hardening
- Validation command with grammar, uniqueness and range checks

**Interfaces**

- `assay` CLI: `analyze`, `batch`, `sbom`, `rules`, `diff`, `parse`,
  `dump-rules`; text and JSON output; CI-oriented exit codes
- Tauri 2 desktop workbench with seven tabs (Overview, Structure, Imports,
  Strings, Indicators, ATT&CK, Findings), drag-and-drop, native file dialog
- CycloneDX output consumable by standard SBOM tooling

**Engineering**

- Hand-written SHA-256, SHA-1, MD5 and CRC-32, pinned against NIST/RFC vectors
- Hand-written DER reader for Authenticode field extraction
- Bounded `Reader` with absolute-offset error reporting; `#![forbid(unsafe_code)]`
- 170 unit tests plus a deterministic fuzz test over 64 synthetic buffers
- Fixture generator (`scripts/make_samples.py`) and icon generator
  (`scripts/make_icons.py`) — no binary blobs in the repository
- CI across Linux, macOS and Windows: fmt, clippy, test, UI typecheck, desktop
  build

### Known limitations

Documented rather than hidden; see [`docs/FORMATS.md`](docs/FORMATS.md) and
[`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md).

- Signature **verification** is not performed — only field extraction. This is a
  permanent design decision, not a gap.
- No disassembly; capability inference works from the import surface.
- Archives are enumerated, never decompressed; nested packages are not recursed.
- Fat Mach-O binaries report all slices but analyse only the first.
- .NET metadata tables, DWARF, relocations and entitlements are not decoded.
- Fully static binaries report zero imports, which the packer detector treats as a
  (moderate) packing signal — inspectable in the evidence list.

[Unreleased]: https://github.com/nebula-eng/assay/compare/v0.1.3...HEAD
[0.1.3]: https://github.com/nebula-eng/assay/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/nebula-eng/assay/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/nebula-eng/assay/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/nebula-eng/assay/releases/tag/v0.1.0

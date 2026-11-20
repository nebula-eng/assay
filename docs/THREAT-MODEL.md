# Threat model

Two threat models apply to a tool like this, and they get conflated.

The first is the adversary whose artefact you are examining. The second is the adversary who attacks the analyser itself, or who exploits the analyst's trust in its output. Both are covered here, because a static analyser that is easy to blind is worse than none: it produces confident wrong answers.

## Part 1 — The artefact is hostile

### A1. Crafted lengths and counts

Claim 65 535 sections, a 4 GiB thunk array, or a resource tree that points into itself, and a naive analyser allocates, loops or recurses until it dies.

Every loop over an attacker-controlled count has a named cap: 96 sections, 4096 import descriptors, 65 536 thunks each, 8192 resource entries, depth 4, 4096 load commands. Caps are checked before allocation rather than after the first iteration. The resource walker carries a global budget on top of its depth limit, because a cycle alternating between two directories passes a naive depth check forever.

The caps bound the work rather than removing it. A file with 96 sections, each holding 4096 import descriptors of 65 536 thunks, is legal under the caps and would take a long time and produce an enormous report. Seconds rather than milliseconds is an acceptable bound.

### A2. Type confusion in the byte stream

Put a value in a field the parser assumes is one width and read it as another. This is the classic failure of hand-written parsers that cast.

One bounded reader, `bytes::Reader`, is the only way parsers touch input. Every read is width-explicit (`u16_le`, `u32_be`, `uleb128`), every index is computed with `checked_add`, and `#![forbid(unsafe_code)]` at the crate root removes any path around it.

### A3. Decompression bombs

Ship a 42 KB zip that expands to 4 TB, or a nested archive that expands into another archive forever.

Assay never constructs a decompressor. Enumeration stops at the container tables: central directory, member names, declared sizes. A declared ratio above 100:1 is reported as a finding and nothing else happens. Nested archives are not recursed into.

The remaining cost is analytical rather than a vulnerability: Assay cannot tell you what is inside a nested package. That is a documented capability gap.

### A4. Parser differential as evasion

Craft a file that Assay parses one way and Windows parses another, so the reported imports are not the ones that will be resolved at load time.

Some of this is inherent to static analysis and cannot be solved without a loader. Assay narrows the gap by mapping every RVA through the validated section table, by honouring the delay-load attributes bit that distinguishes RVAs from VAs, and by recording the structural anomalies that usually accompany a crafted differential: overlapping raw ranges, section data past EOF, a `SizeOfHeaders` larger than the file.

A binary that loads correctly on Windows and reports nothing useful to Assay remains possible. The defence is the diagnostic channel: when parsing hits a wall, `diagnostics` says so and the exit code becomes 3, which a CI gate treats as failure rather than success.

### A5. Anti-analysis by construction

Pack the payload until no static signal survives, or import nothing and resolve everything through `GetProcAddress`.

Assay reports the limit instead of guessing past it. A packed binary gets `packer.likelihood: 100` with the evidence listed, and the verdict says to expect anti-analysis and virtualised code instead of pretending the payload was analysed. Packing alone is capped below critical, because packing is not evidence of malice.

A well-packed sample yields little. That is expected; the next step is dynamic analysis, which Assay does not do.

## Part 2 — Assay itself

### B1. Supply-chain risk in Assay's dependencies

The dependency surface is deliberately small: `serde`, `serde_json`, `thiserror`, `clap`, `regex-lite`, `rayon`, plus Tauri for the desktop shell. No binary-parsing crate, no crypto library (SHA-256, SHA-1, MD5 and CRC-32 are hand-written and pinned against published vectors), and `regex-lite` is the only regex engine in the core path. The lockfile is committed because this is an application rather than a library.

Tauri pulls a large tree regardless. `cargo deny` and `cargo audit` run in CI, and the desktop shell is treated as the largest attack surface in the project because it is.

### B2. The output is trusted more than it deserves

This is not a technical attack. An analyst reads "score 0, clean" and ships a binary that Assay simply had no rule for.

Every surface states the limit. `findings: []` renders as "no rule matched, which is not a clean bill of health" rather than a green tick. An `unknown` format renders with a diagnostic. The verdict sentence names the contributors, so `packed.exe` at 55 names UPX, the writable-and-executable section, and the finding that set the floor. Packer evidence, structural notes and diagnostics each have their own panel.

This is the primary risk of any scoring tool and cannot be engineered away. It is why the weights are conservative and why the floor applies only to unambiguous findings.

### B3. Sensitive data in reports

A report contains strings, registry paths, plaintext credentials where they exist in the sample, and PDB paths that carry developer usernames and internal directory structure. Committing a report to a repository leaks all of it.

Nothing is written anywhere unless the caller asks with `-o`. There is no telemetry, no crash reporting, no update check and no cache directory. The tool makes zero network calls at runtime, which is verifiable by running it in a network namespace with no interfaces.

Users will still paste reports into tickets. [`SECURITY.md`](../SECURITY.md) advises reviewing the string and indicator sections before sharing.

### B4. Assay as an attack tool

It reads a file and prints observations. There is no scanning, no injection, no exploitation and no payload generation. The indicators it extracts were already present in the file the attacker had to ship anyway. Capability inference tells a defender what the attacker already knows about their own tool.

### B5. Execution of analysed content

Get Assay to execute something from the sample: a thumbnail handler, a shell extension, a `rundll32` invocation.

The analysis path has no `Command::spawn`, no `dlopen` and no `LoadLibrary`. The only process creation in the project is `reveal_in_folder` in the desktop shell, which is an explicit user action running `explorer /select,<path>` with a fixed argument shape.

A grep for process creation is part of the review checklist for any pull request touching `assay-core`.

```bash
grep -rn "Command::new\|std::process" crates/assay-core/src/ || echo "clean"
```

## Part 3 — Non-goals

Out of scope, so nobody assumes otherwise.

| Not defended against | Why |
|---|---|
| A malicious rule file | Rules are inert data; the engine does not evaluate code. A rule can produce a finding, never a side effect |
| A malicious Tauri front end | The UI is served from bundled resources under a restrictive CSP; replacing it needs local write access, at which point the attacker has already won |
| Timing side channels in analysis duration | Analysis does not depend on secrets |
| Memory disclosure of the analysed file to other processes | Out of scope for a user-space tool; use OS-level isolation |
| Denial of service by very large files | `batch` is bounded by `--max-size-mb`; a single `analyze` of a 10 GB file uses memory proportional to the file. Run it in a container with a memory limit |
| Correctness of the platform trust store | Assay does not evaluate trust at all, see [Part 4](#part-4--the-signature-boundary) |

## Part 4 — The signature boundary

This is where a static analyser is most tempted to lie.

Assay parses the `WIN_CERTIFICATE` framing, walks the PKCS#7 `SignedData` with a hand-written DER reader, and reports the digest algorithm the signature names (flagging MD5 and SHA-1 as broken), the signer and issuer common names from the embedded certificate, the certificate validity window, whether a countersignature timestamp is present, and the SHA-256 of the raw signature blob.

It does not verify the signature, not partially and not as a heuristic. Verification requires:

1. Recomputing the Authenticode digest over the PE with specific fields excluded and the certificate table entry zeroed.
2. Parsing and validating the SpcIndirectDataContent digest match.
3. RSA or ECDSA verification against the signer's public key.
4. Building and validating a chain to a trusted root, with revocation checking.
5. Applying platform policy such as Windows driver signing or macOS notarisation.

Steps 4 and 5 need a trust store and network access for revocation. A tool that skips them and prints "signature valid" produces a false assurance worse than silence, because "signed" is exactly the signal an analyst uses to lower their guard.

The output is therefore "signed by X, issued by Y, digest sha256, timestamped: yes", plus "no countersignature timestamp" as an issue when absent. The reader draws the trust conclusion, with the platform's own verifier if they need one: `signtool verify`, `codesign -v`.

## Reporting a vulnerability

See [`../SECURITY.md`](../SECURITY.md). Parser crashes on hostile input are in scope and treated as real bugs. The constraint that a crash is a win for the attacker, described in [ARCHITECTURE.md](ARCHITECTURE.md#1-constraints-that-decided-the-rest), exists because "it only crashes on malformed files" is not a defence.

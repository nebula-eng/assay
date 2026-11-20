# Security policy

## Reporting a vulnerability

**Do not open a public issue for a security problem.**

Report privately through GitHub's [security advisory
form](https://github.com/nebula-eng/assay/security/advisories/new), or by email
to `security@assay.dev` if you prefer. Include:

- What the issue is and what an attacker gains.
- The smallest input that reproduces it (a hex snippet or a short Python builder
  is better than a binary attachment).
- The affected version, from `assay --version`.

You will get an acknowledgement within 72 hours. If the report is valid you will
be credited in the release notes unless you ask otherwise.

## What counts as a vulnerability

This project has an unusual threat model: every input is hostile. That makes some
things vulnerabilities here that would be robustness issues elsewhere.

### In scope

| Class | Example |
|---|---|
| Panic on malformed input | A crafted PE section table makes the parser `unwrap` on `None` |
| Out-of-bounds read | A resource tree offset that escapes the mapping |
| Unbounded resource consumption | A file that makes analysis allocate until OOM, or loop for hours, despite the documented caps |
| Incorrect verdict due to parser confusion | A file that Assay reports as having no imports while Windows resolves them — i.e. a detection bypass enabled by a parsing bug |
| Silent partial analysis | A parse failure that produces `diagnostics: []` and exit code 0, so CI treats a blind run as a clean one |
| Process execution from analysed content | Any path where analysing a file causes a process to start |
| Network access from the analysis path | Any outbound connection during analysis |
| Desktop shell escape | Getting the Tauri webview to load remote content, or to invoke a command with attacker-controlled arguments |
| Supply-chain compromise | A dependency that is not what it claims |

### Out of scope

| Class | Why |
|---|---|
| False positives / false negatives in detection | These are quality issues, not vulnerabilities. Open a regular issue with the sample structure described |
| Signature verification is not performed | Documented behaviour, see [THREAT-MODEL.md Part 4](docs/THREAT-MODEL.md#part-4--the-signature-boundary) |
| Packed samples yield little information | Documented limitation, not a bug |
| Reports contain sensitive data from the sample | Inherent to the function. Do not share reports without reviewing them |
| Denial of service by analysing a very large file | Bounded by `--max-size-mb` in `batch`; a single `analyze` is proportional to input size by design. Use a container memory limit |
| `unsafe` in dependencies | Report upstream; Assay itself is `#![forbid(unsafe_code)]` |

## Supported versions

The latest minor release receives security fixes. Pre-1.0, that means the most
recent `0.x` tag.

| Version | Supported |
|---|---|
| latest `0.x` | ✅ |
| older `0.x` | ❌ |

## Design commitments relevant to security

These are promises the codebase makes; a change that breaks one is a security
regression, not a refactor.

1. **No execution of analysed content.** The analysis path contains no
   `Command::spawn`, no dynamic library loading, no shell.
2. **No decompression.** Archive enumeration stops at the container tables.
3. **No network.** Zero outbound connections at runtime, in any code path.
4. **No panics on hostile input.** Enforced by construction (bounded reader) and
   by a fuzz test that runs deterministic malformed buffers through the whole
   pipeline.
5. **Partial analysis is visible.** A run that could not fully parse a file
   reports a diagnostic and exits 3, never 0.
6. **No silent trust claims.** Signature fields describe; they never assert
   validity.

## Verifying the no-network claim

The engine makes no network calls. You do not have to take that on faith:

```bash
# Linux: run with no network namespace
unshare -n assay analyze sample.exe

# Or watch the syscall surface
strace -f -e trace=network assay analyze sample.exe 2>&1 | grep -v ENOENT
```

A clean run produces no socket, connect or sendmsg calls. The single exception in
the whole project is `reveal_in_folder` in the desktop shell, which launches the
platform file manager as an explicit, user-initiated action.

## Hardening the analyser itself

Assay reads untrusted files, so run it with the same suspicion you would apply to
any parser:

- Analyse samples in a container with a memory limit and no network interface.
- Do not run `assay analyze` as root; it needs no privileges.
- Treat generated reports as sensitive: they contain strings, paths and possibly
  credentials recovered from the sample.
- Pin the version you gate builds with. A rule update can change a verdict, and
  that is the point — but it should be a deliberate change, not a surprise.

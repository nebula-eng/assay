# Command-line reference

```
assay <COMMAND> [OPTIONS]

Commands:
  analyze    Analyse one artefact and print a report
  batch      Analyse every file in a directory
  sbom       Emit a CycloneDX SBOM
  rules      Inspect or validate rule files
  diff       Compare two artefacts structurally
  parse      Show parsed structure without scoring
  dump-rules Print the built-in rule set
  help       Print help for a subcommand
```

Global flags:

| Flag | Effect |
|---|---|
| `--quiet` | Suppress progress lines on stderr. Report output is unaffected |
| `--color <auto\|always\|never>` | ANSI colour in text output. Default `auto` |

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Clean or low risk, or the operation succeeded without a risk verdict |
| `1` | High risk (or the `--fail-on` / `--threshold` grade was reached) |
| `2` | Critical risk |
| `3` | Usage error, I/O error, invalid rule file, or a report with diagnostics |

Code `3` deliberately outranks `1`/`2`: a run that could not fully analyse a file
must not be mistaken for a clean run by a CI script that only checks for
non-zero.

## `assay analyze`

```
assay analyze <FILE> [OPTIONS]

  -f, --format <text|json>   Output format (default: text)
  -o, --output <FILE>        Write to a file instead of stdout
      --rules <FILE>         Replace the built-in rule set with this file
      --deep                 Lower string threshold, finer entropy windows
      --fast                 Shallower profile for triage
      --fail-on <GRADE>      never|low|medium|high|critical (default: high)
```

`--deep` vs `--fast`:

| Setting | default | `--fast` | `--deep` |
|---|---|---|---|
| `min_string_length` | 5 | 6 | 4 |
| `max_strings` | 100 000 | 20 000 | 400 000 |
| `string_sample` | 2 000 | 500 | 20 000 |
| `entropy_window` | 4096 | 8192 | 1024 |

Example:

```bash
assay analyze sample.exe --format json --output report.json
echo $?   # 0 clean/low · 1 high · 2 critical · 3 error
```

## `assay batch`

```
assay batch <PATH> [OPTIONS]

  -f, --format <text|json>   Aggregate output format (default: text)
  -o, --output <FILE>        Write aggregate to a file
      --no-recursive         Only the given directory
      --max-size-mb <MB>     Skip files larger than this (default: 512)
      --rules <FILE>         Custom rule file
      --threshold <GRADE>    Exit non-zero when any file reaches this grade (default: high)
```

Files are analysed in parallel (`rayon`). Output is sorted by path, not by
completion order, so two runs over the same tree produce identical output.

Text output is one line per file:

```bash
$ assay batch samples
clean        0  pe        benign.exe
medium      40  zip       bundle.zip
high        55  elf       librpath.so
high        55  pe        packed.exe
critical    75  pe        ransom.exe
high        55  script    stager.sh
high        55  pe        suspicious.exe

7 files scanned; worst grade: critical
```

JSON output is an array of summaries, one object per file, with `name`, `path`,
`score`, `grade`, `format`, `findings`, `techniques`, `indicators`, `sha256`.
Full per-file reports are available via `analyze --format json`.

## `assay sbom`

```
assay sbom <FILE> [OPTIONS]

  -o, --output <FILE>   Write the BOM here instead of stdout
```

Produces CycloneDX 1.5. Components are the imported libraries plus any resource
that carries bytes. One decision worth knowing: **no version numbers are
invented**. An import table does not record which version of `kernel32.dll` a
binary was linked against, so every component carries
`version: "unknown"` plus a property explaining why. A BOM with fabricated
versions is worse than one that admits ignorance.

The `serialNumber` is derived from the file digest alone, so two runs over the
same input produce the same identifier, which keeps diffs between BOMs
meaningful. CycloneDX says every BOM *should* carry a serial unique even when the
contents match; this deliberately trades that for reproducibility, because the
alternative is a pipeline that cannot tell "the artefact changed" from "the clock
moved". The generation time is still recorded in `metadata.timestamp`.

## `assay rules`

```
assay rules list
assay rules validate <FILE>
```

`list` prints id, severity and name for every active built-in rule.

`validate` checks grammar, unique ids, numeric ranges, id charset, and that every
rule carries at least one condition, because a rule with an empty `match` would
fire on every artefact at its stated severity. Unknown clause names are parse errors
rather than silent no-ops, so a typo cannot quietly widen a rule. Exit code `3` on
any problem.

## `assay diff`

```
assay diff <OLD> <NEW> [OPTIONS]

  -f, --format <text|json>   Output format
```

Compares two artefacts structurally:

- score delta (`+12`, `-3`)
- sections added / removed
- ATT&CK techniques added / removed

Designed for "did the new build change in a way I should care about":

```bash
$ assay diff samples/benign.exe samples/suspicious.exe
old: benign.exe (2048 bytes, pe x86) · score 0/100 (clean)
new: suspicious.exe (4096 bytes, pe x86) · score 55/100 (high) · 5 findings · 3 ATT&CK techniques · 6 indicators
score delta: +55
sections added:   .data
techniques added:   T1055, T1059.001, T1056.001
```

## `assay parse`

```
assay parse <FILE> [OPTIONS]

  -f, --format <text|json>   Output format
```

Structure only: no strings, no scoring, no rules. Useful when you want the section
table without the rest.

Text output:

```
Pe X86 (32-bit)
entry point: Some(4096)
sections (3):
  NAME                          VADDR      VSIZE PERM   ENTROPY
  .text                          1000        178 rwx      4.66
  .data                          2000        800 rw-      7.91
  .idata                         3000        21c rw-      2.63
imports: 13  exports: 0
note: section `.text` is writable and executable
```

## `assay dump-rules`

Prints the built-in rule JSON verbatim. Use it as a starting point for a custom
corpus:

```bash
assay dump-rules > corp-rules.json
$EDITOR corp-rules.json
assay rules validate corp-rules.json
assay analyze sample.exe --rules corp-rules.json
```

## JSON report schema

`schema_version: "1.0"`. Additive changes do not bump the version; consumers
should ignore unknown fields.

```jsonc
{
  "schema_version": "1.0",
  "tool": { "name": "assay", "version": "0.1.3", "build": "…" },

  "artefact": {
    "path": "sample.exe", "name": "sample.exe", "size": 4096,
    "sha256": "…", "sha1": "…", "md5": "…",
    "fuzzy": "3072:AAAA…:BBBB…",           // CTPH, for family clustering
    "detected_format": "pe",
    "detection_confidence": "certain",      // certain | structural | weak
    "magic": "4d5a90000300…",
    "detection_reason": "MZ DOS header"
  },

  "image": {
    "format": "pe", "kind": "executable", "arch": "x86", "endian": "little",
    "bitness": 32, "entry_point": 4096, "image_base": 4194304,
    "sections": [ { "name": ".text", "entropy": 6.21, "permissions": {…}, … } ],
    "imports":  [ { "library": "kernel32.dll", "symbol": "CreateFileA", … } ],
    "exports":  [ … ],
    "resources": [ … ],
    "debug_artifacts": [ { "kind": "pdb", "value": "C:\\…\\app.pdb (guid …)", "trusted": true } ],
    "signature": { "present": false, "issues": [ … ], … },
    "structural_notes": [ "section `.text` is writable and executable" ],
    "unreadable_tables": [ "section header table declared at 0x40, past the end of a 0x40-byte file" ],
    "metadata": { "format": "pe", "machine_name": "i386", … }
  },

  "entropy": {
    "overall": 7.41, "mean_windowed": 7.02, "stdev_windowed": 1.13,
    "window": 4096,
    "windows": [ { "offset": 0, "length": 4096, "entropy": 3.12 }, … ],
    "longest_high_run": { "offset": 8192, "length": 12288, "entropy": 7.88 },
    "peak_offset": 8192, "peak_entropy": 7.91,
    "high_entropy_fraction": 0.43
  },

  "strings": [ { "offset": 1024, "encoding": "ascii", "text": "…", "length": 24 } ],
  "string_stats": { "total": 812, "unique": 640, "ascii": 700, "utf16le": 112, … },

  "indicators": {
    "indicators": [ { "kind": "url", "value": "http://…", "occurrences": 2,
                      "offsets": [2048], "confidence": 0.95, "rationale": "…" } ],
    "by_kind": [ ["url", 3], ["domain", 3] ]
  },

  "packer": {
    "likelihood": 100, "signatures": ["UPX"], "summary": "protected by UPX …",
    "evidence": [ { "key": "signature:upx", "detail": "…", "weight": 45 } ]
  },

  "techniques": [ { "id": "T1055", "sub_id": null, "name": "Process Injection",
                    "tactic": "defense-evasion", "confidence": 0.94,
                    "evidence": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
                    "note": "…", "detection": "…" } ],

  "score": {
    "score": 55, "grade": "high",
    "factors": [ { "key": "capability", "name": "Offensive capability",
                   "points": 35, "max_points": 35, "detail": "…", "evidence": [ … ] } ],
    "verdict": "High risk executable, score 55/100. …"
  },

  "findings": [ { "rule_id": "capability-injection", "rule_name": "Process injection capability",
                  "severity": "high", "description": "…", "evidence": [ … ],
                  "tags": ["defense-evasion", "injection"] } ],

  "rules_evaluated": 24,
  "diagnostics": [ { "stage": "parse", "severity": "error", "kind": "truncated",
                     "message": "truncated section table at offset 0x3c0: …" } ],

  "timing": { "detect_ms": 0, "parse_ms": 1, "strings_ms": 3,
              "analysis_ms": 2, "rules_ms": 0, "total_ms": 7 }
}
```

### `rules_evaluated`

`0` means rule checking was disabled (`--rules` pointed at an empty set, or the
embedder turned it off). That is a materially different result from "no rule
matched", and the UI reports the two differently, because silence without a reason
reads as a clean bill of health.

### `image.unreadable_tables`

Names tables the parser saw declared but could not read — a section table whose
offset is past the end of the file, a Mach-O load-command region larger than the
file, a gzip shorter than its own trailer.

This is separate from `structural_notes` because the two make different claims. A
note reports an observation ("no `PT_GNU_RELRO`, so the GOT stays writable"); this
reports a limit on what was examined. A truncated ELF used to arrive as "0
sections, no RELRO, no NX" — three confident negatives — when the parser had in
fact read nothing. Every entry here also appears as a warning diagnostic, so a
consumer that ignores `image` still sees it.

### Stability guarantees

- `schema_version` changes only when a field is removed or its meaning changes.
- New fields are added without a version bump.
- `image.metadata` is a tagged union on `format`; consumers must switch on it
  rather than assume PE fields exist.
- Arrays are ordered deterministically: sections by parse order, imports by
  table order, findings by severity then rule id, indicators by signal weight
  then confidence.

## Piping and scripting

Report text goes to stdout; progress goes to stderr. So this is always safe:

```bash
assay analyze x.exe --format json | jq -r '.score.grade'
```

Fail a build on any high-risk artefact:

```bash
assay batch dist/ --threshold high || exit 1
```

Generate a per-release SBOM:

```bash
for f in dist/*; do assay sbom "$f" -o "sbom/$(basename "$f").cdx.json"; done
```

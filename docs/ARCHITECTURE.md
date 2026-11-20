# Architecture

Why Assay is built the way it is. For what it does, the [README](../README.md) is shorter.

## 1. Constraints that decided the rest

Four properties of the problem shaped almost every structural decision here.

A file being analysed is, by definition, a file nobody trusts yet. Every length, count, offset and index in it may be a lie. That rules out `unsafe`, indexing a slice before checking it, and any parser that reads the header and hopes.

A crash is a win for whoever crafted the file. If a hostile input can make the analyser panic, a detection problem becomes a denial-of-analysis problem. Every parser therefore has to return a partial result and a diagnostic rather than aborting.

A verdict that cannot be checked is not much of a verdict. Any score, finding or technique must be able to name the bytes behind it, which is why evidence vectors sit on nearly every struct and why the score is decomposed instead of model-derived.

Reproducibility matters more than freshness. There are no network calls, no time-dependent behaviour in the analysis path, and no randomisation. The same bytes and the same rule set produce byte-identical JSON on any machine. The SBOM path does carry a timestamp, but that is document metadata rather than analysis output.

## 2. Stage order

```
identify → parse → measure → infer → judge
```

Format detection decides which parser runs. If it is wrong everything downstream is noise, so it happens first and records its confidence as `certain`, `structural` or `weak`. A file named `invoice.pdf` that starts with `MZ` is reported as a PE with `confidence: certain, reason: "MZ DOS header"`, which tells the analyst the name was ignored.

Measuring before inferring is a real dependency rather than a style choice: indicators need strings, packing detection needs section entropy, and section entropy needs the parser.

There is one genuine cycle. Rules can match on `min_score`, and the score depends on findings. It is broken in five steps:

1. Compute a provisional score from packer, capability, indicators, structure and signature.
2. Evaluate the rule corpus against that provisional score.
3. Compute the final score. Inputs are unchanged, so the result is unchanged.
4. Apply the severity floor implied by the worst finding.
5. If the floor moved the number, evaluate the corpus once more and union the findings by rule id.

Step 5 is there so composite rules such as `min_score: 55` can fire on the post-floor value. It costs one extra pass over about thirty rules and it is what prevents a report where the score says high and no finding explains why.

## 3. The bounded reader

`bytes::Reader` is about 210 lines; the module around it is 443, the remainder being hex helpers, pluralisation and tests. It is the only way any parser touches input.

```rust
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
    base: u64,   // absolute file offset of data[0]
}
```

Every read goes through `take()`, which computes the end index with `checked_add` and returns `Truncated` instead of panicking. There is no `unsafe`, no `get_unchecked`, and no direct `data[i]` outside `take`.

Errors carry absolute positions because of `base`. A failure inside a resource blob at file offset 0x1A2B4 reports 0x1A2B4 rather than "offset 12 of the resource", which is what makes the offset usable in a hex editor.

Every method returns `Result`. Nothing panics, including on a seek past the end, an integer overflow in `checked_add`, or a LEB128 that runs past 64 bits.

### Why not byteorder, nom or binrw

Those libraries express well-formed formats very well. The problem here is malformed ones. A combinator that returns `Err` still leaves the caller deciding whether the failure is fatal, and the ergonomics push toward `?`. One reader whose failure modes are known, enumerated and positioned is worth more than the brevity of a combinator, especially when the whole point is that the parse must survive.

## 4. Parser invariants

### PE

- `NumberOfSections` is capped at 96, the spec maximum, before any allocation. Real linkers emit fewer than 20; a file claiming 65 535 is hostile by definition.
- Import descriptors are capped at 4096 and thunks at 65 536 per descriptor. The walk stops at the first all-zero descriptor rather than trusting a declared size.
- Resource traversal carries a global budget of 8192 entries in addition to a depth limit of 4. A cyclic resource tree would otherwise loop forever, and the budget bounds the worst case even if cycle detection misses it.
- Every RVA is mapped through the validated section table. An RVA landing in the zero-filled tail of a section (`delta >= SizeOfRawData`) maps to `None` rather than to a stale offset.
- The Rich header is decoded by XOR-ing backwards from `Rich` until `DanS` appears. If it never appears, the entry list is empty and the key is still reported: a partial answer that says so.
- Overlay detection subtracts the Authenticode certificate table. The specification puts the signature outside the mapped image, so counting the tail after the last section as appended data made every signed binary look like it carried a payload. Alignment padding to the next file boundary is excluded for the same reason.

### ELF

- Section and program header counts are capped at 8192 before allocation.
- `.dynamic` is walked with a 4096-entry cap and stops at `DT_NULL` or the end of the section.
- String table reads are bounds-checked against the table's own extent rather than the file's.
- A missing `PT_GNU_STACK` is reported as "no PT_GNU_STACK segment, so the loader decides", not as an executable stack. Those are different facts, and conflating them produces false positives on hand-written ELF files.

### Mach-O

- Fat containers record every slice and analyse the first. The report says so in a structural note, because analysing all slices silently would double every count in the summary.
- Load commands are capped at 4096 and each is bounds-checked against `sizeofcmds`, so a command claiming 4 GiB cannot walk off the end.
- `LC_CODE_SIGNATURE` presence is recorded but the blob is not verified. The signature field reads `scheme: "codesign"` with an issue explaining that trust evaluation needs the macOS verifier.

### Archives

- The zip end-of-central-directory record is found by scanning backwards at most 66 000 bytes, the maximum comment length plus the record, rather than trusting a forward offset.
- Zip64 escape values (`0xFFFFFFFF`) are resolved from the Zip64 EOCD and the extended-information extra field.
- No decompressor is ever constructed. Compression ratios come from declared sizes, which is enough to flag a bomb and cannot be exploited.

### Scripts

- UTF-16 detection requires a BOM or consistently zero high bytes. A naive "every other byte is zero" test produces garbage on binary data.
- The scan covers the first 512 bytes, because the markers that matter — shebang, `-EncodedCommand`, `IEX` — sit near the top.

## 5. String recovery

Three encodings are scanned independently: ASCII, UTF-16LE and UTF-16BE.

Scanning only for printable ASCII shreds every UTF-16 string into one-character fragments, which is why so many tools produce unusable output on Windows binaries. Scanning UTF-16 separately means deciding what counts. Assay requires the high byte to be zero and the low byte to be printable. That is the shape of every Windows wide string but not general UTF-16; accepting real UTF-16 would mean validating surrogate pairs for very little extra signal.

Budgets are `min_length` (5), `max_strings` (100 000) and 512 characters per string. The report embeds a bounded sample, 2000 by default, while `string_stats` reports the true totals so the reader can tell how much was left out.

## 6. Indicator confidence

Each indicator carries a confidence between 0 and 1 rather than a boolean, because the evidence behind different kinds varies a lot.

| Kind | Base confidence | Reasoning |
|---|---|---|
| Onion service | 0.99 | No benign reason to ship one |
| URL with scheme | 0.95 | Explicit and unambiguous |
| Bitcoin / Ethereum | 0.90 | Checksummed formats |
| Email | 0.85 | Structured, but common in copyright strings |
| Registry key | 0.80 | Structured path |
| UNC path | 0.75 | Structured |
| User agent | 0.70 | Strong signal of a custom HTTP client |
| IPv4 | 0.65 | Could be a version or a subnet mask |
| Domain | 0.60 | Could be a filename with dots |
| GUID | 0.50 | Usually a CLSID, occasionally an interface id |

Benign shapes are filtered where they are produced:

- `kernel32.dll` is not a domain, by extension allowlist.
- `127.0.0.1`, `0.0.0.0`, `169.254.x.x`, multicast and documentation ranges are not indicators.
- RFC 1918 private ranges are excluded. They matter for lateral movement but they are not external indicators, and mixing them into an IOC list teaches the reader to skim the whole list.
- Version-shaped quads are excluded by requiring a small leading octet and a strictly increasing sequence. `8.8.8.8` is constant rather than monotonic, so it survives.
- Identifier namespaces are not endpoints. `schemas.microsoft.com/SMI/...` appears in the manifest of essentially every Windows binary, and an embedded certificate carries its issuer's publication points such as `www.microsoft.com/pki/certs/...`. Both are names. Treating them as C2 gave `kernel32.dll` full marks on the network factor, so there is now a suffix table plus a path check for `/pki/`, `/certs/` and `.crl`.
- A trailing `.0` octet is a network address or a version component, never a host. That removes the `5.1.0.0` and `6.0.0.0` family of Windows version strings.

## 7. Packing: two weak signals into one

Neither signal carries the verdict alone.

Signatures such as `UPX0`, `MPRESS1` or `.vmp0` have almost no false positives but are defeated by renaming a section. Heuristics such as entropy, W+X, missing imports and entry-point placement survive renaming but fire on legitimately protected software.

Assay reports a likelihood from 0 to 100 with the ordered evidence behind it. Weights are additive and visible.

| Signal | Weight |
|---|---|
| Literal signature match | 45 |
| Executable section entropy ≥ 7.6 | 30 |
| Entry point outside every executable section | 22 |
| Empty import table | 26 |
| Writable and executable section | 20 |
| Section maps at least 8× more than it stores | 16 |
| Fewer than 10 imports | 14 |
| Missing entry point in a PE | 12 |
| Non-standard section names | 8 |
| Checksum mismatch | 8 |
| Overlay after the last section | 7 |
| Managed assembly with a native Rich header | 6 |
| Long run of `0x90` | 5 |

Packing detection is not applied to scripts, archives or unknown blobs. A shell script has no code sections to pack, and running the heuristic on one produced "no imports, therefore packed" on every `.sh` file, which is noise that teaches the analyst to ignore the panel.

The constant-run signal counts `0x90` only. Zero runs are excluded because sections are padded to `SectionAlignment` with zeros, so every binary over a few kilobytes contains multi-kilobyte zero runs and the signal fired on every Microsoft system library. `0xCC` is excluded for the same reason: the MSVC linker fills gaps between sections with INT3, so a 4 KiB INT3 run is an artefact of a large image rather than a sled.

TLS callbacks appear as their own finding and carry no weight here. They used to add ten points of packing on top of that finding, which counted twice a feature MSVC emits for `__declspec(thread)` in a DLL.

## 8. ATT&CK inference

Each rule has four slots.

```rust
struct Rule {
    all_apis:    &'static [&'static str],  // every one must be present
    core_apis:   &'static [&'static str],  // at least `min_core` of these
    min_core:    usize,
    also_apis:   &'static [&'static str],  // at least one, when non-empty
    any_strings: &'static [&'static str],  // at least one, when non-empty
    confidence:  f64,
    ...
}
```

`min_core` carries the domain knowledge and is chosen per symbol: one for something genuinely rare such as `GetAsyncKeyState` or `NtLoadDriver`, two for something common but meaningful in company such as `AdjustTokenPrivileges` or `IsDebuggerPresent`. `OpenProcessToken` and `LookupPrivilegeValue` are excluded from the token rule because ordinary software calls them during setup.

Three guards apply to every rule, so no individual rule can regress.

If the module exports a symbol, that symbol is its product rather than its behaviour. `advapi32.dll` imports `CryptEncrypt` from `CRYPTSP.dll` and exports it too; counting that as cryptography is how the registry library becomes ransomware.

A technique never fires on a single matched symbol, however distinctive. This is enforced centrally rather than per rule.

At 200 exports and 200 imports the module is infrastructure, no technique is reported, and the report says why. See [SCORING.md §8](SCORING.md#8-platform-libraries).

The injection rule is the one worth reading. `VirtualAllocEx` and `WriteProcessMemory` are both required, plus one of `CreateRemoteThread`, `NtCreateThreadEx`, `QueueUserAPC` or `SetThreadContext`. Requiring only `CreateRemoteThread` fires on every debugger and profiler in existence.

Two techniques were removed after measurement. T1113 Screen Capture went because `BitBlt` and `GetDC` are used by every GDI application and no static combination separates a screenshot from ordinary drawing; it fired on `notepad.exe`. T1571 Non-Standard Port went because matching port-number strings such as `8080` or `4443` is a coin flip.

Reporting nothing is better than reporting something an analyst has to disprove.

## 9. Scoring

Five factors with ceilings summing to 100. The additive model exists so ambiguous evidence accumulates slowly and no single weak signal condemns a file.

That assumption breaks in one case: when a rule has already matched the unambiguous shape of an attack. A ransomware binary with an impact finding should not report "low risk, 20/100" because its import table happens to be small.

The floor is applied after rules run.

| Worst finding severity | Floor |
|---|---|
| Critical | 75 |
| High | 55 |
| Medium | 40 |
| Low / info | none |

The floor becomes its own factor carrying the reason and the pre-floor estimate. The verdict sentence is regenerated so the headline number, the band label and the contributor list agree. Worked examples are in [`SCORING.md`](SCORING.md).

## 10. Rule semantics

Clauses inside `match` are conjunctive: every present clause must hold, and an absent one imposes nothing. Disjunctive semantics would make a two-clause rule almost impossible not to match.

Two guards keep useless rules out. `Rule::is_unconditional()` detects a `match` block with no clauses, and a test asserts no built-in rule has one, because such a rule fires on every artefact. The engine also refuses to emit a finding with an empty evidence vector even when the rule technically matched.

`ioc_kinds` without `min_iocs` means at least one indicator of those kinds is present. `min_iocs` without `ioc_kinds` counts all kinds. Together they mean at least N indicators of the listed kinds.

## 11. Threading and memory

The library is single-threaded and synchronous, with no `async`, no locks and no global state. Callers that want parallelism spawn threads: the CLI uses `rayon` over a file list, the desktop shell uses Tauri's command pool.

| Budget | Default |
|---|---|
| Entropy windows retained in the report | 512 |
| Strings recovered | 100 000 |
| Strings embedded in the report | 2 000 |
| Characters per string | 512 |
| Sections per image | 96 (PE), 8192 (ELF) |
| Import descriptors | 4096 |
| Thunks per descriptor | 65 536 |
| Resource entries | 8192 |
| Indicators retained | 5 000 |

The file is read into memory once. Offsets are `u64`, so 32-bit hosts can analyse large artefacts without truncation. There is no mmap: a hostile file that changes underneath the mapping during analysis would be a data race the analyser cannot defend against, and reading is cheap enough.

Bounds that are never measured are wishes. These come from a release build on Windows 11, Intel Core Ultra 5 125H, 16 GB RAM.

| Workload | Result |
|---|---|
| 4 386 files in `C:\Windows\System32`, 2 183 MiB, all cores | 38 s |
| 643 signed system binaries, 518 MB, 8 threads | 17 s |
| One 228 MB binary (`MRT.exe`), single-threaded | 13.4 s |
| Peak working set for that binary | 463 MB (2.1× file size) |

The 2× factor is structural rather than a leak: one copy is the file, the other is the recovered string table capped at 100 000 entries of 512 characters. Peak memory is file size plus a bounded constant, so the default 512 MB `--max-size-mb` implies a ceiling near 1 GB. Raise the cap and the ceiling rises with it.

Reproduce with `/usr/bin/time -v` on Linux or by sampling `tasklist` on Windows.

## 12. Testing

| Layer | Approach |
|---|---|
| Digest primitives | Pinned against NIST and RFC vectors |
| Parsers | Fixtures built by code (`build_minimal_pe` and friends), so a failure names the field that broke |
| Scoring | Property tests: factors never exceed their ceiling, same-tactic techniques never stack, grade bands are monotonic |
| Rules | Every built-in rule loads, has a condition, has a unique id, and every finding carries evidence |
| End to end | `analysis::tests::fuzz_never_panics` pushes 64 deterministic pseudo-random buffers through the pipeline with format magics sprinkled in, so every parser branch runs |
| CLI | Integration tests over generated fixtures, asserting exit codes and JSON shape |

The fuzz test is a smoke test rather than a coverage-guided campaign. It catches the class of bug where a new parser branch forgets a bound.

## 13. Left out on purpose

Each of these would be a reasonable next step and each had a reason to wait.

- **Signature verification.** Needs RSA or ECDSA arithmetic plus Windows and macOS trust policy. Doing it partially would be worse than not doing it.
- **Disassembly.** Would let capability inference see call sequences instead of import-table possibilities, and multiplies the failure surface by an order of magnitude.
- **.NET metadata tables.** Would identify managed types and strings precisely, at the cost of decoding six interdependent heaps.
- **Decompression.** Would allow recursive analysis of nested packages and introduce every archive attack in the book.
- **Multi-slice Mach-O analysis.** Would catch decoy-slice tricks. Currently reported as a note instead.

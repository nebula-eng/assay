# Rule grammar

Rules are JSON. They are evaluated after parsing, extraction and inference, and before the final score is fixed, which is why a rule can match on `min_score`. See [ARCHITECTURE.md §2](ARCHITECTURE.md#2-stage-order) for how that cycle is broken.

## 1. Shape

A rule file is either a bare array or a named wrapper.

```json
{
  "name": "corp-baseline",
  "version": "2026.11.1",
  "rules": [ /* ... */ ]
}
```

Each rule looks like this.

```json
{
  "id": "corp-unsigned-delivery",
  "name": "Unsigned PE that talks to the network",
  "severity": "high",
  "description": "Delivery-stage binaries in our estate are always signed.",
  "match": { "format": ["pe"], "signed": false, "min_iocs": 1 },
  "tags": ["delivery"],
  "enabled": true
}
```

| Field | Required | Notes |
|---|---|---|
| `id` | yes | ASCII alphanumerics plus `-`, `_`, `.`; ≤ 128 chars; unique within the file |
| `name` | no | Falls back to `id` |
| `severity` | yes | `info`, `low`, `medium`, `high` or `critical` |
| `description` | no | Shown under the finding. Write the reason, not a restatement of the name |
| `match` | yes | An empty `match` is rejected by the validator and produces no finding at runtime |
| `tags` | no | Free-form, for filtering |
| `enabled` | no | Defaults to `true` |

## 2. How `match` is evaluated

Every clause present must hold, and an absent clause imposes nothing. Conjunctive semantics is the only reading that makes a two-clause rule say what its author meant: unsigned and carrying network indicators.

An empty `match` block would match everything. The engine refuses to emit a finding with no evidence, so such a rule produces nothing, but `Rule::is_unconditional()` lets a validator reject it up front and a test asserts no built-in rule has one.

## 3. Clauses

### Container identity

| Clause | Type | Matches when |
|---|---|---|
| `format` | string[] | `image.format` equals any entry: `pe`, `elf`, `macho`, `ar`, `zip`, `gzip`, `tar`, `script`, `unknown` |
| `kind` | string[] | `image.kind` equals any entry: `executable`, `shared_library`, `object`, `managed_assembly`, `installer`, `driver`, `script`, `package`, `other` |

### Signing

| Clause | Type | Matches when |
|---|---|---|
| `signed` | bool | `true` requires a signature blob, `false` requires its absence |

### Imports

| Clause | Type | Matches when |
|---|---|---|
| `any_imports` | string[] | At least one symbol is imported, case-insensitive exact match |
| `all_imports` | string[] | Every listed symbol is imported |
| `max_imports` | int | Non-delay-load import count ≤ N. `0` means it must import nothing |

Symbol matching uses the symbol name only, not `library!symbol`. Write `any_imports: ["CreateRemoteThread"]`, not `["kernel32.dll!CreateRemoteThread"]`.

### Strings

| Clause | Type | Matches when |
|---|---|---|
| `any_strings` | string[] | At least one substring appears in any recovered string, case-insensitive |

Substring rather than regex. A rule that needs structure should use a capability clause instead, because regex over a 100 000-entry string set is a performance trap and a false-positive generator.

The clause reads the same evidence set as the ATT&CK layer. Strings that are a location, a schema fragment, a debug path, the module's own name, or the Windows Script Host `GetResource = Eval(name)` helper never reach a rule, because none of them names something the code acts on. [SCORING.md §9](SCORING.md#the-five-predicates) gives the binary behind each predicate. A needle that only ever hits one of those is a rule that cannot fire, which `rules validate` cannot detect and a calibration run can.

### Indicators

| Clause | Type | Matches when |
|---|---|---|
| `min_iocs` | int | At least N indicators match the `ioc_kinds` filter, or all kinds when the filter is empty |
| `ioc_kinds` | string[] | Restricts which kinds count toward `min_iocs`. Without `min_iocs`, it means at least one of these kinds is present |

Kinds: `url`, `domain`, `ipv4`, `ipv6`, `email`, `bitcoin`, `ethereum`, `onion`, `registry_key`, `file_path`, `guid`, `user_agent`, `named_object`.

### Analysis products

| Clause | Type | Matches when |
|---|---|---|
| `min_packer` | int | Packer likelihood ≥ N (0–100) |
| `min_score` | int | Composite score ≥ N (0–100), see the ordering note below |
| `min_entropy` | float | Peak section entropy ≥ N (0.0–8.0) |
| `min_wx_sections` | int | At least N sections are both writable and executable and have bytes |
| `min_executable_entries` | int | At least N archive entries have an executable or script name. Always fails on non-archives |
| `techniques` | string[] | At least one ATT&CK id matches, against `id` or `sub_id` |

### Format-specific

| Clause | Type | Matches when |
|---|---|---|
| `has_tls` | bool | PE TLS callbacks present or absent. Always fails on non-PE |
| `is_dotnet` | bool | PE has a CLR header. Always fails on non-PE |
| `relro` | bool | ELF has `PT_GNU_RELRO`. Always fails on non-ELF |
| `loader_paths` | string[] | Interpreter, RPATH, RUNPATH or dylib install name contains any substring, case-insensitive |

A clause that cannot apply to a format makes the whole rule fail rather than pass. A rule requiring `relro: false` on a PE does not match vacuously, because vacuous truth would be a false positive on every Windows file.

## 4. `min_score` and ordering

> The two composite rules `score-high-overall` and `score-critical-overall` were removed from the shipped corpus. They fired because the score had already been raised by another finding's floor, so they appeared as findings that explained nothing, and the report already states the score twice. The `min_score` clause remains available for custom sets.

Rules are evaluated twice in one narrow case: once against the additive score, and again after the severity floor is applied. Findings from both passes are unioned by rule id.

A rule like this one can therefore fire as a consequence of another finding raising the floor.

```json
{ "id": "score-high", "severity": "high", "match": { "min_score": 55 } }
```

That is intentional, since the report should say when the composite score is high, but it makes such a rule a summary rather than an independent signal. Do not build automation that counts it.

## 5. Writing a rule that holds up

Encode a combination with a reason to hold. A rule matching `any_imports: ["CreateRemoteThread"]` alone fires on debuggers, profilers, anti-cheat and injection frameworks. Require the triad.

```json
{
  "id": "corp-injection-triad",
  "name": "Canonical injection sequence",
  "severity": "high",
  "match": {
    "all_imports": ["VirtualAllocEx", "WriteProcessMemory"],
    "any_imports": ["CreateRemoteThread", "NtCreateThreadEx", "QueueUserAPC"]
  }
}
```

Prefer capability over strings, because strings are attacker-controlled decoration while the import table follows from what the code calls.

Choose severity by consequence rather than confidence. A rule that fires often and is sometimes wrong belongs at `medium`; one that fires rarely and is almost always right belongs at `critical`. Severity also drives the score floor, so `critical` is expensive and should be spent on unambiguous shapes.

Write the description as a reason. "Unsigned PE carrying network indicators" restates the name. "Delivery-stage binaries in our estate are always signed, so an unsigned one is either mis-built or not ours" explains why anyone should care.

## 6. Built-in corpus

24 rules ship in [`rules/builtin.json`](../rules/builtin.json).

```bash
assay rules list
assay dump-rules > my-rules.json     # full JSON, as a template
```

Grouped by intent, with the severity each ships at. Severity drives the [score floor](SCORING.md#4-the-severity-floor), so the distinction is functional rather than cosmetic: `critical` means there is no benign reading of the shape, and it is reserved for the four impact rules. `low` covers signals that are real but indistinguishable from ordinary compiler or platform behaviour. Two rows moved from `medium` to `low` in 0.1.3 because a 4 386-file calibration run showed what `medium` was costing.

| Group | Rule | Severity |
|---|---|---|
| Delivery shape | `pe-unsigned-with-network` | low |
| | `packed-and-networked` | medium |
| | `archive-ships-executables` | medium |
| | `script-obfuscation-markers` | high |
| Packing | `pe-no-imports` (executables only) | medium |
| | `pe-tls-callbacks` | low |
| | `packed-likely` | medium |
| | `high-entropy-code` | medium |
| | `pe-wx-section` | high |
| Managed | `pe-managed-with-rich-header` | medium |
| Drivers | `pe-unsigned-driver` | critical |
| Capability | `capability-injection` | medium |
| | `capability-credential-theft` | high |
| | `capability-input-capture` | medium |
| Impact | `impact-ransomware-shape` | critical |
| | `impact-recovery-inhibition` | critical |
| Evasion | `defense-tool-tampering` | high |
| | `evasion-debugger-check` | low |
| C2 | `c2-tor-hidden-service` | critical |
| | `c2-wallet-address` | high |
| Persistence | `persistence-registry-run` | medium |
| Platform | `elf-rpath-hijack` | high |
| | `elf-no-relro-network` | medium |
| | `macho-unsigned-executable` | high |

### Why the capability rules are not `high`

Naming a rule `capability-*` and shipping it at `high` is a category error. It produced 40 high verdicts across a few hundred signed system binaries.

`capability-injection` describes the allocate-write-execute triad. That triad is also the shape of a debugger, a compatibility shim, a remote-session helper and a time-travel injection tool; the Windows service control manager and the RDP clipboard bridge both carry it. The capability is a fact about the code, and whether it is hostile is what the rest of the report is for.

The same holds for `persistence-registry-run`. Writing a Run key is the documented mechanism for every installer, updater and startup manager, and `msconfig` and Task Manager do it as their normal function.

`high` and `critical` are load-bearing because they set the score floor. Spending them on a capability that half the operating system shares makes the whole scale unreadable.

### Removed rules

`score-high-overall` and `score-critical-overall` no longer ship, for the reason given in §4.

Every remaining rule is tested for valid grammar, a non-empty condition set, a unique id, and evidence on every finding it produces.

## 7. Validation

```bash
assay rules validate corp.json
```

Checked: the JSON parses, every rule validates, ids are unique within the file, numeric ranges are sane (`min_entropy` within 0–8, `min_score` and `min_packer` within 0–100), and ids contain only permitted characters.

It does not check that a rule is useful. A rule matching `format: ["pe"]` alone is valid and harmless, just not interesting.

## 8. Limits

- 24 rules in the built-in set. A custom set of several hundred is fine; evaluation is linear in rules times clauses with set lookups.
- No regex clauses, see §3.
- No cross-file rules. A rule sees one artefact.
- No scripting. If a condition needs code, it belongs in the engine.

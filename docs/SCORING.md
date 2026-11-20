# Scoring model

The score is arithmetic you can redo on paper, not a learned model. A security verdict nobody can audit ends up either ignored or worshipped, and both are failures.

## 1. Shape

```
score = clamp( Σ factor_points , 0, 100 )        then     score = max(score, floor)
```

Five factors, ceilings summing to exactly 100.

| Key | Name | Ceiling |
|---|---|---|
| `capability` | Offensive capability | 35 |
| `packer` | Packing / protection | 28 |
| `signature` | Code signing | 15 |
| `network` | Network indicators | 14 |
| `structure` | Structural anomalies | 8 |
| Total | | 100 |

## 2. Why these weights

Capability carries the most at 35 because inferring an ATT&CK technique needs a combination of imports to hold: three symbols in the right relationship for process injection, a crypto primitive plus extortion strings for ransomware. Tripping that by accident is far harder than shipping an unsigned binary. The weight tracks how hard the signal is to fake rather than how alarming it sounds.

Packing is second at 28. The evidence is strong but genuinely ambiguous. Legitimate software uses UPX, VMProtect protects commercial products, and .NET obfuscators are common in harmless code. Twenty-eight can reach medium on its own and no further.

Signing is only 15. Most niche and open-source software is unsigned, and on Windows most trusted binaries carry a catalog signature rather than an embedded blob, which this tool cannot verify. Treating that absence as half the risk budget would make the tool useless on exactly the artefacts that need it most. The factor exists so that signed-and-tampered, signed-with-SHA-1 and missing-a-timestamp can be scored. Since 0.1.3, "no embedded signature" is recorded and costs zero points, because an observation the tool cannot interpret is not evidence.

Network is 14. Embedded endpoints are a strong signal since legitimate binaries rarely hard-code them, but they are also the easiest thing to add to a decoy, so the contribution is capped: seven URLs score the same as two.

Structure is 8. W+X sections, overlays and checksum mismatches are each a real observation and none is conclusive.

## 3. Per-factor formulas

### Capability

```
for each technique:
    if tactic already counted: skip
    tactic_weight = { impact: 1.00, credential-access: 0.95, lateral-movement: 0.90,
                      command-and-control: 0.90, defense-evasion: 0.80,
                      persistence: 0.80, privilege-escalation: 0.75,
                      execution: 0.70, collection: 0.60, discovery: 0.40 }.get(tactic, 0.50)
    points += 35 × 0.50 × confidence × tactic_weight

capability_points = min(round(points), 35)
```

Only one technique per tactic counts. A binary that can do five different discovery things is not five times as dangerous as one that can do one; it is a binary that enumerates. Stacking would let reconnaissance inflate the score past what the capability justifies.

The 0.50 multiplier means a single high-confidence impact technique yields `35 × 0.5 × 0.95 × 1.0 ≈ 17` points, enough to reach medium alone and not enough to reach high without corroboration. That is the intended shape: no single capability finding should be the whole argument.

### Packer

| Likelihood | Points |
|---|---|
| ≥ 70 | 28 |
| 45–69 | 21 |
| 20–44 | 9 |
| < 20 | 0 |

The likelihood is the sum of the evidence weights in [ARCHITECTURE.md §7](ARCHITECTURE.md#7-packing-two-weak-signals-into-one), clamped to 100. Packing detection does not run on scripts or archives.

### Signature

| Condition | Points |
|---|---|
| Not present (binary containers only) | +8 |
| Digest algorithm is MD5 or SHA-1 | +14 |
| No countersignature timestamp | +4 |
| Present but signer identity unrecoverable | +6 |

Bounded to 15. An `Unknown` container scores zero here. An opaque blob has no signature slot to leave empty, and charging it for a property it cannot have made every unrecognised file start at eight.

### Network

```
high_value = indicators of kind url | onion | bitcoin | ethereum | ipv4 | ipv6
             with confidence ≥ 0.60, capped at 12 entries
network_points = min(len(high_value) × 2, 14)
```

### Structure

```
structure_points = min(len(structural_notes) × 2, 8)
```

Structural notes come from the parsers rather than from rules: W+X sections, overlapping raw ranges, section data past EOF, missing imports, appended overlay.

## 4. The severity floor

The additive model is deliberately conservative, and that conservatism is wrong in one situation: when a rule has already matched the unambiguous shape of an attack.

```
worst_finding_severity → floor
    critical → 75
    high     → 55
    medium   → 40
    low/info → none

if score < floor:
    score  = floor
    grade  = grade_of(floor)
    factors.push({ key: "severity-floor", points: floor - old_score,
                   detail: reason, evidence: ["additive score was N, raised to F"] })
    verdict = rebuild_from(factors, score, grade) + " Raised from the additive
              estimate of N because <reason>."
```

Three properties keep this from being a magic constant. The uplift appears as its own factor, so the factor list still sums to the score. The reason names the rule that triggered it. And the verdict sentence is regenerated, so the headline number, the band label and the contributor list cannot disagree.

## 5. Worked examples

Every figure below comes from `assay analyze --format json` on the fixture corpus, so the document cannot drift from the implementation. Reproduce any of them with `make samples && assay analyze samples/<file>`.

### A plain utility: `benign.exe`

```
capability   0/35   no ATT&CK technique could be inferred from imports
packer       0/28   no packing indicators
signature    0/15   no embedded signature (catalog signing not checked)
network      0/14   no network indicators recovered
structure    0/8    structure is internally consistent
──────────────────
score        0      grade: clean
```

Zero, with a reason in every row rather than blank space. The absence of an embedded signature is still stated; it is simply not charged, because the tool cannot check the catalog that would make it meaningful.

### UPX-packed with a W+X section: `packed.exe`

```
capability   0/35   (no imports at all, so nothing to infer from)
packer      28/28   protected by UPX — expect anti-analysis and virtualised code
signature    0/15   no embedded signature (catalog signing not checked)
network      0/14
structure    6/8    3 structural notes
──────────────────
additive    34
findings    pe-wx-section (high), high-entropy-code (medium),
            packed-likely (medium), pe-no-imports (medium)
floor       55      worst finding is high
──────────────────
score       55      grade: high
```

Packing alone lands one point under the review band. The floor puts the finding into the number without letting the heuristics claim more than they can prove.

### Ransomware shape: `ransom.exe`

```
capability  15/35   T1486 at 0.86; T1490 skipped as same-tactic
signature    0/15   no embedded signature (catalog signing not checked)
network      2/14   1 high-value indicator (a Bitcoin address)
packer       0/28
structure    0/8
──────────────────
additive    17
findings    impact-ransomware-shape (critical),
            impact-recovery-inhibition (critical),
            c2-wallet-address (high)
floor       75      worst finding is critical
──────────────────
score       75      grade: critical
```

An additive estimate of 17 reads "low". That is the case the floor exists for: the imports are sparse, the file is 1.5 KiB, no quantitative signal is strong, but the combination is a complete extortion workflow.

### Injection, keylogging and endpoints: `suspicious.exe`

```
capability  35/35   3 techniques inferred across 3 tactics
packer       9/28   weak indicators of packing
signature    0/15   no embedded signature (catalog signing not checked)
network      6/14   3 high-value indicators embedded in the artefact
structure    2/8    1 structural note
──────────────────
additive    52
findings    pe-wx-section (high), capability-injection (medium),
            capability-input-capture (medium), high-entropy-code (medium),
            pe-unsigned-with-network (low)
floor       55      worst finding is high
──────────────────
score       55      grade: high
```

The only fixture that maxes the capability factor, which it does with three techniques in three different tactics. The W+X section is what crosses into high.

### A Windows system library: `kernel32.dll`

```
capability   0/35   withheld: platform library surface
packer       0/28
signature    4/15   no countersignature timestamp
network      0/14
structure    2/8
──────────────────
score        6      grade: clean
```

`kernel32.dll` both exports and imports a large API surface, so capability inference is withheld rather than answered. See [§8](#8-platform-libraries). Before this rule existed the same file scored 55/100 with five inferred techniques including process injection and rootkit, because it provides the APIs those rules look for.

## 6. Grade bands

| Score | Grade | Interpretation |
|---|---|---|
| 0–14 | `clean` | Nothing notable. |
| 15–34 | `low` | Worth a glance; likely a false positive on an unsigned niche tool. |
| 35–54 | `medium` | Review before deployment. |
| 55–74 | `high` | Strong indicators of malicious intent or high exposure. |
| 75–100 | `critical` | Treat as hostile until a human says otherwise. |

Bands are half-open on the upper end (`0..=14`, `15..=34`, …) and the mapping is a pure function tested at every boundary.

## 7. What the score does not mean

- It is not a probability. "60" does not mean "60% likely malicious"; it means the evidence awarded 60 of 100 points under this rubric.
- It is not comparable across rule sets. A custom corpus with different severities moves the floor and therefore the score.
- It is not a substitute for reading the findings. A 55 built from `pe-wx-section` and a 55 built from `capability-credential-theft` mean different things, and the factor list is how you tell them apart.
- Absence of findings is not a clean bill of health. It means no rule in the loaded set described what the file does.

## 8. Platform libraries

A module that both provides and consumes a large API surface is infrastructure. `kernel32.dll` exports 1 697 symbols and imports 1 292; `advapi32.dll` exports 854 and imports 786. Malware minimises its export table, and a loader usually exports nothing at all, so this shape is not something a payload imitates.

The distinction matters because capability inference asks whether a module uses process injection. For the module that implements the injection APIs, the question has no useful answer, and answering it anyway is how a naive analyser labels the Windows registry library as ransomware: `advapi32.dll` exports `CryptEncrypt` and imports it from `CRYPTSP.dll`, the classic API-forwarding pattern.

Two guards implement this. Exports disqualify a symbol, since an exported API is the module's product rather than its behaviour, and the symbol is removed from the evidence set before any rule runs. And at 200 exports and 200 imports the module is treated as infrastructure, no technique is reported, and the report says so in a structural note — silence without a reason reads as "nothing found", which is a different claim.

The thresholds are blunt and stated in source (`BinaryImage::is_library_surface`). A trojanised system library would still pass the shape test; catching it is the job of the signature and structural checks, which is where that judgement belongs.

## 9. Calibration against signed system binaries

The fixture corpus proves that true positives fire. It cannot prove the absence of false positives, which is the more valuable claim, and a detector tuned only against samples you wrote yourself will always look perfect.

So the calibration set is the host operating system: every file in `C:\Windows\System32`, no filter. Whatever the analyser says about them is either right or a bug.[^1] On the machine last measured that is 4 386 files and 2 183 MiB, taking 38 s on all cores.

The number is reproducible rather than remembered.

```bash
python scripts/calibrate.py            # whole directory, prints the distribution
python scripts/calibrate.py --top 30   # and the files at medium or above
```

`tests/e2e.py` runs fifteen of these files as a regression gate on every push.

| | clean | low | medium | high | critical |
|---|---|---|---|---|---|
| 0.1.3 as shipped | 2 188 | 399 | 1 789 | 10 | 9 |
| after the fixes below | 3 796 | 389 | 199 | 2 | 0 |

Nine critical verdicts on the operating system's own libraries, and 1 789 files at medium, which is 41% of the corpus. Every one traced to a check that matched a noun where it needed an action, or scored a fact it could not interpret.

| File | Was read as | Actually was |
|---|---|---|
| `EdgeContent.dll`, `MFMediaEngine.dll`, `Windows.Payments.dll` and five more | ransomware, critical | a cipher API plus the string `payment`, in a billing stack |
| `ResetEngine.dll` | ransomware, critical | "failed to wait for bcdedit -set debug on", a factory reset |
| `slmgr.vbs`, `winrm.vbs` | obfuscated stager, high | the Windows Script Host `GetResource = Eval(name)` helper |
| 426 libraries | empty import table, medium | data-only DLLs; keyboard layouts have nothing to import |
| every catalog-signed binary | +8 for being unsigned | an embedded-signature slot that a catalog replaces |

An earlier version of this section quoted a 643-file subset. That measurement was real, but its selection rule was never written down, so nobody including this project could reproduce it, and re-running the whole directory produced a materially different picture. A number that cannot be reproduced is not a calibration.

The following cases started the string-hygiene work in 0.1.2. They are still in the e2e gate.

| File | Was read as | Actually was |
|---|---|---|
| `Taskmgr.exe` | credential dumper | lists `lsass.exe` in the process table |
| `Taskmgr.exe` | defence evader | draws `msmpeng.exe`'s icon from a path |
| `certutil.exe` | defence evader | carries `vega.ws.symantec.com`, a CRL endpoint |
| `wbadmin.exe` | deletes recovery catalogue | prints its own name in usage text |
| `AppxPackaging.dll` | ransomware | ships the AppX manifest XSD as literal strings |
| `SystemSettingsAdminFlows.exe` | defence evader | the Settings UI, which genuinely can disable Defender |

### The five predicates

String evidence passes through filters before any rule sees it. Since 0.1.3 the rule engine applies the same filters as the technique layer, because a string that is not evidence for one is not evidence for the other. Each predicate exists because of a specific binary.

Word boundaries: `payment` matched `pospaymentconnector` and `shadowcopy` matched `shadowcopyexcludefile`, both XML schema element names. A match must sit on a word boundary unless the needle itself begins or ends with punctuation, so `.locked` still matches inside `file.locked.bak`.

Locations are not intent: `%programfiles%\windows defender\msmpeng.exe` is where Task Manager looks to draw an icon, and `vega.ws.symantec.com` is where certutil fetches a revocation list. Paths, URLs and hostnames belong to the indicator layer. Registry keys are exempt, because `SOFTWARE\...\Run` is an object code acts on and the persistence rule depends on it.

Markup is not a message: a string starting with `<` is schema rather than prose.

Self-reference: the linker embeds its own output path, so `wbadmin.exe` contains `C:\build\amd64\wbadmin.pdb` and prints `wbadmin.exe` in its usage text. Matching a rule keyed on a tool name against the tool itself is circular.

Script plumbing is not obfuscation: `slmgr.vbs` and `winrm.vbs` both define `GetResource = Eval(name)` to read a string from a resource DLL. A rule that treats `eval(` as dynamic execution convicted both as fileless stagers. The predicate matches only the assignment form, so `eval($payload)` still fires.

### Enumeration as the discriminator

Two rules can be suppressed entirely for a module that lists processes or services. An enumerator's string table necessarily holds the names of everything it displays, so a name in it says nothing about intent.

`T1003` and `T1562.001` carry `suppressed_by_enumeration: true`. A credential stealer and Task Manager both import `OpenProcess` and both can name `lsass.exe`; only the stealthy one reaches the target directly instead of walking a list.

### Wallet addresses are checksummed

`APMon.dll`, a Microsoft performance-monitoring library, carries `3dMPXjCZeBMGVAXdgiZNgsKHRj7FE`: 31 Base58 characters starting with `3`, the exact shape of a P2SH address. It scored high for contacting a ransom wallet.

Base58Check exists to prevent that. The last four bytes are `SHA-256(SHA-256(payload))[..4]`, so verifying the checksum turns a one-in-a-few-thousand accident into a one-in-2^32 one. Every Bitcoin address in a report now carries a valid checksum, and the reported confidence rose from 0.90 to 0.97 because the evidence is proof rather than resemblance.

[^1]: Windows holds the corpus because it has the densest supply of signed binaries and is the population this project targets. The same method applies to `/usr/lib` and `/System/Library`, and the e2e gate falls back to those on other platforms.

### The two remaining high findings

`SystemSettingsAdminFlows.exe` scores 55. That is correct: it is the Settings app's administrative flow and it genuinely carries the switches that turn real-time protection off. A settings UI, an enterprise management agent and an AV killer are statically indistinguishable, since all three stop the service and all three carry the exclusion API.

`dpapisrv.dll` also scores 55, for `capability-credential-theft`. That is also correct as stated: the DPAPI server opens an LSA policy handle, takes a process token and names `lsass.exe`, because unwrapping a master key means talking to LSASS. The capability is the module's job description. A credential provider and a credential dumper are the same shape to a static analyser; the difference is who signed the file and where it runs.

Tuning either away would be overfitting. Two honest findings in 4 386 files beats zero achieved by making a rule unable to fire.

## 10. Tuning for your environment

If your estate signs everything, add a rule.

```json
{
  "id": "corp-unsigned",
  "name": "Unsigned artefact in a signed-only estate",
  "severity": "high",
  "match": { "format": ["pe", "macho"], "signed": false }
}
```

That raises the floor to 55 for every unsigned binary, which is correct for you and wrong in general. It is why the weights are constants in source rather than configuration: a rubric that changes per deployment cannot be compared across teams, and comparison is most of the value.

# Format support matrix

What Assay parses, what it extracts, and where it stops. Blind spots sit next to capabilities because a support table listing only the wins is marketing.

Legend: ✅ full · ◐ partial · ❌ not implemented

## Windows PE

| Area | Status | Extracted |
|---|---|---|
| DOS header | ✅ | `MZ`, `e_lfanew` validated against 0x40 and file length |
| COFF header | ✅ | Machine, section count (capped 96), timestamp, characteristics |
| Optional header | ✅ | PE32 and PE32+, entry point, image base, alignments, subsystem, DLL characteristics |
| Data directories | ✅ | All 16 read; export, import, resource, certificate, debug, TLS, delay-import and CLR are acted on |
| Sections | ✅ | Name, VA, virtual size, raw offset and size, characteristics, per-section entropy, SHA-256 |
| Imports | ✅ | `IMAGE_IMPORT_DESCRIPTOR` plus ILT/IAT thunk walk, ordinal and by-name, hint |
| Delay-load imports | ◐ | Descriptors parsed, attributes bit 0 (RVA vs VA) honoured; no delay-load IAT patching |
| Exports | ✅ | Name table, ordinal table, forwarders such as `NTDLL.RtlAllocateHeap` |
| Resources | ◐ | Tree walked to depth 4, leaf data hashed; no structured decoding of `RT_MANIFEST` or `RT_VERSION` |
| Debug directory | ✅ | CodeView `RSDS`/`NB10` to PDB path and GUID; type inventory |
| TLS directory | ✅ | `AddressOfCallbacks` resolved to a callback VA list (capped 64) |
| Rich header | ✅ | XOR key recovered, `@comp.id` records decoded until `DanS` |
| CLR header | ◐ | Presence, runtime version, metadata version string; no metadata table decoding |
| Authenticode | ◐ | `WIN_CERTIFICATE` framing, PKCS#7 walk, digest algorithm, signer and issuer CN, validity window, countersignature presence. No signature verification |
| Checksum | ✅ | Recomputed and compared |
| Overlay | ✅ | Bytes after the last section, with the certificate table subtracted |
| Bound imports | ❌ | Directory read, contents ignored |
| Load config | ❌ | Directory read, contents ignored |
| Relocations | ❌ | Not applied; RVAs are reported as stored |
| Exception table | ❌ | Directory read, contents ignored |

Blind spots. A .NET assembly's IL is not disassembled, so a managed loader that resolves everything through reflection looks benign at the import level. The `pe-managed-with-rich-header` rule flags the common "native stub plus managed payload" shape, but that is a heuristic rather than proof.

A PE that both exports and imports 200 or more symbols is treated as infrastructure: capability inference is withheld and the report says so. Without that rule, `advapi32.dll` scored critical for credential theft and ransomware, because a module that forwards an API also imports it.

## ELF

| Area | Status | Extracted |
|---|---|---|
| Identification | ✅ | 32/64-bit, both endians, OS ABI, version |
| ELF header | ✅ | Type, machine, entry, program and section header offsets and counts (capped 8192) |
| Section headers | ✅ | Name via `.shstrtab`, type, flags, address, offset, size, link, entsize |
| Program headers | ✅ | Type, flags, offset, vaddr, filesz, memsz, including 32-bit field order |
| `.dynamic` | ✅ | `DT_NEEDED`, `DT_SONAME`, `DT_RPATH`, `DT_RUNPATH`, `DT_BIND_NOW`, `DT_FLAGS` |
| `.dynsym` | ✅ | Undefined symbols as imports, defined globals as exports (capped 200 000) |
| Build ID | ✅ | `.note.gnu.build-id` (`NT_GNU_BUILD_ID` with a `GNU` owner) |
| Compiler strings | ✅ | `.comment` split on NUL |
| Hardening posture | ✅ | `PT_GNU_STACK` NX, `PT_GNU_RELRO`, `ET_DYN` plus interpreter for PIE |
| Interpreter | ✅ | `.interp` or `PT_INTERP` path |
| Relocations | ❌ | GOT/PLT symbol resolution not performed |
| DWARF | ❌ | Debug info not read |
| Symbol versions | ❌ | `.gnu.version` not applied to names |
| Compressed sections | ❌ | `SHF_COMPRESSED` not decompressed |

Blind spot. Because `.dynsym` is the import source, a fully static binary reports zero imports, which the packer detector reads as a packing signal. A statically linked Go or Rust binary will therefore carry some packing likelihood. The evidence list makes it inspectable — the entry reads "import table is empty" — and that weight is moderate rather than decisive.

## Mach-O

| Area | Status | Extracted |
|---|---|---|
| Thin binaries | ✅ | 32/64-bit, both endians |
| Fat and universal | ◐ | All slices inventoried, only the first analysed |
| Load commands | ✅ | Capped 4096, each bounds-checked against `sizeofcmds` |
| Segments | ✅ | `LC_SEGMENT` and `LC_SEGMENT_64`, protection flags |
| Sections | ✅ | Per-section name, address, size, offset, entropy |
| Dylibs | ✅ | `LC_LOAD_DYLIB`, `LC_LOAD_WEAK_DYLIB`, `LC_REEXPORT_DYLIB`, `LC_ID_DYLIB` |
| `LC_UUID` | ✅ | Canonical UUID string |
| `LC_BUILD_VERSION` | ✅ | Platform, minimum OS, SDK |
| `LC_MAIN` | ✅ | Entry offset |
| Code signature | ◐ | `LC_CODE_SIGNATURE` presence and blob hash. No CMS parsing or trust evaluation |
| `LC_RPATH` | ✅ | Search paths |
| Entitlements | ❌ | Embedded plist not decoded |
| Symbols | ◐ | `LC_SYMTAB` count only; names not resolved |

Blind spot. A universal binary whose x86-64 slice is a decoy and whose arm64 slice carries the payload is only half analysed. The report says "universal binary with N slices, only one analysed in depth" rather than summarising one slice as if it were the file.

## Archives and packages

| Format | Status | Extracted |
|---|---|---|
| zip | ✅ | Central directory walk, membership, declared sizes, method, DOS timestamps, Unix mode bits |
| Zip64 | ✅ | EOCD locator, EOCD record, extended-information extra field |
| `.jar` | ✅ | Classified via `META-INF/MANIFEST.MF`; signature files detected |
| `.apk` | ✅ | Classified via `AndroidManifest.xml` and `classes.dex` |
| `.whl` | ✅ | Classified via `.dist-info/` or `WHEEL` |
| `.nupkg` | ✅ | Classified via `.nuspec` |
| `.vsix` | ✅ | Classified via `extension.vsixmanifest` |
| `.epub` | ✅ | Classified via `mimetype` and `OEBPS/` |
| OOXML | ✅ | Classified via `word/document.xml` or `xl/workbook.xml` |
| `ar` (`.a`, `.lib`) | ✅ | Member headers, GNU long-name table |
| `.deb` | ✅ | Classified via `debian-binary`; member list |
| tar | ✅ | ustar/GNU/pax, header checksum validated, long-name extended headers skipped |
| gzip | ◐ | Header only: method, flags, mtime, FNAME. Payload not decompressed |
| 7z / rar / xz / bzip2 | ❌ | Not recognised |
| Nested archives | ❌ | Not recursed into |

No decompressor is ever constructed. Compression ratios come from declared sizes, which flags a bomb without exposing the analyser to one.

## Scripts

| Area | Status | Extracted |
|---|---|---|
| Shebang dispatch | ✅ | Python, POSIX shell, perl, ruby, node |
| UTF-16 detection | ✅ | BOM or consistently zero high bytes, first 512 bytes only |
| PowerShell markers | ✅ | `-EncodedCommand`, `Invoke-Expression`, `IEX(`, `New-Object Net.WebClient` |
| Generic obfuscation markers | ✅ | `FromBase64String`, `eval(`, `base64_decode` |
| JavaScript and VBScript | ◐ | Marker scan only, no parser |
| Deobfuscation | ❌ | Not attempted |

## Not formats, but relevant

| Thing | Treatment |
|---|---|
| Extension | Used only as a tie-breaker when no magic matches, recorded as `confidence: weak` |
| Filename | Never influences the verdict |
| Timestamp | Reported, labelled "frequently forged" |
| File size | Drives no heuristic except the `SizeOfHeaders` sanity check |

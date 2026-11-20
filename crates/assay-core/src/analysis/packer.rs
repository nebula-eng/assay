//! Packer and protector detection.
//!
//! Two independent signals are fused:
//!
//! * **Signature** — a literal byte string that a specific packer leaves behind
//!   (`UPX0`, `MPRESS1`, `.vmp0`). Near-zero false positive rate, but trivially
//!   defeated by renaming a section.
//! * **Heuristics** — the *shape* of a packed binary: a high-entropy code
//!   section whose entry point is elsewhere, almost no imports, a writable
//!   executable section, virtual sizes dwarfing raw sizes.
//!
//! Reporting a single boolean would be dishonest, because neither signal is
//! sufficient. The engine emits a **likelihood plus the exact evidence** that
//! produced it, so a human can disagree with a specific reason rather than with
//! a black box.

use serde::{Deserialize, Serialize};

use crate::format::{BinaryImage, Format};

/// A packer signature keyed on bytes that survive compilation.
#[derive(Debug, Clone, Copy)]
pub struct PackerSignature {
    /// Display name of the packer/protector.
    pub name: &'static str,
    /// Byte sequence to look for.
    pub needle: &'static [u8],
    /// Where to look.
    pub scope: SignatureScope,
    /// Family label used for grouping in the UI.
    pub family: &'static str,
}

/// Where a signature should be searched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureScope {
    /// Anywhere in the file.
    Anywhere,
    /// Only inside section names.
    SectionNames,
    /// Only inside the first 64 KiB (the header region).
    Header,
    /// Only inside imported symbol names.
    ImportNames,
}

/// Built-in signatures. Ordered roughly by how often each is seen in the wild.
pub const SIGNATURES: &[PackerSignature] = &[
    PackerSignature {
        name: "UPX",
        needle: b"UPX0",
        scope: SignatureScope::SectionNames,
        family: "upx",
    },
    PackerSignature {
        name: "UPX",
        needle: b"UPX1",
        scope: SignatureScope::SectionNames,
        family: "upx",
    },
    PackerSignature {
        name: "UPX",
        needle: b"UPX!",
        scope: SignatureScope::Anywhere,
        family: "upx",
    },
    PackerSignature {
        name: "UPX (NRV)",
        needle: b"UPX2",
        scope: SignatureScope::SectionNames,
        family: "upx",
    },
    PackerSignature {
        name: "MPRESS",
        needle: b"MPRESS1",
        scope: SignatureScope::SectionNames,
        family: "mpress",
    },
    PackerSignature {
        name: "MPRESS",
        needle: b"MPRESS2",
        scope: SignatureScope::SectionNames,
        family: "mpress",
    },
    PackerSignature {
        name: "ASPack",
        needle: b".aspack",
        scope: SignatureScope::SectionNames,
        family: "aspack",
    },
    PackerSignature {
        name: "ASPack",
        needle: b".adata",
        scope: SignatureScope::SectionNames,
        family: "aspack",
    },
    PackerSignature {
        name: "PECompact",
        needle: b"PECompact2",
        scope: SignatureScope::Anywhere,
        family: "pecompact",
    },
    PackerSignature {
        name: "Themida / WinLicense",
        needle: b".themida",
        scope: SignatureScope::SectionNames,
        family: "themida",
    },
    PackerSignature {
        name: "Themida / WinLicense",
        needle: b".winlice",
        scope: SignatureScope::SectionNames,
        family: "themida",
    },
    PackerSignature {
        name: "VMProtect",
        needle: b".vmp0",
        scope: SignatureScope::SectionNames,
        family: "vmprotect",
    },
    PackerSignature {
        name: "VMProtect",
        needle: b".vmp1",
        scope: SignatureScope::SectionNames,
        family: "vmprotect",
    },
    PackerSignature {
        name: "VMProtect",
        needle: b".vmp2",
        scope: SignatureScope::SectionNames,
        family: "vmprotect",
    },
    PackerSignature {
        name: "Enigma Protector",
        needle: b".enigma1",
        scope: SignatureScope::SectionNames,
        family: "enigma",
    },
    PackerSignature {
        name: "Enigma Protector",
        needle: b".enigma2",
        scope: SignatureScope::SectionNames,
        family: "enigma",
    },
    PackerSignature {
        name: "Obsidium",
        needle: b".obsidium",
        scope: SignatureScope::SectionNames,
        family: "obsidium",
    },
    PackerSignature {
        name: "NsPack",
        needle: b".nsp0",
        scope: SignatureScope::SectionNames,
        family: "nspack",
    },
    PackerSignature {
        name: "Petite",
        needle: b".petite",
        scope: SignatureScope::SectionNames,
        family: "petite",
    },
    PackerSignature {
        name: "FSG",
        needle: b".fsg",
        scope: SignatureScope::SectionNames,
        family: "fsg",
    },
    PackerSignature {
        name: "MEW",
        needle: b"MEW",
        scope: SignatureScope::SectionNames,
        family: "mew",
    },
    PackerSignature {
        name: "kkrunchy",
        needle: b"kkrunchy",
        scope: SignatureScope::Anywhere,
        family: "kkrunchy",
    },
    PackerSignature {
        name: "MoleBox",
        needle: b".molebox",
        scope: SignatureScope::SectionNames,
        family: "molebox",
    },
    PackerSignature {
        name: "PELock",
        needle: b".pelock",
        scope: SignatureScope::SectionNames,
        family: "pelock",
    },
    PackerSignature {
        name: "RLPack",
        needle: b".rlpack",
        scope: SignatureScope::SectionNames,
        family: "rlpack",
    },
    PackerSignature {
        name: ".NET Reactor",
        needle: b"NETReactor",
        scope: SignatureScope::Anywhere,
        family: "dotnet-reactor",
    },
    PackerSignature {
        name: "ConfuserEx",
        needle: b"ConfusedByAttribute",
        scope: SignatureScope::Anywhere,
        family: "confuserex",
    },
    PackerSignature {
        name: "SmartAssembly",
        needle: b"SmartAssembly",
        scope: SignatureScope::Anywhere,
        family: "smartassembly",
    },
    PackerSignature {
        name: "Babel Obfuscator",
        needle: b"BabelObfuscator",
        scope: SignatureScope::Anywhere,
        family: "babel",
    },
    PackerSignature {
        name: "PyInstaller",
        needle: b"pyi-runtime-tmpdir",
        scope: SignatureScope::Anywhere,
        family: "pyinstaller",
    },
    PackerSignature {
        name: "Py2Exe",
        needle: b"PYTHONSCRIPT",
        scope: SignatureScope::Anywhere,
        family: "py2exe",
    },
    PackerSignature {
        name: "Go build",
        needle: b"Go build ID:",
        scope: SignatureScope::Anywhere,
        family: "go",
    },
    PackerSignature {
        name: "Rust build",
        needle: b"rustc version",
        scope: SignatureScope::Anywhere,
        family: "rust",
    },
    PackerSignature {
        name: "Deno/pkg snapshot",
        needle: b"pkg/prelude/bootstrap.js",
        scope: SignatureScope::Anywhere,
        family: "pkg",
    },
];

/// One piece of evidence behind a verdict.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackerEvidence {
    /// Short machine-readable key.
    pub key: String,
    /// Human sentence explaining what was observed.
    pub detail: String,
    /// Points contributed toward the likelihood.
    pub weight: i32,
}

/// Packer verdict.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackerVerdict {
    /// 0–100, probability that the artefact is packed or protected.
    pub likelihood: u8,
    /// Matched signature names, deduplicated.
    pub signatures: Vec<String>,
    /// Every contributing observation.
    pub evidence: Vec<PackerEvidence>,
    /// One-line summary for the UI badge.
    pub summary: String,
}

/// Section names a normal compiler produces. Anything outside this set is worth
/// a look, though not automatically suspicious — many legit tools invent names.
const STANDARD_SECTIONS: &[&str] = &[
    ".text",
    ".data",
    ".rdata",
    ".bss",
    ".idata",
    ".edata",
    ".pdata",
    ".rsrc",
    ".reloc",
    ".tls",
    ".didat",
    ".didata",
    ".debug",
    ".CRT",
    ".gfids",
    ".00cfg",
    "CODE",
    "DATA",
    "INIT",
    "RTCODE",
    "RTDATA",
    ".textbss",
    ".sdata",
    ".srdata",
    ".xdata",
    ".pdata",
    // MSVC emits this one when the linker is invoked with `/hotpatch`: it holds
    // the five-byte nop before each patchable function. It is absent from this
    // list in the first version of the heuristic, so every large Windows DLL
    // linked that way was told it had "non-standard section names" — 8 points of
    // packing against a compiler artefact.
    ".fothk",
    "__text",
    "__data",
    "__bss",
    "__const",
    "__cstring",
    "__DATA",
    "__TEXT",
    ".init",
    ".fini",
    ".plt",
    ".got",
    ".got.plt",
    ".rodata",
    ".eh_frame",
    ".eh_frame_hdr",
    ".note.gnu.build-id",
    ".note.ABI-tag",
    ".gnu.hash",
    ".dynsym",
    ".dynstr",
    ".comment",
    ".interp",
    ".dynamic",
    ".symtab",
    ".strtab",
    ".shstrtab",
    ".gcc_except_table",
    ".tm_clone_table",
    ".init_array",
    ".fini_array",
    ".preinit_array",
    ".ctors",
    ".dtors",
];

/// Detect packing in a parsed image.
///
/// `data` must be the raw bytes the image was parsed from.
pub fn detect(image: &BinaryImage, data: &[u8]) -> PackerVerdict {
    // Packing is a property of executable containers. A shell script has no
    // code sections to pack, and an archive's payload is opaque to us because
    // we deliberately never decompress. Running the heuristic anyway would
    // produce "no imports, therefore packed" on every `.sh` and every `.zip`,
    // which is exactly the kind of noise that makes analysts stop reading.
    if !matches!(image.format, Format::Pe | Format::Elf | Format::MachO) {
        return PackerVerdict {
            likelihood: 0,
            signatures: Vec::new(),
            evidence: Vec::new(),
            summary: "packing is not applicable to this container".into(),
        };
    }

    let mut evidence: Vec<PackerEvidence> = Vec::new();
    let mut signatures: Vec<String> = Vec::new();
    let mut score: i32 = 0;

    // ---- 1. Signatures ---------------------------------------------------
    let header = &data[..data.len().min(64 * 1024)];
    for sig in SIGNATURES {
        let hit = match sig.scope {
            SignatureScope::Anywhere => find_bytes(data, sig.needle),
            SignatureScope::Header => find_bytes(header, sig.needle),
            SignatureScope::SectionNames => image
                .sections
                .iter()
                .any(|s| s.name.as_bytes() == sig.needle),
            SignatureScope::ImportNames => image
                .imports
                .iter()
                .any(|i| i.symbol.as_bytes() == sig.needle),
        };
        if hit {
            if !signatures.iter().any(|s| s == sig.name) {
                signatures.push(sig.name.to_string());
            }
            evidence.push(PackerEvidence {
                key: format!("signature:{}", sig.family),
                detail: format!(
                    "literal `{}` found ({})",
                    String::from_utf8_lossy(sig.needle),
                    sig.name
                ),
                weight: 45,
            });
            score += 45;
        }
    }

    // ---- 2. Entropy of code sections -------------------------------------
    let code_entropy = image
        .sections
        .iter()
        .filter(|s| s.permissions.execute && s.file_size >= 1024)
        .map(|s| s.entropy)
        .fold(0.0f64, f64::max);

    if code_entropy >= 7.6 {
        evidence.push(PackerEvidence {
            key: "entropy:very-high".into(),
            detail: format!(
                "executable section entropy is {code_entropy:.2} bits/byte — indistinguishable from ciphertext"
            ),
            weight: 30,
        });
        score += 30;
    } else if code_entropy >= 7.2 {
        evidence.push(PackerEvidence {
            key: "entropy:high".into(),
            detail: format!("executable section entropy is {code_entropy:.2} bits/byte"),
            weight: 20,
        });
        score += 20;
    }

    // ---- 3. Entry point placement ----------------------------------------
    if let Some(ep) = image.entry_point {
        let in_code = image.sections.iter().any(|s| {
            let start = s.virtual_address;
            let end = start.saturating_add(s.virtual_size.max(s.file_size));
            ep >= start && ep < end && s.permissions.execute
        });
        if !in_code {
            evidence.push(PackerEvidence {
                key: "entry:outside-code".into(),
                detail: format!("entry point {ep:#x} does not fall inside any executable section"),
                weight: 22,
            });
            score += 22;
        }
    } else if matches!(image.format, Format::Pe) {
        evidence.push(PackerEvidence {
            key: "entry:absent".into(),
            detail: "no entry point recorded, yet the image claims to be a PE".into(),
            weight: 12,
        });
        score += 12;
    }

    // ---- 4. Writable+executable sections ---------------------------------
    let wx: Vec<&str> = image
        .sections
        .iter()
        .filter(|s| s.permissions.is_wx() && s.file_size > 0)
        .map(|s| s.name.as_str())
        .collect();
    if !wx.is_empty() {
        evidence.push(PackerEvidence {
            key: "section:wx".into(),
            detail: format!("writable+executable sections: {}", wx.join(", ")),
            weight: 20,
        });
        score += 20;
    }

    // ---- 5. Import scarcity ----------------------------------------------
    let import_count = image.imports.len();
    if import_count == 0 {
        evidence.push(PackerEvidence {
            key: "imports:none".into(),
            detail: "import table is empty; a packer stub resolves everything dynamically".into(),
            weight: 26,
        });
        score += 26;
    } else if import_count < 10 {
        evidence.push(PackerEvidence {
            key: "imports:few".into(),
            detail: format!("only {import_count} imported symbols, far below a normal build"),
            weight: 14,
        });
        score += 14;
    }

    // ---- 6. Virtual/raw size disparity -----------------------------------
    for s in &image.sections {
        if s.file_size == 0 || s.virtual_size == 0 {
            continue;
        }
        let ratio = s.virtual_size as f64 / s.file_size as f64;
        if ratio >= 8.0 {
            evidence.push(PackerEvidence {
                key: "section:inflation".into(),
                detail: format!(
                    "section `{}` maps {} bytes in memory from {} on disk ({ratio:.1}x) — an unpacking target",
                    s.name, s.virtual_size, s.file_size
                ),
                weight: 16,
            });
            score += 16;
            break;
        }
    }

    // ---- 7. Non-standard section names -----------------------------------
    let odd: Vec<&str> = image
        .sections
        .iter()
        .map(|s| s.name.as_str())
        .filter(|n| !n.is_empty())
        .filter(|n| {
            !STANDARD_SECTIONS
                .iter()
                .any(|std| std.eq_ignore_ascii_case(n))
                && !n.starts_with("__")
                && !n.starts_with(".debug_")
                && !n.starts_with(".note")
                && !n.starts_with(".rela")
        })
        .collect();
    if !odd.is_empty() && odd.len() <= 8 {
        evidence.push(PackerEvidence {
            key: "section:odd-names".into(),
            detail: format!("non-standard section names: {}", odd.join(", ")),
            weight: 8,
        });
        score += 8;
    }

    // ---- 8. TLS callbacks ------------------------------------------------
    if let crate::format::FormatMetadata::Pe(pe) = &image.metadata {
        // TLS callbacks are reported as their own finding. They are deliberately
        // not counted as packing evidence: MSVC emits them for `__declspec
        // (thread)` in a DLL, so they are present in a large share of the
        // operating system's own libraries, and charging 10 points of "packing"
        // for a compiler feature double-counts a signal that is already stated at
        // low severity elsewhere.
        if pe.is_dotnet && !pe.rich_entries.is_empty() {
            // Managed assemblies almost never carry a Rich header.
            evidence.push(PackerEvidence {
                key: "dotnet:rich-header".into(),
                detail:
                    "managed assembly carries an MSVC Rich header, suggesting a native dropper stub"
                        .into(),
                weight: 6,
            });
            score += 6;
        }
        if !pe.checksum_valid && pe.declared_checksum != 0 {
            evidence.push(PackerEvidence {
                key: "pe:checksum".into(),
                detail: "declared PE checksum does not match the computed value".into(),
                weight: 8,
            });
            score += 8;
        }
    }

    // ---- 9. Overlay ------------------------------------------------------
    if image
        .structural_notes
        .iter()
        .any(|n| n.contains("appended after the last section"))
    {
        evidence.push(PackerEvidence {
            key: "container:overlay".into(),
            detail: "data appended after the last mapped section".into(),
            weight: 7,
        });
        score += 7;
    }

    // ---- 10. Long NOP runs -----------------------------------------------
    //
    // Zero runs are excluded deliberately. A section is padded to
    // SectionAlignment with zeros, so every binary larger than a few kilobytes
    // contains multi-kilobyte zero runs; counting them made this signal fire on
    // every Microsoft system library.
    //
    // `0xCC` is excluded for the same reason as zero. The MSVC linker fills the
    // gaps between sections with INT3, so a 4 KiB INT3 run is a normal artefact
    // of a large image — the first version of this heuristic charged five points
    // of "packing" to any binary over a few megabytes for its own padding. A NOP
    // sled inside code is the thing worth reporting.
    if let Some((offset, byte, len)) = crate::analysis::entropy::longest_constant_run(data, 2048) {
        if byte == 0x90 && len >= 2048 {
            evidence.push(PackerEvidence {
                key: "bytes:nop-run".into(),
                detail: format!(
                    "{len} consecutive NOP bytes at {offset:#x} — hand-written padding or a sled"
                ),
                weight: 5,
            });
            score += 5;
        }
    }

    let likelihood = score.clamp(0, 100) as u8;
    let summary = match likelihood {
        0..=19 => "no packing indicators".to_string(),
        20..=44 => {
            if signatures.is_empty() {
                "weak indicators of packing".to_string()
            } else {
                format!("matches {}", signatures.join(", "))
            }
        }
        45..=69 => {
            if signatures.is_empty() {
                "likely packed or protected".to_string()
            } else {
                format!("packed with {}", signatures.join(", "))
            }
        }
        _ => {
            if signatures.is_empty() {
                "strongly packed; static analysis of the payload will be limited".to_string()
            } else {
                format!(
                    "protected by {} — expect anti-analysis and virtualised code",
                    signatures.join(", ")
                )
            }
        }
    };

    // Strongest evidence first.
    evidence.sort_by_key(|item| std::cmp::Reverse(item.weight));

    PackerVerdict {
        likelihood,
        signatures,
        evidence,
        summary,
    }
}

/// Naive `memmem`: fine for the handful of short needles we search for.
fn find_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::{
        Architecture, BinaryImage, BinaryKind, Endianness, Format, FormatMetadata, ImportEntry,
        Permissions, SectionInfo,
    };

    fn image_with(sections: Vec<SectionInfo>, imports: Vec<ImportEntry>) -> BinaryImage {
        BinaryImage {
            format: Format::Pe,
            kind: BinaryKind::Executable,
            arch: Architecture::X86_64,
            endian: Endianness::Little,
            bitness: 64,
            entry_point: Some(0x1000),
            image_base: 0x400000,
            sections,
            imports,
            exports: Vec::new(),
            resources: Vec::new(),
            debug_artifacts: Vec::new(),
            signature: crate::format::SignatureInfo::absent(),
            structural_notes: Vec::new(),
            unreadable_tables: Vec::new(),
            metadata: FormatMetadata::None,
        }
    }

    fn section(name: &str, entropy: f64, perms: (bool, bool, bool)) -> SectionInfo {
        SectionInfo {
            name: name.into(),
            virtual_address: 0x1000,
            virtual_size: 0x1000,
            file_offset: 0x400,
            file_size: 0x1000,
            entropy,
            permissions: Permissions::new(perms.0, perms.1, perms.2),
            sha256: String::new(),
            raw_characteristics: 0,
        }
    }

    #[test]
    fn clean_binary_scores_low() {
        let imports: Vec<ImportEntry> = (0..40)
            .map(|i| ImportEntry {
                library: "kernel32.dll".into(),
                symbol: format!("Func{i}"),
                ordinal: None,
                hint: None,
                delayed: false,
            })
            .collect();
        let image = image_with(vec![section(".text", 6.2, (true, false, true))], imports);
        let verdict = detect(&image, &[0u8; 4096]);
        assert!(verdict.likelihood < 20, "got {}", verdict.likelihood);
        assert!(verdict.signatures.is_empty());
    }

    #[test]
    fn upx_signature_is_detected() {
        let image = image_with(vec![section("UPX0", 7.9, (true, true, true))], Vec::new());
        let verdict = detect(&image, b"UPX0\x00\x00\x00\x00");
        assert!(verdict.signatures.contains(&"UPX".to_string()));
        assert!(verdict.likelihood >= 45);
    }

    #[test]
    fn high_entropy_code_raises_score() {
        let imports: Vec<ImportEntry> = (0..40)
            .map(|i| ImportEntry {
                library: "k.dll".into(),
                symbol: format!("F{i}"),
                ordinal: None,
                hint: None,
                delayed: false,
            })
            .collect();
        let image = image_with(vec![section(".text", 7.85, (true, false, true))], imports);
        let verdict = detect(&image, &[0u8; 4096]);
        assert!(verdict
            .evidence
            .iter()
            .any(|e| e.key == "entropy:very-high"));
        assert!(verdict.likelihood >= 25);
    }

    #[test]
    fn empty_imports_score_high() {
        let image = image_with(vec![section(".text", 6.0, (true, false, true))], Vec::new());
        let verdict = detect(&image, &[0u8; 4096]);
        assert!(verdict.evidence.iter().any(|e| e.key == "imports:none"));
    }

    #[test]
    fn wx_section_is_flagged() {
        let imports: Vec<ImportEntry> = (0..40)
            .map(|i| ImportEntry {
                library: "k.dll".into(),
                symbol: format!("F{i}"),
                ordinal: None,
                hint: None,
                delayed: false,
            })
            .collect();
        let image = image_with(vec![section(".text", 6.0, (true, true, true))], imports);
        let verdict = detect(&image, &[0u8; 4096]);
        assert!(verdict.evidence.iter().any(|e| e.key == "section:wx"));
    }

    #[test]
    fn evidence_is_sorted_by_weight() {
        let image = image_with(vec![section("UPX0", 7.9, (true, true, true))], Vec::new());
        let verdict = detect(&image, b"UPX0");
        let weights: Vec<i32> = verdict.evidence.iter().map(|e| e.weight).collect();
        let mut sorted = weights.clone();
        sorted.sort_by(|a, b| b.cmp(a));
        assert_eq!(weights, sorted);
    }

    #[test]
    fn vmprotect_signature_matches() {
        let image = image_with(vec![section(".vmp0", 7.8, (true, true, true))], Vec::new());
        let verdict = detect(&image, &[0u8; 128]);
        assert!(verdict.signatures.iter().any(|s| s.contains("VMProtect")));
    }

    #[test]
    fn hotpatch_section_is_not_odd() {
        // `/hotpatch` emits a `.fothk` section. Treating it as a non-standard name
        // put eight points of "packing" on every DLL the linker built that way,
        // which is a large share of Windows.
        let image = image_with(
            vec![
                section(".text", 6.0, (true, true, true)),
                section(".fothk", 4.0, (true, true, true)),
            ],
            (0..30)
                .map(|i| ImportEntry {
                    library: "k.dll".into(),
                    symbol: format!("F{i}"),
                    ordinal: None,
                    hint: None,
                    delayed: false,
                })
                .collect(),
        );
        let verdict = detect(&image, &[0u8; 4096]);
        assert!(
            !verdict
                .evidence
                .iter()
                .any(|e| e.key == "section:odd-names"),
            "`.fothk` must not count as a non-standard section name"
        );
    }

    #[test]
    fn int3_padding_is_not_a_sled() {
        // The MSVC linker pads section gaps with 0xCC. A 4 KiB INT3 run is normal
        // output, not evidence of packing; only a NOP run counts.
        let image = image_with(
            vec![section(".text", 6.0, (true, true, true))],
            (0..30)
                .map(|i| ImportEntry {
                    library: "k.dll".into(),
                    symbol: format!("F{i}"),
                    ordinal: None,
                    hint: None,
                    delayed: false,
                })
                .collect(),
        );
        let int3 = vec![0xCCu8; 8192];
        let verdict = detect(&image, &int3);
        assert!(!verdict.evidence.iter().any(|e| e.key == "bytes:nop-run"));

        let nops = vec![0x90u8; 8192];
        let verdict = detect(&image, &nops);
        assert!(verdict.evidence.iter().any(|e| e.key == "bytes:nop-run"));
    }
}

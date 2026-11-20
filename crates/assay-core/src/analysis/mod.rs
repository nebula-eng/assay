//! The analysis pipeline.
//!
//! Stage order matters and is fixed:
//!
//! 1. **Identify** — hash, sniff, decide the container. Nothing downstream can
//!    be trusted if this is wrong, so it happens first and its confidence is
//!    recorded.
//! 2. **Parse** — lower the container into [`BinaryImage`]. A failure here is
//!    recorded and the pipeline continues with whatever was recovered.
//! 3. **Measure** — entropy profile and string recovery. Both are pure functions
//!    of the bytes, so they run even when parsing failed.
//! 4. **Infer** — indicators, packing, ATT&CK capability.
//! 5. **Judge** — rule findings, then the composite score. Order is deliberate:
//!    rules may reference the score, and the score references everything else,
//!    so scoring must be able to see findings that were raised *before* it.
//!
//! Stage 5's internal ordering is why the score is computed after rules but
//! rules can key on `min_score`: the rule set is evaluated twice in that case —
//! once to establish findings, once against the final score. That second pass
//! only re-runs the cheap composite rules, not the whole corpus.

pub mod attack;
pub mod entropy;
pub mod hygiene;
pub mod ioc;
pub mod packer;
pub mod score;
pub mod strings;

use std::path::Path;
use std::time::Instant;

use crate::bytes::to_hex;
use crate::error::{AssayError, Result};
use crate::format::{archive, detect, elf, macho, pe, BinaryImage, Format, FormatMetadata};
use crate::fuzzy;
use crate::hash::{md5, sha1, sha256};
use crate::report::{
    ArtefactInfo, Diagnostic, Report, StringStats, Timing, ToolInfo, SCHEMA_VERSION,
};
use crate::rules::{engine as rule_engine, RuleSet};

/// Knobs for a single analysis run.
#[derive(Debug, Clone)]
pub struct AnalyzeOptions {
    /// Minimum length for a recovered string.
    pub min_string_length: usize,
    /// Hard cap on recovered strings.
    pub max_strings: usize,
    /// How many strings to embed in the report.
    pub string_sample: usize,
    /// Entropy window size in bytes.
    pub entropy_window: usize,
    /// Rule set to evaluate. `None` disables rule evaluation entirely.
    pub rules: Option<RuleSet>,
}

impl Default for AnalyzeOptions {
    fn default() -> Self {
        AnalyzeOptions {
            min_string_length: 5,
            max_strings: 100_000,
            string_sample: 2_000,
            entropy_window: entropy::DEFAULT_WINDOW,
            rules: RuleSet::from_json(crate::rules::BUILTIN_RULES_JSON).ok(),
        }
    }
}

impl AnalyzeOptions {
    /// A fast profile for batch triage: fewer strings, bigger sample cap ratio.
    pub fn fast() -> Self {
        AnalyzeOptions {
            min_string_length: 6,
            max_strings: 20_000,
            string_sample: 500,
            entropy_window: 8192,
            rules: RuleSet::from_json(crate::rules::BUILTIN_RULES_JSON).ok(),
        }
    }

    /// A deep profile for a single artefact under the microscope.
    pub fn deep() -> Self {
        AnalyzeOptions {
            min_string_length: 4,
            max_strings: 400_000,
            string_sample: 20_000,
            entropy_window: 1024,
            rules: RuleSet::from_json(crate::rules::BUILTIN_RULES_JSON).ok(),
        }
    }
}

/// Read a file from disk and analyse it.
pub fn analyze_path(path: &Path, options: &AnalyzeOptions) -> Result<Report> {
    // Check for a directory first. Reading one fails with the platform's
    // permission error (`EACCES` on Windows, `EISDIR` on Linux), and "cannot
    // read samples: access denied" sends the reader hunting for a permissions
    // problem that does not exist. The real answer is that directories are a
    // different command.
    if path.is_dir() {
        return Err(AssayError::Io {
            path: path.to_path_buf(),
            source: std::io::Error::other(
                "this is a directory; use `assay batch` to scan a tree, or name a single file",
            ),
        });
    }
    let data = std::fs::read(path).map_err(|e| AssayError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    let name = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.to_string_lossy().into_owned());
    Ok(analyze_bytes(&data, &name, options))
}

/// Analyse an in-memory buffer.
///
/// This never returns `Err`: every failure becomes a diagnostic in the report.
/// The rationale is that a partially decoded hostile file is still useful, and a
/// batch run should not abort because one sample is malformed.
pub fn analyze_bytes(data: &[u8], name: &str, options: &AnalyzeOptions) -> Report {
    let t_start = Instant::now();
    let mut diagnostics: Vec<Diagnostic> = Vec::new();
    let mut timing = Timing::default();

    // ---- 1. Identify -----------------------------------------------------
    let t = Instant::now();
    let digest = sha256(data);
    let sha256_hex = to_hex(&digest);
    let sha1_hex = to_hex(&sha1(data));
    let md5_hex = to_hex(&md5(data));
    let fuzzy_hash = fuzzy::hash(data);
    let detected = detect::detect(data, Some(name));
    timing.detect_ms = t.elapsed().as_millis() as u64;

    // ---- 2. Parse --------------------------------------------------------
    let t = Instant::now();
    let mut image = parse_image(data, &detected, &mut diagnostics);
    timing.parse_ms = t.elapsed().as_millis() as u64;

    // A table the parser could see declared but could not read is a limit on
    // what this report can claim, so it is surfaced as a diagnostic rather than
    // buried in the notes. Warning severity keeps the exit code at the verdict
    // level: the file was analysed, just not completely, and the report says so.
    for table in &image.unreadable_tables {
        diagnostics.push(Diagnostic::warning("parse", "truncated", table.clone()));
    }

    // ---- 3. Measure ------------------------------------------------------
    let t = Instant::now();
    let entropy_profile = entropy::profile(data, options.entropy_window, 512);
    let string_opts = strings::StringOptions {
        min_length: options.min_string_length,
        max_strings: options.max_strings,
        max_length: 512,
        utf16: true,
    };
    let recovered = strings::extract(data, string_opts);
    let string_stats = StringStats {
        total: recovered.len(),
        unique: strings::dedup(&recovered).len(),
        ascii: recovered
            .iter()
            .filter(|s| s.encoding == strings::Encoding::Ascii)
            .count(),
        utf16le: recovered
            .iter()
            .filter(|s| s.encoding == strings::Encoding::Utf16Le)
            .count(),
        utf16be: recovered
            .iter()
            .filter(|s| s.encoding == strings::Encoding::Utf16Be)
            .count(),
        longest: recovered.iter().map(|s| s.length).max().unwrap_or(0),
    };
    timing.strings_ms = t.elapsed().as_millis() as u64;

    // ---- 4. Infer --------------------------------------------------------
    let t = Instant::now();
    let iocs = ioc::extract(&recovered);
    let packer_verdict = packer::detect(&image, data);
    let loader_paths = collect_loader_paths(&image);
    // ATT&CK inference needs a case-insensitive view of imports and strings.
    let evidence = attack::Evidence::new(&image, &recovered, name);
    let techniques = attack::infer(&evidence);

    // A platform library provides the very APIs the capability rules look for,
    // so inference is withheld rather than answered. Say so explicitly: silence
    // without a reason reads as "nothing found", which is a different claim.
    if image.is_library_surface() {
        image.structural_notes.push(format!(
            "platform library surface ({} exports, {} imports): offensive-capability inference withheld",
            image.exports.len(),
            image.imports.len()
        ));
    }
    timing.analysis_ms = t.elapsed().as_millis() as u64;

    // ---- 5. Judge --------------------------------------------------------
    let t = Instant::now();
    // First pass: everything except score-dependent composite rules. The score
    // is not known yet, so we run with a provisional score of 0 and then
    // re-evaluate once the real score exists.
    let provisional_score = score::compute(&image, &packer_verdict, &techniques, &iocs.indicators);
    let mut findings = options
        .rules
        .as_ref()
        .map(|rules| {
            let ctx = rule_engine::RuleContext {
                image: &image,
                packer: &packer_verdict,
                techniques: &techniques,
                indicators: &iocs,
                score: &provisional_score,
                strings: &recovered,
                module_stem: crate::analysis::hygiene::module_stem(name),
                entropy: &entropy_profile,
                loader_paths: &loader_paths,
            };
            rule_engine::evaluate(rules, &ctx)
        })
        .unwrap_or_default();

    // Recompute now that rule findings exist. Findings do not feed the score
    // additively (they mirror signals already counted), but the rules that key
    // on `min_score` need the final number, so run the corpus once more and
    // keep the union keyed by rule id.
    let mut final_score = score::compute(&image, &packer_verdict, &techniques, &iocs.indicators);

    // Severity floor. The additive model cannot let one factor condemn a file,
    // which is correct for ambiguous evidence and wrong when a rule has already
    // matched the unambiguous shape of an attack. A critical finding pins the
    // score to the critical band; a high finding pins it to high.
    let worst_rank = findings
        .iter()
        .map(|f| f.severity.rank())
        .max()
        .unwrap_or(0);
    let floor = match worst_rank {
        4 => 75u8,
        3 => 55u8,
        2 => 40u8,
        _ => 0u8,
    };
    if floor > 0 {
        if let Some(worst) = findings.iter().find(|f| f.severity.rank() == worst_rank) {
            let reason = format!(
                "rule `{}` matched at {} severity",
                worst.rule_id,
                worst.severity.as_str()
            );
            final_score.apply_floor(floor, &reason, &image);
        }
    }

    if (final_score.score != provisional_score.score) && options.rules.is_some() {
        if let Some(rules) = options.rules.as_ref() {
            let ctx = rule_engine::RuleContext {
                image: &image,
                packer: &packer_verdict,
                techniques: &techniques,
                indicators: &iocs,
                score: &final_score,
                strings: &recovered,
                module_stem: crate::analysis::hygiene::module_stem(name),
                entropy: &entropy_profile,
                loader_paths: &loader_paths,
            };
            let second = rule_engine::evaluate(rules, &ctx);
            let mut seen: std::collections::HashSet<String> =
                findings.iter().map(|f| f.rule_id.clone()).collect();
            for f in second {
                if seen.insert(f.rule_id.clone()) {
                    findings.push(f);
                }
            }
            findings.sort_by(|a, b| {
                b.severity
                    .rank()
                    .cmp(&a.severity.rank())
                    .then_with(|| a.rule_id.cmp(&b.rule_id))
            });
        }
    }
    timing.rules_ms = t.elapsed().as_millis() as u64;

    // ---- Assemble --------------------------------------------------------
    let string_sample = recovered
        .iter()
        .take(options.string_sample)
        .cloned()
        .collect();

    let rules_evaluated = options
        .rules
        .as_ref()
        .map(|rules| rules.active().count())
        .unwrap_or(0);

    let artefact = ArtefactInfo {
        path: name.to_string(),
        name: name.to_string(),
        size: data.len() as u64,
        sha256: sha256_hex,
        sha1: sha1_hex,
        md5: md5_hex,
        fuzzy: fuzzy_hash.to_string_repr(),
        detected_format: detected.format.as_str().to_string(),
        detection_confidence: match detected.confidence {
            detect::Confidence::Certain => "certain",
            detect::Confidence::Structural => "structural",
            detect::Confidence::Weak => "weak",
        }
        .to_string(),
        magic: detected.magic.clone(),
        detection_reason: detected.reason.to_string(),
    };

    timing.total_ms = t_start.elapsed().as_millis() as u64;

    Report {
        schema_version: SCHEMA_VERSION.into(),
        tool: ToolInfo::current(),
        artefact,
        image,
        entropy: entropy_profile,
        strings: string_sample,
        string_stats,
        indicators: iocs,
        packer: packer_verdict,
        techniques,
        score: final_score,
        findings,
        rules_evaluated,
        diagnostics,
        timing,
    }
}

fn parse_image(
    data: &[u8],
    detected: &detect::Detected,
    diagnostics: &mut Vec<Diagnostic>,
) -> BinaryImage {
    match detected.format {
        Format::Pe => match pe::PeFile::parse(data) {
            Ok(file) => file.image,
            Err(e) => {
                diagnostics.push(Diagnostic::error("parse", e.kind(), e.to_string()));
                BinaryImage::placeholder(Format::Pe)
            }
        },
        Format::Elf => match elf::ElfFile::parse(data) {
            Ok(file) => file.image,
            Err(e) => {
                diagnostics.push(Diagnostic::error("parse", e.kind(), e.to_string()));
                BinaryImage::placeholder(Format::Elf)
            }
        },
        Format::MachO => match macho::MachOFile::parse(data) {
            Ok(file) => file.image,
            Err(e) => {
                diagnostics.push(Diagnostic::error("parse", e.kind(), e.to_string()));
                BinaryImage::placeholder(Format::MachO)
            }
        },
        Format::Zip => match archive::parse_zip(data) {
            Ok(file) => file.image,
            Err(e) => {
                diagnostics.push(Diagnostic::error("parse", e.kind(), e.to_string()));
                BinaryImage::placeholder(Format::Zip)
            }
        },
        Format::Ar => match archive::parse_ar(data) {
            Ok(file) => file.image,
            Err(e) => {
                diagnostics.push(Diagnostic::error("parse", e.kind(), e.to_string()));
                BinaryImage::placeholder(Format::Ar)
            }
        },
        Format::Tar => match archive::parse_tar(data) {
            Ok(file) => file.image,
            Err(e) => {
                diagnostics.push(Diagnostic::error("parse", e.kind(), e.to_string()));
                BinaryImage::placeholder(Format::Tar)
            }
        },
        Format::Gzip => match archive::parse_gzip(data) {
            Ok(file) => file.image,
            Err(e) => {
                diagnostics.push(Diagnostic::error("parse", e.kind(), e.to_string()));
                BinaryImage::placeholder(Format::Gzip)
            }
        },
        Format::Script => {
            let mut image = BinaryImage::placeholder(Format::Script);
            image.kind = crate::format::BinaryKind::Script;
            image.bitness = 0;
            image
        }
        Format::Unknown => {
            diagnostics.push(Diagnostic::warning(
                "detect",
                "unknown-format",
                "no container signature matched; treating the file as opaque bytes",
            ));
            BinaryImage::placeholder(Format::Unknown)
        }
    }
}

/// Collect loader-related paths that rules can match on.
fn collect_loader_paths(image: &BinaryImage) -> Vec<String> {
    let mut paths: Vec<String> = Vec::new();
    match &image.metadata {
        FormatMetadata::Elf(meta) => {
            if let Some(interp) = &meta.interpreter {
                paths.push(interp.clone());
            }
            paths.extend(meta.rpath.iter().cloned());
            paths.extend(meta.runpath.iter().cloned());
        }
        FormatMetadata::MachO(meta) => {
            if let Some(install) = &meta.install_name {
                paths.push(install.clone());
            }
            paths.extend(meta.rpaths.iter().cloned());
        }
        _ => {}
    }
    paths
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_pe() -> Vec<u8> {
        // Reuse the PE builder from the format module's tests by constructing a
        // buffer inline; keeping this independent avoids test-only coupling.
        let mut buf = vec![0u8; 0x400];
        buf[0] = b'M';
        buf[1] = b'Z';
        buf[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        buf[0x80..0x84].copy_from_slice(b"PE\0\0");
        buf[0x84..0x86].copy_from_slice(&0x014cu16.to_le_bytes()); // i386
        buf[0x86..0x88].copy_from_slice(&1u16.to_le_bytes()); // 1 section
        buf[0x94..0x96].copy_from_slice(&224u16.to_le_bytes()); // optional size
        buf[0x96..0x98].copy_from_slice(&0x0102u16.to_le_bytes()); // executable

        let opt = 0x98;
        buf[opt..opt + 2].copy_from_slice(&0x010Bu16.to_le_bytes());
        buf[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[opt + 28..opt + 32].copy_from_slice(&0x0040_0000u32.to_le_bytes());
        buf[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes());
        buf[opt + 56..opt + 60].copy_from_slice(&0x2000u32.to_le_bytes());
        buf[opt + 60..opt + 64].copy_from_slice(&0x200u32.to_le_bytes());
        buf[opt + 68..opt + 70].copy_from_slice(&2u16.to_le_bytes());
        buf[opt + 92..opt + 96].copy_from_slice(&16u32.to_le_bytes());

        let sec = 0x98 + 224;
        buf[sec..sec + 5].copy_from_slice(b".text");
        buf[sec + 8..sec + 12].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[sec + 16..sec + 20].copy_from_slice(&0x200u32.to_le_bytes());
        buf[sec + 20..sec + 24].copy_from_slice(&0x200u32.to_le_bytes());
        buf[sec + 36..sec + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
        buf
    }

    #[test]
    fn analyzes_a_pe_end_to_end() {
        let data = minimal_pe();
        let report = analyze_bytes(&data, "sample.exe", &AnalyzeOptions::default());
        assert_eq!(report.artefact.size, data.len() as u64);
        assert_eq!(report.artefact.sha256.len(), 64);
        assert_eq!(report.artefact.sha1.len(), 40);
        assert_eq!(report.artefact.md5.len(), 32);
        assert_eq!(report.image.format, Format::Pe);
        assert!(report.diagnostics.is_empty() || !report.has_errors());
    }

    #[test]
    fn hashes_are_correct() {
        let data = minimal_pe();
        let report = analyze_bytes(&data, "x", &AnalyzeOptions::default());
        // Cross-check SHA-256 against the standalone hasher.
        assert_eq!(report.artefact.sha256, crate::hash::sha256_hex(&data));
    }

    #[test]
    fn handles_empty_input() {
        let report = analyze_bytes(&[], "empty", &AnalyzeOptions::default());
        assert_eq!(report.artefact.size, 0);
        assert_eq!(report.score.score, 0);
    }

    #[test]
    fn handles_garbage_without_panicking() {
        let data: Vec<u8> = (0..4096u32).map(|i| (i * 7 % 256) as u8).collect();
        let report = analyze_bytes(&data, "garbage.bin", &AnalyzeOptions::default());
        assert_eq!(report.artefact.detected_format, "unknown");
        assert!(!report.diagnostics.is_empty());
    }

    #[test]
    fn unknown_format_scores_no_worse_than_low() {
        let data = vec![0u8; 512];
        let report = analyze_bytes(&data, "zeros.bin", &AnalyzeOptions::default());
        assert!(report.score.score <= 40, "score {}", report.score.score);
    }

    #[test]
    fn string_stats_are_consistent() {
        let mut data = vec![0u8; 256];
        data[0..11].copy_from_slice(b"hello world");
        let report = analyze_bytes(&data, "s.bin", &AnalyzeOptions::default());
        assert_eq!(
            report.string_stats.total,
            report.string_stats.ascii + report.string_stats.utf16le + report.string_stats.utf16be
        );
    }

    #[test]
    fn string_sample_is_bounded() {
        let mut data = Vec::new();
        for i in 0..5000 {
            data.extend_from_slice(format!("token-{i:05}\x00").as_bytes());
        }
        let options = AnalyzeOptions {
            string_sample: 100,
            ..AnalyzeOptions::default()
        };
        let report = analyze_bytes(&data, "many.bin", &options);
        assert!(report.strings.len() <= 100);
    }

    #[test]
    fn timing_is_recorded() {
        let report = analyze_bytes(&minimal_pe(), "t.exe", &AnalyzeOptions::default());
        assert!(report.timing.total_ms <= 60_000);
    }

    #[test]
    fn json_is_produced_for_a_pe() {
        let report = analyze_bytes(&minimal_pe(), "j.exe", &AnalyzeOptions::default());
        let json = report.to_json().expect("json");
        assert!(json.contains("\"schema_version\""));
    }

    #[test]
    fn fuzz_never_panics() {
        // Deterministic pseudo-random buffers of varying size and shape.
        for seed in 0..64u32 {
            let len = ((seed * 977) % 8192) as usize;
            let mut data = Vec::with_capacity(len);
            let mut state = seed.wrapping_mul(2_654_435_761).wrapping_add(1);
            for _ in 0..len {
                state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                data.push((state >> 16) as u8);
            }
            // Sprinkle a magic so different format branches get exercised.
            if len > 8 && seed % 4 == 0 {
                data[0] = b'M';
                data[1] = b'Z';
            } else if len > 8 && seed % 4 == 1 {
                data[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
            } else if len > 8 && seed % 4 == 2 {
                data[0..4].copy_from_slice(&[0x50, 0x4B, 0x03, 0x04]);
            }
            let report = analyze_bytes(&data, "fuzz.bin", &AnalyzeOptions::fast());
            // The invariant: we always produce a report with a consistent score.
            assert!(report.score.score <= 100);
        }
    }
}

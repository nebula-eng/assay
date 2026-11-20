//! The analysis report: one serialisable document describing one artefact.
//!
//! Everything the engine observed is in here, including what it *could not* do.
//! A report that silently omits a parse failure is worse than one that admits
//! the file was only partially decoded, because the reader cannot tell "no
//! findings" from "we gave up at byte 512".

use serde::{Deserialize, Serialize};

use crate::analysis::attack::Technique;
use crate::analysis::entropy::EntropyProfile;
use crate::analysis::ioc::IocSet;
use crate::analysis::packer::PackerVerdict;
use crate::analysis::score::RiskScore;
use crate::analysis::strings::ExtractedString;
use crate::format::BinaryImage;
use crate::rules::engine::Finding;

/// Schema version of the JSON this module emits.
///
/// Bumped whenever a field is removed or its meaning changes. Additive changes
/// do not bump it, so consumers should ignore unknown fields.
pub const SCHEMA_VERSION: &str = "1.0";

/// Identity of the tool that produced a report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInfo {
    /// Tool name.
    pub name: String,
    /// Semantic version.
    pub version: String,
    /// Build identifier (commit hash or `dev`).
    pub build: String,
}

impl ToolInfo {
    /// The running tool's identity.
    pub fn current() -> Self {
        ToolInfo {
            name: "assay".into(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            build: option_env!("ASSAY_BUILD").unwrap_or("dev").to_string(),
        }
    }
}

/// Facts about the file itself, independent of its contents' meaning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtefactInfo {
    /// Path as given by the caller, or a synthetic name for in-memory input.
    pub path: String,
    /// Final path component.
    pub name: String,
    /// Size in bytes.
    pub size: u64,
    /// SHA-256, hex.
    pub sha256: String,
    /// SHA-1, hex. Present because most threat-intel platforms still key on it.
    pub sha1: String,
    /// MD5, hex. Same rationale.
    pub md5: String,
    /// CTPH fuzzy hash, useful for family clustering.
    pub fuzzy: String,
    /// Detected container format.
    pub detected_format: String,
    /// How confident the detection was (`certain`, `structural`, `weak`).
    pub detection_confidence: String,
    /// First bytes, hex, for eyeballing.
    pub magic: String,
    /// Why the format was chosen.
    pub detection_reason: String,
}

/// A problem encountered during analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Diagnostic {
    /// Pipeline stage that produced it (`parse`, `strings`, `rules`, …).
    pub stage: String,
    /// `error` or `warning`.
    pub severity: String,
    /// Machine-readable category.
    pub kind: String,
    /// Human explanation.
    pub message: String,
}

impl Diagnostic {
    /// Record an error.
    pub fn error(stage: &str, kind: &str, message: impl Into<String>) -> Self {
        Diagnostic {
            stage: stage.into(),
            severity: "error".into(),
            kind: kind.into(),
            message: message.into(),
        }
    }

    /// Record a warning.
    pub fn warning(stage: &str, kind: &str, message: impl Into<String>) -> Self {
        Diagnostic {
            stage: stage.into(),
            severity: "warning".into(),
            kind: kind.into(),
            message: message.into(),
        }
    }
}

/// Wall-clock cost of each pipeline stage.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Timing {
    /// Hashing and format detection.
    pub detect_ms: u64,
    /// Container parsing.
    pub parse_ms: u64,
    /// String recovery.
    pub strings_ms: u64,
    /// Entropy, packer, ATT&CK inference.
    pub analysis_ms: u64,
    /// Rule evaluation.
    pub rules_ms: u64,
    /// Everything.
    pub total_ms: u64,
}

/// Summary statistics over the recovered strings.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StringStats {
    /// Total strings recovered.
    pub total: usize,
    /// Distinct texts.
    pub unique: usize,
    /// Recovered as ASCII.
    pub ascii: usize,
    /// Recovered as UTF-16LE.
    pub utf16le: usize,
    /// Recovered as UTF-16BE.
    pub utf16be: usize,
    /// Longest string length in characters.
    pub longest: usize,
}

/// The complete report for one artefact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    /// Report schema version.
    pub schema_version: String,
    /// Tool identity.
    pub tool: ToolInfo,
    /// File facts.
    pub artefact: ArtefactInfo,
    /// Parsed structure.
    pub image: BinaryImage,
    /// Entropy profile.
    pub entropy: EntropyProfile,
    /// A bounded sample of recovered strings, not the full set.
    pub strings: Vec<ExtractedString>,
    /// Aggregate string statistics over the full set.
    pub string_stats: StringStats,
    /// Recovered indicators.
    pub indicators: IocSet,
    /// Packer verdict.
    pub packer: PackerVerdict,
    /// Inferred ATT&CK techniques.
    pub techniques: Vec<Technique>,
    /// Risk score with its decomposition.
    pub score: RiskScore,
    /// Rule findings.
    pub findings: Vec<Finding>,
    /// Number of rules that were evaluated. Zero means rule checking was
    /// disabled, which is a materially different result from "no rule matched".
    pub rules_evaluated: usize,
    /// Problems encountered; an empty list means every stage completed.
    pub diagnostics: Vec<Diagnostic>,
    /// Per-stage timing.
    pub timing: Timing,
}

impl Report {
    /// True when any stage reported an error.
    pub fn has_errors(&self) -> bool {
        self.diagnostics.iter().any(|d| d.severity == "error")
    }

    /// Highest severity among findings, as a rank (0 = none).
    pub fn max_finding_severity(&self) -> u8 {
        self.findings
            .iter()
            .map(|f| f.severity.rank())
            .max()
            .unwrap_or(0)
    }

    /// One-paragraph executive summary suitable for a ticket or a PR comment.
    pub fn summary(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        parts.push(format!(
            "{} ({} bytes, {} {})",
            self.artefact.name,
            self.artefact.size,
            self.image.format.as_str(),
            self.image.arch.label()
        ));
        parts.push(format!(
            "score {}/100 ({})",
            self.score.score,
            self.score.grade.as_str()
        ));
        if !self.findings.is_empty() {
            parts.push(crate::bytes::plural(self.findings.len(), "finding", None));
        }
        if !self.techniques.is_empty() {
            parts.push(crate::bytes::plural(
                self.techniques.len(),
                "ATT&CK technique",
                None,
            ));
        }
        if !self.indicators.is_empty() {
            parts.push(crate::bytes::plural(
                self.indicators.indicators.len(),
                "indicator",
                None,
            ));
        }
        if self.has_errors() {
            parts.push("partial analysis (see diagnostics)".into());
        }
        parts.join(" · ")
    }

    /// Serialise to pretty JSON.
    pub fn to_json(&self) -> crate::Result<String> {
        serde_json::to_string_pretty(self).map_err(|e| crate::error::AssayError::Unsupported {
            what: "report",
            detail: format!("could not serialise report: {e}"),
        })
    }

    /// Exit-code-compatible severity: 0 clean, 1 high, 2 critical.
    ///
    /// Aimed at CI usage, where a pipeline wants to fail on a threshold rather
    /// than parse JSON.
    pub fn exit_code(&self) -> i32 {
        if self.has_errors() {
            return 3;
        }
        match self.score.grade {
            crate::analysis::score::Grade::Critical => 2,
            crate::analysis::score::Grade::High => 1,
            _ => 0,
        }
    }
}

/// Render a report as plain text, sized for a terminal or a log line.
pub fn render_text(report: &Report) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{}  {}",
        report.artefact.name,
        crate::analysis::score::ascii_bar(report.score.score, 20)
    );
    let _ = writeln!(
        out,
        "  {} {} · {} · SHA-256 {}",
        report.image.format.as_str(),
        report.image.arch.label(),
        format_size(report.artefact.size),
        &report.artefact.sha256[..16.min(report.artefact.sha256.len())]
    );
    let _ = writeln!(out, "  {}", report.score.verdict);
    let _ = writeln!(out);

    if !report.findings.is_empty() {
        // Three lines is the useful maximum: format, the discriminator, and the
        // count. Two truncated the substantive clause on multi-condition rules.
        const EVIDENCE_LINES: usize = 3;
        let _ = writeln!(out, "Findings:");
        for f in report.findings.iter().take(12) {
            let _ = writeln!(
                out,
                "  [{}] {} — {}",
                f.severity.as_str().to_uppercase(),
                f.rule_id,
                f.rule_name
            );
            for e in f.evidence.iter().take(EVIDENCE_LINES) {
                let _ = writeln!(out, "        {e}");
            }
            if f.evidence.len() > EVIDENCE_LINES {
                let _ = writeln!(
                    out,
                    "        … and {} not shown",
                    crate::bytes::plural(
                        f.evidence.len() - EVIDENCE_LINES,
                        "more observation",
                        None
                    )
                );
            }
        }
        if report.findings.len() > 12 {
            let _ = writeln!(
                out,
                "  … and {}",
                crate::bytes::plural(report.findings.len() - 12, "further finding", None)
            );
        }
        let _ = writeln!(out);
    }

    if !report.techniques.is_empty() {
        let _ = writeln!(out, "ATT&CK:");
        for t in report.techniques.iter().take(10) {
            let _ = writeln!(
                out,
                "  {} {} ({}%) — {}",
                t.id,
                t.name,
                (t.confidence * 100.0) as u8,
                t.tactic
            );
        }
        let _ = writeln!(out);
    }

    if !report.indicators.is_empty() {
        let _ = writeln!(out, "Indicators:");
        for i in report.indicators.top(10) {
            let _ = writeln!(out, "  {:<14} {}", i.kind.as_str(), i.value);
        }
        let _ = writeln!(out);
    }

    if !report.diagnostics.is_empty() {
        let _ = writeln!(out, "Diagnostics:");
        for d in report.diagnostics.iter().take(8) {
            let _ = writeln!(out, "  {} [{}] {}", d.severity, d.stage, d.message);
        }
        let _ = writeln!(out);
    }

    // A partial analysis must never read like a complete one.
    if report.has_errors() {
        let _ = writeln!(
            out,
            "  This analysis is incomplete. Structural results above are what could be recovered."
        );
    }

    out
}

/// Human-readable byte size (`1.4 MiB`).
pub fn format_size(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::entropy::EntropyProfile;
    use crate::analysis::ioc::IocSet;
    use crate::analysis::packer::PackerVerdict;
    use crate::analysis::score::{Grade, RiskScore};
    use crate::format::{BinaryImage, Format};

    fn minimal_report(grade: Grade, score: u8) -> Report {
        Report {
            schema_version: SCHEMA_VERSION.into(),
            tool: ToolInfo::current(),
            artefact: ArtefactInfo {
                path: "x.exe".into(),
                name: "x.exe".into(),
                size: 4096,
                sha256: "ab".repeat(32),
                sha1: "cd".repeat(20),
                md5: "ef".repeat(16),
                fuzzy: "3:abc:def".into(),
                detected_format: "pe".into(),
                detection_confidence: "certain".into(),
                magic: "4d5a".into(),
                detection_reason: "MZ".into(),
            },
            image: BinaryImage::placeholder(Format::Pe),
            entropy: EntropyProfile {
                overall: 0.0,
                mean_windowed: 0.0,
                stdev_windowed: 0.0,
                window: 4096,
                windows: Vec::new(),
                longest_high_run: crate::analysis::entropy::EntropyWindow {
                    offset: 0,
                    length: 0,
                    entropy: 0.0,
                },
                peak_offset: 0,
                peak_entropy: 0.0,
                high_entropy_fraction: 0.0,
            },
            strings: Vec::new(),
            string_stats: StringStats::default(),
            indicators: IocSet::default(),
            packer: PackerVerdict {
                likelihood: 0,
                signatures: Vec::new(),
                evidence: Vec::new(),
                summary: String::new(),
            },
            techniques: Vec::new(),
            score: RiskScore {
                score,
                grade,
                factors: Vec::new(),
                verdict: "verdict".into(),
            },
            findings: Vec::new(),
            rules_evaluated: 0,
            diagnostics: Vec::new(),
            timing: Timing::default(),
        }
    }

    #[test]
    fn exit_code_follows_grade() {
        assert_eq!(minimal_report(Grade::Clean, 0).exit_code(), 0);
        assert_eq!(minimal_report(Grade::Medium, 40).exit_code(), 0);
        assert_eq!(minimal_report(Grade::High, 60).exit_code(), 1);
        assert_eq!(minimal_report(Grade::Critical, 80).exit_code(), 2);
    }

    #[test]
    fn errors_dominate_exit_code() {
        let mut r = minimal_report(Grade::Clean, 0);
        r.diagnostics
            .push(Diagnostic::error("parse", "truncated", "short file"));
        assert_eq!(r.exit_code(), 3);
        assert!(r.has_errors());
    }

    #[test]
    fn summary_mentions_key_facts() {
        let r = minimal_report(Grade::High, 60);
        let s = r.summary();
        assert!(s.contains("x.exe"));
        assert!(s.contains("60/100"));
    }

    #[test]
    fn json_round_trips() {
        let r = minimal_report(Grade::Low, 20);
        let json = r.to_json().expect("serialise");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("parse");
        assert_eq!(parsed["schema_version"], SCHEMA_VERSION);
        assert_eq!(parsed["artefact"]["name"], "x.exe");
    }

    #[test]
    fn text_render_contains_sections() {
        let r = minimal_report(Grade::Medium, 40);
        let text = render_text(&r);
        assert!(text.contains("x.exe"));
        assert!(text.contains("verdict"));
    }

    #[test]
    fn size_formatting() {
        assert_eq!(format_size(512), "512 B");
        assert_eq!(format_size(1024), "1.0 KiB");
        assert_eq!(format_size(1536), "1.5 KiB");
        assert_eq!(format_size(1024 * 1024), "1.0 MiB");
    }

    #[test]
    fn max_severity_is_zero_without_findings() {
        assert_eq!(minimal_report(Grade::Clean, 0).max_finding_severity(), 0);
    }
}

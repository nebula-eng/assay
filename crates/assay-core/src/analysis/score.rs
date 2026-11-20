//! Multi-factor risk scoring.
//!
//! A single number is only useful if a human can argue with it. This module
//! therefore produces a score **and** the exact decomposition that produced it:
//! every factor reports its own points, its ceiling, the observation that earned
//! those points, and the raw evidence strings behind the observation.
//!
//! Weights were chosen so that no single signal can condemn a file on its own:
//! the largest single factor (30 points) caps at "medium" without corroboration,
//! which is deliberate — a signed, unpacked binary that merely imports
//! `GetAsyncKeyState` (an input-method product) should not rank alongside a
//! packed, unsigned, C2-beaconing loader.

use serde::{Deserialize, Serialize};

use crate::analysis::attack::Technique;
use crate::analysis::ioc::{Indicator, IocKind};
use crate::analysis::packer::PackerVerdict;
use crate::format::{BinaryImage, Format};

/// Qualitative band derived from the numeric score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Grade {
    /// Nothing of note.
    Clean,
    /// Worth a glance; may be a false positive.
    Low,
    /// Warrants review before deployment.
    Medium,
    /// Strong indicators of malicious intent or high exposure.
    High,
    /// Treat as hostile until proven otherwise.
    Critical,
}

impl Grade {
    /// Map a 0–100 score to a band.
    pub fn from_score(score: u8) -> Grade {
        match score {
            0..=14 => Grade::Clean,
            15..=34 => Grade::Low,
            35..=54 => Grade::Medium,
            55..=74 => Grade::High,
            _ => Grade::Critical,
        }
    }

    /// Stable lowercase identifier.
    pub fn as_str(self) -> &'static str {
        match self {
            Grade::Clean => "clean",
            Grade::Low => "low",
            Grade::Medium => "medium",
            Grade::High => "high",
            Grade::Critical => "critical",
        }
    }

    /// One-word verdict for report headers.
    pub fn label(self) -> &'static str {
        match self {
            Grade::Clean => "Clean",
            Grade::Low => "Low risk",
            Grade::Medium => "Medium risk",
            Grade::High => "High risk",
            Grade::Critical => "Critical",
        }
    }
}

/// One dimension of the score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Factor {
    /// Stable key for the UI (`packer`, `signature`, `capability`, …).
    pub key: String,
    /// Display name.
    pub name: String,
    /// Points awarded, never above `max_points`.
    pub points: i32,
    /// Ceiling for this factor.
    pub max_points: i32,
    /// One sentence explaining the award.
    pub detail: String,
    /// Raw observations behind it.
    pub evidence: Vec<String>,
}

impl Factor {
    /// Fraction of the ceiling that was awarded, 0.0–1.0.
    pub fn fill(&self) -> f64 {
        if self.max_points <= 0 {
            0.0
        } else {
            (self.points as f64 / self.max_points as f64).clamp(0.0, 1.0)
        }
    }
}

impl RiskScore {
    /// Raise the score to `floor` because a downstream check demands it.
    ///
    /// The additive model is deliberately conservative: no single factor can
    /// condemn a file. That is right for ambiguous evidence, and wrong when a
    /// rule fires on the unambiguous shape of a ransomware binary or an
    /// obfuscated stager. In those cases a *floor* applies — the score cannot
    /// land below the band implied by the most severe finding — and the uplift
    /// is recorded as its own factor so the arithmetic still explains itself.
    pub fn apply_floor(&mut self, floor: u8, reason: &str, image: &BinaryImage) {
        if self.score >= floor {
            return;
        }
        let additive = self.score;
        let delta = i32::from(floor) - i32::from(self.score);
        self.factors.push(Factor {
            key: "severity-floor".into(),
            name: "Severity floor".into(),
            points: delta,
            max_points: 100,
            detail: reason.to_string(),
            evidence: vec![format!(
                "additive score was {additive}, raised to the floor of {floor}"
            )],
        });
        self.factors
            .sort_by_key(|factor| std::cmp::Reverse(factor.points));
        self.score = floor;
        self.grade = Grade::from_score(floor);
        // Regenerate from scratch so the headline number, the band label and the
        // contributor list all agree with the post-floor state.
        let base = build_verdict(floor, self.grade, &self.factors, image);
        self.verdict = format!(
            "{}. Raised from the additive estimate of {additive} because {reason}.",
            base.trim_end_matches('.')
        );
    }
}

/// The complete scoring result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskScore {
    /// 0–100, higher is worse.
    pub score: u8,
    /// Band derived from `score`.
    pub grade: Grade,
    /// Every contributing factor, ordered by points descending.
    pub factors: Vec<Factor>,
    /// A sentence a reviewer can paste into a ticket.
    pub verdict: String,
}

/// Factor ceilings. They sum to 100 by construction.
///
/// Calibration note: `CAPABILITY` carries the most weight because inferring an
/// ATT&CK technique requires a *combination* of imports, which is far harder to
/// trip accidentally than an unsigned file or a high-entropy section. The
/// per-technique multiplier is 0.5 rather than 0.34 so that a single
/// high-confidence impact technique (ransomware encryption, credential dumping)
/// moves the score into the review band on its own — while still leaving room
/// for corroboration to push it further.
pub mod weights {
    /// Packing / protection.
    pub const PACKER: i32 = 28;
    /// Code-signing posture.
    pub const SIGNATURE: i32 = 15;
    /// ATT&CK capability breadth.
    pub const CAPABILITY: i32 = 35;
    /// Network indicators.
    pub const NETWORK: i32 = 14;
    /// Structural anomalies.
    pub const STRUCTURE: i32 = 8;
}

/// Compute the score.
pub fn compute(
    image: &BinaryImage,
    packer: &PackerVerdict,
    techniques: &[Technique],
    indicators: &[Indicator],
) -> RiskScore {
    let mut factors = Vec::with_capacity(5);

    // ---- 1. Packing ------------------------------------------------------
    let packer_points = if packer.likelihood >= 70 {
        weights::PACKER
    } else if packer.likelihood >= 45 {
        weights::PACKER * 3 / 4
    } else if packer.likelihood >= 20 {
        weights::PACKER / 3
    } else {
        0
    };
    factors.push(Factor {
        key: "packer".into(),
        name: "Packing / protection".into(),
        points: packer_points,
        max_points: weights::PACKER,
        detail: packer.summary.clone(),
        evidence: packer
            .evidence
            .iter()
            .take(6)
            .map(|e| format!("{} (+{})", e.detail, e.weight))
            .collect(),
    });

    // ---- 2. Signature ----------------------------------------------------
    let mut sig_points = 0i32;
    let mut sig_evidence: Vec<String> = Vec::new();
    let sig = &image.signature;
    // An opaque blob has no signature slot to be empty. Charging it for being
    // "unsigned" would make every unknown file start at eight points for a
    // property it cannot have.
    if matches!(image.format, Format::Unknown) {
        // leave sig_points at zero
    } else if !sig.present {
        // No *embedded* signature is recorded as an observation and costs
        // nothing.
        //
        // The distinction matters: Windows signs many of its own binaries through
        // a security catalog rather than an embedded blob, so `notepad.exe` has
        // no Authenticode signature yet is fully trusted by the OS. Verifying a
        // catalog requires the platform API, which this tool does not call. Until
        // this was fixed, every catalog-signed system binary started eight points
        // down — a fifth of the medium band — for a property the tool cannot
        // observe. An observation that cannot be interpreted is not evidence, and
        // scoring it is the same mistake as reading a truncated file as
        // "unhardened".
        sig_evidence
            .push("no embedded Authenticode signature (catalog signing is not checked)".into());
    } else {
        if let Some(alg) = &sig.digest_algorithm {
            if alg == "md5" || alg == "sha1" || alg.contains("md5") || alg.contains("sha1") {
                sig_points += 14;
                sig_evidence.push(format!("signature digest uses broken algorithm `{alg}`"));
            }
        }
        if !sig.timestamped {
            sig_points += 4;
            sig_evidence.push("no countersignature timestamp".into());
        }
        for issue in &sig.issues {
            sig_evidence.push(issue.clone());
        }
        if sig.signer.is_none() && sig.present {
            sig_points += 6;
            sig_evidence
                .push("signature present but signer identity could not be recovered".into());
        }
    }
    // A managed assembly with no strong-name signature is a weak signal only.
    if sig_points > weights::SIGNATURE {
        sig_points = weights::SIGNATURE;
    }
    factors.push(Factor {
        key: "signature".into(),
        name: "Code signing".into(),
        points: sig_points,
        max_points: weights::SIGNATURE,
        detail: if sig.present {
            match (&sig.signer, &sig.issuer) {
                (Some(s), Some(i)) => format!("signed by {s} (issuer {i})"),
                (Some(s), None) => format!("signed by {s}"),
                _ => "signature blob present, identity unresolved".into(),
            }
        } else {
            "no embedded signature (catalog signing not checked)".into()
        },
        evidence: sig_evidence,
    });

    // ---- 3. Capability ---------------------------------------------------
    // Weight each technique by its confidence and by how late it sits in the
    // kill chain: an impact technique is worth more than a discovery one.
    let mut cap_points = 0.0f64;
    let mut cap_evidence: Vec<String> = Vec::new();
    let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for t in techniques {
        if !seen.insert(t.tactic.as_str()) {
            // Count at most one technique per tactic toward the score; the rest
            // still appear in the report, but they should not stack.
            continue;
        }
        let tactic_weight = match t.tactic.as_str() {
            "impact" => 1.0,
            "credential-access" => 0.95,
            "lateral-movement" => 0.9,
            "command-and-control" => 0.9,
            "defense-evasion" => 0.8,
            "persistence" => 0.8,
            "privilege-escalation" => 0.75,
            "execution" => 0.7,
            "collection" => 0.6,
            "discovery" => 0.4,
            _ => 0.5,
        };
        cap_points += f64::from(weights::CAPABILITY) * 0.5 * t.confidence * tactic_weight;
        cap_evidence.push(format!(
            "{} {} ({}%)",
            t.id,
            t.name,
            (t.confidence * 100.0) as u8
        ));
    }
    let cap_points = (cap_points.round() as i32).min(weights::CAPABILITY);
    factors.push(Factor {
        key: "capability".into(),
        name: "Offensive capability".into(),
        points: cap_points,
        max_points: weights::CAPABILITY,
        detail: if techniques.is_empty() {
            "no ATT&CK technique could be inferred from imports".into()
        } else {
            {
                let tactics = techniques
                    .iter()
                    .map(|t| t.tactic.as_str())
                    .collect::<std::collections::HashSet<_>>()
                    .len();
                format!(
                    "{} inferred across {}",
                    crate::bytes::plural(techniques.len(), "technique", None),
                    crate::bytes::plural(tactics, "tactic", None)
                )
            }
        },
        evidence: cap_evidence,
    });

    // ---- 4. Network indicators -------------------------------------------
    let high_value: Vec<&Indicator> = indicators
        .iter()
        .filter(|i| {
            matches!(
                i.kind,
                IocKind::Url
                    | IocKind::Onion
                    | IocKind::Bitcoin
                    | IocKind::Ethereum
                    | IocKind::Ipv4
            ) && i.confidence >= 0.6
        })
        .take(12)
        .collect();
    let net_points = ((high_value.len() as i32) * 2).min(weights::NETWORK);
    factors.push(Factor {
        key: "network".into(),
        name: "Network indicators".into(),
        points: net_points,
        max_points: weights::NETWORK,
        detail: if high_value.is_empty() {
            "no network indicators recovered".into()
        } else {
            format!(
                "{} embedded in the artefact",
                crate::bytes::plural(high_value.len(), "high-value indicator", None)
            )
        },
        evidence: high_value
            .iter()
            .map(|i| format!("{} {}", i.kind.as_str(), i.value))
            .collect(),
    });

    // ---- 5. Structural anomalies -----------------------------------------
    let mut struct_points = 0i32;
    let mut struct_evidence: Vec<String> = Vec::new();
    for note in image.structural_notes.iter().take(12) {
        struct_points += 2;
        struct_evidence.push(note.clone());
    }
    // Note: an unrecognised container is *not* scored as an anomaly. "We do not
    // know what this is" is an epistemic limit, not evidence of malice, and
    // charging points for it made every empty or truncated file start at four.
    let struct_points = struct_points.min(weights::STRUCTURE);
    factors.push(Factor {
        key: "structure".into(),
        name: "Structural anomalies".into(),
        points: struct_points,
        max_points: weights::STRUCTURE,
        detail: if image.structural_notes.is_empty() {
            "structure is internally consistent".into()
        } else {
            crate::bytes::plural(image.structural_notes.len(), "structural note", None)
        },
        evidence: struct_evidence,
    });

    factors.sort_by_key(|factor| std::cmp::Reverse(factor.points));

    let total: i32 = factors.iter().map(|f| f.points).sum();
    let score = total.clamp(0, 100) as u8;
    let grade = Grade::from_score(score);

    let verdict = build_verdict(score, grade, &factors, image);

    RiskScore {
        score,
        grade,
        factors,
        verdict,
    }
}

fn build_verdict(score: u8, grade: Grade, factors: &[Factor], image: &BinaryImage) -> String {
    let top: Vec<String> = factors
        .iter()
        .filter(|f| f.points > 0)
        .take(2)
        .map(|f| format!("{} ({}/{})", f.name.to_lowercase(), f.points, f.max_points))
        .collect();

    let kind = match image.kind {
        crate::format::BinaryKind::Executable => "executable",
        crate::format::BinaryKind::SharedLibrary => "library",
        crate::format::BinaryKind::Driver => "kernel driver",
        crate::format::BinaryKind::ManagedAssembly => "managed assembly",
        crate::format::BinaryKind::Installer => "installer",
        crate::format::BinaryKind::Script => "script",
        crate::format::BinaryKind::Package => "package",
        crate::format::BinaryKind::Object => "object file",
        crate::format::BinaryKind::Other => "artefact",
    };

    if top.is_empty() {
        return format!(
            "{} {kind} with a score of {score}/100: nothing notable was found.",
            grade.label()
        );
    }

    format!(
        "{} {kind}, score {score}/100. Main contributors: {}.",
        grade.label(),
        top.join(", ")
    )
}

/// Render the score as a compact ASCII bar for terminal output.
pub fn ascii_bar(score: u8, width: usize) -> String {
    let filled = ((u32::from(score) * width as u32) / 100) as usize;
    let mut out = String::with_capacity(width + 2);
    out.push('[');
    for i in 0..width {
        out.push(if i < filled { '#' } else { '.' });
    }
    out.push(']');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::packer::PackerVerdict;
    use crate::analysis::strings::Encoding;
    use crate::format::{Architecture, BinaryImage, BinaryKind, Endianness, Format, ImportEntry};

    fn clean_image() -> BinaryImage {
        let mut image = BinaryImage::placeholder(Format::Pe);
        image.kind = BinaryKind::Executable;
        image.arch = Architecture::X86_64;
        image.endian = Endianness::Little;
        image.bitness = 64;
        for i in 0..40 {
            image.imports.push(ImportEntry {
                library: "kernel32.dll".into(),
                symbol: format!("Api{i}"),
                ordinal: None,
                hint: None,
                delayed: false,
            });
        }
        image
    }

    fn benign_packer() -> PackerVerdict {
        PackerVerdict {
            likelihood: 0,
            signatures: Vec::new(),
            evidence: Vec::new(),
            summary: "no packing indicators".into(),
        }
    }

    #[test]
    fn clean_binary_scores_low() {
        let image = clean_image();
        let score = compute(&image, &benign_packer(), &[], &[]);
        assert!(score.score < 20, "score was {}", score.score);
        assert_eq!(score.grade, Grade::Clean);
    }

    #[test]
    fn packed_capable_binary_with_onion_scores_at_least_medium() {
        // The additive model alone must not call this clean: a UPX-shaped,
        // ransomware-capable binary with an onion endpoint is not a low-risk
        // file. It is not *high* on the additive sum either, and that is
        // deliberate — the pipeline reaches Critical here because
        // `c2-tor-hidden-service` fires and the severity floor lifts it to 75.
        // This test pins the additive half of that split.
        let mut image = clean_image();
        image.signature = crate::format::SignatureInfo::absent();
        image
            .structural_notes
            .push("section `.text` is writable and executable".into());
        let packer = PackerVerdict {
            likelihood: 90,
            signatures: vec!["UPX".into()],
            evidence: vec![crate::analysis::packer::PackerEvidence {
                key: "signature:upx".into(),
                detail: "literal UPX0 found".into(),
                weight: 45,
            }],
            summary: "packed with UPX".into(),
        };
        let techniques = vec![Technique {
            id: "T1486".into(),
            sub_id: None,
            name: "Data Encrypted for Impact".into(),
            tactic: "impact".into(),
            confidence: 0.9,
            evidence: vec!["CryptEncrypt".into()],
            note: String::new(),
            detection: String::new(),
        }];
        let indicators = vec![Indicator {
            kind: IocKind::Onion,
            value: "abc.onion".into(),
            occurrences: 1,
            offsets: vec![0],
            confidence: 0.99,
            rationale: String::new(),
        }];
        let score = compute(&image, &packer, &techniques, &indicators);
        assert!(score.score >= 45, "score was {}", score.score);
        assert!(
            matches!(score.grade, Grade::Medium | Grade::High | Grade::Critical),
            "grade was {:?}",
            score.grade
        );
    }

    #[test]
    fn factors_never_exceed_their_ceiling() {
        let image = clean_image();
        let packer = PackerVerdict {
            likelihood: 100,
            signatures: vec!["a".into(), "b".into()],
            evidence: vec![crate::analysis::packer::PackerEvidence {
                key: "k".into(),
                detail: "d".into(),
                weight: 100,
            }],
            summary: "s".into(),
        };
        let indicators: Vec<Indicator> = (0..50)
            .map(|i| Indicator {
                kind: IocKind::Url,
                value: format!("https://x{i}.example.com"),
                occurrences: 1,
                offsets: vec![0],
                confidence: 0.9,
                rationale: String::new(),
            })
            .collect();
        let score = compute(&image, &packer, &[], &indicators);
        for f in &score.factors {
            assert!(f.points <= f.max_points, "{} exceeded ceiling", f.key);
            assert!(f.fill() <= 1.0);
        }
        assert!(score.score <= 100);
    }

    #[test]
    fn factors_sorted_by_points() {
        let image = clean_image();
        let score = compute(&image, &benign_packer(), &[], &[]);
        let points: Vec<i32> = score.factors.iter().map(|f| f.points).collect();
        let mut sorted = points.clone();
        sorted.sort_by(|a, b| b.cmp(a));
        assert_eq!(points, sorted);
    }

    #[test]
    fn grade_bands() {
        assert_eq!(Grade::from_score(0), Grade::Clean);
        assert_eq!(Grade::from_score(14), Grade::Clean);
        assert_eq!(Grade::from_score(15), Grade::Low);
        assert_eq!(Grade::from_score(34), Grade::Low);
        assert_eq!(Grade::from_score(35), Grade::Medium);
        assert_eq!(Grade::from_score(54), Grade::Medium);
        assert_eq!(Grade::from_score(55), Grade::High);
        assert_eq!(Grade::from_score(74), Grade::High);
        assert_eq!(Grade::from_score(75), Grade::Critical);
        assert_eq!(Grade::from_score(100), Grade::Critical);
    }

    #[test]
    fn verdict_is_a_sentence() {
        let image = clean_image();
        let score = compute(&image, &benign_packer(), &[], &[]);
        assert!(score.verdict.contains("score"));
        assert!(score.verdict.ends_with('.'));
    }

    #[test]
    fn ascii_bar_length() {
        assert_eq!(ascii_bar(0, 10), "[..........]");
        assert_eq!(ascii_bar(100, 10), "[##########]");
        assert_eq!(ascii_bar(50, 10), "[#####.....]");
    }

    #[test]
    fn one_technique_per_tactic_counts() {
        let image = clean_image();
        let mk = |id: &str, tactic: &str| Technique {
            id: id.into(),
            sub_id: None,
            name: "x".into(),
            tactic: tactic.into(),
            confidence: 0.9,
            evidence: Vec::new(),
            note: String::new(),
            detection: String::new(),
        };
        let one = compute(&image, &benign_packer(), &[mk("T1", "impact")], &[]);
        let two = compute(
            &image,
            &benign_packer(),
            &[mk("T1", "impact"), mk("T2", "impact")],
            &[],
        );
        let cap_one = one
            .factors
            .iter()
            .find(|f| f.key == "capability")
            .unwrap()
            .points;
        let cap_two = two
            .factors
            .iter()
            .find(|f| f.key == "capability")
            .unwrap()
            .points;
        assert_eq!(cap_one, cap_two, "same tactic must not stack");
    }

    #[test]
    fn empty_strings_struct_ok() {
        let s = crate::analysis::strings::ExtractedString {
            offset: 0,
            encoding: Encoding::Ascii,
            length: 0,
            text: String::new(),
        };
        assert_eq!(s.length, 0);
    }
}

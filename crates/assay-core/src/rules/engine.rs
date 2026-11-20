//! Rule evaluation.
//!
//! Conditions inside a rule are conjunctive: every clause that is present must
//! hold. A clause that is absent imposes nothing. This is the least surprising
//! semantics for someone writing a rule by hand, and it makes an empty `match`
//! block obvious in review (which is why [`super::Rule::is_unconditional`]
//! exists as a guard).

use crate::analysis::attack::Technique;
use crate::analysis::entropy::EntropyProfile;
use crate::analysis::hygiene::{
    is_debug_symbol, is_location, is_markup, is_script_resource_lookup, is_self_reference,
};
use crate::analysis::ioc::IocSet;
use crate::analysis::packer::PackerVerdict;
use crate::analysis::score::RiskScore;
use crate::analysis::strings::ExtractedString;
use crate::format::BinaryImage;

use super::{Rule, RuleSet, Severity};

/// Everything a rule can inspect.
pub struct RuleContext<'a> {
    /// The parsed image.
    pub image: &'a BinaryImage,
    /// Packer verdict.
    pub packer: &'a PackerVerdict,
    /// Inferred ATT&CK techniques.
    pub techniques: &'a [Technique],
    /// Recovered indicators.
    pub indicators: &'a IocSet,
    /// Risk score.
    pub score: &'a RiskScore,
    /// Recovered strings (already truncated by the extractor).
    pub strings: &'a [ExtractedString],
    /// The artefact's file stem, used to drop self-referential strings.
    pub module_stem: &'a str,
    /// Entropy profile.
    pub entropy: &'a EntropyProfile,
    /// Loader-related paths (interpreter, RPATH, RUNPATH).
    pub loader_paths: &'a [String],
}

/// A rule that matched.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Finding {
    /// Originating rule id.
    pub rule_id: String,
    /// Originating rule name.
    pub rule_name: String,
    /// Declared severity.
    pub severity: Severity,
    /// Rule description.
    pub description: String,
    /// Specific observations that satisfied each clause.
    pub evidence: Vec<String>,
    /// Rule tags.
    pub tags: Vec<String>,
}

/// Evaluate every active rule.
pub fn evaluate(set: &RuleSet, ctx: &RuleContext<'_>) -> Vec<Finding> {
    let mut findings: Vec<Finding> = Vec::new();
    for rule in set.active() {
        if let Some(finding) = apply(rule, ctx) {
            findings.push(finding);
        }
    }
    // Most severe first, then alphabetical for stable output.
    findings.sort_by(|a, b| {
        b.severity
            .rank()
            .cmp(&a.severity.rank())
            .then_with(|| a.rule_id.cmp(&b.rule_id))
    });
    findings
}

fn apply(rule: &Rule, ctx: &RuleContext<'_>) -> Option<Finding> {
    let spec = &rule.match_spec;
    let mut evidence: Vec<String> = Vec::new();
    let image = ctx.image;

    // ---- format ----------------------------------------------------------
    if !spec.format.is_empty() {
        let actual = image.format.as_str();
        if !spec.format.iter().any(|f| f.eq_ignore_ascii_case(actual)) {
            return None;
        }
        evidence.push(format!("format is {actual}"));
    }

    // ---- kind ------------------------------------------------------------
    if !spec.kind.is_empty() {
        let actual = kind_label(image);
        if !spec.kind.iter().any(|k| k.eq_ignore_ascii_case(actual)) {
            return None;
        }
        evidence.push(format!("artefact kind is {actual}"));
    }

    // ---- signature state -------------------------------------------------
    if let Some(want) = spec.signed {
        if image.signature.present != want {
            return None;
        }
        evidence.push(if want {
            "an embedded signature is present".to_string()
        } else {
            "no embedded signature (catalog signing is not checked)".to_string()
        });
    }

    // ---- indicator count -------------------------------------------------
    if let Some(min) = spec.min_iocs {
        let count = if spec.ioc_kinds.is_empty() {
            ctx.indicators.indicators.len()
        } else {
            ctx.indicators
                .indicators
                .iter()
                .filter(|i| {
                    spec.ioc_kinds
                        .iter()
                        .any(|k| k.eq_ignore_ascii_case(i.kind.as_str()))
                })
                .count()
        };
        if count < min {
            return None;
        }
        evidence.push(format!(
            "{} (minimum {min})",
            crate::bytes::plural(count, "matching indicator", None)
        ));
    } else if !spec.ioc_kinds.is_empty() {
        // ioc_kinds without min_iocs means "at least one of these kinds".
        let present: Vec<&str> = ctx
            .indicators
            .indicators
            .iter()
            .filter(|i| {
                spec.ioc_kinds
                    .iter()
                    .any(|k| k.eq_ignore_ascii_case(i.kind.as_str()))
            })
            .map(|i| i.value.as_str())
            .take(3)
            .collect();
        if present.is_empty() {
            return None;
        }
        evidence.push(format!("indicators present: {}", present.join(", ")));
    }

    // ---- packer likelihood ----------------------------------------------
    if let Some(min) = spec.min_packer {
        if ctx.packer.likelihood < min {
            return None;
        }
        evidence.push(format!(
            "packer likelihood {} meets the {min} threshold",
            ctx.packer.likelihood
        ));
    }

    // ---- score -----------------------------------------------------------
    if let Some(min) = spec.min_score {
        if ctx.score.score < min {
            return None;
        }
        evidence.push(format!(
            "risk score {} meets the {min} threshold",
            ctx.score.score
        ));
    }

    // ---- required imports (all) -----------------------------------------
    if !spec.all_imports.is_empty() {
        let present: Vec<&str> = spec.all_imports.iter().map(String::as_str).collect();
        for required in &present {
            if !has_import(image, required) {
                return None;
            }
        }
        evidence.push(format!("imports present: {}", present.join(", ")));
    }

    // ---- alternative imports (any) --------------------------------------
    if !spec.any_imports.is_empty() {
        let matched: Vec<String> = spec
            .any_imports
            .iter()
            .filter(|needle| has_import(image, needle))
            .cloned()
            .collect();
        if matched.is_empty() {
            return None;
        }
        evidence.push(format!("imports matched: {}", matched.join(", ")));
    }

    // ---- maximum imports -------------------------------------------------
    if let Some(max) = spec.max_imports {
        // Delay-load entries are excluded: they are resolved after start-up and
        // do not appear in the standard import table.
        let count = image.imports.iter().filter(|i| !i.delayed).count();
        if count > max {
            return None;
        }
        evidence.push(format!("import count {count} does not exceed {max}"));
    }

    // ---- RELRO -----------------------------------------------------------
    if let Some(want) = spec.relro {
        let has = match &image.metadata {
            crate::format::FormatMetadata::Elf(meta) => meta.relro,
            _ => return None,
        };
        if has != want {
            return None;
        }
        evidence.push(if want {
            "ELF has PT_GNU_RELRO".to_string()
        } else {
            "ELF has no PT_GNU_RELRO, so the GOT stays writable".to_string()
        });
    }

    // ---- strings (any) --------------------------------------------------
    if !spec.any_strings.is_empty() {
        let mut matched: Vec<String> = Vec::new();
        for needle in &spec.any_strings {
            let lower = needle.to_ascii_lowercase();
            if let Some(found) = ctx.strings.iter().find(|s| {
                // The same hygiene the technique layer applies: a rule must not
                // match a string that names a location, a data-format
                // declaration, a debug path, a script's boilerplate or the
                // module's own name. `script-obfuscation-markers` convicted
                // `slmgr.vbs` on `GetResource = Eval(name)` before this gate
                // existed — see `analysis::hygiene`.
                !is_ignorable_string(&s.text, ctx.module_stem)
                    && s.text.to_ascii_lowercase().contains(&lower)
            }) {
                matched.push(truncate(&found.text, 72));
                if matched.len() >= 3 {
                    break;
                }
            }
        }
        if matched.is_empty() {
            return None;
        }
        evidence.push(format!("strings matched: {}", matched.join(" | ")));
    }

    // ---- ATT&CK techniques ----------------------------------------------
    if !spec.techniques.is_empty() {
        let matched: Vec<String> = spec
            .techniques
            .iter()
            .filter(|wanted| {
                ctx.techniques.iter().any(|t| {
                    t.id.eq_ignore_ascii_case(wanted)
                        || t.sub_id
                            .as_deref()
                            .is_some_and(|s| s.eq_ignore_ascii_case(wanted))
                })
            })
            .cloned()
            .collect();
        if matched.is_empty() {
            return None;
        }
        evidence.push(format!("techniques matched: {}", matched.join(", ")));
    }

    // ---- TLS callbacks ---------------------------------------------------
    if let Some(want) = spec.has_tls {
        let has = match &image.metadata {
            crate::format::FormatMetadata::Pe(pe) => pe.has_tls,
            _ => !image.debug_artifacts.iter().any(|a| a.kind == "tls"),
        };
        if has != want {
            return None;
        }
        evidence.push(if want {
            "TLS callbacks present".into()
        } else {
            "no TLS callbacks".into()
        });
    }

    // ---- .NET ------------------------------------------------------------
    if let Some(want) = spec.is_dotnet {
        let is = match &image.metadata {
            crate::format::FormatMetadata::Pe(pe) => pe.is_dotnet,
            _ => false,
        };
        if is != want {
            return None;
        }
        evidence.push(if want {
            "managed assembly".into()
        } else {
            "native image".into()
        });
    }

    // ---- entropy ---------------------------------------------------------
    if let Some(min) = spec.min_entropy {
        let observed = image.max_section_entropy();
        if observed < min {
            return None;
        }
        evidence.push(format!(
            "peak section entropy {observed:.2} meets the {min:.2} threshold"
        ));
    }

    // ---- writable+executable sections -----------------------------------
    if let Some(min) = spec.min_wx_sections {
        let count = image
            .sections
            .iter()
            .filter(|s| s.permissions.is_wx() && s.file_size > 0)
            .count();
        if count < min {
            return None;
        }
        evidence.push(crate::bytes::plural(
            count,
            "writable and executable section",
            None,
        ));
    }

    // ---- executable archive entries -------------------------------------
    //
    // Reads the entry names the archive parser already classified. A container
    // with no entries, or with entries that are all documents, cannot satisfy
    // this — which is the distinction the rule's name has always claimed.
    if let Some(min) = spec.min_executable_entries {
        let entries: &[String] = match &image.metadata {
            crate::format::FormatMetadata::Archive(a) => &a.executable_entries,
            _ => &[],
        };
        if entries.len() < min {
            return None;
        }
        evidence.push(crate::bytes::plural(
            entries.len(),
            "executable or script entry",
            None,
        ));
        for name in entries.iter().take(3) {
            evidence.push(format!("entry: {name}"));
        }
    }

    // ---- loader paths ----------------------------------------------------
    if !spec.loader_paths.is_empty() {
        let mut matched: Vec<String> = Vec::new();
        for wanted in &spec.loader_paths {
            let lower = wanted.to_ascii_lowercase();
            if let Some(found) = ctx
                .loader_paths
                .iter()
                .find(|p| p.to_ascii_lowercase().contains(&lower))
            {
                matched.push(found.clone());
            }
        }
        if matched.is_empty() {
            return None;
        }
        evidence.push(format!("loader paths matched: {}", matched.join(", ")));
    }

    // A rule that reached this point with zero evidence had no clauses; refuse
    // to emit a finding rather than produce an unexplainable hit.
    if evidence.is_empty() {
        return None;
    }

    Some(Finding {
        rule_id: rule.id.clone(),
        rule_name: rule.name.clone(),
        severity: rule.severity,
        description: rule.description.clone(),
        evidence,
        tags: rule.tags.clone(),
    })
}

fn kind_label(image: &BinaryImage) -> &'static str {
    match image.kind {
        crate::format::BinaryKind::Executable => "executable",
        crate::format::BinaryKind::SharedLibrary => "shared_library",
        crate::format::BinaryKind::Object => "object",
        crate::format::BinaryKind::ManagedAssembly => "managed_assembly",
        crate::format::BinaryKind::Installer => "installer",
        crate::format::BinaryKind::Driver => "driver",
        crate::format::BinaryKind::Script => "script",
        crate::format::BinaryKind::Package => "package",
        crate::format::BinaryKind::Other => "other",
    }
}

fn has_import(image: &BinaryImage, needle: &str) -> bool {
    let lower = needle.to_ascii_lowercase();
    image
        .imports
        .iter()
        .any(|i| i.symbol.to_ascii_lowercase() == lower)
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        s.chars().take(max).collect::<String>() + "…"
    }
}

/// True when a string names something the code merely mentions.
///
/// Delegates to the predicates in [`crate::analysis::hygiene`] so the rule engine
/// and the technique layer cannot drift apart: a string that is not evidence for
/// ATT&CK inference is not evidence for a rule either.
fn is_ignorable_string(text: &str, module_stem: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    is_location(&lower)
        || is_markup(&lower)
        || is_debug_symbol(&lower)
        || is_script_resource_lookup(&lower)
        || is_self_reference(&lower, module_stem)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::entropy::EntropyProfile;
    use crate::analysis::ioc::{Indicator, IocKind, IocSet};
    use crate::analysis::packer::PackerVerdict;
    use crate::analysis::score::{Grade, RiskScore};
    use crate::analysis::strings::Encoding;
    use crate::format::{
        Architecture, BinaryImage, BinaryKind, Endianness, Format, ImportEntry, SignatureInfo,
    };
    use crate::rules::RuleSet;

    fn base_image() -> BinaryImage {
        let mut image = BinaryImage::placeholder(Format::Pe);
        image.kind = BinaryKind::Executable;
        image.arch = Architecture::X86_64;
        image.endian = Endianness::Little;
        image.bitness = 64;
        image.signature = SignatureInfo::absent();
        image
    }

    fn ctx<'a>(
        image: &'a BinaryImage,
        packer: &'a PackerVerdict,
        techniques: &'a [Technique],
        indicators: &'a IocSet,
        score: &'a RiskScore,
        strings: &'a [ExtractedString],
        entropy: &'a EntropyProfile,
        loader: &'a [String],
    ) -> RuleContext<'a> {
        RuleContext {
            image,
            packer,
            techniques,
            indicators,
            score,
            strings,
            // Tests build images without a filename; an empty stem disables only
            // the self-reference predicate.
            module_stem: "",
            entropy,
            loader_paths: loader,
        }
    }

    fn empty_packer() -> PackerVerdict {
        PackerVerdict {
            likelihood: 0,
            signatures: Vec::new(),
            evidence: Vec::new(),
            summary: String::new(),
        }
    }

    fn zero_score() -> RiskScore {
        RiskScore {
            score: 0,
            grade: Grade::Clean,
            factors: Vec::new(),
            verdict: String::new(),
        }
    }

    fn empty_entropy() -> EntropyProfile {
        EntropyProfile {
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
        }
    }

    fn rules(json: &str) -> RuleSet {
        RuleSet::from_json(json).unwrap()
    }

    #[test]
    fn format_clause_filters() {
        let image = base_image();
        let packer = empty_packer();
        let iocs = IocSet::default();
        let score = zero_score();
        let entropy = empty_entropy();
        let set =
            rules(r#"[{"id":"elf-only","name":"x","severity":"low","match":{"format":["elf"]}}]"#);
        let c = ctx(&image, &packer, &[], &iocs, &score, &[], &entropy, &[]);
        assert!(evaluate(&set, &c).is_empty());
    }

    #[test]
    fn signed_clause_matches_unsigned() {
        let image = base_image();
        let packer = empty_packer();
        let iocs = IocSet::default();
        let score = zero_score();
        let entropy = empty_entropy();
        let set =
            rules(r#"[{"id":"unsigned","name":"x","severity":"high","match":{"signed":false}}]"#);
        let c = ctx(&image, &packer, &[], &iocs, &score, &[], &entropy, &[]);
        assert_eq!(evaluate(&set, &c).len(), 1);
    }

    #[test]
    fn min_iocs_clause() {
        let image = base_image();
        let packer = empty_packer();
        let mut iocs = IocSet::default();
        iocs.indicators.push(Indicator {
            kind: IocKind::Url,
            value: "https://x.example".into(),
            occurrences: 1,
            offsets: vec![0],
            confidence: 0.9,
            rationale: String::new(),
        });
        let score = zero_score();
        let entropy = empty_entropy();
        let set = rules(r#"[{"id":"net","name":"x","severity":"high","match":{"min_iocs":2}}]"#);
        let c = ctx(&image, &packer, &[], &iocs, &score, &[], &entropy, &[]);
        assert!(evaluate(&set, &c).is_empty());

        let set1 = rules(r#"[{"id":"net","name":"x","severity":"high","match":{"min_iocs":1}}]"#);
        assert_eq!(evaluate(&set1, &c).len(), 1);
    }

    #[test]
    fn ioc_kinds_restrict_counting() {
        let image = base_image();
        let packer = empty_packer();
        let mut iocs = IocSet::default();
        iocs.indicators.push(Indicator {
            kind: IocKind::Guid,
            value: "abc".into(),
            occurrences: 1,
            offsets: vec![0],
            confidence: 0.5,
            rationale: String::new(),
        });
        let score = zero_score();
        let entropy = empty_entropy();
        let set = rules(
            r#"[{"id":"net","name":"x","severity":"high","match":{"min_iocs":1,"ioc_kinds":["url"]}}]"#,
        );
        let c = ctx(&image, &packer, &[], &iocs, &score, &[], &entropy, &[]);
        assert!(
            evaluate(&set, &c).is_empty(),
            "GUID must not satisfy a url clause"
        );
    }

    #[test]
    fn import_clauses_work() {
        let mut image = base_image();
        image.imports.push(ImportEntry {
            library: "k.dll".into(),
            symbol: "CreateRemoteThread".into(),
            ordinal: None,
            hint: None,
            delayed: false,
        });
        let packer = empty_packer();
        let iocs = IocSet::default();
        let score = zero_score();
        let entropy = empty_entropy();
        let set = rules(
            r#"[{"id":"inj","name":"x","severity":"high","match":{"any_imports":["CreateRemoteThread"]}}]"#,
        );
        let c = ctx(&image, &packer, &[], &iocs, &score, &[], &entropy, &[]);
        assert_eq!(evaluate(&set, &c).len(), 1);

        let set_all = rules(
            r#"[{"id":"inj","name":"x","severity":"high","match":{"all_imports":["CreateRemoteThread","VirtualAllocEx"]}}]"#,
        );
        assert!(
            evaluate(&set_all, &c).is_empty(),
            "all_imports must require every symbol"
        );
    }

    #[test]
    fn string_clause_is_case_insensitive() {
        let image = base_image();
        let packer = empty_packer();
        let iocs = IocSet::default();
        let score = zero_score();
        let entropy = empty_entropy();
        let strings = vec![ExtractedString {
            offset: 0,
            encoding: Encoding::Ascii,
            length: 20,
            text: "PowerShell -EncodedCommand".into(),
        }];
        let set = rules(
            r#"[{"id":"ps","name":"x","severity":"high","match":{"any_strings":["powershell"]}}]"#,
        );
        let c = ctx(&image, &packer, &[], &iocs, &score, &strings, &entropy, &[]);
        assert_eq!(evaluate(&set, &c).len(), 1);
    }

    #[test]
    fn technique_clause_matches_sub_id() {
        let image = base_image();
        let packer = empty_packer();
        let iocs = IocSet::default();
        let score = zero_score();
        let entropy = empty_entropy();
        let techniques = vec![Technique {
            id: "T1055".into(),
            sub_id: Some("T1055.012".into()),
            name: "Process Injection: Process Hollowing".into(),
            tactic: "defense-evasion".into(),
            confidence: 0.9,
            evidence: Vec::new(),
            note: String::new(),
            detection: String::new(),
        }];
        let set = rules(
            r#"[{"id":"hollow","name":"x","severity":"high","match":{"techniques":["T1055.012"]}}]"#,
        );
        let c = ctx(
            &image,
            &packer,
            &techniques,
            &iocs,
            &score,
            &[],
            &entropy,
            &[],
        );
        assert_eq!(evaluate(&set, &c).len(), 1);
    }

    #[test]
    fn findings_sorted_by_severity() {
        let image = base_image();
        let packer = empty_packer();
        let iocs = IocSet::default();
        let score = zero_score();
        let entropy = empty_entropy();
        let set = RuleSet::from_json(
            r#"[
                {"id":"a-low","name":"a","severity":"low","match":{"format":["pe"]}},
                {"id":"z-critical","name":"z","severity":"critical","match":{"format":["pe"]}},
                {"id":"m-medium","name":"m","severity":"medium","match":{"format":["pe"]}}
            ]"#,
        )
        .unwrap();
        let c = ctx(&image, &packer, &[], &iocs, &score, &[], &entropy, &[]);
        let findings = evaluate(&set, &c);
        assert_eq!(findings.len(), 3);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[2].severity, Severity::Low);
    }

    #[test]
    fn unconditional_rule_emits_nothing() {
        // The loader rejects such a rule, so this constructs it directly to prove
        // the evaluator is also safe: defence in depth, because a future caller
        // could build a RuleSet in code without going through `from_json`.
        let image = base_image();
        let packer = empty_packer();
        let iocs = IocSet::default();
        let score = zero_score();
        let entropy = empty_entropy();
        let set = RuleSet {
            name: String::new(),
            version: "test".into(),
            rules: vec![crate::rules::Rule {
                id: "noop".into(),
                name: "x".into(),
                severity: crate::rules::Severity::Low,
                description: String::new(),
                match_spec: crate::rules::MatchSpec::default(),
                tags: Vec::new(),
                enabled: true,
            }],
        };
        let c = ctx(&image, &packer, &[], &iocs, &score, &[], &entropy, &[]);
        assert!(evaluate(&set, &c).is_empty());
    }

    #[test]
    fn string_clause_applies_the_same_hygiene_as_technique_inference() {
        // `slmgr.vbs` and `winrm.vbs` were graded high for obfuscation because
        // both carry the Windows Script Host resource helper
        // `GetResource = Eval(name)`. The rule engine used to match raw
        // substrings; it now drops the same strings the technique layer drops.
        let image = base_image();
        let packer = empty_packer();
        let iocs = IocSet::default();
        let score = zero_score();
        let entropy = empty_entropy();
        let set = rules(
            r#"[{"id":"eval","name":"x","severity":"high","match":{"any_strings":["eval("]}}]"#,
        );

        let idiom = vec![ExtractedString {
            offset: 0,
            encoding: Encoding::Ascii,
            length: 24,
            text: "GetResource = Eval(name)".into(),
        }];
        let c = ctx(&image, &packer, &[], &iocs, &score, &idiom, &entropy, &[]);
        assert!(
            evaluate(&set, &c).is_empty(),
            "a WSH resource lookup is not dynamic execution"
        );

        let obfuscated = vec![ExtractedString {
            offset: 0,
            encoding: Encoding::Ascii,
            length: 24,
            text: "eval($_POST['payload'])".into(),
        }];
        let c = ctx(
            &image,
            &packer,
            &[],
            &iocs,
            &score,
            &obfuscated,
            &entropy,
            &[],
        );
        assert_eq!(evaluate(&set, &c).len(), 1);
    }

    #[test]
    fn every_finding_has_evidence() {
        let image = base_image();
        let packer = empty_packer();
        let iocs = IocSet::default();
        let score = zero_score();
        let entropy = empty_entropy();
        let set = crate::rules::builtin().unwrap();
        let c = ctx(&image, &packer, &[], &iocs, &score, &[], &entropy, &[]);
        for finding in evaluate(&set, &c) {
            assert!(
                !finding.evidence.is_empty(),
                "finding {} has no evidence",
                finding.rule_id
            );
        }
    }
}

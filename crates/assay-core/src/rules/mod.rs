//! Declarative detection rules.
//!
//! A rule is a JSON document describing a *conjunction of conditions* over the
//! analysed artefact. The point is not to replace the built-in heuristics —
//! those encode reasoning that is awkward to express as data — but to let an
//! analyst add org-specific policy without recompiling:
//!
//! ```json
//! {
//!   "id": "corp-unsigned-delivery",
//!   "name": "Unsigned PE that talks to the network",
//!   "severity": "high",
//!   "description": "Delivery-stage binaries in our estate are always signed.",
//!   "match": {
//!     "format": ["pe"],
//!     "signed": false,
//!     "min_iocs": 1,
//!     "ioc_kinds": ["url", "ipv4"]
//!   },
//!   "tags": ["delivery"]
//! }
//! ```
//!
//! Every field inside `match` is optional, and omitted fields impose no
//! constraint. `null` and omission are therefore the same thing, which keeps
//! rules readable.

pub mod engine;

use serde::{Deserialize, Serialize};

use crate::error::{AssayError, Result};

/// How bad a match is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Context only.
    Info,
    /// Worth knowing.
    Low,
    /// Should be reviewed.
    Medium,
    /// Should block deployment.
    High,
    /// Treat as hostile.
    Critical,
}

impl Severity {
    /// Stable lowercase label.
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    /// Numeric rank for sorting.
    pub fn rank(self) -> u8 {
        match self {
            Severity::Info => 0,
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
        }
    }
}

/// The condition block of a rule.
///
/// `deny_unknown_fields` is load-bearing, not tidiness. Without it a misspelled
/// clause is silently dropped, the condition set becomes empty, and the rule
/// matches **every** artefact at its stated severity — `min_entrpy` instead of
/// `min_entropy` turned a narrow rule into a blanket high-severity finding. An
/// unknown field is a mistake the author can see and fix; a silently widened
/// match is one they cannot.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatchSpec {
    /// Accepted container formats (`pe`, `elf`, `macho`, `zip`, …).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub format: Vec<String>,
    /// Accepted artefact kinds (`executable`, `shared_library`, …).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub kind: Vec<String>,
    /// Required signature state; `Some(false)` means "must be unsigned".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed: Option<bool>,
    /// Minimum number of indicators that must be present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_iocs: Option<usize>,
    /// Indicator kinds that count toward `min_iocs` (empty means all kinds).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ioc_kinds: Vec<String>,
    /// Minimum packer likelihood (0–100).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_packer: Option<u8>,
    /// Minimum risk score (0–100).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_score: Option<u8>,
    /// At least one of these imported symbols must be present.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub any_imports: Vec<String>,
    /// All of these imported symbols must be present.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub all_imports: Vec<String>,
    /// Maximum number of imported symbols; `0` means "must import nothing".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_imports: Option<usize>,
    /// Required RELRO state (ELF only). `Some(false)` means "must have no RELRO".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relro: Option<bool>,
    /// At least one of these substrings must appear in a recovered string.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub any_strings: Vec<String>,
    /// ATT&CK technique ids; at least one must have been inferred.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub techniques: Vec<String>,
    /// Require TLS callbacks to be present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub has_tls: Option<bool>,
    /// Require the image to be a managed assembly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_dotnet: Option<bool>,
    /// Minimum peak section entropy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_entropy: Option<f64>,
    /// Require this many writable+executable sections at minimum.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_wx_sections: Option<usize>,
    /// Require this many archive entries whose names look executable.
    ///
    /// An archive being a package says nothing about what it carries. Without
    /// this clause `archive-ships-executables` matched every zip, tar, ar and
    /// gzip — including a truncated 12-byte gzip with no entries at all — because
    /// its only conditions were the format and the inferred kind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_executable_entries: Option<usize>,
    /// Require an interpreter or RPATH entry matching any of these substrings.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub loader_paths: Vec<String>,
}

/// One detection rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// Stable identifier, unique within a rule set.
    pub id: String,
    /// Display name.
    pub name: String,
    /// How bad a match is.
    pub severity: Severity,
    /// Why the rule exists.
    #[serde(default)]
    pub description: String,
    /// Conditions. Serialised as `match` so rule files read naturally.
    #[serde(default, rename = "match")]
    pub match_spec: MatchSpec,
    /// Free-form tags for filtering.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Whether the rule is active. Defaults to true when omitted.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_enabled() -> bool {
    true
}

impl Rule {
    /// Validate structural invariants and return a normalised copy.
    pub fn validate(mut self) -> Result<Rule> {
        if self.id.trim().is_empty() {
            return Err(AssayError::InvalidRule {
                id: "<unnamed>".into(),
                detail: "id must not be empty".into(),
            });
        }
        if self.id.len() > 128 {
            return Err(AssayError::InvalidRule {
                id: self.id.clone(),
                detail: "id is longer than 128 characters".into(),
            });
        }
        if !self
            .id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
        {
            return Err(AssayError::InvalidRule {
                id: self.id.clone(),
                detail: "id may only contain ASCII alphanumerics, `-`, `_` and `.`".into(),
            });
        }
        if self.name.trim().is_empty() {
            self.name = self.id.clone();
        }
        if self
            .match_spec
            .min_entropy
            .is_some_and(|e| !(0.0..=8.0).contains(&e))
        {
            return Err(AssayError::InvalidRule {
                id: self.id,
                detail: "min_entropy must be within 0.0–8.0".into(),
            });
        }
        if self.match_spec.min_score.is_some_and(|s| s > 100) {
            return Err(AssayError::InvalidRule {
                id: self.id,
                detail: "min_score must be within 0–100".into(),
            });
        }
        if self.match_spec.min_packer.is_some_and(|p| p > 100) {
            return Err(AssayError::InvalidRule {
                id: self.id,
                detail: "min_packer must be within 0–100".into(),
            });
        }
        // A rule with no conditions fires on every artefact at its stated
        // severity. That is never what the author meant, and `rules validate`
        // silently accepting one turned a typo into a blanket detection.
        if self.is_unconditional() {
            return Err(AssayError::InvalidRule {
                id: self.id,
                detail: "no conditions: this rule would match every artefact, so it is \
                         rejected rather than shipped"
                    .into(),
            });
        }
        Ok(self)
    }

    /// True when the rule imposes no condition at all, in which case it would
    /// fire on every artefact and is almost certainly a mistake.
    pub fn is_unconditional(&self) -> bool {
        let m = &self.match_spec;
        m.format.is_empty()
            && m.kind.is_empty()
            && m.signed.is_none()
            && m.min_iocs.is_none()
            && m.ioc_kinds.is_empty()
            && m.min_packer.is_none()
            && m.min_score.is_none()
            && m.any_imports.is_empty()
            && m.all_imports.is_empty()
            && m.max_imports.is_none()
            && m.relro.is_none()
            && m.any_strings.is_empty()
            && m.techniques.is_empty()
            && m.has_tls.is_none()
            && m.is_dotnet.is_none()
            && m.min_entropy.is_none()
            && m.min_wx_sections.is_none()
            && m.min_executable_entries.is_none()
            && m.loader_paths.is_empty()
    }
}

/// A named collection of rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleSet {
    /// Human-readable set name.
    #[serde(default)]
    pub name: String,
    /// Rule version, for provenance.
    #[serde(default)]
    pub version: String,
    /// The rules.
    pub rules: Vec<Rule>,
}

impl RuleSet {
    /// Parse a rule set from JSON, reporting the first invalid rule.
    pub fn from_json(json: &str) -> Result<RuleSet> {
        // Accept both `{ "rules": [...] }` and a bare `[...]`.
        let trimmed = json.trim_start();
        if trimmed.starts_with('[') {
            let rules: Vec<Rule> =
                serde_json::from_str(json).map_err(|e| AssayError::InvalidRule {
                    id: "<file>".into(),
                    detail: format!("not valid rule JSON: {e}"),
                })?;
            return Ok(RuleSet {
                name: "custom".into(),
                version: String::new(),
                rules: rules
                    .into_iter()
                    .map(Rule::validate)
                    .collect::<Result<Vec<_>>>()?,
            });
        }

        let set: RuleSet = serde_json::from_str(json).map_err(|e| AssayError::InvalidRule {
            id: "<file>".into(),
            detail: format!("not valid rule JSON: {e}"),
        })?;
        let mut validated = Vec::with_capacity(set.rules.len());
        for rule in set.rules {
            validated.push(rule.validate()?);
        }
        Ok(RuleSet {
            name: set.name,
            version: set.version,
            rules: validated,
        })
    }

    /// Rules that will actually run.
    pub fn active(&self) -> impl Iterator<Item = &Rule> {
        self.rules.iter().filter(|r| r.enabled)
    }

    /// Detect duplicate ids, which would make findings ambiguous.
    pub fn duplicate_ids(&self) -> Vec<String> {
        let mut seen = std::collections::HashSet::new();
        let mut dups = Vec::new();
        for r in &self.rules {
            if !seen.insert(r.id.as_str()) {
                dups.push(r.id.clone());
            }
        }
        dups
    }
}

/// The built-in rule set, embedded at compile time.
///
/// Keeping it as a `&str` (rather than generated code) means users can read the
/// exact logic that produced a finding, and can copy it as a starting point.
pub const BUILTIN_RULES_JSON: &str = include_str!("../../../../rules/builtin.json");

/// Load the built-in rules.
pub fn builtin() -> Result<RuleSet> {
    RuleSet::from_json(BUILTIN_RULES_JSON)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bare_array() {
        let json = r#"[
            {"id":"r1","name":"Rule one","severity":"high","match":{"format":["pe"]}}
        ]"#;
        let set = RuleSet::from_json(json).unwrap();
        assert_eq!(set.rules.len(), 1);
        assert_eq!(set.rules[0].severity, Severity::High);
        assert!(set.rules[0].enabled);
    }

    #[test]
    fn parses_wrapped_set() {
        let json = r#"{
            "name":"corp",
            "version":"1.0",
            "rules":[
                {"id":"r1","name":"Rule one","severity":"low","match":{"signed":false}}
            ]
        }"#;
        let set = RuleSet::from_json(json).unwrap();
        assert_eq!(set.name, "corp");
        assert_eq!(set.rules.len(), 1);
    }

    #[test]
    fn rejects_empty_id() {
        let json = r#"[{"id":"","name":"x","severity":"low","match":{"format":["pe"]}}]"#;
        assert!(RuleSet::from_json(json).is_err());
    }

    #[test]
    fn rejects_bad_id_characters() {
        let json = r#"[{"id":"bad id!","name":"x","severity":"low","match":{"format":["pe"]}}]"#;
        assert!(RuleSet::from_json(json).is_err());
    }

    #[test]
    fn rejects_out_of_range_entropy() {
        let json = r#"[{"id":"r","name":"x","severity":"low","match":{"min_entropy":9.5}}]"#;
        assert!(RuleSet::from_json(json).is_err());
    }

    #[test]
    fn rejects_unconditional_rule() {
        // A rule with no conditions matches every artefact at its stated
        // severity, so it is refused at load time rather than shipped. Before
        // this, `rules validate` accepted `"match": {}` and the resulting rule
        // flagged the entire corpus.
        let json = r#"[{"id":"r","name":"x","severity":"low","match":{}}]"#;
        assert!(RuleSet::from_json(json).is_err());
    }

    #[test]
    fn rejects_a_misspelled_clause() {
        // The dangerous failure is silent: serde would drop an unknown key, the
        // condition set would become empty, and the rule would match everything.
        let json = r#"[{"id":"r","name":"x","severity":"low","match":{"min_entrpy":7.0}}]"#;
        let error = RuleSet::from_json(json).unwrap_err().to_string();
        assert!(
            error.contains("min_entrpy"),
            "the error must name the offending field: {error}"
        );
    }

    #[test]
    fn duplicate_ids_are_reported() {
        let json = r#"[
            {"id":"dup","name":"a","severity":"low","match":{"format":["pe"]}},
            {"id":"dup","name":"b","severity":"low","match":{"format":["elf"]}}
        ]"#;
        let set = RuleSet::from_json(json).unwrap();
        assert_eq!(set.duplicate_ids(), vec!["dup"]);
    }

    #[test]
    fn disabled_rules_are_filtered() {
        let json = r#"[
            {"id":"a","name":"a","severity":"low","enabled":false,"match":{"format":["pe"]}},
            {"id":"b","name":"b","severity":"low","match":{"format":["pe"]}}
        ]"#;
        let set = RuleSet::from_json(json).unwrap();
        assert_eq!(set.active().count(), 1);
    }

    #[test]
    fn severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }

    #[test]
    fn builtin_rules_load_and_validate() {
        let set = builtin().expect("built-in rules must parse");
        assert!(!set.rules.is_empty(), "built-in set must not be empty");
        assert!(
            set.duplicate_ids().is_empty(),
            "built-in ids must be unique"
        );
        for rule in &set.rules {
            assert!(
                !rule.is_unconditional(),
                "rule `{}` has no conditions and would fire on everything",
                rule.id
            );
        }
    }
}

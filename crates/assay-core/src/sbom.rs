//! CycloneDX SBOM synthesis.
//!
//! Imports are the closest thing a compiled binary has to a dependency list, so
//! that is what we emit: one component per imported library, with the imported
//! symbol count as a property and the section digests as component hashes. The
//! goal is that `assay sbom app.exe > bom.json` produces a document a real SBOM
//! consumer accepts, not a bespoke JSON that only Assay can read.
//!
//! Deliberate omission: no version numbers are invented. A PE import table does
//! not record which version of `kernel32.dll` a binary was linked against, and
//! guessing from the timestamp would be fabrication. Components carry
//! `version: "unknown"` and a property explaining why.

use serde::{Deserialize, Serialize};

use crate::bytes::to_hex;
use crate::format::BinaryImage;
use crate::hash::sha256;

/// Tool identity block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tool {
    /// Vendor name.
    pub vendor: String,
    /// Tool name.
    pub name: String,
    /// Tool version.
    pub version: String,
}

/// CycloneDX property (free-form key/value).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Property {
    /// Property name, conventionally namespaced.
    pub name: String,
    /// Property value.
    pub value: String,
}

/// CycloneDX hash entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BomHash {
    /// Algorithm name (`SHA-256`).
    pub alg: String,
    /// Hex digest.
    pub content: String,
}

/// CycloneDX component.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Component {
    /// Component type (`library`, `application`, `file`).
    #[serde(rename = "type")]
    pub comp_type: String,
    /// Stable reference within this document.
    #[serde(rename = "bom-ref")]
    pub bom_ref: String,
    /// Component name.
    pub name: String,
    /// Component version, `unknown` when the container does not record one.
    pub version: String,
    /// Package URL when one can be formed meaningfully.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purl: Option<String>,
    /// Hashes over the component's bytes, when known.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub hashes: Vec<BomHash>,
    /// Free-form properties.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub properties: Vec<Property>,
}

/// Document metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metadata {
    /// ISO-8601 UTC timestamp.
    pub timestamp: String,
    /// Tools that produced the document.
    pub tools: Vec<Tool>,
    /// The artefact the BOM describes.
    pub component: Component,
}

/// A complete CycloneDX BOM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bom {
    /// Always `CycloneDX`.
    #[serde(rename = "bomFormat")]
    pub bom_format: String,
    /// Spec version this document targets.
    #[serde(rename = "specVersion")]
    pub spec_version: String,
    /// Unique document identifier.
    #[serde(rename = "serialNumber")]
    pub serial_number: String,
    /// Document revision.
    pub version: u32,
    /// Document metadata.
    pub metadata: Metadata,
    /// Discovered components.
    pub components: Vec<Component>,
}

/// Build a BOM for one artefact.
///
/// `artefact_name` and `digest` describe the file itself; `digest` should be the
/// SHA-256 of the whole file, hex encoded.
pub fn build(image: &BinaryImage, artefact_name: &str, digest: &str, tool_version: &str) -> Bom {
    let timestamp = iso8601_now();

    let root = Component {
        comp_type: match image.kind {
            crate::format::BinaryKind::Executable => "application".into(),
            crate::format::BinaryKind::SharedLibrary => "library".into(),
            crate::format::BinaryKind::Driver => "operating-system".into(),
            crate::format::BinaryKind::Package => "container".into(),
            crate::format::BinaryKind::Script => "file".into(),
            _ => "file".into(),
        },
        bom_ref: format!("assay:root:{digest}"),
        name: artefact_name.to_string(),
        version: "unknown".into(),
        purl: None,
        hashes: if digest.is_empty() {
            Vec::new()
        } else {
            vec![BomHash {
                alg: "SHA-256".into(),
                content: digest.to_string(),
            }]
        },
        properties: vec![
            Property {
                name: "assay:format".into(),
                value: image.format.as_str().to_string(),
            },
            Property {
                name: "assay:architecture".into(),
                value: image.arch.label().to_string(),
            },
            Property {
                name: "assay:bitness".into(),
                value: image.bitness.to_string(),
            },
            Property {
                name: "assay:section-count".into(),
                value: image.sections.len().to_string(),
            },
        ],
    };

    // One component per supplying library, with an aggregate symbol count.
    let mut by_library: std::collections::BTreeMap<String, (usize, usize)> =
        std::collections::BTreeMap::new();
    for import in &image.imports {
        let key = import.library.to_ascii_lowercase();
        let entry = by_library.entry(key).or_insert((0, 0));
        entry.0 += 1;
        if import.delayed {
            entry.1 += 1;
        }
    }

    let mut components: Vec<Component> = Vec::with_capacity(by_library.len());
    for (library, (symbols, delayed)) in by_library {
        let mut properties = vec![Property {
            name: "assay:imported-symbol-count".into(),
            value: symbols.to_string(),
        }];
        if delayed > 0 {
            properties.push(Property {
                name: "assay:delayed-imports".into(),
                value: delayed.to_string(),
            });
        }
        properties.push(Property {
            name: "assay:version-note".into(),
            value: "import tables do not record library versions; reported as unknown rather than guessed"
                .into(),
        });

        components.push(Component {
            comp_type: "library".into(),
            bom_ref: format!("assay:lib:{library}"),
            name: library.clone(),
            version: "unknown".into(),
            purl: purl_for(&library),
            hashes: Vec::new(),
            properties,
        });
    }

    // Resources that carry bytes get their own components with real hashes.
    for resource in image.resources.iter().take(256) {
        if resource.size == 0 || resource.sha256.is_empty() {
            continue;
        }
        components.push(Component {
            comp_type: "file".into(),
            bom_ref: format!(
                "assay:resource:{}:{}:{}",
                resource.kind, resource.name, resource.file_offset
            ),
            name: format!("{}:{}", resource.kind, resource.name),
            version: "unknown".into(),
            purl: None,
            hashes: vec![BomHash {
                alg: "SHA-256".into(),
                content: resource.sha256.clone(),
            }],
            properties: vec![
                Property {
                    name: "assay:resource-size".into(),
                    value: resource.size.to_string(),
                },
                Property {
                    name: "assay:resource-offset".into(),
                    value: format!("{:#x}", resource.file_offset),
                },
            ],
        });
    }

    Bom {
        bom_format: "CycloneDX".into(),
        spec_version: "1.5".into(),
        // Derived from the digest alone, deliberately.
        //
        // CycloneDX says every BOM *should* carry a unique serial even when the
        // contents are identical, which argues for mixing in the wall clock. This
        // tool's premise is the opposite: the same bytes and the same version must
        // produce the same document, or a pipeline cannot tell "the artefact
        // changed" from "the clock moved". The timestamp stays in `metadata` where
        // it is informative but does not perturb identity.
        serial_number: format!("urn:uuid:{}", uuid_from(digest, b"assay-sbom-v1")),
        version: 1,
        metadata: Metadata {
            timestamp,
            tools: vec![Tool {
                vendor: "Assay".into(),
                name: "assay".into(),
                version: tool_version.to_string(),
            }],
            component: root,
        },
        components,
    }
}

/// Serialise a BOM as pretty-printed JSON.
pub fn to_json(bom: &Bom) -> crate::Result<String> {
    serde_json::to_string_pretty(bom).map_err(|e| crate::error::AssayError::Unsupported {
        what: "sbom",
        detail: format!("could not serialise BOM: {e}"),
    })
}

fn purl_for(library: &str) -> Option<String> {
    if library.is_empty() {
        return None;
    }
    // Install names on macOS/ELF are frequently absolute paths; a purl must be
    // a package identity, so reduce to the basename first.
    let base = library.rsplit(['/', '\\']).next().unwrap_or(library);
    if base.is_empty() {
        return None;
    }
    if base.ends_with(".dll") || base.ends_with(".exe") || base.ends_with(".dylib") {
        Some(format!("pkg:generic/{base}"))
    } else if base.starts_with("lib") && base.contains(".so") {
        let stem = base.split(".so").next().unwrap_or(base);
        Some(format!("pkg:generic/{stem}"))
    } else {
        None
    }
}

/// Derive a deterministic RFC-4122-shaped identifier from inputs.
///
/// Not cryptographic: it exists so repeated runs over the same input produce the
/// same `serialNumber`, which keeps diffs between BOMs meaningful.
fn uuid_from(a: &str, b: &[u8]) -> String {
    let mut input = Vec::with_capacity(a.len() + b.len() + 1);
    input.extend_from_slice(a.as_bytes());
    input.push(0);
    input.extend_from_slice(b);
    let digest = sha256(&input);
    let hex = to_hex(&digest[..16]);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

/// Current time as `YYYY-MM-DDTHH:MM:SSZ`, computed without external crates.
pub fn iso8601_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y,
        m,
        d,
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Civil date from days since the Unix epoch (Howard Hinnant's algorithm).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::{
        Architecture, BinaryImage, BinaryKind, Endianness, Format, ImportEntry, ResourceEntry,
    };

    fn sample_image() -> BinaryImage {
        let mut image = BinaryImage::placeholder(Format::Pe);
        image.kind = BinaryKind::Executable;
        image.arch = Architecture::X86_64;
        image.endian = Endianness::Little;
        image.bitness = 64;
        image.imports = vec![
            ImportEntry {
                library: "KERNEL32.dll".into(),
                symbol: "CreateFileA".into(),
                ordinal: None,
                hint: None,
                delayed: false,
            },
            ImportEntry {
                library: "user32.dll".into(),
                symbol: "MessageBoxA".into(),
                ordinal: None,
                hint: None,
                delayed: false,
            },
            ImportEntry {
                library: "user32.dll".into(),
                symbol: "GetDC".into(),
                ordinal: None,
                hint: None,
                delayed: true,
            },
        ];
        image.resources.push(ResourceEntry {
            kind: "RT_MANIFEST".into(),
            name: "1".into(),
            language: Some("1033".into()),
            file_offset: 0x400,
            size: 128,
            sha256: "ab".repeat(32),
        });
        image
    }

    #[test]
    fn bom_has_required_fields() {
        let bom = build(&sample_image(), "app.exe", &"cd".repeat(32), "0.1.0");
        assert_eq!(bom.bom_format, "CycloneDX");
        assert_eq!(bom.spec_version, "1.5");
        assert!(bom.serial_number.starts_with("urn:uuid:"));
        assert_eq!(bom.version, 1);
        assert!(bom.metadata.timestamp.ends_with('Z'));
    }

    #[test]
    fn one_component_per_library() {
        let bom = build(&sample_image(), "app.exe", "", "0.1.0");
        let libs: Vec<&str> = bom
            .components
            .iter()
            .filter(|c| c.comp_type == "library")
            .map(|c| c.name.as_str())
            .collect();
        assert_eq!(libs.len(), 2);
        assert!(libs.contains(&"kernel32.dll"));
    }

    #[test]
    fn delayed_imports_are_recorded() {
        let bom = build(&sample_image(), "app.exe", "", "0.1.0");
        let user32 = bom
            .components
            .iter()
            .find(|c| c.name == "user32.dll")
            .unwrap();
        assert!(user32
            .properties
            .iter()
            .any(|p| p.name == "assay:delayed-imports"));
    }

    #[test]
    fn version_is_unknown_not_invented() {
        let bom = build(&sample_image(), "app.exe", "", "0.1.0");
        for c in &bom.components {
            assert_eq!(c.version, "unknown");
        }
    }

    #[test]
    fn resources_become_file_components() {
        let bom = build(&sample_image(), "app.exe", "", "0.1.0");
        assert!(bom.components.iter().any(|c| c.comp_type == "file"));
    }

    #[test]
    fn serial_number_is_deterministic() {
        // The build takes its timestamp from the wall clock, so this assertion used
        // to hold only because both calls landed in the same second. The serial is
        // now derived from the digest alone, which makes the property real rather
        // than a coincidence — and makes a BOM diff mean "the artefact changed".
        let a = build(&sample_image(), "app.exe", &"ef".repeat(32), "0.1.0");
        let b = build(&sample_image(), "app.exe", &"ef".repeat(32), "0.1.0");
        assert_eq!(a.serial_number, b.serial_number);

        // A different file must not inherit the identifier.
        let other = build(&sample_image(), "app.exe", &"aa".repeat(32), "0.1.0");
        assert_ne!(a.serial_number, other.serial_number);
    }

    #[test]
    fn json_round_trips() {
        let bom = build(&sample_image(), "app.exe", &"aa".repeat(32), "0.1.0");
        let json = to_json(&bom).expect("serialise");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("parse");
        assert_eq!(parsed["bomFormat"], "CycloneDX");
        assert!(parsed["components"].is_array());
    }

    #[test]
    fn purl_generation_is_conservative() {
        assert_eq!(
            purl_for("kernel32.dll").as_deref(),
            Some("pkg:generic/kernel32.dll")
        );
        assert_eq!(
            purl_for("libssl.so.3").as_deref(),
            Some("pkg:generic/libssl")
        );
        assert_eq!(
            purl_for("/usr/lib/libz.dylib").as_deref(),
            Some("pkg:generic/libz.dylib")
        );
        assert!(purl_for("").is_none());
    }

    #[test]
    fn civil_dates_are_correct() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(10_957), (2000, 1, 1));
        assert_eq!(civil_from_days(19_782), (2024, 2, 29));
    }
}

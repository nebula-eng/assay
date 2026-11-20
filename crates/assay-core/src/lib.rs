//! # Assay — static supply-chain analysis engine
//!
//! Assay dissects a compiled artefact and answers the questions a defender
//! actually asks: *what is this, what can it do, where does it point, and how
//! much should I trust it* — entirely offline, without executing the sample.
//!
//! ## What it does
//!
//! * Parses **PE**, **ELF**, **Mach-O**, **ar**, **zip/jar/apk/wheel**, **tar**
//!   and **gzip** containers down to their tables — imports, exports, sections,
//!   resources, debug artefacts and signature blobs — with hand-written parsers
//!   that never trust an attacker-controlled length.
//! * Measures **entropy** with a sliding window, so high-entropy regions are
//!   located rather than merely averaged.
//! * Recovers **strings** in ASCII and both UTF-16 byte orders, then extracts
//!   **indicators** — URLs, domains, addresses, wallet identifiers, onion
//!   services, registry keys — with a confidence attached to each.
//! * Scores **packing** from fused signature and heuristic evidence.
//! * Maps the import set onto **MITRE ATT&CK** techniques, using combinations
//!   rather than single-API greps.
//! * Produces a **composite risk score** whose every point is attributable.
//! * Emits a **CycloneDX SBOM** so the result plugs into existing supply-chain
//!   tooling.
//!
//! ## What it deliberately does not do
//!
//! * It never executes, emulates or sandboxes the artefact.
//! * It never decompresses archives — enumeration stops at the container tables,
//!   which is where decompression-bomb and traversal attacks live.
//! * It does not verify cryptographic signatures. It reports which algorithm a
//!   signature names and which identity the certificate claims; establishing
//!   *trust* requires the platform verifier and a trust store, and pretending
//!   otherwise would be the most dangerous kind of wrong.
//! * It does not disassemble. Capability inference works from the import table
//!   and string evidence, which is weaker than full analysis and is labelled as
//!   such in the output.
//!
//! ## Example
//!
//! ```no_run
//! use assay_core::{analyze_path, AnalyzeOptions};
//! use std::path::Path;
//!
//! let report = analyze_path(Path::new("sample.exe"), &AnalyzeOptions::default())
//!     .expect("read the file");
//! println!("{}", report.summary());
//! for finding in &report.findings {
//!     println!("[{}] {}", finding.severity.as_str(), finding.rule_name);
//! }
//! ```
//!
//! ## Design constraints
//!
//! * **Total functions.** No parser panics on malformed input; a broken header
//!   yields a diagnostic, not an abort. The fuzz test in
//!   [`analysis`] asserts this over thousands of synthetic buffers.
//! * **Bounded memory.** Every loop that walks an attacker-controlled count has
//!   an explicit cap, listed next to the constant.
//! * **Attributable output.** A score, a technique, or a finding that cannot
//!   point at the bytes that produced it is a bug.
//! * **No hidden I/O.** The engine reads the file it was given and nothing else:
//!   no network, no reputation lookup, no external database. Reproducibility is
//!   a feature.

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]
#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod analysis;
pub mod asn1;
pub mod bytes;
pub mod error;
pub mod format;
pub mod fuzzy;
pub mod hash;
pub mod report;
pub mod rules;
pub mod sbom;

pub use analysis::{analyze_bytes, analyze_path, AnalyzeOptions};
pub use error::{AssayError, Result};
pub use report::Report;

/// The crate version, as recorded in every report.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Parse a file's bytes into the unified image model without running the full
/// analysis pipeline.
///
/// Useful when a caller only needs the structural view — for example a package
/// browser that wants section tables but no scoring.
pub fn parse_only(data: &[u8]) -> Result<format::BinaryImage> {
    let detected = format::detect::detect(data, None);
    match detected.format {
        format::Format::Pe => Ok(format::pe::PeFile::parse(data)?.image),
        format::Format::Elf => Ok(format::elf::ElfFile::parse(data)?.image),
        format::Format::MachO => Ok(format::macho::MachOFile::parse(data)?.image),
        format::Format::Zip => Ok(format::archive::parse_zip(data)?.image),
        format::Format::Ar => Ok(format::archive::parse_ar(data)?.image),
        format::Format::Tar => Ok(format::archive::parse_tar(data)?.image),
        format::Format::Gzip => Ok(format::archive::parse_gzip(data)?.image),
        other => Err(AssayError::unsupported(
            "container",
            format!("no structural parser for `{}`", other.as_str()),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_recorded() {
        assert!(!VERSION.is_empty());
    }

    #[test]
    fn parse_only_rejects_unknown() {
        assert!(parse_only(&[0u8; 32]).is_err());
    }

    #[test]
    fn public_api_is_reachable() {
        let report = analyze_bytes(&[0u8; 64], "x", &AnalyzeOptions::fast());
        assert_eq!(report.schema_version, report::SCHEMA_VERSION);
        assert!(report.to_json().is_ok());
    }
}

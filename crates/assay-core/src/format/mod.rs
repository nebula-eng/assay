//! Container formats and the unified model every parser lowers into.
//!
//! A PE, an ELF and a Mach-O agree on almost nothing at the byte level, yet a
//! security analyst asks the same five questions of all of them: *what is this,
//! what does it import, what does it ship, how is it laid out, and who built
//! it*. [`BinaryImage`] is that common answer. Anything format-specific that
//! does not fit the model lives in [`FormatMetadata`], so the generic analysis
//! passes stay honest instead of accumulating `if format == Pe` branches.

pub mod archive;
pub mod detect;
pub mod elf;
pub mod macho;
pub mod pe;

use serde::{Deserialize, Serialize};

/// Container family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    /// Windows Portable Executable (`MZ` … `PE\0\0`).
    Pe,
    /// Unix Executable and Linkable Format.
    Elf,
    /// Apple Mach-O, thin or fat.
    MachO,
    /// `ar` archive, `.a`, `.lib`, Debian `.deb`.
    Ar,
    /// Zip container: `.zip`, `.jar`, `.apk`, `.whl`, `.nupkg`, `.vsix`.
    Zip,
    /// Gzip stream.
    Gzip,
    /// Tar archive.
    Tar,
    /// Plain text script (shell, Python, PowerShell, JavaScript).
    Script,
    /// Raw bytes we could not classify further.
    Unknown,
}

impl Format {
    /// Stable lowercase identifier used in JSON output and rule files.
    pub fn as_str(self) -> &'static str {
        match self {
            Format::Pe => "pe",
            Format::Elf => "elf",
            Format::MachO => "macho",
            Format::Ar => "ar",
            Format::Zip => "zip",
            Format::Gzip => "gzip",
            Format::Tar => "tar",
            Format::Script => "script",
            Format::Unknown => "unknown",
        }
    }
}

/// What role the artefact plays, inferred from container headers and mode bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BinaryKind {
    /// Runnable program.
    Executable,
    /// Loadable library (`.dll`, `.so`, `.dylib`).
    SharedLibrary,
    /// Static library or relocatable object.
    Object,
    /// Managed bytecode assembly (.NET, Java class).
    ManagedAssembly,
    /// Installer or self-extracting package.
    Installer,
    /// Device driver.
    Driver,
    /// Interpreter script.
    Script,
    /// Data package (zip/apk/jar/wheel).
    Package,
    /// Unclassified.
    Other,
}

/// Instruction set architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Architecture {
    /// x86 32-bit.
    X86,
    /// x86-64 / AMD64.
    X86_64,
    /// ARM 32-bit.
    Arm,
    /// AArch64.
    Arm64,
    /// RISC-V 32/64.
    RiscV,
    /// PowerPC.
    PowerPc,
    /// MIPS.
    Mips,
    /// WebAssembly.
    Wasm,
    /// .NET CIL / Java bytecode (architecture independent).
    Bytecode,
    /// Could not be determined.
    Unknown,
}

impl Architecture {
    /// Human readable label for the UI.
    pub fn label(self) -> &'static str {
        match self {
            Architecture::X86 => "x86",
            Architecture::X86_64 => "x86-64",
            Architecture::Arm => "ARM",
            Architecture::Arm64 => "ARM64",
            Architecture::RiscV => "RISC-V",
            Architecture::PowerPc => "PowerPC",
            Architecture::Mips => "MIPS",
            Architecture::Wasm => "WebAssembly",
            Architecture::Bytecode => "Bytecode",
            Architecture::Unknown => "unknown",
        }
    }
}

/// Byte order of multi-byte fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Endianness {
    /// Least significant byte first.
    Little,
    /// Most significant byte first.
    Big,
}

/// Memory protection flags derived from section characteristics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Permissions {
    /// Section can be read.
    pub read: bool,
    /// Section can be written at runtime.
    pub write: bool,
    /// Section contains executable code.
    pub execute: bool,
}

impl Permissions {
    /// Construct from three booleans.
    pub fn new(read: bool, write: bool, execute: bool) -> Self {
        Permissions {
            read,
            write,
            execute,
        }
    }

    /// Compact `rwx`-style rendering; `-` marks an absent bit.
    pub fn render(&self) -> String {
        format!(
            "{}{}{}",
            if self.read { 'r' } else { '-' },
            if self.write { 'w' } else { '-' },
            if self.execute { 'x' } else { '-' }
        )
    }

    /// A section that is both writable and executable defeats W^X and is one of
    /// the strongest single-file indicators of unpacking stubs and shellcode
    /// staging.
    pub fn is_wx(&self) -> bool {
        self.write && self.execute
    }
}

/// One mapped region of the image.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionInfo {
    /// Section name as stored (truncated to 8 bytes on PE).
    pub name: String,
    /// Virtual address (RVA on PE, `sh_addr` on ELF).
    pub virtual_address: u64,
    /// Size in memory.
    pub virtual_size: u64,
    /// File offset of the backing bytes.
    pub file_offset: u64,
    /// Number of bytes present in the file.
    pub file_size: u64,
    /// Shannon entropy of the backing bytes, in bits per byte.
    pub entropy: f64,
    /// Memory protection flags.
    pub permissions: Permissions,
    /// SHA-256 of the backing bytes (hex). Empty when the section has no bytes.
    pub sha256: String,
    /// Raw characteristics/type word from the format, kept for rule matching.
    pub raw_characteristics: u64,
}

/// A symbol the image expects to resolve at load time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportEntry {
    /// Providing library (`kernel32.dll`, `libc.so.6`).
    pub library: String,
    /// Symbol name; empty when imported by ordinal only.
    pub symbol: String,
    /// Ordinal, when the import uses one.
    pub ordinal: Option<u16>,
    /// Hint/ordinal value or GOT slot, when known.
    pub hint: Option<u16>,
    /// Whether the import is resolved lazily (delay-load / PLT).
    pub delayed: bool,
}

impl ImportEntry {
    /// `library!symbol` rendering used in findings and SBOM component ids.
    pub fn qualified(&self) -> String {
        if self.symbol.is_empty() {
            match self.ordinal {
                Some(o) => format!("{}!#{o}", self.library),
                None => self.library.clone(),
            }
        } else {
            format!("{}!{}", self.library, self.symbol)
        }
    }
}

/// A symbol the image offers to others.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportEntry {
    /// Exported name; empty when exported by ordinal only.
    pub name: String,
    /// Ordinal assigned by the linker.
    pub ordinal: Option<u32>,
    /// RVA/address of the exported symbol.
    pub address: u64,
    /// True when the export is a forwarder (`NTDLL.RtlAllocateHeap`).
    pub forwarded_to: Option<String>,
}

/// A shipped resource, flattened from whatever tree the container uses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceEntry {
    /// Resource type (`RT_ICON`, `MANIFEST`, `10` for `RCDATA`).
    pub kind: String,
    /// Resource name or numeric id.
    pub name: String,
    /// Language/locale identifier when the format carries one.
    pub language: Option<String>,
    /// File offset of the payload.
    pub file_offset: u64,
    /// Payload length in bytes.
    pub size: u64,
    /// SHA-256 of the payload.
    pub sha256: String,
}

/// A build-system pointer recovered from the image.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugArtifact {
    /// Artifact type (`pdb`, `dwarf`, `build-id`, `linker-version`).
    pub kind: String,
    /// Value, e.g. the PDB path or build id hex.
    pub value: String,
    /// Confidence that this is a genuine build artefact rather than a decoy.
    pub trusted: bool,
}

/// A digital signature blob attached to the image.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureInfo {
    /// Where the signature is stored (`authenticode`, `codesign`, `none`).
    pub scheme: String,
    /// Whether a blob is present at all.
    pub present: bool,
    /// Signer common name, when the certificate chain could be decoded.
    pub signer: Option<String>,
    /// Issuer common name.
    pub issuer: Option<String>,
    /// Digest algorithm named by the signature (`sha256`, `sha1`, `md5`).
    pub digest_algorithm: Option<String>,
    /// Not-before / not-after as Unix seconds.
    pub valid_from: Option<i64>,
    /// Not-after date as Unix seconds.
    pub valid_to: Option<i64>,
    /// True when a countersignature timestamp is present.
    pub timestamped: bool,
    /// Problems found while inspecting the signature.
    pub issues: Vec<String>,
    /// SHA-256 over the raw signature blob.
    pub blob_sha256: String,
}

impl SignatureInfo {
    /// A signature slot that exists structurally but carries no blob.
    pub fn absent() -> Self {
        SignatureInfo {
            scheme: "none".into(),
            present: false,
            signer: None,
            issuer: None,
            digest_algorithm: None,
            valid_from: None,
            valid_to: None,
            timestamped: false,
            issues: Vec::new(),
            blob_sha256: String::new(),
        }
    }
}

/// Format-specific facts that do not generalise.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "format", rename_all = "lowercase")]
pub enum FormatMetadata {
    /// Windows-specific header facts.
    Pe(pe::PeMetadata),
    /// ELF-specific header facts.
    Elf(elf::ElfMetadata),
    /// Mach-O-specific header facts.
    MachO(macho::MachOMetadata),
    /// Archive/package facts.
    Archive(archive::ArchiveMetadata),
    /// Nothing format-specific.
    None,
}

/// The unified view of one analysed container.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryImage {
    /// Container family.
    pub format: Format,
    /// Inferred role.
    pub kind: BinaryKind,
    /// Instruction set.
    pub arch: Architecture,
    /// Byte order.
    pub endian: Endianness,
    /// 32 or 64, or 0 when not meaningful (bytecode, scripts).
    pub bitness: u8,
    /// Entry point address, virtual.
    pub entry_point: Option<u64>,
    /// Preferred load address.
    pub image_base: u64,
    /// Mapped regions.
    pub sections: Vec<SectionInfo>,
    /// Imported symbols.
    pub imports: Vec<ImportEntry>,
    /// Exported symbols.
    pub exports: Vec<ExportEntry>,
    /// Shipped resources.
    pub resources: Vec<ResourceEntry>,
    /// Build-system artefacts.
    pub debug_artifacts: Vec<DebugArtifact>,
    /// Signature material.
    pub signature: SignatureInfo,
    /// Structural anomalies worth surfacing even before rules run.
    pub structural_notes: Vec<String>,
    /// Tables the parser knew about but could not read, with the reason.
    ///
    /// Distinct from `structural_notes` on purpose. A note states an observation
    /// ("no PT_GNU_RELRO, so the GOT stays writable"); this states an epistemic
    /// limit ("the segment table starts past the end of the file, so nothing
    /// about the segment table is known"). Collapsing the two is how a truncated
    /// ELF ends up reported as unhardened rather than unreadable.
    pub unreadable_tables: Vec<String>,
    /// Format-specific extras.
    pub metadata: FormatMetadata,
}

impl BinaryImage {
    /// An empty image for a format we recognised but could not decode.
    pub fn placeholder(format: Format) -> Self {
        BinaryImage {
            format,
            kind: BinaryKind::Other,
            arch: Architecture::Unknown,
            endian: Endianness::Little,
            bitness: 0,
            entry_point: None,
            image_base: 0,
            sections: Vec::new(),
            imports: Vec::new(),
            exports: Vec::new(),
            resources: Vec::new(),
            debug_artifacts: Vec::new(),
            signature: SignatureInfo::absent(),
            structural_notes: Vec::new(),
            unreadable_tables: Vec::new(),
            metadata: FormatMetadata::None,
        }
    }

    /// Distinct supplying libraries, sorted, deduplicated.
    pub fn libraries(&self) -> Vec<String> {
        let mut libs: Vec<String> = self
            .imports
            .iter()
            .map(|i| i.library.to_ascii_lowercase())
            .collect();
        libs.sort();
        libs.dedup();
        libs
    }
    /// Highest single-section entropy, ignoring sections with no bytes.
    pub fn max_section_entropy(&self) -> f64 {
        self.sections
            .iter()
            .filter(|s| s.file_size >= 256)
            .map(|s| s.entropy)
            .fold(0.0f64, f64::max)
    }

    /// True when this looks like a platform library rather than an application
    /// or a payload.
    ///
    /// The test is deliberately blunt: a module that both **provides** and
    /// **consumes** a large API surface is infrastructure. `kernel32.dll` exports
    /// 1 697 symbols and imports 1 292; `advapi32.dll` exports 854 and imports
    /// 786. Malware minimises its export table — a loader usually exports
    /// nothing at all — so this shape is not something a payload imitates.
    ///
    /// The distinction matters because capability inference asks "does this
    /// module *use* process injection?". For the module that *implements* the
    /// injection APIs, the question has no meaning; answering it anyway is how a
    /// naive analyser labels Windows system libraries as ransomware.
    pub fn is_library_surface(&self) -> bool {
        const MIN_EXPORTS: usize = 200;
        const MIN_IMPORTS: usize = 200;
        self.exports.len() >= MIN_EXPORTS && self.imports.len() >= MIN_IMPORTS
    }
}

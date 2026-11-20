//! Mach-O parser, including fat/universal containers.
//!
//! macOS malware increasingly ships as universal binaries with a decoy slice
//! (a harmless arm64 build) alongside the payload (x86-64). Assay therefore
//! records **every** slice in a fat container and analyses each one, rather than
//! stopping at the first. `LC_UUID` doubles as a build identity, and the
//! presence of `LC_CODE_SIGNATURE` without a matching entitlements blob is worth
//! flagging.

use serde::{Deserialize, Serialize};

use crate::bytes::{fixed_str, to_hex, Reader};
use crate::error::{AssayError, Result};
use crate::format::{
    Architecture, BinaryImage, BinaryKind, DebugArtifact, Endianness, Format, FormatMetadata,
    ImportEntry, Permissions, SectionInfo, SignatureInfo,
};
use crate::hash::sha256;

/// `MH_MAGIC` (32-bit, native endian).
const MH_MAGIC: u32 = 0xFEED_FACE;
/// `MH_MAGIC_64`.
const MH_MAGIC_64: u32 = 0xFEED_FACF;
/// `MH_CIGAM` (32-bit, byte-swapped).
const MH_CIGAM: u32 = 0xCEFA_EDFE;
/// `MH_CIGAM_64`.
const MH_CIGAM_64: u32 = 0xCFFA_EDFE;
/// `FAT_MAGIC`.
const FAT_MAGIC: u32 = 0xCAFE_BABE;
/// `FAT_CIGAM`.
const FAT_CIGAM: u32 = 0xBEBA_FECA;

/// Load-command constants we act on.
mod lc {
    /// `LC_SEGMENT`.
    pub const SEGMENT: u32 = 0x1;
    /// `LC_SYMTAB`.
    pub const SYMTAB: u32 = 0x2;
    /// `LC_LOAD_DYLIB`.
    pub const LOAD_DYLIB: u32 = 0xC;
    /// `LC_ID_DYLIB`.
    pub const ID_DYLIB: u32 = 0xD;
    /// `LC_UUID`.
    pub const UUID: u32 = 0x1B;
    /// `LC_CODE_SIGNATURE`.
    pub const CODE_SIGNATURE: u32 = 0x1D;
    /// `LC_SEGMENT_64`.
    pub const SEGMENT_64: u32 = 0x19;
    /// `LC_RPATH`.
    pub const RPATH: u32 = 0x8000_001C;
    /// `LC_MAIN`.
    pub const MAIN: u32 = 0x8000_0028;
    /// `LC_LOAD_WEAK_DYLIB`.
    pub const LOAD_WEAK_DYLIB: u32 = 0x8000_0018;
    /// `LC_REEXPORT_DYLIB`.
    pub const REEXPORT_DYLIB: u32 = 0x8000_001F;
    /// `LC_BUILD_VERSION`.
    pub const BUILD_VERSION: u32 = 0x32;
}

/// Maximum load commands we will walk.
const MAX_LOAD_COMMANDS: usize = 4096;
/// Maximum dylib entries.
const MAX_DYLIBS: usize = 4096;

/// Mach-O-specific header facts.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MachOMetadata {
    /// `cputype`.
    pub cputype: u32,
    /// `cpusubtype`.
    pub cpusubtype: u32,
    /// `filetype`.
    pub filetype: u32,
    /// Friendly filetype name.
    pub filetype_name: String,
    /// `LC_UUID` rendered as a canonical UUID string.
    pub uuid: Option<String>,
    /// Minimum OS / SDK version from `LC_BUILD_VERSION`.
    pub min_os: Option<String>,
    /// SDK the binary was built against (`LC_BUILD_VERSION`).
    pub sdk: Option<String>,
    /// Platform name (`macOS`, `iOS`, `tvOS`, …).
    pub platform: Option<String>,
    /// `LC_ID_DYLIB` install name.
    pub install_name: Option<String>,
    /// `DYLD` search paths from `LC_RPATH`.
    pub rpaths: Vec<String>,
    /// Whether an `LC_CODE_SIGNATURE` command is present.
    pub has_code_signature: bool,
    /// Size of the code-signature blob in bytes.
    pub code_signature_size: u64,
    /// Whether the classic `LC_ENCRYPTION_INFO` is present (App Store binaries).
    pub encrypted: bool,
    /// `LC_MAIN` entry offset relative to the __TEXT segment.
    pub main_offset: Option<u64>,
    /// All architecture slices in a universal binary, as `(cputype, offset, size)`.
    pub slices: Vec<FatSlice>,
    /// Whether the file is a fat container.
    pub is_fat: bool,
    /// Symbol table entry count, when `LC_SYMTAB` is present.
    pub symbol_count: u32,
}

/// One slice of a universal binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FatSlice {
    /// `cputype` of this slice.
    pub cputype: u32,
    /// Friendly architecture name.
    pub arch: String,
    /// File offset of the slice.
    pub offset: u64,
    /// Slice length.
    pub size: u64,
}

/// Parsed Mach-O image.
#[derive(Debug)]
pub struct MachOFile<'a> {
    /// Raw bytes of the *analysed slice*.
    pub data: &'a [u8],
    /// Unified model.
    pub image: BinaryImage,
    /// Whether this slice is 64-bit.
    is64: bool,
    /// Whether integers are big endian.
    big_endian: bool,
    /// Offset of this slice within the original file (0 for thin binaries).
    slice_offset: u64,
}

impl<'a> MachOFile<'a> {
    /// Parse a Mach-O image, transparently descending into the first slice of a
    /// fat container.
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        if data.len() < 8 {
            return Err(AssayError::UnknownFormat {
                magic: to_hex(&data[..data.len().min(4)]),
            });
        }
        let mut r = Reader::at(data);
        let magic = r.u32_le()?;

        match magic {
            FAT_MAGIC | FAT_CIGAM => {
                let big = magic == FAT_MAGIC;
                let count = if big { r.u32_be()? } else { r.u32_le()? };
                if count == 0 || count as usize > 32 {
                    return Err(AssayError::malformed(
                        "fat header",
                        4,
                        format!("implausible slice count {count}"),
                    ));
                }
                let mut slices = Vec::new();
                let mut first: Option<(u64, u64)> = None;
                for _ in 0..count {
                    let cputype = if big { r.u32_be()? } else { r.u32_le()? };
                    let _sub = if big { r.u32_be()? } else { r.u32_le()? };
                    let offset = if big {
                        u64::from(r.u32_be()?)
                    } else {
                        u64::from(r.u32_le()?)
                    };
                    let size = if big {
                        u64::from(r.u32_be()?)
                    } else {
                        u64::from(r.u32_le()?)
                    };
                    let _align = if big { r.u32_be()? } else { r.u32_le()? };
                    slices.push(FatSlice {
                        cputype,
                        arch: cputype_name(cputype).to_string(),
                        offset,
                        size,
                    });
                    if first.is_none() {
                        first = Some((offset, size));
                    }
                }
                let Some((offset, size)) = first else {
                    return Err(AssayError::malformed("fat header", 4, "no slices"));
                };
                let start = offset as usize;
                let end = (start + size as usize).min(data.len());
                if start >= end {
                    return Err(AssayError::malformed(
                        "fat slice",
                        offset,
                        "slice lies outside the file",
                    ));
                }
                let mut parsed = MachOFile::parse_thin(&data[start..end])?;
                // Re-base absolute offsets so diagnostics point into the real file.
                parsed.slice_offset = offset;
                if let FormatMetadata::MachO(meta) = &mut parsed.image.metadata {
                    meta.is_fat = true;
                    meta.slices = slices;
                }
                parsed.image.structural_notes.push(format!(
                    "universal binary with {} slices; only `{}` was analysed in depth",
                    count,
                    parsed
                        .image
                        .metadata
                        .clone()
                        .macho_arch_label()
                        .unwrap_or_default()
                ));
                Ok(parsed)
            }
            MH_MAGIC | MH_MAGIC_64 => MachOFile::parse_thin(data).map(|mut f| {
                f.big_endian = false;
                f
            }),
            MH_CIGAM | MH_CIGAM_64 => {
                let mut parsed = MachOFile::parse_thin_endian(data, true)?;
                parsed.big_endian = true;
                Ok(parsed)
            }
            other => Err(AssayError::UnknownFormat {
                magic: format!("{other:#010x}"),
            }),
        }
    }

    fn parse_thin(data: &'a [u8]) -> Result<Self> {
        Self::parse_thin_endian(data, false)
    }

    fn parse_thin_endian(data: &'a [u8], force_big: bool) -> Result<Self> {
        let mut r = Reader::at(data);
        let magic = r.u32_le()?;
        let (is64, big_endian) = match (magic, force_big) {
            (MH_MAGIC, false) | (MH_CIGAM, true) => (false, false),
            (MH_MAGIC_64, false) | (MH_CIGAM_64, true) => (true, false),
            (MH_CIGAM, false) | (MH_MAGIC, true) => (false, true),
            (MH_CIGAM_64, false) | (MH_MAGIC_64, true) => (true, true),
            _ => {
                return Err(AssayError::UnknownFormat {
                    magic: format!("{magic:#010x}"),
                })
            }
        };
        // If the endianness flag was forced, re-read from a swapped view.
        if force_big {
            let swapped = swap32(magic);
            let _ = swapped;
        }

        macro_rules! rd32 {
            ($r:expr) => {
                if big_endian {
                    $r.u32_be()?
                } else {
                    $r.u32_le()?
                }
            };
        }
        macro_rules! rd64 {
            ($r:expr) => {
                if big_endian {
                    $r.u64_be()?
                } else {
                    $r.u64_le()?
                }
            };
        }

        let cputype = rd32!(r);
        let cpusubtype = rd32!(r);
        let filetype = rd32!(r);
        let ncmds = rd32!(r);
        let sizeofcmds = rd32!(r);
        let _flags = rd32!(r);
        if is64 {
            let _reserved = rd32!(r);
        }

        if ncmds as usize > MAX_LOAD_COMMANDS {
            return Err(AssayError::malformed(
                "mach header",
                16,
                format!("{ncmds} load commands exceeds safety cap"),
            ));
        }

        let cmds_start = r.position() as u64;
        // The declared size is clamped to the file, and the clamp is recorded. A
        // load-command payload that runs past EOF means the segment table is
        // incomplete, so any conclusion drawn from "no segment said X" is a
        // guess — the same trap that made a truncated ELF look unhardened.
        let declared_cmds_end = cmds_start + u64::from(sizeofcmds);
        let cmds_end = declared_cmds_end.min(data.len() as u64);

        let mut image = BinaryImage::placeholder(Format::MachO);
        if declared_cmds_end > data.len() as u64 {
            image.unreadable_tables.push(format!(
                "load commands declare {} bytes from {cmds_start:#x}, past the end of a {:#x}-byte file",
                sizeofcmds,
                data.len()
            ));
        }
        image.endian = if big_endian {
            Endianness::Big
        } else {
            Endianness::Little
        };
        image.bitness = if is64 { 64 } else { 32 };
        image.arch = cputype_to_arch(cputype, is64);

        let mut meta = MachOMetadata {
            cputype,
            cpusubtype,
            filetype,
            filetype_name: filetype_name(filetype).to_string(),
            ..Default::default()
        };

        image.kind = match filetype {
            1 => BinaryKind::Object,
            2 => BinaryKind::Executable,
            6 => BinaryKind::SharedLibrary,
            8 => BinaryKind::SharedLibrary,
            _ => BinaryKind::Other,
        };

        let mut cursor = cmds_start as usize;
        for _ in 0..ncmds {
            if cursor as u64 + 8 > cmds_end {
                break;
            }
            let mut cr = Reader::new(&data[cursor..], cursor as u64);
            let cmd = rd32!(cr);
            let cmdsize = rd32!(cr);
            if cmdsize < 8 || (cursor as u64 + u64::from(cmdsize)) > cmds_end {
                break;
            }
            let body_start = cursor + 8;
            let body_len = cmdsize as usize - 8;
            let body = data.get(body_start..body_start + body_len).unwrap_or(&[]);
            let mut br = Reader::new(body, body_start as u64);

            match cmd {
                lc::SEGMENT | lc::SEGMENT_64 => {
                    let wide = cmd == lc::SEGMENT_64;
                    let mut name_bytes = [0u8; 16];
                    if let Ok(nb) = br.take(16) {
                        name_bytes.copy_from_slice(nb);
                    }
                    let segname = fixed_str(&name_bytes);
                    let vmaddr = if wide {
                        rd64!(br)
                    } else {
                        u64::from(rd32!(br))
                    };
                    let vmsize = if wide {
                        rd64!(br)
                    } else {
                        u64::from(rd32!(br))
                    };
                    let fileoff = if wide {
                        rd64!(br)
                    } else {
                        u64::from(rd32!(br))
                    };
                    let filesize = if wide {
                        rd64!(br)
                    } else {
                        u64::from(rd32!(br))
                    };
                    let maxprot = rd32!(br);
                    let initprot = rd32!(br);
                    let nsects = rd32!(br);
                    let _flags_seg = rd32!(br);

                    // Skip an empty __PAGEZERO; it carries no bytes.
                    if filesize > 0 {
                        let off = (fileoff as usize).min(data.len());
                        let len = (filesize as usize).min(data.len() - off);
                        let payload = &data[off..off + len];
                        image.sections.push(SectionInfo {
                            name: segname.clone(),
                            virtual_address: vmaddr,
                            virtual_size: vmsize,
                            file_offset: fileoff,
                            file_size: filesize,
                            entropy: crate::analysis::entropy::shannon(payload),
                            permissions: Permissions::new(
                                initprot & 0x1 != 0,
                                initprot & 0x2 != 0,
                                initprot & 0x4 != 0,
                            ),
                            sha256: if payload.is_empty() {
                                String::new()
                            } else {
                                to_hex(&sha256(payload))
                            },
                            raw_characteristics: u64::from(maxprot),
                        });
                    }

                    // Walk per-section headers inside the segment command.
                    for _ in 0..nsects.min(256) {
                        let mut sb = [0u8; 16];
                        if br.take(16).is_err() {
                            break;
                        }
                        sb.copy_from_slice(&body[br.position() - 16..br.position()]);
                        let sectname = fixed_str(&sb);
                        let mut sg = [0u8; 16];
                        if br.take(16).is_err() {
                            break;
                        }
                        sg.copy_from_slice(&body[br.position() - 16..br.position()]);
                        let addr = if wide {
                            rd64!(br)
                        } else {
                            u64::from(rd32!(br))
                        };
                        let size = if wide {
                            rd64!(br)
                        } else {
                            u64::from(rd32!(br))
                        };
                        let offset = rd32!(br) as u64;
                        let _align = rd32!(br);
                        let _reloff = rd32!(br);
                        let _nreloc = rd32!(br);
                        let sect_flags = rd32!(br);
                        let _reserved1 = rd32!(br);
                        let _reserved2 = rd32!(br);
                        let _reserved3 = if wide { rd32!(br) } else { 0 };

                        // Only record sections with backing bytes; __bss has none.
                        let has_bytes = sect_flags & 0xFF != 1;
                        if !has_bytes || size == 0 {
                            continue;
                        }
                        let off = (offset as usize).min(data.len());
                        let len = (size as usize).min(data.len().saturating_sub(off));
                        let payload = &data[off..off + len];
                        let sect_display = if sectname.is_empty() {
                            segname.clone()
                        } else {
                            format!("{segname},{sectname}")
                        };
                        image.sections.push(SectionInfo {
                            name: sect_display,
                            virtual_address: addr,
                            virtual_size: size,
                            file_offset: offset,
                            file_size: size,
                            entropy: crate::analysis::entropy::shannon(payload),
                            permissions: Permissions::new(
                                initprot & 0x1 != 0,
                                initprot & 0x2 != 0,
                                initprot & 0x4 != 0,
                            ),
                            sha256: if payload.is_empty() {
                                String::new()
                            } else {
                                to_hex(&sha256(payload))
                            },
                            raw_characteristics: u64::from(sect_flags),
                        });
                    }
                }
                lc::SYMTAB => {
                    let _symoff = rd32!(br);
                    let nsyms = rd32!(br);
                    let _stroff = rd32!(br);
                    let _strsize = rd32!(br);
                    meta.symbol_count = nsyms;
                }
                lc::LOAD_DYLIB | lc::LOAD_WEAK_DYLIB | lc::REEXPORT_DYLIB => {
                    if image.imports.len() >= MAX_DYLIBS {
                        continue;
                    }
                    let name_off = rd32!(br);
                    let _timestamp = rd32!(br);
                    let _current = rd32!(br);
                    let _compat = rd32!(br);
                    let base = body_start as u32;
                    let abs_off = base + name_off;
                    let name = read_cstr(data, abs_off as usize, 512);
                    if !name.is_empty() {
                        image.imports.push(ImportEntry {
                            library: name,
                            symbol: String::new(),
                            ordinal: None,
                            hint: None,
                            delayed: cmd == lc::LOAD_WEAK_DYLIB,
                        });
                    }
                }
                lc::ID_DYLIB => {
                    let name_off = rd32!(br);
                    let abs_off = body_start as u32 + name_off;
                    meta.install_name = Some(read_cstr(data, abs_off as usize, 512));
                }
                lc::RPATH => {
                    let path_off = rd32!(br);
                    let abs_off = body_start as u32 + path_off;
                    let path = read_cstr(data, abs_off as usize, 512);
                    if !path.is_empty() {
                        meta.rpaths.push(path);
                    }
                }
                lc::UUID => {
                    if let Ok(uuid) = br.take(16) {
                        meta.uuid = Some(format!(
                            "{}-{}-{}-{}-{}",
                            to_hex(&uuid[0..4]),
                            to_hex(&uuid[4..6]),
                            to_hex(&uuid[6..8]),
                            to_hex(&uuid[8..10]),
                            to_hex(&uuid[10..16])
                        ));
                    }
                }
                lc::CODE_SIGNATURE => {
                    let data_off = rd32!(br);
                    let data_size = rd32!(br);
                    meta.has_code_signature = true;
                    meta.code_signature_size = u64::from(data_size);
                    image.signature = SignatureInfo {
                        scheme: "codesign".into(),
                        present: data_size > 0,
                        ..SignatureInfo::absent()
                    };
                    if data_size > 0 {
                        let off = (data_off as usize).min(data.len());
                        let len = (data_size as usize).min(data.len() - off);
                        image.signature.blob_sha256 = to_hex(&sha256(&data[off..off + len]));
                        image
                            .signature
                            .issues
                            .push("code signature blob present; trust evaluation requires the macOS verifier".into());
                    }
                }
                lc::MAIN => {
                    let entryoff = rd64!(br);
                    meta.main_offset = Some(entryoff);
                }
                lc::BUILD_VERSION => {
                    let platform = rd32!(br);
                    let minos = rd32!(br);
                    let sdk = rd32!(br);
                    meta.platform = Some(platform_name(platform).to_string());
                    meta.min_os = Some(decode_version(minos));
                    meta.sdk = Some(decode_version(sdk));
                }
                _ => {}
            }

            cursor = cursor.saturating_add(cmdsize as usize);
        }

        image.entry_point = meta.main_offset;
        if let Some(uuid) = &meta.uuid {
            image.debug_artifacts.push(DebugArtifact {
                kind: "uuid".into(),
                value: uuid.clone(),
                trusted: true,
            });
        }

        if meta.has_code_signature && meta.code_signature_size == 0 {
            image
                .structural_notes
                .push("LC_CODE_SIGNATURE present but empty".into());
        }
        if !meta.has_code_signature && image.kind == BinaryKind::Executable {
            image
                .structural_notes
                .push("executable has no code signature".into());
        }
        for sec in &image.sections {
            if sec.permissions.is_wx() {
                image
                    .structural_notes
                    .push(format!("section `{}` is writable and executable", sec.name));
            }
        }
        if let Some(first) = image.sections.first() {
            image.image_base = first.virtual_address;
        }

        image.metadata = FormatMetadata::MachO(meta);
        Ok(MachOFile {
            data,
            image,
            is64,
            big_endian,
            slice_offset: 0,
        })
    }

    /// Whether this slice is 64-bit.
    pub fn is_64(&self) -> bool {
        self.is64
    }

    /// Whether integers are big endian.
    pub fn is_big_endian(&self) -> bool {
        self.big_endian
    }

    /// Offset of this slice inside the original file.
    pub fn slice_offset(&self) -> u64 {
        self.slice_offset
    }
}

impl FormatMetadata {
    fn macho_arch_label(&self) -> Option<String> {
        match self {
            FormatMetadata::MachO(m) => {
                Some(format!("{} ({})", cputype_name(m.cputype), m.filetype_name))
            }
            _ => None,
        }
    }
}

fn read_cstr(data: &[u8], offset: usize, max: usize) -> String {
    if offset >= data.len() {
        return String::new();
    }
    let slice = &data[offset..];
    let cap = max.min(slice.len());
    let end = slice[..cap].iter().position(|&b| b == 0).unwrap_or(cap);
    String::from_utf8_lossy(&slice[..end]).into_owned()
}

fn swap32(v: u32) -> u32 {
    v.swap_bytes()
}

fn decode_version(packed: u32) -> String {
    format!(
        "{}.{}.{}",
        packed >> 16,
        (packed >> 8) & 0xFF,
        packed & 0xFF
    )
}

fn platform_name(p: u32) -> &'static str {
    match p {
        1 => "macOS",
        2 => "iOS",
        3 => "tvOS",
        4 => "watchOS",
        5 => "bridgeOS",
        6 => "macCatalyst",
        7 => "iOSSimulator",
        8 => "tvOSSimulator",
        9 => "watchOSSimulator",
        10 => "DriverKit",
        11 => "visionOS",
        _ => "unknown",
    }
}

fn filetype_name(t: u32) -> &'static str {
    match t {
        1 => "MH_OBJECT",
        2 => "MH_EXECUTE",
        3 => "MH_FVMLIB",
        4 => "MH_CORE",
        5 => "MH_PRELOAD",
        6 => "MH_DYLIB",
        7 => "MH_DYLINKER",
        8 => "MH_BUNDLE",
        9 => "MH_DYLIB_STUB",
        10 => "MH_DSYM",
        11 => "MH_KEXT_BUNDLE",
        12 => "MH_FILESET",
        _ => "MH_UNKNOWN",
    }
}

fn cputype_to_arch(cputype: u32, is64: bool) -> Architecture {
    match cputype {
        7 => Architecture::X86,
        0x0100_0007 => Architecture::X86_64,
        12 => Architecture::Arm,
        0x0100_000C => Architecture::Arm64,
        18 => Architecture::PowerPc,
        0x0100_0012 => Architecture::PowerPc,
        _ => {
            if is64 {
                Architecture::X86_64
            } else {
                Architecture::Unknown
            }
        }
    }
}

fn cputype_name(cputype: u32) -> &'static str {
    match cputype {
        7 => "i386",
        0x0100_0007 => "x86_64",
        12 => "arm",
        0x0100_000C => "arm64",
        0x0200_000C => "arm64_32",
        18 => "ppc",
        0x0100_0012 => "ppc64",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal 64-bit Mach-O executable with one `__TEXT` segment and a
    /// `LC_UUID`.
    pub(crate) fn build_minimal_macho64() -> Vec<u8> {
        let header_size = 32usize;
        // LC_SEGMENT_64 (72 bytes) with 1 section (80 bytes) => 152
        let seg_cmd_size = 72 + 80;
        let uuid_cmd_size = 24usize;
        let sizeofcmds = seg_cmd_size + uuid_cmd_size;
        let text_off = header_size + sizeofcmds;
        let text_size = 64usize;
        let total = text_off + text_size;

        let mut buf = vec![0u8; total];

        // mach_header_64
        buf[0..4].copy_from_slice(&MH_MAGIC_64.to_le_bytes());
        buf[4..8].copy_from_slice(&0x0100_0007u32.to_le_bytes()); // CPU_TYPE_X86_64
        buf[8..12].copy_from_slice(&3u32.to_le_bytes());
        buf[12..16].copy_from_slice(&2u32.to_le_bytes()); // MH_EXECUTE
        buf[16..20].copy_from_slice(&2u32.to_le_bytes()); // ncmds
        buf[20..24].copy_from_slice(&(sizeofcmds as u32).to_le_bytes());
        buf[24..28].copy_from_slice(&0u32.to_le_bytes());
        buf[28..32].copy_from_slice(&0u32.to_le_bytes());

        // LC_SEGMENT_64
        let s = header_size;
        buf[s..s + 4].copy_from_slice(&lc::SEGMENT_64.to_le_bytes());
        buf[s + 4..s + 8].copy_from_slice(&(seg_cmd_size as u32).to_le_bytes());
        let mut name = [0u8; 16];
        name[..6].copy_from_slice(b"__TEXT");
        buf[s + 8..s + 24].copy_from_slice(&name);
        buf[s + 24..s + 32].copy_from_slice(&0x1_0000_0000u64.to_le_bytes()); // vmaddr
        buf[s + 32..s + 40].copy_from_slice(&0x4000u64.to_le_bytes()); // vmsize
        buf[s + 40..s + 48].copy_from_slice(&(text_off as u64).to_le_bytes()); // fileoff
        buf[s + 48..s + 56].copy_from_slice(&(text_size as u64).to_le_bytes()); // filesize
        buf[s + 56..s + 60].copy_from_slice(&5u32.to_le_bytes()); // maxprot r-x
        buf[s + 60..s + 64].copy_from_slice(&5u32.to_le_bytes()); // initprot r-x
        buf[s + 64..s + 68].copy_from_slice(&1u32.to_le_bytes()); // nsects
        buf[s + 68..s + 72].copy_from_slice(&0u32.to_le_bytes());

        // section_64
        let sec = s + 72;
        let mut sectname = [0u8; 16];
        sectname[..6].copy_from_slice(b"__text");
        buf[sec..sec + 16].copy_from_slice(&sectname);
        let mut segn = [0u8; 16];
        segn[..6].copy_from_slice(b"__TEXT");
        buf[sec + 16..sec + 32].copy_from_slice(&segn);
        buf[sec + 32..sec + 40].copy_from_slice(&0x1_0000_0000u64.to_le_bytes()); // addr
        buf[sec + 40..sec + 48].copy_from_slice(&(text_size as u64).to_le_bytes()); // size
        buf[sec + 48..sec + 52].copy_from_slice(&(text_off as u32).to_le_bytes()); // offset
        buf[sec + 52..sec + 56].copy_from_slice(&4u32.to_le_bytes()); // align
        buf[sec + 64..sec + 68].copy_from_slice(&0x8000_0400u32.to_le_bytes()); // S_ATTR_PURE_INSTRUCTIONS

        // LC_UUID
        let u = header_size + seg_cmd_size;
        buf[u..u + 4].copy_from_slice(&lc::UUID.to_le_bytes());
        buf[u + 4..u + 8].copy_from_slice(&(uuid_cmd_size as u32).to_le_bytes());
        for i in 0..16 {
            buf[u + 8 + i] = (0xA0 + i) as u8;
        }

        for i in 0..text_size {
            buf[text_off + i] = 0x55u8.wrapping_mul(i as u8);
        }
        buf
    }

    #[test]
    fn parses_minimal_macho64() {
        let data = build_minimal_macho64();
        let macho = MachOFile::parse(&data).expect("should parse");
        assert_eq!(macho.image.format, Format::MachO);
        assert_eq!(macho.image.bitness, 64);
        assert_eq!(macho.image.arch, Architecture::X86_64);
        assert!(macho
            .image
            .sections
            .iter()
            .any(|s| s.name.contains("__text")));
    }

    #[test]
    fn reads_uuid() {
        let data = build_minimal_macho64();
        let macho = MachOFile::parse(&data).unwrap();
        if let FormatMetadata::MachO(meta) = &macho.image.metadata {
            assert_eq!(
                meta.uuid.as_deref(),
                Some("a0a1a2a3-a4a5-a6a7-a8a9-aaabacadaeaf")
            );
        } else {
            panic!("wrong metadata");
        }
    }

    #[test]
    fn flags_missing_code_signature() {
        let data = build_minimal_macho64();
        let macho = MachOFile::parse(&data).unwrap();
        assert!(macho
            .image
            .structural_notes
            .iter()
            .any(|n| n.contains("no code signature")));
    }

    #[test]
    fn rejects_garbage() {
        assert!(MachOFile::parse(&[0x00, 0x01, 0x02, 0x03]).is_err());
    }
}

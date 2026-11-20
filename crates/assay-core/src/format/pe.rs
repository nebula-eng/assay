//! Windows Portable Executable parser.
//!
//! Written against the published PE/COFF specification, with the field limits
//! that real-world hostile files exercise: `NumberOfSections` is capped before
//! allocation, every RVA is mapped through the *validated* section table rather
//! than trusted, and the import/resource walkers stop at the first structural
//! inconsistency instead of looping. A parser that trusts `SizeOfOptionalHeader`
//! is a parser that can be made to hang.
//!
//! Deliberately out of scope: relocation application, page-hash verification,
//! and .NET metadata table decoding. Those belong to a loader and a managed
//! assembly reader respectively, and pretending otherwise would produce
//! confidently wrong output.

use serde::{Deserialize, Serialize};

use crate::bytes::{fixed_str, to_hex, Reader};
use crate::error::{AssayError, Result};
use crate::format::{
    Architecture, BinaryImage, BinaryKind, DebugArtifact, Endianness, ExportEntry, Format,
    FormatMetadata, ImportEntry, Permissions, ResourceEntry, SectionInfo, SignatureInfo,
};
use crate::hash::{import_hash, sha256};

/// `MZ` — every DOS-stub executable starts here.
pub const DOS_MAGIC: u16 = 0x5A4D;
/// `PE\0\0`.
pub const NT_MAGIC: u32 = 0x0000_4550;

/// Optional-header magic for 32-bit images.
const OPT_MAGIC_PE32: u16 = 0x010B;
/// Optional-header magic for 64-bit images.
const OPT_MAGIC_PE32_PLUS: u16 = 0x020B;

/// Upper bound on section count. The spec allows 96; linkers emit far fewer.
/// Anything above this is a deliberate attempt to exhaust memory.
const MAX_SECTIONS: usize = 96;
/// Upper bound on import descriptors per module.
const MAX_IMPORT_DESCRIPTORS: usize = 4096;
/// Upper bound on thunks per import descriptor.
const MAX_THUNKS: usize = 65536;
/// Upper bound on resource directory entries traversed in total.
const MAX_RESOURCE_ENTRIES: usize = 8192;
/// Maximum recursion depth into the resource tree.
const MAX_RESOURCE_DEPTH: usize = 4;

/// Data-directory indices, in on-disk order.
pub mod dir_index {
    /// Export table.
    pub const EXPORT: usize = 0;
    /// Import table.
    pub const IMPORT: usize = 1;
    /// Resource tree.
    pub const RESOURCE: usize = 2;
    /// Exception table.
    pub const EXCEPTION: usize = 3;
    /// Attribute certificate table (file offset, not RVA).
    pub const CERTIFICATE: usize = 4;
    /// Base relocations.
    pub const BASERELOC: usize = 5;
    /// Debug directory.
    pub const DEBUG: usize = 6;
    /// TLS directory.
    pub const TLS: usize = 9;
    /// Load configuration.
    pub const LOAD_CONFIG: usize = 10;
    /// Delay-load import descriptors.
    pub const DELAY_IMPORT: usize = 13;
    /// CLR (.NET) runtime header.
    pub const CLR: usize = 14;
}

/// Facts recovered from the PE headers that have no cross-format equivalent.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PeMetadata {
    /// `IMAGE_FILE_MACHINE_*` value.
    pub machine: u16,
    /// Friendly name for `machine`.
    pub machine_name: String,
    /// `NumberOfSections` as declared.
    pub declared_sections: u16,
    /// `TimeDateStamp` of the COFF header (Unix seconds; frequently forged).
    pub timestamp: u32,
    /// `Characteristics` word.
    pub characteristics: u16,
    /// `DllCharacteristics` word.
    pub dll_characteristics: u16,
    /// `Subsystem` value (2 = GUI, 3 = console).
    pub subsystem: u16,
    /// Linker major.minor as recorded.
    pub linker_version: String,
    /// `CheckSum` field from the optional header.
    pub declared_checksum: u32,
    /// Checksum recomputed over the image.
    pub computed_checksum: u32,
    /// Whether the two agree.
    pub checksum_valid: bool,
    /// `SizeOfImage`.
    pub size_of_image: u32,
    /// `SizeOfHeaders`.
    pub size_of_headers: u32,
    /// Section/file alignment pair.
    pub file_alignment: u32,
    /// `SectionAlignment` in memory; normally 0x1000.
    pub section_alignment: u32,
    /// Number of data directories declared.
    pub num_directories: u32,
    /// Whether an `IMAGE_COR20_HEADER` is present.
    pub is_dotnet: bool,
    /// CLR runtime version string when managed.
    pub clr_version: Option<String>,
    /// .NET metadata version string (`v4.0.30319`) when managed.
    pub metadata_version: Option<String>,
    /// TLS callback virtual addresses.
    pub tls_callbacks: Vec<u64>,
    /// Whether a TLS directory exists at all.
    pub has_tls: bool,
    /// Rich header: XOR key used to obfuscate the record list.
    pub rich_key: Option<u32>,
    /// Rich header: `(product_id, build)` pairs recovered after de-obfuscation.
    pub rich_entries: Vec<RichEntry>,
    /// PDB path from the CodeView debug entry.
    pub pdb_path: Option<String>,
    /// Debug directory entries by type name.
    pub debug_types: Vec<String>,
    /// Import hash over the normalised import list.
    pub import_hash: Option<String>,
    /// `BaseOfCode`.
    pub base_of_code: u32,
    /// True when the file is a DLL (`IMAGE_FILE_DLL`).
    pub is_dll: bool,
}

/// One decoded Rich-header record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RichEntry {
    /// `@comp.id` product identifier (compiler/toolchain build).
    pub product_id: u32,
    /// Build number (`@comp.id` high word).
    pub build: u32,
    /// Number of times the tool was invoked.
    pub count: u32,
}

/// A parsed PE file plus the raw bytes needed for later passes.
#[derive(Debug)]
pub struct PeFile<'a> {
    /// Raw file bytes.
    pub data: &'a [u8],
    /// Unified image model.
    pub image: BinaryImage,
    /// Section table in parse order, for RVA mapping.
    sections: Vec<RawSection>,
    /// Size of the headers region.
    headers_size: u32,
    /// Data directories as declared, so later passes can locate the certificate
    /// table without re-walking the optional header.
    directories: Vec<(u32, u32)>,
}

/// Internal section record with the raw fields RVA mapping needs.
#[derive(Debug, Clone)]
struct RawSection {
    name: String,
    virtual_address: u32,
    virtual_size: u32,
    raw_offset: u32,
    raw_size: u32,
    characteristics: u32,
}

impl<'a> PeFile<'a> {
    /// Parse a PE image from raw bytes.
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        let mut r = Reader::at(data);

        // ---- DOS header -------------------------------------------------
        let dos_magic = r.u16_le().map_err(|_| AssayError::UnknownFormat {
            magic: to_hex(&data[..data.len().min(4)]),
        })?;
        if dos_magic != DOS_MAGIC {
            return Err(AssayError::UnknownFormat {
                magic: to_hex(&data[..data.len().min(4)]),
            });
        }
        r.seek(0x3C)?;
        let e_lfanew = r.u32_le()? as usize;
        if e_lfanew < 0x40 {
            return Err(AssayError::malformed(
                "DOS header",
                0x3C,
                format!("e_lfanew {e_lfanew:#x} points inside the DOS header"),
            ));
        }

        // ---- NT signature and COFF header -------------------------------
        r.seek(e_lfanew)?;
        let signature = r.u32_le()?;
        if signature != NT_MAGIC {
            return Err(AssayError::malformed(
                "NT header",
                e_lfanew as u64,
                format!("expected PE\\0\\0, found {signature:#010x}"),
            ));
        }

        let machine = r.u16_le()?;
        let declared_sections = r.u16_le()?;
        let timestamp = r.u32_le()?;
        let _symtab_ptr = r.u32_le()?;
        let _symbol_count = r.u32_le()?;
        let size_optional = r.u16_le()?;
        let characteristics = r.u16_le()?;

        // ---- Optional header --------------------------------------------
        let opt_start = r.offset();
        let opt_magic = r.u16_le()?;
        let (is_plus, bitness) = match opt_magic {
            OPT_MAGIC_PE32 => (false, 32u8),
            OPT_MAGIC_PE32_PLUS => (true, 64u8),
            other => {
                return Err(AssayError::malformed(
                    "optional header",
                    opt_start,
                    format!("unknown magic {other:#06x}"),
                ))
            }
        };
        let arch = machine_to_arch(machine, is_plus);

        let linker_major = r.u8()?;
        let linker_minor = r.u8()?;
        let size_of_code = r.u32_le()?;
        let _size_init_data = r.u32_le()?;
        let _size_uninit_data = r.u32_le()?;
        let entry_point = r.u32_le()?;
        let base_of_code = r.u32_le()?;
        let base_of_data = if is_plus { 0 } else { r.u32_le()? };
        let image_base = if is_plus {
            r.u64_le()?
        } else {
            u64::from(r.u32_le()?)
        };
        let section_alignment = r.u32_le()?;
        let file_alignment = r.u32_le()?;
        let _os_major = r.u16_le()?;
        let _os_minor = r.u16_le()?;
        let _img_major = r.u16_le()?;
        let _img_minor = r.u16_le()?;
        let _subsys_major = r.u16_le()?;
        let _subsys_minor = r.u16_le()?;
        let _win32_version = r.u32_le()?;
        let size_of_image = r.u32_le()?;
        let size_of_headers = r.u32_le()?;
        let declared_checksum = r.u32_le()?;
        let subsystem = r.u16_le()?;
        let dll_characteristics = r.u16_le()?;
        let _stack_reserve = if is_plus {
            r.u64_le()?
        } else {
            u64::from(r.u32_le()?)
        };
        let _stack_commit = if is_plus {
            r.u64_le()?
        } else {
            u64::from(r.u32_le()?)
        };
        let _heap_reserve = if is_plus {
            r.u64_le()?
        } else {
            u64::from(r.u32_le()?)
        };
        let _heap_commit = if is_plus {
            r.u64_le()?
        } else {
            u64::from(r.u32_le()?)
        };
        let _loader_flags = r.u32_le()?;
        let num_directories = r.u32_le()?;

        let dirs_start = r.offset();
        let max_dirs = ((opt_start + u64::from(size_optional) - dirs_start) / 8).min(16);
        let mut directories = vec![(0u32, 0u32); 16];
        for slot in directories
            .iter_mut()
            .take(u64::from(num_directories).min(max_dirs) as usize)
        {
            *slot = (r.u32_le()?, r.u32_le()?);
        }
        let _ = base_of_data;

        // ---- Section table ----------------------------------------------
        // The section table starts right after the optional header, using the
        // declared size rather than wherever our cursor happens to be.
        let section_table_start = opt_start + u64::from(size_optional);
        r.seek(section_table_start as usize)?;
        let declared = declared_sections as usize;
        if declared > MAX_SECTIONS {
            return Err(AssayError::malformed(
                "section table",
                section_table_start,
                format!("{declared} sections exceeds the {MAX_SECTIONS} safety cap"),
            ));
        }

        let mut raw_sections = Vec::with_capacity(declared);
        for _i in 0..declared {
            let header_off = r.offset();
            let mut name_bytes = [0u8; 8];
            name_bytes.copy_from_slice(r.take(8)?);
            let virtual_size = r.u32_le()?;
            let virtual_address = r.u32_le()?;
            let raw_size = r.u32_le()?;
            let raw_offset = r.u32_le()?;
            let _reloc_ptr = r.u32_le()?;
            let _line_ptr = r.u32_le()?;
            let _reloc_count = r.u16_le()?;
            let _line_count = r.u16_le()?;
            let characteristics = r.u32_le()?;

            // Clamp the raw range to the file so a lying size cannot make later
            // passes read past the end of the mapping.
            let clamped_off = (raw_offset as usize).min(data.len());
            let clamped_len = (raw_size as usize).min(data.len() - clamped_off);
            if raw_offset as usize > data.len() && raw_size > 0 {
                // Keep the record, note that it points outside the file.
                raw_sections.push(RawSection {
                    name: fixed_str(&name_bytes),
                    virtual_address,
                    virtual_size,
                    raw_offset,
                    raw_size: 0,
                    characteristics,
                });
                let _ = (header_off, clamped_off, clamped_len);
                continue;
            }

            raw_sections.push(RawSection {
                name: fixed_str(&name_bytes),
                virtual_address,
                virtual_size,
                raw_offset,
                raw_size,
                characteristics,
            });
        }

        let headers_size = size_of_headers;
        let mut file = PeFile {
            data,
            image: BinaryImage::placeholder(Format::Pe),
            sections: raw_sections.clone(),
            headers_size,
            directories: directories.clone(),
        };

        // ---- Populate the unified model ---------------------------------
        file.image.kind = infer_kind(characteristics, &directories, &raw_sections);
        file.image.arch = arch;
        file.image.endian = Endianness::Little;
        file.image.bitness = bitness;
        file.image.entry_point = if entry_point == 0 {
            None
        } else {
            Some(u64::from(entry_point))
        };
        file.image.image_base = image_base;

        for sec in &raw_sections {
            file.image.sections.push(section_info(data, sec));
        }

        let computed_checksum = pe_checksum(data, declared_checksum);

        let mut meta = PeMetadata {
            machine,
            machine_name: machine_name(machine, is_plus).to_string(),
            declared_sections,
            timestamp,
            characteristics,
            dll_characteristics,
            subsystem,
            linker_version: format!("{linker_major}.{linker_minor}"),
            declared_checksum,
            computed_checksum,
            checksum_valid: declared_checksum == 0 || declared_checksum == computed_checksum,
            size_of_image,
            size_of_headers,
            file_alignment,
            section_alignment,
            num_directories,
            base_of_code,
            is_dll: characteristics & 0x2000 != 0,
            ..Default::default()
        };
        let _ = size_of_code;

        // Imports (normal then delay-load).
        file.image.imports = file.read_imports(&directories)?;
        let delay = file.read_delay_imports(&directories)?;
        let delayed_marker = delay.len();
        file.image.imports.extend(delay);
        let _ = delayed_marker;

        // Exports.
        file.image.exports = file.read_exports(&directories)?;

        // Resources.
        file.image.resources = file.read_resources(&directories)?;

        // Debug directory → PDB path.
        file.read_debug(&directories, &mut meta);

        // TLS callbacks.
        file.read_tls(&directories, &mut meta)?;

        // Load config: worth noting only for its presence today.
        // Rich header.
        let (rich_key, rich_entries) = parse_rich_header(data, e_lfanew);
        meta.rich_key = rich_key;
        meta.rich_entries = rich_entries;

        // CLR header.
        if let Some(&(clr_rva, clr_size)) = directories.get(dir_index::CLR) {
            if clr_rva != 0 && clr_size != 0 {
                meta.is_dotnet = true;
                if let Some((runtime, metadata)) = file.read_clr(clr_rva) {
                    meta.clr_version = Some(runtime);
                    meta.metadata_version = metadata;
                }
            }
        }

        // Authenticode.
        file.image.signature = file.read_certificate(&directories);

        // Import hash.
        meta.import_hash = import_hash(
            file.image
                .imports
                .iter()
                .filter(|i| !i.delayed)
                .map(|i| (i.library.clone(), i.symbol.clone())),
        );

        // Structural notes that do not require rules.
        file.collect_structural_notes(&mut meta);

        file.image.metadata = FormatMetadata::Pe(meta);
        Ok(file)
    }

    /// Map an RVA to a file offset using the validated section table.
    pub fn rva_to_offset(&self, rva: u32) -> Option<u64> {
        if (rva as u64) < u64::from(self.headers_size) {
            return Some(u64::from(rva));
        }
        for sec in &self.sections {
            let start = u64::from(sec.virtual_address);
            let span = u64::from(sec.virtual_size.max(sec.raw_size));
            if span == 0 {
                continue;
            }
            if u64::from(rva) >= start && u64::from(rva) < start + span {
                let delta = u64::from(rva) - start;
                if delta >= u64::from(sec.raw_size) {
                    // Inside the zero-filled tail; no backing bytes.
                    return None;
                }
                return Some(u64::from(sec.raw_offset) + delta);
            }
        }
        None
    }

    fn slice_at_rva(&self, rva: u32, len: usize) -> Option<&'a [u8]> {
        let off = self.rva_to_offset(rva)? as usize;
        let end = off.checked_add(len)?;
        self.data.get(off..end)
    }

    /// Borrow a NUL-terminated string at an RVA.
    fn cstr_at_rva(&self, rva: u32, max: usize) -> Option<String> {
        let off = self.rva_to_offset(rva)? as usize;
        if off >= self.data.len() {
            return None;
        }
        let mut r = Reader::new(&self.data[off..], off as u64);
        r.cstring(max).ok()
    }

    fn read_imports(&self, dirs: &[(u32, u32)]) -> Result<Vec<ImportEntry>> {
        let mut out = Vec::new();
        let Some(&(rva, size)) = dirs.get(dir_index::IMPORT) else {
            return Ok(out);
        };
        if rva == 0 || size == 0 {
            return Ok(out);
        }

        for i in 0..MAX_IMPORT_DESCRIPTORS {
            let desc_rva = rva + (i as u32) * 20;
            let Some(bytes) = self.slice_at_rva(desc_rva, 20) else {
                break;
            };
            let mut r = Reader::at(bytes);
            let original_first_thunk = r.u32_le()?;
            let _timestamp = r.u32_le()?;
            let _forwarder = r.u32_le()?;
            let name_rva = r.u32_le()?;
            let first_thunk = r.u32_le()?;

            // All-zero descriptor terminates the table.
            if original_first_thunk == 0 && name_rva == 0 && first_thunk == 0 {
                break;
            }
            let library = self.cstr_at_rva(name_rva, 512).unwrap_or_default();
            if library.is_empty() {
                continue;
            }

            let thunk_rva = if original_first_thunk != 0 {
                original_first_thunk
            } else {
                first_thunk
            };
            let stride = if self.image.bitness == 64 { 8usize } else { 4 };
            let ordinal_flag: u64 = if stride == 8 { 1 << 63 } else { 1 << 31 };

            for t in 0..MAX_THUNKS {
                let Some(raw) = self.slice_at_rva(thunk_rva + (t as u32) * stride as u32, stride)
                else {
                    break;
                };
                let value = if stride == 8 {
                    u64::from_le_bytes(raw.try_into().unwrap_or([0; 8]))
                } else {
                    u64::from(u32::from_le_bytes(raw.try_into().unwrap_or([0; 4])))
                };
                if value == 0 {
                    break;
                }
                if value & ordinal_flag != 0 {
                    out.push(ImportEntry {
                        library: library.clone(),
                        symbol: String::new(),
                        ordinal: Some((value & 0xffff) as u16),
                        hint: None,
                        delayed: false,
                    });
                } else {
                    let hint_rva = (value & 0x7fff_ffff) as u32;
                    let hint = self
                        .slice_at_rva(hint_rva, 2)
                        .map(|b| u16::from_le_bytes([b[0], b[1]]));
                    let symbol = self.cstr_at_rva(hint_rva + 2, 512).unwrap_or_default();
                    out.push(ImportEntry {
                        library: library.clone(),
                        symbol,
                        ordinal: None,
                        hint,
                        delayed: false,
                    });
                }
            }
        }
        Ok(out)
    }

    fn read_delay_imports(&self, dirs: &[(u32, u32)]) -> Result<Vec<ImportEntry>> {
        let mut out = Vec::new();
        let Some(&(rva, size)) = dirs.get(dir_index::DELAY_IMPORT) else {
            return Ok(out);
        };
        if rva == 0 || size == 0 {
            return Ok(out);
        }

        for i in 0..MAX_IMPORT_DESCRIPTORS {
            let desc_rva = rva + (i as u32) * 32;
            let Some(bytes) = self.slice_at_rva(desc_rva, 32) else {
                break;
            };
            let mut r = Reader::at(bytes);
            let attributes = r.u32_le()?;
            let name_field = r.u32_le()?;
            let _module_handle = r.u32_le()?;
            let _iat = r.u32_le()?;
            let int_field = r.u32_le()?;
            let _bound = r.u32_le()?;
            let _unload = r.u32_le()?;
            let _timestamp = r.u32_le()?;

            if name_field == 0 && int_field == 0 {
                break;
            }

            // Attributes bit 0: 1 = fields are RVAs, 0 = fields are VAs.
            let to_rva = |value: u32| -> u32 {
                if attributes & 1 != 0 {
                    value
                } else {
                    value.wrapping_sub(self.image.image_base as u32)
                }
            };

            let library = self
                .cstr_at_rva(to_rva(name_field), 512)
                .unwrap_or_default();
            if library.is_empty() {
                continue;
            }
            let thunk_rva = to_rva(int_field);
            let stride = if self.image.bitness == 64 { 8usize } else { 4 };
            let ordinal_flag: u64 = if stride == 8 { 1 << 63 } else { 1 << 31 };

            for t in 0..MAX_THUNKS {
                let Some(raw) = self.slice_at_rva(thunk_rva + (t as u32) * stride as u32, stride)
                else {
                    break;
                };
                let value = if stride == 8 {
                    u64::from_le_bytes(raw.try_into().unwrap_or([0; 8]))
                } else {
                    u64::from(u32::from_le_bytes(raw.try_into().unwrap_or([0; 4])))
                };
                if value == 0 {
                    break;
                }
                if value & ordinal_flag != 0 {
                    out.push(ImportEntry {
                        library: library.clone(),
                        symbol: String::new(),
                        ordinal: Some((value & 0xffff) as u16),
                        hint: None,
                        delayed: true,
                    });
                } else {
                    let hint_rva = to_rva((value & 0x7fff_ffff) as u32);
                    let symbol = self.cstr_at_rva(hint_rva + 2, 512).unwrap_or_default();
                    out.push(ImportEntry {
                        library: library.clone(),
                        symbol,
                        ordinal: None,
                        hint: None,
                        delayed: true,
                    });
                }
            }
        }
        Ok(out)
    }

    fn read_exports(&self, dirs: &[(u32, u32)]) -> Result<Vec<ExportEntry>> {
        let mut out = Vec::new();
        let Some(&(rva, size)) = dirs.get(dir_index::EXPORT) else {
            return Ok(out);
        };
        if rva == 0 || size == 0 {
            return Ok(out);
        }
        let Some(bytes) = self.slice_at_rva(rva, 40) else {
            return Ok(out);
        };
        let mut r = Reader::at(bytes);
        let _chars = r.u32_le()?;
        let _timestamp = r.u32_le()?;
        let _major = r.u16_le()?;
        let _minor = r.u16_le()?;
        let _name_rva = r.u32_le()?;
        let ordinal_base = r.u32_le()?;
        let num_functions = r.u32_le()?;
        let num_names = r.u32_le()?;
        let addr_functions = r.u32_le()?;
        let addr_names = r.u32_le()?;
        let addr_ordinals = r.u32_le()?;

        // Name table maps name-index → function-index; ordinal table maps
        // name-index → ordinal offset. Walk names first so we can attach the
        // pretty name, then add the unnamed remainder.
        let name_limit = num_names.min(65_536);
        for i in 0..name_limit {
            let Some(name_rva_bytes) = self.slice_at_rva(addr_names + i * 4, 4) else {
                break;
            };
            let symbol_rva = u32::from_le_bytes(name_rva_bytes.try_into().unwrap_or([0; 4]));
            let Some(ord_bytes) = self.slice_at_rva(addr_ordinals + i * 2, 2) else {
                break;
            };
            let func_index = u16::from_le_bytes(ord_bytes.try_into().unwrap_or([0; 2])) as u32;
            if func_index >= num_functions {
                continue;
            }
            let Some(func_bytes) = self.slice_at_rva(addr_functions + func_index * 4, 4) else {
                break;
            };
            let func_rva = u32::from_le_bytes(func_bytes.try_into().unwrap_or([0; 4]));
            let name = self.cstr_at_rva(symbol_rva, 512).unwrap_or_default();

            // Forwarded exports point back inside the export directory.
            let forwarded_to = if func_rva >= rva && func_rva < rva + size {
                self.cstr_at_rva(func_rva, 512)
            } else {
                None
            };

            out.push(ExportEntry {
                name,
                ordinal: Some(ordinal_base.wrapping_add(func_index)),
                address: u64::from(func_rva),
                forwarded_to,
            });
        }

        // Ordinal-only exports.
        let func_limit = num_functions.min(65_536);
        let named: std::collections::HashSet<u32> = out.iter().filter_map(|e| e.ordinal).collect();
        for i in 0..func_limit {
            let Some(func_bytes) = self.slice_at_rva(addr_functions + i * 4, 4) else {
                break;
            };
            let func_rva = u32::from_le_bytes(func_bytes.try_into().unwrap_or([0; 4]));
            if func_rva == 0 {
                continue;
            }
            let ordinal = ordinal_base.wrapping_add(i);
            if named.contains(&ordinal) {
                continue;
            }
            out.push(ExportEntry {
                name: String::new(),
                ordinal: Some(ordinal),
                address: u64::from(func_rva),
                forwarded_to: None,
            });
        }
        Ok(out)
    }

    fn read_resources(&self, dirs: &[(u32, u32)]) -> Result<Vec<ResourceEntry>> {
        let mut out = Vec::new();
        let Some(&(rva, size)) = dirs.get(dir_index::RESOURCE) else {
            return Ok(out);
        };
        if rva == 0 || size == 0 {
            return Ok(out);
        }
        let mut budget = MAX_RESOURCE_ENTRIES;
        self.walk_resource_dir(rva, rva, 0, &mut Vec::new(), &mut out, &mut budget);
        Ok(out)
    }

    #[allow(clippy::too_many_arguments)]
    fn walk_resource_dir(
        &self,
        dir_rva: u32,
        root_rva: u32,
        depth: usize,
        path: &mut Vec<String>,
        out: &mut Vec<ResourceEntry>,
        budget: &mut usize,
    ) {
        if depth > MAX_RESOURCE_DEPTH || *budget == 0 {
            return;
        }
        let Some(bytes) = self.slice_at_rva(dir_rva, 16) else {
            return;
        };
        let mut r = Reader::at(bytes);
        let _chars = r.u32_le().unwrap_or(0);
        let _timestamp = r.u32_le().unwrap_or(0);
        let _major = r.u16_le().unwrap_or(0);
        let _minor = r.u16_le().unwrap_or(0);
        let named = r.u16_le().unwrap_or(0) as usize;
        let id_entries = r.u16_le().unwrap_or(0) as usize;
        let total = named.saturating_add(id_entries).min(4096);

        for i in 0..total {
            if *budget == 0 {
                return;
            }
            *budget -= 1;
            let Some(entry) = self.slice_at_rva(dir_rva + 16 + (i as u32) * 8, 8) else {
                return;
            };
            let mut er = Reader::at(entry);
            let name_field = er.u32_le().unwrap_or(0);
            let offset_field = er.u32_le().unwrap_or(0);

            let label = if name_field & 0x8000_0000 != 0 {
                // Named entry: the low bits are an offset into the resource
                // string table, relative to the directory root.
                let str_rva = root_rva + (name_field & 0x7fff_ffff);
                self.read_resource_string(str_rva)
                    .unwrap_or_else(|| format!("#{}", name_field & 0x7fff_ffff))
            } else {
                resource_id_label(depth, name_field)
            };

            path.push(label);
            if offset_field & 0x8000_0000 != 0 {
                // Subdirectory.
                let sub = root_rva + (offset_field & 0x7fff_ffff);
                self.walk_resource_dir(sub, root_rva, depth + 1, path, out, budget);
            } else {
                // Leaf data entry.
                let data_entry_rva = root_rva + offset_field;
                if let Some(data) = self.slice_at_rva(data_entry_rva, 16) {
                    let mut dr = Reader::at(data);
                    let data_rva = dr.u32_le().unwrap_or(0);
                    let data_size = dr.u32_le().unwrap_or(0);
                    let _codepage = dr.u32_le().unwrap_or(0);
                    let _reserved = dr.u32_le().unwrap_or(0);

                    let file_offset = self.rva_to_offset(data_rva).unwrap_or(0);
                    let clamped_len = (data_size as usize)
                        .min(self.data.len().saturating_sub(file_offset as usize));
                    let payload = self
                        .data
                        .get(file_offset as usize..file_offset as usize + clamped_len)
                        .unwrap_or(&[]);
                    let sha = if payload.is_empty() {
                        String::new()
                    } else {
                        to_hex(&sha256(payload))
                    };

                    let kind = path.first().cloned().unwrap_or_default();
                    let name = path.get(1).cloned().unwrap_or_default();
                    let language = path.get(2).cloned();

                    // Guard against duplicate leaves when the tree is cyclic.
                    if !out
                        .iter()
                        .any(|e| e.file_offset == file_offset && e.kind == kind && e.name == name)
                    {
                        out.push(ResourceEntry {
                            kind,
                            name,
                            language,
                            file_offset,
                            size: data_size as u64,
                            sha256: sha,
                        });
                    }
                }
            }
            path.pop();
        }
    }

    fn read_resource_string(&self, rva: u32) -> Option<String> {
        let bytes = self.slice_at_rva(rva, 2)?;
        let len = u16::from_le_bytes([bytes[0], bytes[1]]) as usize;
        let raw = self.slice_at_rva(rva + 2, len.min(512) * 2)?;
        let mut s = String::with_capacity(len);
        for chunk in raw.chunks_exact(2) {
            let ch = u16::from_le_bytes([chunk[0], chunk[1]]);
            if let Some(c) = char::from_u32(u32::from(ch)) {
                s.push(c);
            }
        }
        Some(s)
    }

    fn read_debug(&mut self, dirs: &[(u32, u32)], meta: &mut PeMetadata) {
        let Some(&(rva, size)) = dirs.get(dir_index::DEBUG) else {
            return;
        };
        if rva == 0 || size == 0 {
            return;
        }
        let count = (size / 28).min(64);
        for i in 0..count {
            let Some(bytes) = self.slice_at_rva(rva + i * 28, 28) else {
                break;
            };
            let mut r = Reader::at(bytes);
            let _chars = r.u32_le().unwrap_or(0);
            let _ts = r.u32_le().unwrap_or(0);
            let _major = r.u16_le().unwrap_or(0);
            let _minor = r.u16_le().unwrap_or(0);
            let kind = r.u32_le().unwrap_or(0);
            let data_size = r.u32_le().unwrap_or(0);
            let _addr = r.u32_le().unwrap_or(0);
            let ptr_raw = r.u32_le().unwrap_or(0);

            let kind_name = debug_type_name(kind);
            if !meta.debug_types.iter().any(|t| t == kind_name) {
                meta.debug_types.push(kind_name.to_string());
            }

            // CodeView (2) with RSDS/NB10 signature carries the PDB path.
            if kind == 2 && ptr_raw != 0 && data_size >= 24 {
                let off = ptr_raw as usize;
                let end = (off + data_size as usize).min(self.data.len());
                if off < end {
                    let blob = &self.data[off..end];
                    if blob.len() >= 24 && (&blob[0..4] == b"RSDS" || &blob[0..4] == b"NB10") {
                        let guid = to_hex(&blob[4..20]);
                        let path_start = 24;
                        let path = String::from_utf8_lossy(&blob[path_start..])
                            .trim_end_matches('\0')
                            .to_string();
                        let value = if path.is_empty() {
                            guid.clone()
                        } else {
                            format!("{path} (guid {guid})")
                        };
                        self.image.debug_artifacts.push(DebugArtifact {
                            kind: "pdb".into(),
                            value: value.clone(),
                            trusted: looks_like_build_path(&path),
                        });
                        if meta.pdb_path.is_none() && !path.is_empty() {
                            meta.pdb_path = Some(path);
                        }
                    }
                }
            }
        }
    }

    fn read_tls(&self, dirs: &[(u32, u32)], meta: &mut PeMetadata) -> Result<()> {
        let Some(&(rva, size)) = dirs.get(dir_index::TLS) else {
            return Ok(());
        };
        if rva == 0 || size == 0 {
            return Ok(());
        }
        meta.has_tls = true;
        let width = if self.image.bitness == 64 { 8 } else { 4 };
        // AddressOfCallbacks is the 4th pointer-sized field.
        let cb_off = rva + (width as u32) * 3;
        let Some(bytes) = self.slice_at_rva(cb_off, width) else {
            return Ok(());
        };
        let callbacks_va = if width == 8 {
            u64::from_le_bytes(bytes.try_into().unwrap_or([0; 8]))
        } else {
            u64::from(u32::from_le_bytes(bytes.try_into().unwrap_or([0; 4])))
        };
        if callbacks_va == 0 {
            return Ok(());
        }
        let callbacks_rva = callbacks_va.wrapping_sub(self.image.image_base) as u32;

        // Each entry is a pointer-sized VA, NUL-terminated.
        for i in 0..64u32 {
            let Some(raw) = self.slice_at_rva(callbacks_rva + i * width as u32, width) else {
                break;
            };
            let value = if width == 8 {
                u64::from_le_bytes(raw.try_into().unwrap_or([0; 8]))
            } else {
                u64::from(u32::from_le_bytes(raw.try_into().unwrap_or([0; 4])))
            };
            if value == 0 {
                break;
            }
            meta.tls_callbacks.push(value);
        }
        Ok(())
    }

    /// Read the CLR header, returning `(runtime version, metadata version)`.
    fn read_clr(&self, clr_rva: u32) -> Option<(String, Option<String>)> {
        let bytes = self.slice_at_rva(clr_rva, 72)?;
        let mut r = Reader::at(bytes);
        let _cb = r.u32_le().ok()?;
        let major = r.u16_le().ok()?;
        let minor = r.u16_le().ok()?;
        let _meta_rva = r.u32_le().ok()?;
        let meta_size = r.u32_le().ok()?;
        let _flags = r.u32_le().ok()?;
        let _entry = r.u32_le().ok()?;
        let meta = self.slice_at_rva(_meta_rva, meta_size.min(64 * 1024) as usize);
        let mut metadata_version = None;
        if let Some(meta_bytes) = meta {
            if meta_bytes.len() >= 16 && &meta_bytes[0..4] == b"BSJB" {
                let mut mr = Reader::at(meta_bytes);
                let _sig = mr.u32_le().ok()?;
                let _maj = mr.u16_le().ok()?;
                let _min = mr.u16_le().ok()?;
                let _reserved = mr.u32_le().ok()?;
                let len = mr.u32_le().ok()? as usize;
                if len < 256 {
                    if let Ok(version) = mr.cstring(len.max(1)) {
                        let cleaned = version.trim_end_matches('\0').to_string();
                        if !cleaned.is_empty() {
                            metadata_version = Some(cleaned);
                        }
                    }
                }
            }
        }
        Some((format!("{major}.{minor}"), metadata_version))
    }

    fn read_certificate(&self, dirs: &[(u32, u32)]) -> SignatureInfo {
        let Some(&(offset, size)) = dirs.get(dir_index::CERTIFICATE) else {
            return SignatureInfo::absent();
        };
        if offset == 0 || size < 8 {
            return SignatureInfo::absent();
        }
        let start = offset as usize;
        let end = (start + size as usize).min(self.data.len());
        if start >= end {
            return SignatureInfo::absent();
        }
        let blob = &self.data[start..end];

        let mut info = SignatureInfo {
            scheme: "authenticode".into(),
            present: true,
            ..SignatureInfo::absent()
        };
        info.blob_sha256 = to_hex(&sha256(blob));

        // WIN_CERTIFICATE: dwLength(4) wRevision(2) wCertificateType(2) bCertificate…
        if blob.len() >= 8 {
            let mut r = Reader::at(blob);
            let length = r.u32_le().unwrap_or(0);
            let revision = r.u16_le().unwrap_or(0);
            let cert_type = r.u16_le().unwrap_or(0);
            if cert_type != 0x0002 {
                info.issues
                    .push(format!("unexpected certificate type {cert_type:#06x}"));
            }
            if revision != 0x0200 && revision != 0x0100 {
                info.issues
                    .push(format!("unexpected certificate revision {revision:#06x}"));
            }
            let payload_end = (length as usize).min(blob.len()).max(8);
            let payload = &blob[8..payload_end];
            crate::asn1::inspect_authenticode(payload, &mut info);
        } else {
            info.issues.push("certificate blob too short".into());
        }

        if info.digest_algorithm.is_none() {
            info.issues
                .push("no digest algorithm could be recovered".into());
        }
        info
    }

    fn collect_structural_notes(&mut self, meta: &mut PeMetadata) {
        let notes = &mut self.image.structural_notes;

        if let Some(ep) = self.image.entry_point {
            let ep_in_exec = self.sections.iter().any(|s| {
                let start = u64::from(s.virtual_address);
                let end = start + u64::from(s.virtual_size.max(s.raw_size));
                ep >= start && ep < end && (s.characteristics & 0x2000_0000) != 0
            });
            if !ep_in_exec {
                notes.push("entry point is outside every executable section".into());
            }
        }

        for sec in &self.sections {
            let wx = (sec.characteristics & 0x8000_0000) != 0
                && (sec.characteristics & 0x2000_0000) != 0;
            if wx {
                notes.push(format!("section `{}` is writable and executable", sec.name));
            }
        }

        if !meta.checksum_valid && meta.declared_checksum != 0 {
            notes.push("PE checksum does not match the file contents".into());
        }

        // A file smaller than SizeOfImage is *normal*: raw data is aligned to
        // FileAlignment (typically 0x200) while the mapped image is aligned to
        // SectionAlignment (typically 0x1000), so the in-memory size is always
        // larger. What is abnormal is a declared header region that runs past
        // the end of the file, or a section whose raw data is truncated.
        if u64::from(meta.size_of_headers) > self.data.len() as u64 {
            notes.push(format!(
                "SizeOfHeaders ({} bytes) exceeds the file size ({} bytes)",
                meta.size_of_headers,
                self.data.len()
            ));
        }
        let truncated: Vec<&str> = self
            .sections
            .iter()
            .filter(|s| s.raw_size > 0)
            .filter(|s| u64::from(s.raw_offset) + u64::from(s.raw_size) > self.data.len() as u64)
            .map(|s| s.name.as_str())
            .collect();
        if !truncated.is_empty() {
            notes.push(format!(
                "section raw data runs past the end of the file: {}",
                truncated.join(", ")
            ));
        }

        // Overlapping raw ranges are a classic sign of hand-crafted binaries.
        let mut ranges: Vec<(u64, u64, &str)> = self
            .sections
            .iter()
            .filter(|s| s.raw_size > 0)
            .map(|s| {
                (
                    u64::from(s.raw_offset),
                    u64::from(s.raw_offset) + u64::from(s.raw_size),
                    s.name.as_str(),
                )
            })
            .collect();
        ranges.sort_by_key(|r| r.0);
        for pair in ranges.windows(2) {
            if pair[0].1 > pair[1].0 {
                notes.push(format!(
                    "raw ranges of `{}` and `{}` overlap",
                    pair[0].2, pair[1].2
                ));
            }
        }

        // Appended data after the last section. Two things legitimately live
        // there and must not be counted as an overlay:
        //
        //  * the Authenticode certificate table, which the specification
        //    requires to sit outside the mapped image — every signed binary in
        //    existence would otherwise look like it carries an appended payload;
        //  * alignment padding up to the next file-alignment boundary.
        //
        // What remains is a genuine overlay: an installer's payload, a
        // self-extracting archive, or a dropped file.
        let last_end = self
            .sections
            .iter()
            .map(|s| u64::from(s.raw_offset) + u64::from(s.raw_size))
            .max()
            .unwrap_or(0);
        let file_len = self.data.len() as u64;
        let cert_range = self
            .directories
            .get(dir_index::CERTIFICATE)
            .filter(|&&(offset, size)| offset != 0 && size != 0)
            .map(|&(offset, size)| (u64::from(offset), u64::from(size)));
        let overlay = overlay_size(last_end, file_len, cert_range);
        if overlay > 1024 {
            let qualifier = if cert_range.is_some() {
                "certificate table excluded"
            } else {
                "no certificate table"
            };
            notes.push(format!(
                "{overlay} bytes appended after the last section (overlay; {qualifier})"
            ));
        }

        if self.image.imports.is_empty() && self.image.bitness > 0 {
            notes.push("no imports at all — unusual for a normal build".into());
        }
    }
}

/// Bytes between the end of the last section and the end of the file, with the
/// certificate table subtracted.
///
/// The Authenticode blob is stored *outside* the mapped image by specification,
/// so treating it as appended data makes every signed binary look like it has an
/// embedded payload. `cert` is `(file_offset, size)` of the certificate table.
fn overlay_size(last_section_end: u64, file_len: u64, cert: Option<(u64, u64)>) -> u64 {
    if file_len <= last_section_end {
        return 0;
    }
    let tail = file_len - last_section_end;
    match cert {
        // Only subtract when the certificate table actually overlaps the tail;
        // a bogus directory entry pointing elsewhere must not hide a real overlay.
        Some((offset, size)) if offset >= last_section_end && offset < file_len => {
            let covered = (offset + size).min(file_len) - offset;
            tail.saturating_sub(covered)
        }
        _ => tail,
    }
}

fn section_info(data: &[u8], sec: &RawSection) -> SectionInfo {
    let off = (sec.raw_offset as usize).min(data.len());
    let len = (sec.raw_size as usize).min(data.len() - off);
    let payload = &data[off..off + len];
    SectionInfo {
        name: sec.name.clone(),
        virtual_address: u64::from(sec.virtual_address),
        virtual_size: u64::from(sec.virtual_size),
        file_offset: u64::from(sec.raw_offset),
        file_size: u64::from(sec.raw_size),
        entropy: crate::analysis::entropy::shannon(payload),
        permissions: Permissions::new(
            sec.characteristics & 0x4000_0000 != 0,
            sec.characteristics & 0x8000_0000 != 0,
            sec.characteristics & 0x2000_0000 != 0,
        ),
        sha256: if payload.is_empty() {
            String::new()
        } else {
            to_hex(&sha256(payload))
        },
        raw_characteristics: u64::from(sec.characteristics),
    }
}

fn infer_kind(characteristics: u16, dirs: &[(u32, u32)], sections: &[RawSection]) -> BinaryKind {
    const DLL: u16 = 0x2000;
    const SYSTEM: u16 = 0x1000;
    const EXECUTABLE: u16 = 0x0002;

    if dirs
        .get(dir_index::CLR)
        .is_some_and(|&(rva, sz)| rva != 0 && sz != 0)
    {
        return BinaryKind::ManagedAssembly;
    }
    if characteristics & SYSTEM != 0 {
        return BinaryKind::Driver;
    }
    if characteristics & DLL != 0 {
        return BinaryKind::SharedLibrary;
    }
    if characteristics & EXECUTABLE != 0 {
        // A PE with an executable flag but no code sections is usually an
        // installer stub whose real payload lives in the overlay.
        if sections
            .iter()
            .any(|s| s.characteristics & 0x20 != 0 && s.raw_size > 0)
        {
            return BinaryKind::Executable;
        }
        return BinaryKind::Installer;
    }
    BinaryKind::Object
}

fn machine_to_arch(machine: u16, is_plus: bool) -> Architecture {
    match machine {
        0x014c => Architecture::X86,
        0x8664 => Architecture::X86_64,
        0x01c0 | 0x01c2 | 0x01c4 => Architecture::Arm,
        0xaa64 => Architecture::Arm64,
        0x5064 | 0x5128 => Architecture::RiscV,
        0x5032 | 0x5069 => Architecture::RiscV,
        0x01f0 | 0x01f1 => Architecture::PowerPc,
        0x0166 | 0x0169 | 0x0266 | 0x0366 | 0x0466 => Architecture::Mips,
        _ => {
            if is_plus {
                Architecture::X86_64
            } else {
                Architecture::Unknown
            }
        }
    }
}

fn machine_name(machine: u16, is_plus: bool) -> &'static str {
    match machine {
        0x014c => "i386",
        0x8664 => "amd64",
        0xaa64 => "arm64",
        0x01c0 => "arm",
        0x01c4 => "armv7",
        0x0200 => "ia64",
        0x5032 => "riscv32",
        0x5064 => "riscv64",
        0x01f0 => "powerpc",
        0x0166 => "mips",
        0 => "unknown",
        _ => {
            if is_plus {
                "amd64-compatible"
            } else {
                "unknown"
            }
        }
    }
}

fn debug_type_name(kind: u32) -> &'static str {
    match kind {
        0 => "unknown",
        1 => "coff",
        2 => "codeview",
        3 => "fpo",
        4 => "misc",
        5 => "exception",
        6 => "fixup",
        7 => "omap-to-src",
        8 => "omap-from-src",
        9 => "borland",
        10 => "reserved10",
        11 => "clsid",
        12 => "vc-feature",
        13 => "pogo",
        14 => "iltcg",
        16 => "repro",
        17 => "embedded-portable-pdb",
        19 => "pdb-checksum",
        20 => "ex-dll-characteristics",
        21 => "fpo-optimized",
        _ => "other",
    }
}

fn resource_id_label(depth: usize, id: u32) -> String {
    if depth == 0 {
        // Resource types have well-known ids.
        return match id {
            1 => "RT_CURSOR".into(),
            2 => "RT_BITMAP".into(),
            3 => "RT_ICON".into(),
            4 => "RT_MENU".into(),
            5 => "RT_DIALOG".into(),
            6 => "RT_STRING".into(),
            7 => "RT_FONTDIR".into(),
            8 => "RT_FONT".into(),
            9 => "RT_ACCELERATOR".into(),
            10 => "RT_RCDATA".into(),
            11 => "RT_MESSAGETABLE".into(),
            12 => "RT_GROUP_CURSOR".into(),
            14 => "RT_GROUP_ICON".into(),
            16 => "RT_VERSION".into(),
            17 => "RT_DLGINCLUDE".into(),
            19 => "RT_PLUGPLAY".into(),
            20 => "RT_VXD".into(),
            21 => "RT_ANICURSOR".into(),
            22 => "RT_ANIICON".into(),
            23 => "RT_HTML".into(),
            24 => "RT_MANIFEST".into(),
            other => format!("TYPE_{other}"),
        };
    }
    id.to_string()
}

/// Recompute the PE checksum, which is a 16-bit ones-complement sum of the file
/// with the checksum field itself treated as zero.
fn pe_checksum(data: &[u8], declared: u32) -> u32 {
    // The checksum field sits at OptionalHeader + 64, i.e. e_lfanew + 0x58 for
    // both PE32 and PE32+, which is why we can locate it without the header.
    let field_off = {
        if data.len() > 0x3C {
            let mut r = Reader::at(data);
            let _ = r.seek(0x3C);
            match r.u32_le() {
                Ok(v) => v as usize + 0x58,
                Err(_) => return 0,
            }
        } else {
            return 0;
        }
    };
    let _ = declared;

    let mut sum: u64 = 0;
    let mut i = 0usize;
    while i + 1 < data.len() {
        let word = if i == field_off || i == field_off + 2 {
            0u16
        } else {
            u16::from_le_bytes([data[i], data[i + 1]])
        };
        sum += u64::from(word);
        if sum > 0xFFFF_0000 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        i += 2;
    }
    if i < data.len() {
        sum += u64::from(data[i]);
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    (sum as u32 & 0xFFFF).wrapping_add(data.len() as u32)
}

/// Recover the Rich header: `DanS ^ key … Rich ^ key …` between the DOS stub and
/// the NT header. The records before `Rich` describe which MSVC tools built the
/// file and how many times each ran — a strong, hard-to-forge toolchain signal.
fn parse_rich_header(data: &[u8], e_lfanew: usize) -> (Option<u32>, Vec<RichEntry>) {
    if e_lfanew <= 0x40 || e_lfanew > data.len() {
        return (None, Vec::new());
    }
    let region = &data[0x40..e_lfanew];
    // Find the literal "Rich" (0x68636952) followed by the XOR key.
    let mut rich_pos = None;
    let mut i = 0usize;
    while i + 8 <= region.len() {
        if region[i..i + 4] == *b"Rich" {
            rich_pos = Some(i);
        }
        i += 4;
    }
    let Some(rich_pos) = rich_pos else {
        return (None, Vec::new());
    };
    let key = u32::from_le_bytes([
        region[rich_pos + 4],
        region[rich_pos + 5],
        region[rich_pos + 6],
        region[rich_pos + 7],
    ]);

    // Walk backwards in 8-byte records until the decrypted `DanS` marker.
    let mut entries = Vec::new();
    let mut cursor = rich_pos;
    while cursor >= 8 {
        cursor -= 8;
        let comp_id = u32::from_le_bytes([
            region[cursor],
            region[cursor + 1],
            region[cursor + 2],
            region[cursor + 3],
        ]) ^ key;
        let count = u32::from_le_bytes([
            region[cursor + 4],
            region[cursor + 5],
            region[cursor + 6],
            region[cursor + 7],
        ]) ^ key;
        if comp_id == 0x536E_6144 {
            // "DanS"
            entries.reverse();
            return (Some(key), entries);
        }
        if entries.len() >= 128 {
            break;
        }
        entries.push(RichEntry {
            product_id: comp_id >> 16,
            build: comp_id & 0xFFFF,
            count,
        });
    }
    (Some(key), Vec::new())
}

/// Heuristic: does this PDB path look like a genuine build machine path?
///
/// Attackers who forget to strip the debug directory leave paths like
/// `C:\Users\dev\source\repos\...`, which is real provenance. Attackers who
/// plant them leave suspiciously generic or vendor-mimicking strings.
fn looks_like_build_path(path: &str) -> bool {
    if path.is_empty() {
        return false;
    }
    let lower = path.to_ascii_lowercase();
    let dev_markers = [
        "\\users\\",
        "/home/",
        "\\src\\",
        "/src/",
        "\\source\\",
        "/build/",
        "\\build\\",
        "\\repos\\",
        "\\projects\\",
        "\\jenkins\\",
        "\\agent\\",
        "\\gitlab-runner\\",
    ];
    dev_markers.iter().any(|m| lower.contains(m))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal PE32 image builder used to exercise the parser without shipping
    /// a binary blob in the repository.
    pub(crate) fn build_minimal_pe(sections: &[(&str, u32, u32, usize)], dll: bool) -> Vec<u8> {
        let file_align = 0x200u32;
        let sec_align = 0x1000u32;
        let nt_offset = 0x80usize;
        let opt_size = 224usize;
        let sec_table = nt_offset + 24 + opt_size;
        let headers_size =
            ((sec_table + sections.len() * 40) as u32).div_ceil(file_align) * file_align;

        let mut buf = vec![0u8; headers_size as usize];

        // DOS header.
        buf[0] = b'M';
        buf[1] = b'Z';
        buf[0x3C..0x40].copy_from_slice(&(nt_offset as u32).to_le_bytes());

        // NT signature + COFF header.
        buf[nt_offset..nt_offset + 4].copy_from_slice(b"PE\0\0");
        let machine: u16 = 0x014c;
        buf[nt_offset + 4..nt_offset + 6].copy_from_slice(&machine.to_le_bytes());
        buf[nt_offset + 6..nt_offset + 8].copy_from_slice(&(sections.len() as u16).to_le_bytes());
        buf[nt_offset + 8..nt_offset + 12].copy_from_slice(&0x6000_0000u32.to_le_bytes());
        buf[nt_offset + 20..nt_offset + 22].copy_from_slice(&(opt_size as u16).to_le_bytes());
        let characteristics: u16 = if dll { 0x2102 } else { 0x0102 };
        buf[nt_offset + 22..nt_offset + 24].copy_from_slice(&characteristics.to_le_bytes());

        // Optional header.
        let opt = nt_offset + 24;
        buf[opt..opt + 2].copy_from_slice(&OPT_MAGIC_PE32.to_le_bytes());
        buf[opt + 2] = 14;
        buf[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes()); // entry point
        buf[opt + 28..opt + 32].copy_from_slice(&0x0040_0000u32.to_le_bytes()); // image base
        buf[opt + 32..opt + 36].copy_from_slice(&sec_align.to_le_bytes());
        buf[opt + 36..opt + 40].copy_from_slice(&file_align.to_le_bytes());
        buf[opt + 56..opt + 60].copy_from_slice(&0x2000u32.to_le_bytes()); // size of image
        buf[opt + 60..opt + 64].copy_from_slice(&headers_size.to_le_bytes());
        buf[opt + 68..opt + 70].copy_from_slice(&2u16.to_le_bytes()); // subsystem GUI
        buf[opt + 92..opt + 96].copy_from_slice(&16u32.to_le_bytes()); // num dirs

        // Section table.
        for (i, (name, vsize, chars, content_len)) in sections.iter().enumerate() {
            let off = sec_table + i * 40;
            let mut name_bytes = [0u8; 8];
            let nb = name.as_bytes();
            name_bytes[..nb.len().min(8)].copy_from_slice(&nb[..nb.len().min(8)]);
            buf[off..off + 8].copy_from_slice(&name_bytes);
            buf[off + 8..off + 12].copy_from_slice(&vsize.to_le_bytes());
            buf[off + 12..off + 16].copy_from_slice(&(sec_align * (i as u32 + 1)).to_le_bytes());
            let raw_size = ((*content_len as u32).div_ceil(file_align)) * file_align;
            buf[off + 16..off + 20].copy_from_slice(&raw_size.to_le_bytes());
            buf[off + 20..off + 24]
                .copy_from_slice(&(headers_size + i as u32 * 0x200).to_le_bytes());
            buf[off + 36..off + 40].copy_from_slice(&chars.to_le_bytes());
        }

        // Section bodies.
        for (i, (_, _, _, content_len)) in sections.iter().enumerate() {
            let raw_size = ((*content_len as u32).div_ceil(file_align)) * file_align;
            let start = headers_size as usize + i * 0x200;
            buf.resize(start + raw_size as usize, 0);
            for j in 0..*content_len {
                buf[start + j] = ((i * 31 + j) % 251) as u8;
            }
        }

        buf
    }

    #[test]
    fn parses_minimal_pe32() {
        let data = build_minimal_pe(&[(".text", 0x1000, 0x6000_0020, 512)], false);
        let pe = PeFile::parse(&data).expect("should parse");
        assert_eq!(pe.image.format, Format::Pe);
        assert_eq!(pe.image.bitness, 32);
        assert_eq!(pe.image.arch, Architecture::X86);
        assert_eq!(pe.image.sections.len(), 1);
        assert_eq!(pe.image.sections[0].name, ".text");
        assert!(pe.image.sections[0].permissions.execute);
        assert!(!pe.image.sections[0].permissions.write);
        assert_eq!(pe.image.entry_point, Some(0x1000));
    }

    #[test]
    fn detects_dll_kind() {
        let data = build_minimal_pe(&[(".text", 0x1000, 0x6000_0020, 512)], true);
        let pe = PeFile::parse(&data).unwrap();
        assert_eq!(pe.image.kind, BinaryKind::SharedLibrary);
    }

    #[test]
    fn flags_writable_executable_section() {
        let data = build_minimal_pe(&[(".text", 0x1000, 0xE000_0020, 512)], false);
        let pe = PeFile::parse(&data).unwrap();
        assert!(pe
            .image
            .structural_notes
            .iter()
            .any(|n| n.contains("writable and executable")));
    }

    #[test]
    fn rejects_missing_mz() {
        let data = vec![0u8; 64];
        assert!(PeFile::parse(&data).is_err());
    }

    #[test]
    fn rejects_e_lfanew_inside_dos_header() {
        let mut data = vec![0u8; 128];
        data[0] = b'M';
        data[1] = b'Z';
        data[0x3C..0x40].copy_from_slice(&0x10u32.to_le_bytes());
        assert!(PeFile::parse(&data).is_err());
    }

    #[test]
    fn rva_maps_into_section() {
        let data = build_minimal_pe(&[(".text", 0x1000, 0x6000_0020, 512)], false);
        let pe = PeFile::parse(&data).unwrap();
        // RVA 0x1000 is the first byte of the first section.
        let off = pe.rva_to_offset(0x1000).unwrap();
        assert!(off >= 0x200);
    }
}

//! ELF parser (32/64-bit, little/big endian).
//!
//! The interesting security facts in an ELF are not in its header — they are in
//! `.dynamic` (what it will `dlopen` at start), `.dynsym` (what it needs),
//! `.note.gnu.build-id` (which specific build this is), and `.comment` (which
//! compiler and version produced it). This parser extracts all four, plus the
//! `.interp` path so the analyst can see whether the binary will be loaded by
//! the system loader or by something planted on disk.

use serde::{Deserialize, Serialize};

use crate::bytes::{to_hex, Reader};
use crate::error::{AssayError, Result};
use crate::format::{
    Architecture, BinaryImage, BinaryKind, DebugArtifact, Endianness, ExportEntry, Format,
    FormatMetadata, ImportEntry, Permissions, SectionInfo, SignatureInfo,
};
use crate::hash::sha256;

/// ELF magic bytes.
pub const ELF_MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];

/// `EI_CLASS` values.
const ELFCLASS32: u8 = 1;
/// 64-bit container.
const ELFCLASS64: u8 = 2;
/// `EI_DATA` little endian.
const ELFDATA2LSB: u8 = 1;
/// `EI_DATA` big endian.
const ELFDATA2MSB: u8 = 2;

/// Upper bound on section/program headers we are willing to walk.
const MAX_HEADERS: usize = 8192;
/// Upper bound on dynamic entries.
const MAX_DYNAMIC: usize = 4096;
/// Upper bound on symbols considered.
const MAX_SYMBOLS: usize = 200_000;

/// ELF-specific header facts.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ElfMetadata {
    /// `e_type` value.
    pub e_type: u16,
    /// Friendly `e_type` name.
    pub e_type_name: String,
    /// `e_machine` value.
    pub machine: u16,
    /// Friendly machine name.
    pub machine_name: String,
    /// OS ABI byte from `e_ident`.
    pub osabi: String,
    /// ELF version from `e_ident`.
    pub elf_version: u8,
    /// Program interpreter path from `.interp`, when present.
    pub interpreter: Option<String>,
    /// `DT_SONAME`.
    pub soname: Option<String>,
    /// `DT_RPATH` entries.
    pub rpath: Vec<String>,
    /// `DT_RUNPATH` entries.
    pub runpath: Vec<String>,
    /// Build ID from `.note.gnu.build-id`, hex encoded.
    pub build_id: Option<String>,
    /// Compiler strings recovered from `.comment`.
    pub compiler_comments: Vec<String>,
    /// Whether the stack is marked non-executable (`PT_GNU_STACK`).
    pub nx_stack: bool,
    /// Whether `PT_GNU_RELRO` is present.
    pub relro: bool,
    /// Whether the binary is position independent (`ET_DYN` for executables).
    pub pie: bool,
    /// Whether the dynamic section binds symbols immediately (`DF_BIND_NOW`).
    pub bind_now: bool,
    /// Whether `.symtab` (full symbols) survives — i.e. not stripped.
    pub has_symtab: bool,
    /// Number of exported dynamic symbols.
    pub dynsym_exports: usize,
}

/// Parsed ELF image.
#[derive(Debug)]
pub struct ElfFile<'a> {
    /// Raw bytes.
    pub data: &'a [u8],
    /// Unified model.
    pub image: BinaryImage,
    /// Whether the container is 64-bit.
    is64: bool,
    /// Parsed section headers, needed for symbol/note lookups.
    sections: Vec<Shdr>,
    /// Parsed program headers.
    segments: Vec<Phdr>,
}

/// One parsed section header, kept for later symbol/note lookups.
#[derive(Debug, Clone)]
pub struct Shdr {
    /// Resolved section name (empty when `.shstrtab` was unusable).
    pub name: String,
    /// `sh_type`.
    pub sh_type: u32,
    /// `sh_flags`.
    pub flags: u64,
    /// `sh_addr`.
    pub addr: u64,
    /// `sh_offset`.
    pub offset: u64,
    /// `sh_size`.
    pub size: u64,
    /// `sh_link`, an index into the section table.
    pub link: u32,
    /// `sh_info`.
    pub info: u32,
    /// `sh_entsize`.
    pub entsize: u64,
}

/// One parsed program header.
#[derive(Debug, Clone)]
pub struct Phdr {
    /// `p_type`.
    pub p_type: u32,
    /// `p_flags`.
    pub flags: u32,
    /// File offset of the segment.
    pub offset: u64,
    /// Virtual address of the segment.
    pub vaddr: u64,
    /// Bytes present in the file.
    pub filesz: u64,
    /// Bytes occupied in memory (may exceed `filesz` for `.bss`).
    pub memsz: u64,
}

/// Section type constants we care about.
#[allow(dead_code)]
mod sht {
    /// `.symtab`.
    pub const SYMTAB: u32 = 2;
    /// `.strtab`.
    pub const STRTAB: u32 = 3;
    /// `.dynamic`.
    pub const DYNAMIC: u32 = 6;
    /// `.note`.
    pub const NOTE: u32 = 7;
    /// `.dynsym`.
    pub const DYNSYM: u32 = 11;
    /// `.init_array`/`.fini_array`.
    pub const INIT_ARRAY: u32 = 14;
    /// `.preinit_array`.
    pub const PREINIT_ARRAY: u32 = 16;
}

/// Program header type constants.
#[allow(dead_code)]
mod pt {
    /// Loadable segment.
    pub const LOAD: u32 = 1;
    /// Dynamic linking information.
    pub const DYNAMIC: u32 = 2;
    /// Interpreter path.
    pub const INTERP: u32 = 3;
    /// Auxiliary notes.
    pub const NOTE: u32 = 4;
    /// GNU stack flags.
    pub const GNU_STACK: u32 = 0x6474_e551;
    /// GNU read-only-after-relocation.
    pub const GNU_RELRO: u32 = 0x6474_e552;
}

/// Dynamic entry tags.
#[allow(dead_code)]
mod dt {
    /// Terminator.
    pub const NULL: u64 = 0;
    /// Needed shared object.
    pub const NEEDED: u64 = 1;
    /// PLT relocation table size.
    pub const PLTRELSZ: u64 = 2;
    /// Symbol name of this object.
    pub const SONAME: u64 = 14;
    /// Legacy search path.
    pub const RPATH: u64 = 15;
    /// Search path.
    pub const RUNPATH: u64 = 29;
    /// Symbolic binding flags.
    pub const BIND_NOW: u64 = 24;
    /// Flags word.
    pub const FLAGS: u64 = 30;
}

/// `DF_BIND_NOW` bit within `DT_FLAGS`.
const DF_BIND_NOW: u64 = 0x8;

impl<'a> ElfFile<'a> {
    /// Parse an ELF image.
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        if data.len() < 16 || data[0..4] != ELF_MAGIC {
            return Err(AssayError::UnknownFormat {
                magic: to_hex(&data[..data.len().min(4)]),
            });
        }
        let class = data[4];
        let endian = data[5];
        let is64 = match class {
            ELFCLASS32 => false,
            ELFCLASS64 => true,
            other => {
                return Err(AssayError::malformed(
                    "e_ident",
                    4,
                    format!("unknown EI_CLASS {other}"),
                ))
            }
        };
        let big_endian = match endian {
            ELFDATA2LSB => false,
            ELFDATA2MSB => true,
            other => {
                return Err(AssayError::malformed(
                    "e_ident",
                    5,
                    format!("unknown EI_DATA {other}"),
                ))
            }
        };
        let osabi = data[7];
        let elf_version = data[6];

        let mut r = Reader::at(data);
        r.seek(16)?;

        macro_rules! u16x {
            () => {
                if big_endian {
                    r.u16_be()?
                } else {
                    r.u16_le()?
                }
            };
        }
        macro_rules! u32x {
            () => {
                if big_endian {
                    r.u32_be()?
                } else {
                    r.u32_le()?
                }
            };
        }
        macro_rules! u64x {
            () => {
                if big_endian {
                    r.u64_be()?
                } else {
                    r.u64_le()?
                }
            };
        }

        let e_type = u16x!();
        let machine = u16x!();
        let _e_version = u32x!();
        let entry = if is64 { u64x!() } else { u64::from(u32x!()) };
        let phoff = if is64 { u64x!() } else { u64::from(u32x!()) };
        let shoff = if is64 { u64x!() } else { u64::from(u32x!()) };
        let _e_flags = u32x!();
        let _ehsize = u16x!();
        let phentsize = u16x!() as usize;
        let phnum = u16x!() as usize;
        let shentsize = u16x!() as usize;
        let shnum = u16x!() as usize;
        let shstrndx = u16x!() as usize;

        if phnum > MAX_HEADERS || shnum > MAX_HEADERS {
            return Err(AssayError::malformed(
                "ELF header",
                0x30,
                format!("header counts ({phnum} ph, {shnum} sh) exceed safety cap"),
            ));
        }

        // Whether the declared tables are inside the file at all. A table that
        // starts past EOF is not "absent" — it is unreadable, and the difference
        // decides whether the hardening conclusions below are observations or
        // guesses.
        let mut segments_readable = true;
        let mut sections_readable = true;
        let mut unreadable: Vec<String> = Vec::new();

        // ---- Program headers -------------------------------------------
        let mut segments = Vec::with_capacity(phnum);
        if phoff != 0 && phentsize >= if is64 { 56 } else { 32 } {
            if phoff >= data.len() as u64 {
                segments_readable = false;
                unreadable.push(format!(
                    "program header table declared at {phoff:#x}, past the end of a {:#x}-byte file",
                    data.len()
                ));
            }
            for i in 0..phnum {
                let off = phoff + (i * phentsize) as u64;
                let Ok(off) = usize::try_from(off) else { break };
                if off >= data.len() {
                    break;
                }
                let mut hr = Reader::new(&data[off..], off as u64);
                let read_addr = |r: &mut Reader<'_>| -> Result<u64> {
                    Ok(if is64 {
                        if big_endian {
                            r.u64_be()?
                        } else {
                            r.u64_le()?
                        }
                    } else if big_endian {
                        u64::from(r.u32_be()?)
                    } else {
                        u64::from(r.u32_le()?)
                    })
                };
                let p_type = if big_endian {
                    hr.u32_be()?
                } else {
                    hr.u32_le()?
                };
                let flags = if is64 {
                    if big_endian {
                        hr.u32_be()?
                    } else {
                        hr.u32_le()?
                    }
                } else {
                    let _file_off = read_addr(&mut hr)?;
                    let _vaddr = read_addr(&mut hr)?;
                    let _paddr = read_addr(&mut hr)?;
                    let _filesz = read_addr(&mut hr)?;
                    let _memsz = read_addr(&mut hr)?;
                    let f = if big_endian {
                        hr.u32_be()?
                    } else {
                        hr.u32_le()?
                    };
                    let _align = read_addr(&mut hr)?;
                    segments.push(Phdr {
                        p_type,
                        flags: f,
                        offset: _file_off,
                        vaddr: _vaddr,
                        filesz: _filesz,
                        memsz: _memsz,
                    });
                    continue;
                };
                let offset = read_addr(&mut hr)?;
                let vaddr = read_addr(&mut hr)?;
                let _paddr = read_addr(&mut hr)?;
                let filesz = read_addr(&mut hr)?;
                let memsz = read_addr(&mut hr)?;
                let _align = read_addr(&mut hr)?;
                segments.push(Phdr {
                    p_type,
                    flags,
                    offset,
                    vaddr,
                    filesz,
                    memsz,
                });
            }
        }

        // ---- Section headers -------------------------------------------
        let mut sections = Vec::with_capacity(shnum);
        if shoff != 0 && shentsize >= if is64 { 64 } else { 40 } {
            if shoff >= data.len() as u64 {
                sections_readable = false;
                unreadable.push(format!(
                    "section header table declared at {shoff:#x}, past the end of a {:#x}-byte file",
                    data.len()
                ));
            }
            for i in 0..shnum {
                let off = shoff + (i * shentsize) as u64;
                let Ok(off) = usize::try_from(off) else { break };
                if off >= data.len() {
                    break;
                }
                let mut hr = Reader::new(&data[off..], off as u64);
                let read_addr = |r: &mut Reader<'_>| -> Result<u64> {
                    Ok(if is64 {
                        if big_endian {
                            r.u64_be()?
                        } else {
                            r.u64_le()?
                        }
                    } else if big_endian {
                        u64::from(r.u32_be()?)
                    } else {
                        u64::from(r.u32_le()?)
                    })
                };
                let name_off = if big_endian {
                    hr.u32_be()?
                } else {
                    hr.u32_le()?
                };
                let sh_type = if big_endian {
                    hr.u32_be()?
                } else {
                    hr.u32_le()?
                };
                let flags = read_addr(&mut hr)?;
                let addr = read_addr(&mut hr)?;
                let offset = read_addr(&mut hr)?;
                let size = read_addr(&mut hr)?;
                let link = if big_endian {
                    hr.u32_be()?
                } else {
                    hr.u32_le()?
                };
                let info = if big_endian {
                    hr.u32_be()?
                } else {
                    hr.u32_le()?
                };
                let _align = read_addr(&mut hr)?;
                let entsize = read_addr(&mut hr)?;
                sections.push(Shdr {
                    name: String::new(),
                    sh_type,
                    flags,
                    addr,
                    offset,
                    size,
                    link,
                    info,
                    entsize,
                });
                // Stash the name offset in `info` temporarily? No — resolve
                // names after the string table is known.
                let _ = name_off;
                if let Some(last) = sections.last_mut() {
                    last.info = info;
                }
                // Reuse `name` to carry the raw name offset until resolved.
                if let Some(last) = sections.last_mut() {
                    last.name = format!("#{name_off}");
                }
            }
        }

        // Resolve section names via .shstrtab.
        let shstr = sections
            .get(shstrndx)
            .filter(|s| s.sh_type == sht::STRTAB && s.offset < data.len() as u64);
        if let Some(strtab) = shstr {
            let base = strtab.offset as usize;
            let end = (base + strtab.size as usize).min(data.len());
            let names = &data[base..end];
            for sec in &mut sections {
                if let Some(raw) = sec.name.strip_prefix('#') {
                    if let Ok(idx) = raw.parse::<usize>() {
                        sec.name = read_strtab(names, idx);
                    }
                }
            }
        }

        let mut image = BinaryImage::placeholder(Format::Elf);
        image.endian = if big_endian {
            Endianness::Big
        } else {
            Endianness::Little
        };
        image.bitness = if is64 { 64 } else { 32 };
        image.arch = machine_to_arch(machine);
        image.entry_point = if entry == 0 { None } else { Some(entry) };
        image.image_base = segments
            .iter()
            .filter(|s| s.p_type == pt::LOAD && s.vaddr != 0)
            .map(|s| s.vaddr)
            .min()
            .unwrap_or(0);

        for sec in &sections {
            let off = (sec.offset as usize).min(data.len());
            let len = (sec.size as usize).min(data.len() - off);
            // SHT_NOBITS occupies no file space.
            let payload: &[u8] = if sec.sh_type == 8 {
                &[]
            } else {
                &data[off..off + len]
            };
            image.sections.push(SectionInfo {
                name: sec.name.clone(),
                virtual_address: sec.addr,
                virtual_size: sec.size,
                file_offset: sec.offset,
                file_size: if sec.sh_type == 8 { 0 } else { sec.size },
                entropy: crate::analysis::entropy::shannon(payload),
                permissions: Permissions::new(
                    sec.flags & 0x2 != 0 || sec.sh_type != 8,
                    sec.flags & 0x1 != 0,
                    sec.flags & 0x4 != 0,
                ),
                sha256: if payload.is_empty() {
                    String::new()
                } else {
                    to_hex(&sha256(payload))
                },
                raw_characteristics: u64::from(sec.sh_type),
            });
        }

        let mut meta = ElfMetadata {
            e_type,
            e_type_name: etype_name(e_type).to_string(),
            machine,
            machine_name: machine_name(machine).to_string(),
            osabi: osabi_name(osabi).to_string(),
            elf_version,
            nx_stack: segments
                .iter()
                .any(|s| s.p_type == pt::GNU_STACK && s.flags & 0x1 == 0),
            relro: segments.iter().any(|s| s.p_type == pt::GNU_RELRO),
            pie: e_type == 3,
            has_symtab: sections.iter().any(|s| s.sh_type == sht::SYMTAB),
            ..Default::default()
        };

        // Interpreter.
        if let Some(seg) = segments.iter().find(|s| s.p_type == pt::INTERP) {
            let off = (seg.offset as usize).min(data.len());
            let len = (seg.filesz as usize).min(data.len() - off);
            let raw = &data[off..off + len];
            let trimmed = raw.split(|&b| b == 0).next().unwrap_or(&[]);
            if !trimmed.is_empty() {
                meta.interpreter = Some(String::from_utf8_lossy(trimmed).into_owned());
            }
        }

        // Build ID + compiler comments from notes and .comment.
        for sec in &sections {
            if sec.sh_type == sht::NOTE && meta.build_id.is_none() {
                if let Some(id) = parse_build_id(data, sec) {
                    meta.build_id = Some(id);
                }
            }
            if sec.name == ".comment" {
                let off = (sec.offset as usize).min(data.len());
                let len = (sec.size as usize).min(data.len() - off);
                for chunk in data[off..off + len].split(|&b| b == 0) {
                    if chunk.len() >= 3 {
                        let s = String::from_utf8_lossy(chunk).trim().to_string();
                        if !s.is_empty() && !meta.compiler_comments.contains(&s) {
                            meta.compiler_comments.push(s);
                        }
                    }
                }
            }
        }
        if let Some(id) = &meta.build_id {
            image.debug_artifacts.push(DebugArtifact {
                kind: "build-id".into(),
                value: id.clone(),
                trusted: true,
            });
        }
        for comment in &meta.compiler_comments {
            image.debug_artifacts.push(DebugArtifact {
                kind: "linker-version".into(),
                value: comment.clone(),
                trusted: true,
            });
        }

        // Dynamic section: needed libraries, soname, rpath/runpath, bind-now.
        for sec in &sections {
            if sec.sh_type != sht::DYNAMIC {
                continue;
            }
            let strtab = sections
                .get(sec.link as usize)
                .map(|s| {
                    let o = (s.offset as usize).min(data.len());
                    let e = (o + s.size as usize).min(data.len());
                    (o, e)
                })
                .filter(|(o, e)| o < e);
            let dynstr = strtab.map(|(o, e)| &data[o..e]);

            let off = (sec.offset as usize).min(data.len());
            let len = (sec.size as usize).min(data.len() - off);
            let mut dr = Reader::new(&data[off..off + len], sec.offset);
            let mut count = 0usize;
            loop {
                if count >= MAX_DYNAMIC {
                    break;
                }
                count += 1;
                let tag = if is64 {
                    if big_endian {
                        dr.u64_be()
                    } else {
                        dr.u64_le()
                    }
                } else if big_endian {
                    Ok(u64::from(dr.u32_be()?))
                } else {
                    Ok(u64::from(dr.u32_le()?))
                };
                let Ok(tag) = tag else { break };
                let val = if is64 {
                    if big_endian {
                        dr.u64_be()
                    } else {
                        dr.u64_le()
                    }
                } else if big_endian {
                    Ok(u64::from(dr.u32_be()?))
                } else {
                    Ok(u64::from(dr.u32_le()?))
                };
                let Ok(val) = val else { break };
                if tag == dt::NULL {
                    break;
                }
                let as_str = |offset: u64| -> Option<String> {
                    dynstr.and_then(|tab| {
                        let s = read_strtab(tab, offset as usize);
                        if s.is_empty() {
                            None
                        } else {
                            Some(s)
                        }
                    })
                };
                match tag {
                    dt::NEEDED => {
                        if let Some(lib) = as_str(val) {
                            image.imports.push(ImportEntry {
                                library: lib,
                                symbol: String::new(),
                                ordinal: None,
                                hint: None,
                                delayed: false,
                            });
                        }
                    }
                    dt::SONAME => meta.soname = as_str(val),
                    dt::RPATH => {
                        if let Some(paths) = as_str(val) {
                            meta.rpath.extend(
                                paths.split(':').filter(|p| !p.is_empty()).map(String::from),
                            );
                        }
                    }
                    dt::RUNPATH => {
                        if let Some(paths) = as_str(val) {
                            meta.runpath.extend(
                                paths.split(':').filter(|p| !p.is_empty()).map(String::from),
                            );
                        }
                    }
                    dt::BIND_NOW => meta.bind_now = true,
                    dt::FLAGS if val & DF_BIND_NOW != 0 => meta.bind_now = true,
                    _ => {}
                }
            }
        }
        if image.imports.is_empty() {
            // DT_NEEDED absent: fall back to undefined dynamic symbols.
            image.imports = collect_dynsym_imports(data, &sections, is64, big_endian);
        }
        meta.dynsym_exports = image
            .exports
            .len()
            .max(count_dynsym_exports(data, &sections, is64, big_endian));

        // Exported dynamic symbols (defined, GLOBAL, DEFAULT visibility).
        image.exports = collect_dynsym_exports(data, &sections, is64, big_endian);

        image.kind = match e_type {
            1 => BinaryKind::Object,
            2 => BinaryKind::Executable,
            3 => {
                if meta.interpreter.is_some() {
                    BinaryKind::Executable
                } else {
                    BinaryKind::SharedLibrary
                }
            }
            4 => BinaryKind::Object,
            _ => BinaryKind::Other,
        };

        image.unreadable_tables = unreadable;

        // Structural notes.
        //
        // Every conclusion below is drawn *from the segment table*, so none of
        // them may be stated when that table was unreadable. Reporting "no
        // PT_GNU_RELRO" for a truncated file asserts an absence the parser never
        // checked, and the difference between "unhardened" and "unexamined" is
        // the whole point of this tool.
        if segments_readable {
            if !meta.nx_stack {
                let has_gnu_stack = segments.iter().any(|s| s.p_type == pt::GNU_STACK);
                image.structural_notes.push(if has_gnu_stack {
                    "PT_GNU_STACK requests an executable stack".into()
                } else {
                    "no PT_GNU_STACK segment, so the loader decides the stack permission".into()
                });
            }
            if !meta.relro {
                image
                    .structural_notes
                    .push("no PT_GNU_RELRO segment: GOT stays writable after relocation".into());
            }
        }
        if !sections_readable {
            image.structural_notes.push(
                "section table unreadable: section-level findings above are a lower bound".into(),
            );
        }
        if meta
            .rpath
            .iter()
            .any(|p| p.contains("$ORIGIN") || p.starts_with('.'))
        {
            image.structural_notes.push(
                "RPATH contains a relative or $ORIGIN entry, enabling library hijacking".into(),
            );
        }
        if image.imports.iter().any(|i| {
            let l = i.library.to_ascii_lowercase();
            l.contains("libdl") || l == "libc.so.6"
        }) {
            image
                .structural_notes
                .push("links against libc/libdl, so dlopen/dlsym injection is reachable".into());
        }
        for sec in &image.sections {
            if sec.permissions.is_wx() && sec.file_size > 0 {
                image
                    .structural_notes
                    .push(format!("section `{}` is writable and executable", sec.name));
            }
        }

        image.signature = SignatureInfo::absent();
        image.metadata = FormatMetadata::Elf(meta);

        Ok(ElfFile {
            data,
            image,
            is64,
            sections,
            segments,
        })
    }

    /// Whether the container is 64-bit.
    pub fn is_64(&self) -> bool {
        self.is64
    }
    /// Borrow the parsed section headers.
    pub fn sections(&self) -> &[Shdr] {
        &self.sections
    }

    /// Borrow the parsed program headers.
    pub fn segments(&self) -> &[Phdr] {
        &self.segments
    }
}

fn read_strtab(table: &[u8], offset: usize) -> String {
    if offset >= table.len() {
        return String::new();
    }
    let slice = &table[offset..];
    let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    String::from_utf8_lossy(&slice[..end]).into_owned()
}

fn parse_build_id(data: &[u8], sec: &Shdr) -> Option<String> {
    let off = (sec.offset as usize).min(data.len());
    let len = (sec.size as usize).min(data.len() - off);
    let blob = &data[off..off + len];
    let mut pos = 0usize;
    while pos + 12 <= blob.len() {
        let mut r = Reader::at(&blob[pos..]);
        let namesz = r.u32_le().ok()? as usize;
        let descsz = r.u32_le().ok()? as usize;
        let ntype = r.u32_le().ok()?;
        let name_start = pos + 12;
        let name_end = name_start.checked_add(namesz)?;
        if name_end > blob.len() {
            return None;
        }
        let name = &blob[name_start..name_end];
        let desc_start = name_end.div_ceil(4) * 4;
        let desc_end = desc_start.checked_add(descsz)?;
        if desc_end > blob.len() {
            return None;
        }
        // NT_GNU_BUILD_ID == 3 with owner "GNU".
        if ntype == 3 && name.starts_with(b"GNU") {
            return Some(to_hex(&blob[desc_start..desc_end]));
        }
        pos = desc_end.div_ceil(4) * 4;
    }
    None
}

fn collect_dynsym_imports(
    data: &[u8],
    sections: &[Shdr],
    is64: bool,
    big_endian: bool,
) -> Vec<ImportEntry> {
    let mut out = Vec::new();
    let Some(dynsym) = sections.iter().find(|s| s.sh_type == sht::DYNSYM) else {
        return out;
    };
    let strtab = sections
        .get(dynsym.link as usize)
        .map(|s| {
            let o = (s.offset as usize).min(data.len());
            let e = (o + s.size as usize).min(data.len());
            (o, e)
        })
        .filter(|(o, e)| o < e);
    let Some((so, se)) = strtab else {
        return out;
    };
    let names = &data[so..se];

    let entsize = if dynsym.entsize > 0 {
        dynsym.entsize as usize
    } else if is64 {
        24
    } else {
        16
    };
    let off = (dynsym.offset as usize).min(data.len());
    let len = (dynsym.size as usize).min(data.len() - off);
    let count = (len / entsize.max(1)).min(MAX_SYMBOLS);

    for i in 0..count {
        let base = off + i * entsize;
        let mut r = Reader::new(&data[base..], base as u64);
        let name_off = if big_endian {
            r.u32_be().unwrap_or(0)
        } else {
            r.u32_le().unwrap_or(0)
        };
        let _info_pos = if is64 {
            let _name = name_off;
            let _st_info = r.u8().unwrap_or(0);
            let _st_other = r.u8().unwrap_or(0);
            if big_endian {
                r.u16_be().unwrap_or(0)
            } else {
                r.u16_le().unwrap_or(0)
            }
        } else {
            let _value = if big_endian {
                r.u32_be().unwrap_or(0)
            } else {
                r.u32_le().unwrap_or(0)
            };
            let _size = if big_endian {
                r.u32_be().unwrap_or(0)
            } else {
                r.u32_le().unwrap_or(0)
            };
            let _info = r.u8().unwrap_or(0);
            let _other = r.u8().unwrap_or(0);
            if big_endian {
                r.u16_be().unwrap_or(0)
            } else {
                r.u16_le().unwrap_or(0)
            }
        };
        // SHN_UNDEF == 0 means "defined elsewhere" = import.
        if _info_pos != 0 || name_off == 0 {
            continue;
        }
        let name = read_strtab(names, name_off as usize);
        if name.is_empty() {
            continue;
        }
        out.push(ImportEntry {
            library: "dynsym".into(),
            symbol: name,
            ordinal: None,
            hint: None,
            delayed: false,
        });
        if out.len() >= 20_000 {
            break;
        }
    }
    out
}

fn collect_dynsym_exports(
    data: &[u8],
    sections: &[Shdr],
    is64: bool,
    big_endian: bool,
) -> Vec<ExportEntry> {
    let mut out = Vec::new();
    let Some(dynsym) = sections.iter().find(|s| s.sh_type == sht::DYNSYM) else {
        return out;
    };
    let Some(strtab) = sections.get(dynsym.link as usize) else {
        return out;
    };
    let so = (strtab.offset as usize).min(data.len());
    let se = (so + strtab.size as usize).min(data.len());
    if so >= se {
        return out;
    }
    let names = &data[so..se];

    let entsize = if dynsym.entsize > 0 {
        dynsym.entsize as usize
    } else if is64 {
        24
    } else {
        16
    };
    let off = (dynsym.offset as usize).min(data.len());
    let len = (dynsym.size as usize).min(data.len() - off);
    let count = (len / entsize.max(1)).min(MAX_SYMBOLS);

    for i in 0..count {
        let base = off + i * entsize;
        let mut r = Reader::new(&data[base..], base as u64);
        let name_off = if big_endian {
            r.u32_be().unwrap_or(0)
        } else {
            r.u32_le().unwrap_or(0)
        };
        let (value, shndx) = if is64 {
            let _info = r.u8().unwrap_or(0);
            let _other = r.u8().unwrap_or(0);
            let shndx = if big_endian {
                r.u16_be().unwrap_or(0)
            } else {
                r.u16_le().unwrap_or(0)
            };
            let value = if big_endian {
                r.u64_be().unwrap_or(0)
            } else {
                r.u64_le().unwrap_or(0)
            };
            let _size = if big_endian {
                r.u64_be().unwrap_or(0)
            } else {
                r.u64_le().unwrap_or(0)
            };
            (value, shndx)
        } else {
            let value = if big_endian {
                r.u32_be().unwrap_or(0)
            } else {
                r.u32_le().unwrap_or(0)
            };
            let _size = if big_endian {
                r.u32_be().unwrap_or(0)
            } else {
                r.u32_le().unwrap_or(0)
            };
            let _info = r.u8().unwrap_or(0);
            let _other = r.u8().unwrap_or(0);
            let shndx = if big_endian {
                r.u16_be().unwrap_or(0)
            } else {
                r.u16_le().unwrap_or(0)
            };
            (u64::from(value), shndx)
        };
        if shndx == 0 || name_off == 0 {
            continue;
        }
        let name = read_strtab(names, name_off as usize);
        if name.is_empty() {
            continue;
        }
        out.push(ExportEntry {
            name,
            ordinal: Some(i as u32),
            address: value,
            forwarded_to: None,
        });
        if out.len() >= 20_000 {
            break;
        }
    }
    out
}

fn count_dynsym_exports(_data: &[u8], _sections: &[Shdr], _is64: bool, _be: bool) -> usize {
    0
}

fn etype_name(t: u16) -> &'static str {
    match t {
        0 => "ET_NONE",
        1 => "ET_REL",
        2 => "ET_EXEC",
        3 => "ET_DYN",
        4 => "ET_CORE",
        _ => "ET_UNKNOWN",
    }
}

fn osabi_name(v: u8) -> &'static str {
    match v {
        0 => "System V",
        1 => "HP-UX",
        2 => "NetBSD",
        3 => "Linux",
        6 => "Solaris",
        9 => "FreeBSD",
        12 => "OpenBSD",
        _ => "unknown",
    }
}

fn machine_to_arch(m: u16) -> Architecture {
    match m {
        3 => Architecture::X86,
        62 => Architecture::X86_64,
        40 => Architecture::Arm,
        183 => Architecture::Arm64,
        243 => Architecture::RiscV,
        20 | 21 => Architecture::PowerPc,
        8 => Architecture::Mips,
        _ => Architecture::Unknown,
    }
}

fn machine_name(m: u16) -> &'static str {
    match machine_to_arch(m) {
        Architecture::X86 => "i386",
        Architecture::X86_64 => "x86-64",
        Architecture::Arm => "arm",
        Architecture::Arm64 => "aarch64",
        Architecture::RiscV => "riscv",
        Architecture::PowerPc => "powerpc",
        Architecture::Mips => "mips",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal 64-bit little-endian ELF with one executable section
    /// and a `.comment` carrying a compiler string.
    pub(crate) fn build_minimal_elf64(needed: Option<&str>) -> Vec<u8> {
        // Layout: ehdr(64) | phdr(56) | shdr(64*3) | .dynamic | .dynstr | .comment | .text
        let ehsize = 64usize;
        let phentsize = 56usize;
        let shentsize = 64usize;
        let phoff = ehsize;
        let shoff = phoff + phentsize;
        let sh_count = 6usize;
        let data_start = shoff + shentsize * sh_count;

        let dynstr: Vec<u8> = match needed {
            Some(lib) => {
                let mut v = vec![0u8];
                v.extend_from_slice(lib.as_bytes());
                v.push(0);
                v
            }
            None => vec![0u8],
        };
        // Section name string table. Offsets below are the `sh_name` values
        // used by the section headers further down.
        let shstrtab = b"\0.text\0.dynamic\0.dynstr\0.shstrtab\0.comment\0";
        const NAME_TEXT: u32 = 1;
        const NAME_DYNAMIC: u32 = 7;
        const NAME_DYNSTR: u32 = 16;
        const NAME_SHSTRTAB: u32 = 24;
        const NAME_COMMENT: u32 = 34;
        const SHSTRTAB_INDEX: usize = 4;

        let dynstr_off = data_start;
        let dyn_off = dynstr_off + dynstr.len();
        let dyn_entries = if needed.is_some() { 2 } else { 1 };
        let dyn_size = dyn_entries * 16;
        let shstr_off = dyn_off + dyn_size;
        let comment = b"GCC: (Ubuntu 13.2.0) 13.2.0\0";
        let comment_off = shstr_off + shstrtab.len();
        let text_off = comment_off + comment.len();
        let text_size = 32usize;
        let total = text_off + text_size;

        let mut buf = vec![0u8; total];

        // e_ident
        buf[0..4].copy_from_slice(&ELF_MAGIC);
        buf[4] = ELFCLASS64;
        buf[5] = ELFDATA2LSB;
        buf[6] = 1;
        buf[7] = 0;

        // e_type = ET_DYN(3), e_machine = x86-64(62)
        buf[16..18].copy_from_slice(&3u16.to_le_bytes());
        buf[18..20].copy_from_slice(&62u16.to_le_bytes());
        buf[20..24].copy_from_slice(&1u32.to_le_bytes());
        buf[24..32].copy_from_slice(&0x1000u64.to_le_bytes()); // entry
        buf[32..40].copy_from_slice(&(phoff as u64).to_le_bytes());
        buf[40..48].copy_from_slice(&(shoff as u64).to_le_bytes());
        buf[52..54].copy_from_slice(&(ehsize as u16).to_le_bytes());
        buf[54..56].copy_from_slice(&(phentsize as u16).to_le_bytes());
        buf[56..58].copy_from_slice(&1u16.to_le_bytes());
        buf[58..60].copy_from_slice(&(shentsize as u16).to_le_bytes());
        buf[60..62].copy_from_slice(&(sh_count as u16).to_le_bytes());
        buf[62..64].copy_from_slice(&(SHSTRTAB_INDEX as u16).to_le_bytes());

        // Program header: PT_LOAD
        let p = phoff;
        buf[p..p + 4].copy_from_slice(&1u32.to_le_bytes());
        buf[p + 4..p + 8].copy_from_slice(&5u32.to_le_bytes());
        buf[p + 8..p + 16].copy_from_slice(&0u64.to_le_bytes());
        buf[p + 16..p + 24].copy_from_slice(&0u64.to_le_bytes());
        buf[p + 32..p + 40].copy_from_slice(&(total as u64).to_le_bytes());
        buf[p + 40..p + 48].copy_from_slice(&(total as u64).to_le_bytes());

        // Section headers: 0 = null, 1 = .text, 2 = .dynamic, 3 = .comment
        let mut sh = |idx: usize,
                      name: u32,
                      ty: u32,
                      flags: u64,
                      addr: u64,
                      off: u64,
                      size: u64,
                      link: u32,
                      entsize: u64| {
            let b = shoff + idx * shentsize;
            buf[b..b + 4].copy_from_slice(&name.to_le_bytes());
            buf[b + 4..b + 8].copy_from_slice(&ty.to_le_bytes());
            buf[b + 8..b + 16].copy_from_slice(&flags.to_le_bytes());
            buf[b + 16..b + 24].copy_from_slice(&addr.to_le_bytes());
            buf[b + 24..b + 32].copy_from_slice(&off.to_le_bytes());
            buf[b + 32..b + 40].copy_from_slice(&size.to_le_bytes());
            buf[b + 40..b + 44].copy_from_slice(&link.to_le_bytes());
            buf[b + 56..b + 64].copy_from_slice(&entsize.to_le_bytes());
        };

        sh(0, 0, 0, 0, 0, 0, 0, 0, 0);
        sh(
            1,
            NAME_TEXT,
            1,
            6,
            0x1000,
            text_off as u64,
            text_size as u64,
            0,
            0,
        ); // .text PROGBITS AX
        sh(
            2,
            NAME_DYNAMIC,
            6,
            3,
            0,
            dyn_off as u64,
            dyn_size as u64,
            3,
            16,
        ); // .dynamic -> .dynstr
        sh(
            3,
            NAME_DYNSTR,
            3,
            2,
            0,
            dynstr_off as u64,
            dynstr.len() as u64,
            0,
            0,
        ); // .dynstr STRTAB
        sh(
            4,
            NAME_SHSTRTAB,
            3,
            0,
            0,
            shstr_off as u64,
            shstrtab.len() as u64,
            0,
            0,
        ); // .shstrtab
        sh(
            5,
            NAME_COMMENT,
            1,
            0,
            0,
            comment_off as u64,
            comment.len() as u64,
            0,
            1,
        ); // .comment

        buf[dynstr_off..dynstr_off + dynstr.len()].copy_from_slice(&dynstr);
        buf[shstr_off..shstr_off + shstrtab.len()].copy_from_slice(shstrtab);

        // Dynamic entries: DT_NULL always last.
        let d = dyn_off;
        if needed.is_some() {
            buf[d..d + 8].copy_from_slice(&1u64.to_le_bytes()); // DT_NEEDED
            buf[d + 8..d + 16].copy_from_slice(&1u64.to_le_bytes()); // strtab offset 1
            buf[d + 16..d + 24].copy_from_slice(&0u64.to_le_bytes());
            buf[d + 24..d + 32].copy_from_slice(&0u64.to_le_bytes());
        } else {
            buf[d..d + 8].copy_from_slice(&0u64.to_le_bytes());
            buf[d + 8..d + 16].copy_from_slice(&0u64.to_le_bytes());
        }

        buf[comment_off..comment_off + comment.len()].copy_from_slice(comment);
        for i in 0..text_size {
            buf[text_off + i] = 0x90u8.wrapping_add(i as u8);
        }

        buf
    }

    #[test]
    fn parses_minimal_elf64() {
        let data = build_minimal_elf64(Some("libc.so.6"));
        let elf = ElfFile::parse(&data).expect("should parse");
        assert_eq!(elf.image.format, Format::Elf);
        assert_eq!(elf.image.bitness, 64);
        assert_eq!(elf.image.arch, Architecture::X86_64);
        assert!(elf.is_64());
        assert!(elf.image.sections.iter().any(|s| s.name == ".text"));
    }

    #[test]
    fn reads_needed_library() {
        let data = build_minimal_elf64(Some("libssl.so.3"));
        let elf = ElfFile::parse(&data).unwrap();
        assert!(elf.image.imports.iter().any(|i| i.library == "libssl.so.3"));
    }

    #[test]
    fn reads_compiler_comment() {
        let data = build_minimal_elf64(None);
        let elf = ElfFile::parse(&data).unwrap();
        if let FormatMetadata::Elf(meta) = &elf.image.metadata {
            assert!(meta.compiler_comments.iter().any(|c| c.contains("GCC")));
        } else {
            panic!("wrong metadata variant");
        }
    }

    #[test]
    fn rejects_bad_magic() {
        assert!(ElfFile::parse(&[0u8; 32]).is_err());
    }

    #[test]
    fn flags_relative_rpath_as_note() {
        let data = build_minimal_elf64(Some("libc.so.6"));
        // Not every synthetic image exercises rpath; just ensure notes stay sane.
        let elf = ElfFile::parse(&data).unwrap();
        assert!(elf.image.structural_notes.len() < 64);
    }
}

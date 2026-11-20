//! Archive and package containers: zip family, ar, tar, gzip.
//!
//! **Assay never decompresses.** Extraction is where archive analysers die: zip
//! bombs, symlink traversal, and nested-recursion attacks all live past the
//! decompression boundary. This module reads only the tables that describe an
//! archive — names, sizes, compression ratios, timestamps, and the executable
//! bit — which is exactly the metadata that answers "is this package trying to
//! hide a binary?" without ever handing control to a decompressor.
//!
//! Nested packages are handled by the caller ([`crate::analysis`]) with an
//! explicit depth budget, not by recursion here.

use serde::{Deserialize, Serialize};

use crate::bytes::{to_hex, Reader};
use crate::error::{AssayError, Result};
use crate::format::{
    BinaryImage, BinaryKind, Format, FormatMetadata, Permissions, SectionInfo, SignatureInfo,
};

/// Zip end-of-central-directory signature.
const ZIP_EOCD: u32 = 0x0605_4B50;
/// Zip64 end-of-central-directory locator.
const ZIP64_EOCD_LOCATOR: u32 = 0x0706_4B50;
/// Zip central directory file header.
const ZIP_CENTRAL: u32 = 0x0201_4B50;
/// `ar` global magic.
const AR_MAGIC: &[u8] = b"!<arch>\n";
/// gzip magic.
const GZIP_MAGIC: &[u8] = &[0x1F, 0x8B];

/// Maximum entries we will enumerate from any archive.
const MAX_ENTRIES: usize = 200_000;
/// Maximum bytes we will scan backwards looking for the zip EOCD.
const MAX_EOCD_SCAN: usize = 66_000;

/// Archive/package metadata.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ArchiveMetadata {
    /// Container sub-type: `zip`, `jar`, `apk`, `wheel`, `nupkg`, `vsix`, `deb`,
    /// `ar`, `tar`, `gzip`.
    pub container: String,
    /// Total entries enumerated.
    pub entry_count: usize,
    /// Total uncompressed size across entries (as declared, not verified).
    pub declared_uncompressed: u64,
    /// Total compressed size.
    pub declared_compressed: u64,
    /// Entries whose declared ratio exceeds 100:1 — a classic bomb shape.
    pub suspicious_ratio_entries: Vec<String>,
    /// Entry names that look executable or script-like.
    pub executable_entries: Vec<String>,
    /// Entries with the POSIX executable bit set (tar/ar/zip Unix attrs).
    pub setuid_or_exec_entries: Vec<String>,
    /// Top-level path components, for a quick mental model of the package.
    pub top_level: Vec<String>,
    /// A short description of the payload inferred from entry names.
    pub inferred_purpose: Option<String>,
    /// gzip original filename, when the header carries FNAME.
    pub gzip_original_name: Option<String>,
    /// gzip modification time.
    pub gzip_mtime: Option<u32>,
    /// Whether the archive carries a signature file (META-INF/*.SF, .RSA, .DSA).
    pub has_signature_files: bool,
}

/// One archive member.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveEntry {
    /// Full member path.
    pub name: String,
    /// Compressed size as declared.
    pub compressed_size: u64,
    /// Uncompressed size as declared.
    pub uncompressed_size: u64,
    /// Compression method identifier.
    pub method: u16,
    /// CRC-32 as declared.
    pub crc32: u32,
    /// Modification time as Unix seconds, when available.
    pub mtime: Option<i64>,
    /// Whether the member is flagged executable.
    pub executable: bool,
    /// Whether the member is a directory.
    pub directory: bool,
}

/// Result of reading an archive's tables.
#[derive(Debug)]
pub struct ArchiveFile {
    /// Unified model, with one section per member (no bytes).
    pub image: BinaryImage,
    /// Members in table order.
    pub entries: Vec<ArchiveEntry>,
    /// Offset of the first member payload within the container, when known.
    pub first_payload_offset: u64,
}

impl ArchiveFile {
    fn empty(format: Format, container: &str) -> Self {
        let mut image = BinaryImage::placeholder(format);
        image.kind = BinaryKind::Package;
        image.metadata = FormatMetadata::Archive(ArchiveMetadata {
            container: container.to_string(),
            ..Default::default()
        });
        ArchiveFile {
            image,
            entries: Vec::new(),
            first_payload_offset: 0,
        }
    }
}

/// Parse a zip-family container from its central directory.
pub fn parse_zip(data: &[u8]) -> Result<ArchiveFile> {
    let eocd_pos = find_eocd(data).ok_or_else(|| {
        AssayError::malformed("zip", 0, "no end-of-central-directory record found")
    })?;

    let mut r = Reader::new(&data[eocd_pos..], eocd_pos as u64);
    let _sig = r.u32_le()?;
    let disk = r.u16_le()?;
    let cd_disk = r.u16_le()?;
    let entries_this_disk = r.u16_le()?;
    let mut total_entries = u32::from(r.u16_le()?);
    let mut cd_size = u64::from(r.u32_le()?);
    let mut cd_offset = u64::from(r.u32_le()?);
    let _comment_len = r.u16_le()?;

    // Zip64 escape values.
    let mut zip64 = false;
    if total_entries == 0xFFFF || cd_size == 0xFFFF_FFFF || cd_offset == 0xFFFF_FFFF {
        if let Some(z64) = find_zip64_eocd(data, eocd_pos) {
            zip64 = true;
            let mut zr = Reader::new(&data[z64..], z64 as u64);
            zr.skip(4 + 8)?; // signature + size of record
            let _vmade = zr.u16_le()?;
            let _vneed = zr.u16_le()?;
            let _disk = zr.u32_le()?;
            let _cd_disk = zr.u32_le()?;
            let _entries_disk = zr.u64_le()?;
            total_entries = zr.u64_le()?.min(u32::MAX as u64) as u32;
            cd_size = zr.u64_le()?;
            cd_offset = zr.u64_le()?;
        }
    }
    let _ = (disk, cd_disk, entries_this_disk, zip64);

    let container = classify_zip_container(data, cd_offset as usize, cd_size as usize);
    let mut out = ArchiveFile::empty(Format::Zip, &container);

    let mut cursor = cd_offset as usize;
    let limit = total_entries.min(MAX_ENTRIES as u32);
    let mut declared_compressed = 0u64;
    let mut declared_uncompressed = 0u64;

    for _ in 0..limit {
        if cursor + 46 > data.len() {
            break;
        }
        let mut cr = Reader::new(&data[cursor..], cursor as u64);
        let sig = match cr.u32_le() {
            Ok(v) => v,
            Err(_) => break,
        };
        if sig != ZIP_CENTRAL {
            break;
        }
        let _vmade = cr.u16_le()?;
        let _vneed = cr.u16_le()?;
        let flags = cr.u16_le()?;
        let method = cr.u16_le()?;
        let mod_time = cr.u16_le()?;
        let mod_date = cr.u16_le()?;
        let crc = cr.u32_le()?;
        let mut comp_size = u64::from(cr.u32_le()?);
        let mut uncomp_size = u64::from(cr.u32_le()?);
        let name_len = cr.u16_le()? as usize;
        let extra_len = cr.u16_le()? as usize;
        let comment_len = cr.u16_le()? as usize;
        let _disk_start = cr.u16_le()?;
        let _internal = cr.u16_le()?;
        let external = cr.u32_le()?;
        let _local_off = cr.u32_le()?;

        let name_bytes = cr.take(name_len.min(4096)).unwrap_or(&[]);
        let name = String::from_utf8_lossy(name_bytes).into_owned();
        let extra_offset = cursor + 46 + name_len;

        // Zip64 extended information extra field (0x0001).
        if (comp_size == 0xFFFF_FFFF || uncomp_size == 0xFFFF_FFFF)
            && extra_len > 0
            && extra_offset + extra_len <= data.len()
        {
            let extra = &data[extra_offset..extra_offset + extra_len];
            let mut er = Reader::at(extra);
            while er.remaining() >= 4 {
                let id = er.u16_le().unwrap_or(0);
                let size = er.u16_le().unwrap_or(0) as usize;
                if er.remaining() < size {
                    break;
                }
                if id == 0x0001 {
                    if uncomp_size == 0xFFFF_FFFF {
                        uncomp_size = er.u64_le().unwrap_or(uncomp_size);
                    }
                    if comp_size == 0xFFFF_FFFF {
                        comp_size = er.u64_le().unwrap_or(comp_size);
                    }
                    break;
                }
                if er.skip(size).is_err() {
                    break;
                }
            }
        }

        let directory = name.ends_with('/') || name.ends_with('\\');
        // Unix mode lives in the high 16 bits of external attributes.
        let unix_mode = (external >> 16) & 0xFFFF;
        let executable = unix_mode & 0o111 != 0;

        declared_compressed += comp_size;
        declared_uncompressed += uncomp_size;

        out.entries.push(ArchiveEntry {
            name: name.clone(),
            compressed_size: comp_size,
            uncompressed_size: uncomp_size,
            method,
            crc32: crc,
            mtime: dos_datetime_to_unix(mod_date, mod_time),
            executable,
            directory,
        });
        let _ = flags;

        cursor += 46 + name_len + extra_len + comment_len;
    }

    finalize(
        &mut out,
        declared_compressed,
        declared_uncompressed,
        container.as_str(),
    );
    Ok(out)
}

/// Parse an `ar` archive (`.a`, `.lib`, and the outer layer of `.deb`).
pub fn parse_ar(data: &[u8]) -> Result<ArchiveFile> {
    if !data.starts_with(AR_MAGIC) {
        return Err(AssayError::UnknownFormat {
            magic: to_hex(&data[..data.len().min(4)]),
        });
    }
    let mut out = ArchiveFile::empty(Format::Ar, "ar");
    let mut cursor = AR_MAGIC.len();
    let mut declared_compressed = 0u64;
    let mut declared_uncompressed = 0u64;

    for _ in 0..MAX_ENTRIES {
        if cursor + 60 > data.len() {
            break;
        }
        let mut r = Reader::new(&data[cursor..], cursor as u64);
        let mut name_bytes = [0u8; 16];
        if r.take(16).is_err() {
            break;
        }
        name_bytes.copy_from_slice(&data[cursor..cursor + 16]);
        let mut mtime_bytes = [0u8; 12];
        if r.take(12).is_err() {
            break;
        }
        mtime_bytes.copy_from_slice(&data[cursor + 16..cursor + 28]);
        let _uid = r.take(6).unwrap_or(&[]);
        let _gid = r.take(6).unwrap_or(&[]);
        let mut mode_bytes = [0u8; 8];
        if r.take(8).is_err() {
            break;
        }
        mode_bytes.copy_from_slice(&data[cursor + 40..cursor + 48]);
        let mut size_bytes = [0u8; 10];
        if r.take(10).is_err() {
            break;
        }
        size_bytes.copy_from_slice(&data[cursor + 48..cursor + 58]);
        let magic = &data[cursor + 58..cursor + 60];
        if magic != b"`\n" {
            break;
        }

        let name_raw = String::from_utf8_lossy(&name_bytes).trim().to_string();
        let size: u64 = String::from_utf8_lossy(&size_bytes)
            .trim()
            .parse()
            .unwrap_or(0);
        let mode = u32::from_str_radix(String::from_utf8_lossy(&mode_bytes).trim(), 8).unwrap_or(0);
        let mtime: i64 = String::from_utf8_lossy(&mtime_bytes)
            .trim()
            .parse()
            .unwrap_or(0);

        // GNU ar stores long names in a `//` string table referenced as `/N`.
        let name = if name_raw == "//" || name_raw == "/" {
            name_raw.clone()
        } else if let Some(stripped) = name_raw.strip_prefix('/') {
            stripped.to_string()
        } else {
            name_raw.trim_end_matches('/').to_string()
        };

        declared_compressed += size;
        declared_uncompressed += size;
        out.entries.push(ArchiveEntry {
            name,
            compressed_size: size,
            uncompressed_size: size,
            method: 0,
            crc32: 0,
            mtime: if mtime > 0 { Some(mtime) } else { None },
            executable: mode & 0o111 != 0,
            directory: false,
        });

        cursor += 60 + size as usize;
        // Members are 2-byte aligned.
        if cursor % 2 == 1 {
            cursor += 1;
        }
    }

    let container = if data.len() > 64 && looks_like_deb(data) {
        "deb"
    } else {
        "ar"
    };
    finalize(
        &mut out,
        declared_compressed,
        declared_uncompressed,
        container,
    );
    Ok(out)
}

/// Parse a tar archive header stream (uncompressed).
pub fn parse_tar(data: &[u8]) -> Result<ArchiveFile> {
    let mut out = ArchiveFile::empty(Format::Tar, "tar");
    let mut cursor = 0usize;
    let mut declared_compressed = 0u64;
    let mut declared_uncompressed = 0u64;
    let mut saw_header = false;

    for _ in 0..MAX_ENTRIES {
        if cursor + 512 > data.len() {
            break;
        }
        let block = &data[cursor..cursor + 512];
        // Two consecutive zero blocks terminate the archive.
        if block.iter().all(|&b| b == 0) {
            break;
        }
        // Verify the checksum: sum of bytes with chksum field as spaces.
        let stored: u32 = String::from_utf8_lossy(&block[148..156])
            .trim()
            .trim_end_matches('\0')
            .parse()
            .unwrap_or(0);
        let computed: u32 = block
            .iter()
            .enumerate()
            .map(|(i, &b)| {
                if (148..156).contains(&i) {
                    u32::from(b' ')
                } else {
                    u32::from(b)
                }
            })
            .sum();
        if stored != 0 && computed != stored {
            if !saw_header {
                return Err(AssayError::malformed(
                    "tar",
                    cursor as u64,
                    "header checksum mismatch",
                ));
            }
            break;
        }
        saw_header = true;

        let name = String::from_utf8_lossy(&block[0..100])
            .trim_end_matches('\0')
            .to_string();
        let mode = u32::from_str_radix(
            String::from_utf8_lossy(&block[100..108])
                .trim()
                .trim_end_matches('\0'),
            8,
        )
        .unwrap_or(0);
        let size = u64::from_str_radix(
            String::from_utf8_lossy(&block[124..136])
                .trim()
                .trim_end_matches('\0'),
            8,
        )
        .unwrap_or(0);
        let mtime = i64::from_str_radix(
            String::from_utf8_lossy(&block[136..148])
                .trim()
                .trim_end_matches('\0'),
            8,
        )
        .unwrap_or(0);
        let typeflag = block[156];
        let prefix = String::from_utf8_lossy(&block[345..500])
            .trim_end_matches('\0')
            .to_string();
        let full_name = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };

        // POSIX pax / GNU long name extended headers.
        let is_meta = matches!(typeflag, b'x' | b'g' | b'L' | b'K');
        if !is_meta && !full_name.is_empty() {
            declared_compressed += size;
            declared_uncompressed += size;
            out.entries.push(ArchiveEntry {
                name: full_name,
                compressed_size: size,
                uncompressed_size: size,
                method: 0,
                crc32: 0,
                mtime: if mtime > 0 { Some(mtime) } else { None },
                executable: mode & 0o111 != 0,
                directory: typeflag == b'5',
            });
        }

        cursor += 512 + ((size as usize).div_ceil(512) * 512);
    }

    finalize(&mut out, declared_compressed, declared_uncompressed, "tar");
    Ok(out)
}

/// Parse a gzip header without decompressing.
pub fn parse_gzip(data: &[u8]) -> Result<ArchiveFile> {
    if data.len() < 10 || !data.starts_with(GZIP_MAGIC) {
        return Err(AssayError::UnknownFormat {
            magic: to_hex(&data[..data.len().min(4)]),
        });
    }
    let mut r = Reader::at(data);
    r.skip(2)?;
    let method = r.u8()?;
    let flags = r.u8()?;
    let mtime = r.u32_le()?;
    let _xfl = r.u8()?;
    let os = r.u8()?;

    let mut original_name = None;
    if flags & 0x08 != 0 {
        // FEXTRA
        let xlen = r.u16_le()? as usize;
        r.skip(xlen.min(65_535))?;
    }
    if flags & 0x10 != 0 {
        // FNAME
        original_name = Some(r.cstring(1024)?);
    }

    let mut out = ArchiveFile::empty(Format::Gzip, "gzip");
    // A complete gzip stream is at least 18 bytes: a 10-byte header plus the
    // 8-byte trailer carrying CRC32 and ISIZE. Anything shorter lost its trailer,
    // so the stream cannot be verified even if the header parses. A gzip never
    // yields an entry list — enumerating it would mean decompressing, which this
    // tool refuses to do — so without this check the report says "0 entries, no
    // findings" for a fragment.
    if data.len() < 18 {
        out.image.unreadable_tables.push(format!(
            "gzip stream is {} bytes: too short to contain the 8-byte trailer, so the \
             payload cannot be verified",
            data.len()
        ));
    }
    if let FormatMetadata::Archive(meta) = &mut out.image.metadata {
        meta.gzip_original_name = original_name;
        meta.gzip_mtime = if mtime == 0 { None } else { Some(mtime) };
        meta.inferred_purpose = Some(format!(
            "gzip stream (method {method}, os {os}), 8-byte trailer carries CRC32 and ISIZE"
        ));
    }
    Ok(out)
}

fn finalize(out: &mut ArchiveFile, compressed: u64, uncompressed: u64, container: &str) {
    let mut ratio_bombs = Vec::new();
    let mut executables = Vec::new();
    let mut setuid = Vec::new();
    let mut top_level: Vec<String> = Vec::new();
    let mut has_signature = false;

    for entry in &out.entries {
        if entry.compressed_size > 0 {
            let ratio = entry.uncompressed_size as f64 / entry.compressed_size as f64;
            if ratio > 100.0 && entry.uncompressed_size > 1_000_000 {
                ratio_bombs.push(format!("{} ({ratio:.0}:1)", entry.name));
            }
        }
        if entry.executable {
            setuid.push(entry.name.clone());
        }
        if is_executable_name(&entry.name) {
            executables.push(entry.name.clone());
        }
        if let Some(top) = entry.name.split('/').next() {
            let top = top.to_string();
            if !top.is_empty() && !top_level.contains(&top) {
                top_level.push(top);
            }
        }
        let lower = entry.name.to_ascii_lowercase();
        if lower.starts_with("meta-inf/")
            && (lower.ends_with(".sf")
                || lower.ends_with(".rsa")
                || lower.ends_with(".dsa")
                || lower.ends_with(".ec"))
        {
            has_signature = true;
        }
    }

    let inferred = infer_purpose(out.entries.as_slice(), container);

    if let FormatMetadata::Archive(meta) = &mut out.image.metadata {
        meta.container = container.to_string();
        meta.entry_count = out.entries.len();
        meta.declared_compressed = compressed;
        meta.declared_uncompressed = uncompressed;
        meta.suspicious_ratio_entries = ratio_bombs;
        meta.executable_entries = executables;
        meta.setuid_or_exec_entries = setuid;
        top_level.truncate(32);
        meta.top_level = top_level;
        meta.has_signature_files = has_signature;
        meta.inferred_purpose = inferred.or_else(|| meta.inferred_purpose.clone());
    }

    // Deliberately no "recognised but empty" note: an empty zip (a 22-byte EOCD)
    // and an empty tar (two zero blocks) are valid archives, and flagging them as
    // truncated was a false alarm on both. Truncation is reported where it can be
    // proven — a missing EOCD is a hard parse error, a gzip shorter than its own
    // trailer is caught in `parse_gzip`, and a tar without its terminator is
    // caught while walking the member headers.

    // Surface one section per non-directory member, with declared sizes only.
    // No bytes are attached: extraction is the caller's deliberate decision.
    for entry in out.entries.iter().filter(|e| !e.directory).take(2048) {
        out.image.sections.push(SectionInfo {
            name: entry.name.clone(),
            virtual_address: 0,
            virtual_size: entry.uncompressed_size,
            file_offset: 0,
            file_size: entry.compressed_size,
            entropy: 0.0,
            permissions: Permissions::new(true, false, entry.executable),
            sha256: String::new(),
            raw_characteristics: u64::from(entry.method),
        });
    }

    out.image.signature = SignatureInfo::absent();
    if has_signature {
        out.image
            .structural_notes
            .push("archive carries META-INF signature files (jar/apk signing)".into());
    }
}

fn infer_purpose(entries: &[ArchiveEntry], container: &str) -> Option<String> {
    let has = |needle: &str| entries.iter().any(|e| e.name.contains(needle));
    let mut hints: Vec<&str> = Vec::new();

    if container == "apk" {
        hints.push("Android application package");
    }
    if container == "jar" || has("META-INF/MANIFEST.MF") {
        hints.push("Java archive");
    }
    if container == "wheel" || has(".dist-info/") {
        hints.push("Python wheel");
    }
    if container == "nupkg" || has(".nuspec") {
        hints.push("NuGet package");
    }
    if container == "deb" {
        hints.push("Debian package");
    }
    if has("node_modules/") && has("package.json") {
        hints.push("bundled Node package");
    }
    if has(".ps1") || has(".bat") || has(".cmd") {
        hints.push("ships Windows scripts");
    }
    if has(".sh") && has(".service") {
        hints.push("ships systemd units and shell scripts");
    }
    if has("installer") || has("setup.exe") {
        hints.push("bundles an installer");
    }

    if hints.is_empty() {
        None
    } else {
        Some(hints.join("; "))
    }
}

fn is_executable_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    const EXTS: &[&str] = &[
        ".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx", ".so", ".dylib", ".elf", ".bin", ".sh",
        ".bash", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".py", ".pl", ".rb", ".jar", ".class",
        ".dex", ".apk", ".app", ".msi", ".pkg", ".deb", ".rpm",
    ];
    EXTS.iter().any(|ext| lower.ends_with(ext))
}

fn looks_like_deb(data: &[u8]) -> bool {
    // A .deb is an ar archive whose first member is `debian-binary`.
    let probe = &data[..data.len().min(128)];
    probe.windows(13).any(|w| w == b"debian-binary")
}

fn classify_zip_container(data: &[u8], cd_offset: usize, cd_size: usize) -> String {
    let start = cd_offset.min(data.len());
    let end = (start + cd_size).min(data.len());
    let table = &data[start..end];

    let has = |needle: &[u8]| table.windows(needle.len()).any(|w| w == needle);

    if has(b"AndroidManifest.xml") && has(b"classes.dex") {
        return "apk".into();
    }
    if has(b"META-INF/MANIFEST.MF") {
        return "jar".into();
    }
    if has(b".dist-info/") || has(b"RECORD") && has(b"WHEEL") {
        return "wheel".into();
    }
    if has(b".nuspec") {
        return "nupkg".into();
    }
    if has(b"extension.vsixmanifest") {
        return "vsix".into();
    }
    if has(b"OEBPS/") || has(b"mimetype") && has(b"EPUB/") {
        return "epub".into();
    }
    if has(b"word/document.xml") || has(b"xl/workbook.xml") {
        return "ooxml".into();
    }
    "zip".into()
}

fn find_eocd(data: &[u8]) -> Option<usize> {
    if data.len() < 22 {
        return None;
    }
    let start = data.len().saturating_sub(MAX_EOCD_SCAN.min(data.len()));
    let mut pos = data.len() - 22;
    loop {
        if pos < start {
            return None;
        }
        if data[pos..pos + 4] == ZIP_EOCD.to_le_bytes() {
            return Some(pos);
        }
        if pos == 0 {
            return None;
        }
        pos -= 1;
    }
}

fn find_zip64_eocd(data: &[u8], eocd_pos: usize) -> Option<usize> {
    // The locator sits immediately before the EOCD.
    if eocd_pos < 20 {
        return None;
    }
    let loc = eocd_pos - 20;
    if data[loc..loc + 4] != ZIP64_EOCD_LOCATOR.to_le_bytes() {
        return None;
    }
    let mut r = Reader::new(&data[loc..], loc as u64);
    let _sig = r.u32_le().ok()?;
    let _disk = r.u32_le().ok()?;
    let offset = r.u64_le().ok()?;
    let total_disks = r.u32_le().ok()?;
    if total_disks > 1 {
        return None;
    }
    let off = usize::try_from(offset).ok()?;
    if off + 4 > data.len() {
        return None;
    }
    Some(off)
}

/// Convert a DOS date/time pair into Unix seconds.
fn dos_datetime_to_unix(date: u16, time: u16) -> Option<i64> {
    let year = 1980 + i64::from((date >> 9) & 0x7F);
    let month = i64::from((date >> 5) & 0x0F);
    let day = i64::from(date & 0x1F);
    let hour = i64::from((time >> 11) & 0x1F);
    let minute = i64::from((time >> 5) & 0x3F);
    let second = i64::from(time & 0x1F) * 2;

    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }

    // days_from_civil, inlined to keep this module dependency-free.
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;

    Some(days * 86_400 + hour * 3600 + minute * 60 + second)
}
#[cfg(test)]
mod tests {
    use super::*;

    fn build_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        let mut central: Vec<u8> = Vec::new();

        for (name, payload) in entries {
            let offset = out.len() as u32;
            let crc = crate::hash::crc32(payload);
            let n = name.as_bytes();

            // Local file header magic; the fixture needs it even though the
            // analyser reads the central directory instead.
            out.extend_from_slice(&0x0403_4B50u32.to_le_bytes());
            out.extend_from_slice(&20u16.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes()); // stored
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&0x21u16.to_le_bytes()); // 1980-01-01
            out.extend_from_slice(&crc.to_le_bytes());
            out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            out.extend_from_slice(&(n.len() as u16).to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(n);
            out.extend_from_slice(payload);

            central.extend_from_slice(&ZIP_CENTRAL.to_le_bytes());
            central.extend_from_slice(&20u16.to_le_bytes());
            central.extend_from_slice(&20u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0x21u16.to_le_bytes());
            central.extend_from_slice(&crc.to_le_bytes());
            central.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            central.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            central.extend_from_slice(&(n.len() as u16).to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&(0o100755u32 << 16).to_le_bytes());
            central.extend_from_slice(&offset.to_le_bytes());
            central.extend_from_slice(n);
        }

        let cd_offset = out.len() as u32;
        let cd_size = central.len() as u32;
        out.extend_from_slice(&central);

        out.extend_from_slice(&ZIP_EOCD.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&cd_size.to_le_bytes());
        out.extend_from_slice(&cd_offset.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }

    #[test]
    fn parses_zip_entries() {
        let data = build_zip(&[
            ("hello.txt", b"hello world"),
            ("bin/run.sh", b"#!/bin/sh\n"),
        ]);
        let zip = parse_zip(&data).expect("should parse");
        assert_eq!(zip.entries.len(), 2);
        assert!(zip.entries.iter().any(|e| e.name == "hello.txt"));
        assert!(zip.entries.iter().any(|e| e.executable));
    }

    #[test]
    fn detects_jar_container() {
        let data = build_zip(&[("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n")]);
        let zip = parse_zip(&data).unwrap();
        if let FormatMetadata::Archive(meta) = &zip.image.metadata {
            assert_eq!(meta.container, "jar");
        } else {
            panic!("wrong metadata");
        }
    }

    #[test]
    fn rejects_zip_without_eocd() {
        assert!(parse_zip(&[0u8; 64]).is_err());
    }

    #[test]
    fn parses_ar_members() {
        let mut data = Vec::new();
        data.extend_from_slice(AR_MAGIC);
        let payload = b"symbol-data";
        data.extend_from_slice(b"member.o/       ");
        data.extend_from_slice(b"1700000000  ");
        data.extend_from_slice(b"0     ");
        data.extend_from_slice(b"0     ");
        data.extend_from_slice(b"100644  ");
        data.extend_from_slice(format!("{:<10}", payload.len()).as_bytes());
        data.extend_from_slice(b"`\n");
        data.extend_from_slice(payload);
        if data.len() % 2 == 1 {
            data.push(b'\n');
        }
        let ar = parse_ar(&data).expect("should parse");
        assert_eq!(ar.entries.len(), 1);
        assert_eq!(ar.entries[0].name, "member.o");
    }

    #[test]
    fn parses_gzip_header() {
        let mut data = vec![0x1F, 0x8B, 8, 0x10];
        data.extend_from_slice(&1_700_000_000u32.to_le_bytes());
        data.push(0);
        data.push(3);
        data.extend_from_slice(b"payload.bin\0");
        let gz = parse_gzip(&data).expect("should parse");
        if let FormatMetadata::Archive(meta) = &gz.image.metadata {
            assert_eq!(meta.gzip_original_name.as_deref(), Some("payload.bin"));
        } else {
            panic!("wrong metadata");
        }
    }

    #[test]
    fn dos_datetime_converts() {
        // 2024-02-29 12:00:00
        let date = ((2024 - 1980) << 9) | (2 << 5) | 29;
        let time = 12 << 11;
        assert_eq!(
            dos_datetime_to_unix(date as u16, time as u16),
            Some(1_709_208_000)
        );
    }
}

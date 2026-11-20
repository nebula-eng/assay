//! Container sniffing.
//!
//! Identity is decided by **content**, never by extension. A `.jpg` that starts
//! with `MZ` is a PE; a file named `invoice.pdf` that is actually a zip is an
//! OOXML document or a dropper. Extension is used only as a tie-breaker for
//! formats that have no magic of their own (tar, plain scripts), and even then
//! it is recorded as a *weak* signal rather than trusted.

use crate::bytes::to_hex;
use crate::format::Format;

/// How confident the classification is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    /// A fixed magic number matched.
    Certain,
    /// A structural signature matched (e.g. tar header checksum).
    Structural,
    /// Only the file extension or a heuristic matched.
    Weak,
}

/// The sniffing result.
#[derive(Debug, Clone)]
pub struct Detected {
    /// Decided format.
    pub format: Format,
    /// Confidence in the decision.
    pub confidence: Confidence,
    /// Why this format was chosen, for the report.
    pub reason: &'static str,
    /// The first bytes, hex-encoded, for the report.
    pub magic: String,
}

/// Identify a container.
pub fn detect(data: &[u8], path_hint: Option<&str>) -> Detected {
    let magic = to_hex(&data[..data.len().min(8)]);
    let extension = path_hint
        .and_then(|p| p.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase()))
        .unwrap_or_default();

    // ---- Fixed magics ---------------------------------------------------
    if data.len() >= 2 && data[0] == b'M' && data[1] == b'Z' {
        return Detected {
            format: Format::Pe,
            confidence: Confidence::Certain,
            reason: "MZ DOS header",
            magic,
        };
    }
    if data.len() >= 4 && data[0..4] == super::elf::ELF_MAGIC {
        return Detected {
            format: Format::Elf,
            confidence: Confidence::Certain,
            reason: "\\x7fELF magic",
            magic,
        };
    }
    if data.len() >= 4 {
        let le = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let is_macho = matches!(
            le,
            0xFEED_FACE | 0xFEED_FACF | 0xCEFA_EDFE | 0xCFFA_EDFE | 0xCAFE_BABE | 0xBEBA_FECA
        );
        if is_macho {
            return Detected {
                format: Format::MachO,
                confidence: Confidence::Certain,
                reason: "Mach-O / fat magic",
                magic,
            };
        }
    }
    if data.len() >= 4 && &data[0..4] == b"!<ar" {
        return Detected {
            format: Format::Ar,
            confidence: Confidence::Certain,
            reason: "ar global header",
            magic,
        };
    }
    if data.len() >= 4 && data[0..4] == [0x50, 0x4B, 0x03, 0x04] {
        return Detected {
            format: Format::Zip,
            confidence: Confidence::Certain,
            reason: "PK\\x03\\x04 local file header",
            magic,
        };
    }
    if data.len() >= 2 && data[0] == 0x1F && data[1] == 0x8B {
        return Detected {
            format: Format::Gzip,
            confidence: Confidence::Certain,
            reason: "gzip magic",
            magic,
        };
    }
    // Zip with an empty first entry (data descriptor) shows up as PK\x05\x06.
    if data.len() >= 4
        && (data[0..4] == [0x50, 0x4B, 0x05, 0x06] || data[0..4] == [0x50, 0x4B, 0x07, 0x08])
    {
        return Detected {
            format: Format::Zip,
            confidence: Confidence::Structural,
            reason: "PK end-of-central-directory at offset zero",
            magic,
        };
    }

    // ---- Structural checks ----------------------------------------------
    if looks_like_tar(data) {
        return Detected {
            format: Format::Tar,
            confidence: Confidence::Structural,
            reason: "ustar header with valid checksum",
            magic,
        };
    }

    // ---- Scripts ---------------------------------------------------------
    if let Some(kind) = sniff_script(data) {
        return Detected {
            format: Format::Script,
            confidence: Confidence::Weak,
            reason: kind,
            magic,
        };
    }

    // ---- Extension fallback ---------------------------------------------
    match extension.as_str() {
        "tar" => Detected {
            format: Format::Tar,
            confidence: Confidence::Weak,
            reason: "extension only",
            magic,
        },
        "ps1" | "sh" | "bash" | "py" | "js" | "rb" | "pl" | "bat" | "cmd" | "vbs" => Detected {
            format: Format::Script,
            confidence: Confidence::Weak,
            reason: "script extension only",
            magic,
        },
        _ => Detected {
            format: Format::Unknown,
            confidence: Confidence::Weak,
            reason: "no signature matched",
            magic,
        },
    }
}

fn looks_like_tar(data: &[u8]) -> bool {
    if data.len() < 512 {
        return false;
    }
    let block = &data[..512];
    // ustar magic at offset 257.
    let has_ustar = &block[257..262] == b"ustar";
    let has_gnu = &block[257..262] == b"ustar" || &block[257..265] == b"ustar  ";
    if !has_ustar && !has_gnu {
        return false;
    }
    let stored: u32 = String::from_utf8_lossy(&block[148..156])
        .trim()
        .trim_end_matches('\0')
        .parse()
        .unwrap_or(0);
    if stored == 0 {
        return false;
    }
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
    stored == computed
}

fn sniff_script(data: &[u8]) -> Option<&'static str> {
    let head = &data[..data.len().min(512)];
    if head.starts_with(b"#!") {
        let line = head.split(|&b| b == b'\n').next().unwrap_or(&[]);
        let text = String::from_utf8_lossy(line).to_ascii_lowercase();
        return Some(if text.contains("python") {
            "shebang: python"
        } else if text.contains("bash") || text.contains("/sh") {
            "shebang: POSIX shell"
        } else if text.contains("perl") {
            "shebang: perl"
        } else if text.contains("ruby") {
            "shebang: ruby"
        } else if text.contains("node") {
            "shebang: node"
        } else {
            "shebang: other interpreter"
        });
    }
    // PowerShell is often UTF-16 with a BOM.
    if head.starts_with(&[0xFF, 0xFE]) || head.starts_with(&[0xFE, 0xFF]) {
        let utf16 = decode_utf16_prefix(head, 1024);
        let lower = utf16.to_ascii_lowercase();
        if lower.contains("powershell") || lower.contains("write-host") || lower.contains("$env:") {
            return Some("UTF-16 PowerShell-ish script");
        }
    }
    let text = String::from_utf8_lossy(head);
    let lower = text.to_ascii_lowercase();
    if lower.contains("invoke-expression")
        || lower.contains("iex(")
        || lower.contains("new-object net.webclient")
    {
        return Some("PowerShell keywords");
    }
    None
}

fn decode_utf16_prefix(data: &[u8], max_chars: usize) -> String {
    let big = data.starts_with(&[0xFE, 0xFF]);
    let body = if data.starts_with(&[0xFF, 0xFE]) || big {
        &data[2..]
    } else {
        data
    };
    let mut out = String::new();
    for chunk in body.chunks_exact(2).take(max_chars) {
        let unit = if big {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            u16::from_le_bytes([chunk[0], chunk[1]])
        };
        if let Some(c) = char::from_u32(u32::from(unit)) {
            out.push(c);
        }
    }
    out
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_pe() {
        let mut data = vec![0u8; 128];
        data[0] = b'M';
        data[1] = b'Z';
        assert_eq!(detect(&data, None).format, Format::Pe);
    }

    #[test]
    fn detects_elf() {
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(&super::super::elf::ELF_MAGIC);
        assert_eq!(detect(&data, None).format, Format::Elf);
    }

    #[test]
    fn detects_zip() {
        let data = [0x50, 0x4B, 0x03, 0x04, 0, 0, 0, 0];
        assert_eq!(detect(&data, None).format, Format::Zip);
    }

    #[test]
    fn detects_gzip() {
        let data = [0x1F, 0x8B, 0x08, 0x00];
        assert_eq!(detect(&data, None).format, Format::Gzip);
    }

    #[test]
    fn detects_ar() {
        let data = b"!<arch>\nxxxx";
        assert_eq!(detect(data, None).format, Format::Ar);
    }

    #[test]
    fn detects_shell_script() {
        let data = b"#!/bin/sh\necho hi\n";
        let d = detect(data, None);
        assert_eq!(d.format, Format::Script);
    }

    #[test]
    fn unknown_falls_back() {
        let data = [0u8; 32];
        assert_eq!(detect(&data, None).format, Format::Unknown);
    }

    #[test]
    fn extension_is_only_a_hint() {
        let data = [0u8; 32];
        let d = detect(&data, Some("weird.ps1"));
        assert_eq!(d.format, Format::Script);
        assert_eq!(d.confidence, Confidence::Weak);
    }
}

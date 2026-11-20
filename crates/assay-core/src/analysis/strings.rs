//! Printable string recovery.
//!
//! Three alphabets matter in practice: ASCII (CLI arguments, URLs, registry
//! keys), UTF-16LE (Windows APIs and .NET assemblies), and — occasionally —
//! UTF-16BE. Each is scanned separately so that a UTF-16 string is not silently
//! shredded into one-character ASCII "strings", which is what naive extractors
//! do and why their output is unreadable.
//!
//! Everything is capped. A 300 MiB installer with an embedded archive would
//! otherwise produce tens of millions of entries and turn a 200 ms analysis into
//! a memory event.

use serde::{Deserialize, Serialize};

/// Which encoding a recovered string came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Encoding {
    /// Single-byte printable ASCII.
    Ascii,
    /// UTF-16 little endian, as Windows uses.
    Utf16Le,
    /// UTF-16 big endian.
    Utf16Be,
}

/// One recovered string.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedString {
    /// File offset where the string begins.
    pub offset: u64,
    /// Encoding it was recovered from.
    pub encoding: Encoding,
    /// The decoded text.
    pub text: String,
    /// Length in characters.
    pub length: usize,
}

/// Limits applied during extraction.
#[derive(Debug, Clone, Copy)]
pub struct StringOptions {
    /// Minimum run length to accept.
    pub min_length: usize,
    /// Maximum number of strings to return.
    pub max_strings: usize,
    /// Maximum characters retained per string (longer ones are truncated).
    pub max_length: usize,
    /// Whether to scan UTF-16 as well as ASCII.
    pub utf16: bool,
}

impl Default for StringOptions {
    fn default() -> Self {
        StringOptions {
            min_length: 5,
            max_strings: 100_000,
            max_length: 512,
            utf16: true,
        }
    }
}

impl StringOptions {
    /// Tighter budget for whole-file scans of large artefacts.
    pub fn conservative() -> Self {
        StringOptions {
            min_length: 6,
            max_strings: 30_000,
            max_length: 256,
            utf16: true,
        }
    }
}

#[inline]
fn is_ascii_printable(b: u8) -> bool {
    // Exclude DEL; accept tab only inside longer runs is not worth the trouble.
    (0x20..=0x7E).contains(&b)
}

/// Extract strings from a buffer under the given budget.
pub fn extract(data: &[u8], options: StringOptions) -> Vec<ExtractedString> {
    let mut out = Vec::new();
    scan_ascii(data, options, &mut out);
    if options.utf16 && out.len() < options.max_strings {
        scan_utf16(data, options, false, &mut out);
    }
    if options.utf16 && out.len() < options.max_strings {
        scan_utf16(data, options, true, &mut out);
    }
    out.sort_by_key(|s| s.offset);
    out.truncate(options.max_strings);
    out
}

fn scan_ascii(data: &[u8], options: StringOptions, out: &mut Vec<ExtractedString>) {
    let mut start: Option<usize> = None;
    let mut i = 0usize;
    while i < data.len() {
        if is_ascii_printable(data[i]) {
            if start.is_none() {
                start = Some(i);
            }
        } else if let Some(s) = start.take() {
            let len = i - s;
            if len >= options.min_length {
                push(out, s as u64, Encoding::Ascii, &data[s..i], options);
                if out.len() >= options.max_strings {
                    return;
                }
            }
        }
        i += 1;
    }
    if let Some(s) = start {
        let len = data.len() - s;
        if len >= options.min_length {
            push(out, s as u64, Encoding::Ascii, &data[s..], options);
        }
    }
}

fn scan_utf16(
    data: &[u8],
    options: StringOptions,
    big_endian: bool,
    out: &mut Vec<ExtractedString>,
) {
    // Walk in 2-byte units; a run is valid when the high byte is zero and the
    // low byte is printable ASCII. This is the shape of Windows wide strings.
    let units = data.len() / 2;
    let mut start_unit: Option<usize> = None;

    for u in 0..units {
        let (lo, hi) = if big_endian {
            (data[u * 2 + 1], data[u * 2])
        } else {
            (data[u * 2], data[u * 2 + 1])
        };
        let ok = hi == 0x00 && is_ascii_printable(lo);
        if ok {
            if start_unit.is_none() {
                start_unit = Some(u);
            }
        } else if let Some(su) = start_unit.take() {
            let count = u - su;
            if count >= options.min_length {
                let base = su * 2;
                let byte_len = count * 2;
                let encoding = if big_endian {
                    Encoding::Utf16Be
                } else {
                    Encoding::Utf16Le
                };
                let raw: Vec<u8> = data[base..base + byte_len]
                    .chunks_exact(2)
                    .map(|c| if big_endian { c[1] } else { c[0] })
                    .collect();
                push(out, base as u64, encoding, &raw, options);
                if out.len() >= options.max_strings {
                    return;
                }
            }
        }
    }
    if let Some(su) = start_unit {
        let count = units - su;
        if count >= options.min_length {
            let base = su * 2;
            let encoding = if big_endian {
                Encoding::Utf16Be
            } else {
                Encoding::Utf16Le
            };
            let raw: Vec<u8> = data[base..base + count * 2]
                .chunks_exact(2)
                .map(|c| if big_endian { c[1] } else { c[0] })
                .collect();
            push(out, base as u64, encoding, &raw, options);
        }
    }
}

fn push(
    out: &mut Vec<ExtractedString>,
    offset: u64,
    encoding: Encoding,
    raw: &[u8],
    options: StringOptions,
) {
    let truncated = &raw[..raw.len().min(options.max_length * 4)];
    let text = String::from_utf8_lossy(truncated)
        .chars()
        .take(options.max_length)
        .collect::<String>();
    if text.trim().is_empty() {
        return;
    }
    out.push(ExtractedString {
        offset,
        encoding,
        length: text.chars().count(),
        text,
    });
}

/// Deduplicate by text, keeping the first occurrence.
pub fn dedup(strings: &[ExtractedString]) -> Vec<&ExtractedString> {
    let mut seen = std::collections::HashSet::with_capacity(strings.len());
    let mut out = Vec::with_capacity(strings.len());
    for s in strings {
        if seen.insert(s.text.as_str()) {
            out.push(s);
        }
    }
    out
}

/// A coarse guess at what a string is, used to sort the UI's string view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StringCategory {
    /// Looks like a URL or hostname.
    Network,
    /// Looks like a filesystem path.
    Path,
    /// Looks like a registry key.
    Registry,
    /// Looks like an error message or log line.
    Message,
    /// Looks like a format string (`%s`, `%d`).
    FormatString,
    /// Looks like base64 or an encoded blob.
    Encoded,
    /// Everything else.
    Other,
}

/// Classify a string without running the full IOC scan.
pub fn categorize(text: &str) -> StringCategory {
    let lower = text.to_ascii_lowercase();
    if lower.contains("://") || lower.starts_with("\\\\") {
        return StringCategory::Network;
    }
    if lower.contains("hkey_")
        || lower.starts_with("hklm")
        || lower.starts_with("hkcu")
        || lower.starts_with("hkcr")
    {
        return StringCategory::Registry;
    }
    if (lower.contains(":\\") && lower.len() > 3)
        || lower.starts_with("/usr/")
        || lower.starts_with("/etc/")
        || lower.starts_with("c:/")
    {
        return StringCategory::Path;
    }
    let format_specifiers = lower.matches('%').count();
    if format_specifiers >= 2 && lower.chars().any(|c| "sdixufp".contains(c)) {
        return StringCategory::FormatString;
    }
    if lower.len() >= 24
        && lower
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
        && lower.chars().any(|c| c.is_ascii_uppercase())
    {
        return StringCategory::Encoded;
    }
    if lower.contains("error") || lower.contains("failed") || lower.contains("denied") {
        return StringCategory::Message;
    }
    StringCategory::Other
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_ascii_strings() {
        let data = b"\x00\x01hello world\x00\x02tiny\x00";
        let found = extract(data, StringOptions::default());
        assert!(found.iter().any(|s| s.text == "hello world"));
        assert!(!found.iter().any(|s| s.text == "tiny"));
    }

    #[test]
    fn extracts_utf16le() {
        // "C:\\Windows\\System32" in UTF-16LE.
        let mut data = Vec::new();
        for ch in "C:\\Windows\\System32".chars() {
            data.push(ch as u8);
            data.push(0);
        }
        let found = extract(&data, StringOptions::default());
        assert!(found
            .iter()
            .any(|s| s.encoding == Encoding::Utf16Le && s.text.contains("System32")));
    }

    #[test]
    fn does_not_shred_utf16_into_single_chars() {
        let mut data = Vec::new();
        for ch in "abcdefgh".chars() {
            data.push(ch as u8);
            data.push(0);
        }
        let found = extract(&data, StringOptions::default());
        // Must not yield "a", "b", "c"… as separate ASCII strings.
        assert!(!found
            .iter()
            .any(|s| s.encoding == Encoding::Ascii && s.text.len() == 1));
    }

    #[test]
    fn respects_min_length() {
        let data = b"ab\x00abcd\x00abcde\x00";
        let found = extract(
            data,
            StringOptions {
                min_length: 5,
                ..Default::default()
            },
        );
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].text, "abcde");
    }

    #[test]
    fn respects_max_strings() {
        let mut data = Vec::new();
        for i in 0..1000 {
            data.extend_from_slice(format!("string{i:04}\x00").as_bytes());
        }
        let found = extract(
            &data,
            StringOptions {
                max_strings: 10,
                ..Default::default()
            },
        );
        assert!(found.len() <= 10);
    }

    #[test]
    fn truncates_absurdly_long_runs() {
        let data = vec![b'A'; 10_000];
        let found = extract(
            &data,
            StringOptions {
                max_length: 32,
                ..Default::default()
            },
        );
        assert!(found.iter().all(|s| s.text.chars().count() <= 32));
    }

    #[test]
    fn dedup_keeps_first() {
        let strings = vec![
            ExtractedString {
                offset: 0,
                encoding: Encoding::Ascii,
                text: "same".into(),
                length: 4,
            },
            ExtractedString {
                offset: 100,
                encoding: Encoding::Ascii,
                text: "same".into(),
                length: 4,
            },
        ];
        assert_eq!(dedup(&strings).len(), 1);
    }

    #[test]
    fn categorizes_common_shapes() {
        assert_eq!(
            categorize("https://evil.example/x"),
            StringCategory::Network
        );
        assert_eq!(
            categorize("HKEY_LOCAL_MACHINE\\Software"),
            StringCategory::Registry
        );
        assert_eq!(categorize("C:\\Windows\\Temp\\a.exe"), StringCategory::Path);
        assert_eq!(
            categorize("%s failed with %d"),
            StringCategory::FormatString
        );
    }
}

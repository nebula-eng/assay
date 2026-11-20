//! Bounds-checked little/big endian reader.
//!
//! Why not `byteorder` or `nom`? Because the whole point of this crate is that
//! every offset handed to it may be attacker-controlled. Having one
//! ~200-line reader that *provably* cannot index out of bounds — and that
//! reports the absolute file offset of every failure — is worth more than the
//! ergonomics of a combinator library. `Reader` is deliberately total: it never
//! panics, and a `None`/`Err` always carries the position that broke.

use crate::error::{AssayError, Result};

/// A cursor over a byte slice with absolute-offset bookkeeping.
///
/// `base` is the file offset that `data[0]` corresponds to. Without it, error
/// messages from deeply nested structures would report offsets relative to a
/// section or a resource blob, which is useless when you are staring at a hex
/// editor.
#[derive(Clone, Copy, Debug)]
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
    base: u64,
}

impl<'a> Reader<'a> {
    /// Create a reader over `data`, starting at absolute file offset `base`.
    pub fn new(data: &'a [u8], base: u64) -> Self {
        Reader { data, pos: 0, base }
    }

    /// Create a reader whose first byte sits at file offset zero.
    pub fn at(data: &'a [u8]) -> Self {
        Reader::new(data, 0)
    }

    /// Absolute file offset of the cursor.
    #[inline]
    pub fn offset(&self) -> u64 {
        self.base + self.pos as u64
    }

    /// Number of bytes left.
    #[inline]
    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    /// True when the cursor is at the end of the buffer.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Current position within the underlying slice.
    #[inline]
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Move the cursor to an absolute position inside the buffer.
    pub fn seek(&mut self, pos: usize) -> Result<()> {
        if pos > self.data.len() {
            return Err(AssayError::Truncated {
                what: "seek target",
                offset: self.base + pos as u64,
                needed: pos,
                available: self.data.len(),
            });
        }
        self.pos = pos;
        Ok(())
    }

    /// Skip `n` bytes.
    pub fn skip(&mut self, n: usize) -> Result<()> {
        self.take(n).map(|_| ())
    }

    /// Borrow the next `n` bytes and advance.
    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or(AssayError::Truncated {
            what: "slice",
            offset: self.offset(),
            needed: n,
            available: self.remaining(),
        })?;
        if end > self.data.len() {
            return Err(AssayError::Truncated {
                what: "slice",
                offset: self.offset(),
                needed: n,
                available: self.remaining(),
            });
        }
        let out = &self.data[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    /// Borrow the next `n` bytes without advancing.
    pub fn peek(&self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or(AssayError::Truncated {
            what: "peek",
            offset: self.offset(),
            needed: n,
            available: self.remaining(),
        })?;
        if end > self.data.len() {
            return Err(AssayError::Truncated {
                what: "peek",
                offset: self.offset(),
                needed: n,
                available: self.remaining(),
            });
        }
        Ok(&self.data[self.pos..end])
    }

    /// Everything from the cursor to the end, without advancing.
    pub fn tail(&self) -> &'a [u8] {
        &self.data[self.pos..]
    }
    /// Read one byte.
    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    /// Read an `i8`.
    pub fn i8(&mut self) -> Result<i8> {
        Ok(self.u8()? as i8)
    }

    /// Read a little-endian `u16`.
    pub fn u16_le(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    /// Read a big-endian `u16`.
    pub fn u16_be(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    /// Read a little-endian `u32`.
    pub fn u32_le(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Read a big-endian `u32`.
    pub fn u32_be(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Read a little-endian `u64`.
    pub fn u64_le(&mut self) -> Result<u64> {
        let b = self.take(8)?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    /// Read a big-endian `u64`.
    pub fn u64_be(&mut self) -> Result<u64> {
        let b = self.take(8)?;
        Ok(u64::from_be_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }
    /// Read an unsigned LEB128 value, as used by Mach-O's `DYLD_INFO` and DWARF.
    pub fn uleb128(&mut self) -> Result<u64> {
        let mut result: u64 = 0;
        let mut shift = 0u32;
        loop {
            let byte = self.u8()?;
            if shift >= 64 {
                return Err(AssayError::malformed(
                    "uleb128",
                    self.offset(),
                    "value exceeds 64 bits",
                ));
            }
            result |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(result);
            }
            shift += 7;
        }
    }

    /// Read a signed LEB128 value.
    pub fn sleb128(&mut self) -> Result<i64> {
        let mut result: i64 = 0;
        let mut shift = 0u32;
        loop {
            let byte = self.u8()?;
            if shift >= 64 {
                return Err(AssayError::malformed(
                    "sleb128",
                    self.offset(),
                    "value exceeds 64 bits",
                ));
            }
            result |= i64::from(byte & 0x7f) << shift;
            shift += 7;
            if byte & 0x80 == 0 {
                if shift < 64 && byte & 0x40 != 0 {
                    result |= -1i64 << shift;
                }
                return Ok(result);
            }
        }
    }

    /// Read a NUL-terminated string, returning it as a lossy UTF-8 `String`.
    ///
    /// Bytes are capped at `max` so a missing terminator in a hostile file
    /// cannot make us walk the entire image.
    pub fn cstring(&mut self, max: usize) -> Result<String> {
        let start = self.pos;
        let limit = (start + max).min(self.data.len());
        let mut end = start;
        while end < limit && self.data[end] != 0 {
            end += 1;
        }
        let out = String::from_utf8_lossy(&self.data[start..end]).into_owned();
        self.pos = if end < self.data.len() { end + 1 } else { end };
        Ok(out)
    }
}

/// Decode a fixed-width field that may be shorter than `N` (trailing zero pad).
pub fn fixed_str(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end])
        .trim_end()
        .to_string()
}

/// Render bytes as lowercase hex without a separator.
pub fn to_hex(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(LUT[(b >> 4) as usize] as char);
        out.push(LUT[(b & 0x0f) as usize] as char);
    }
    out
}

/// Render bytes as uppercase hex, which is what every Windows tool prints.
pub fn to_hex_upper(bytes: &[u8]) -> String {
    to_hex(bytes).to_uppercase()
}
/// Parse a hex string that may contain whitespace, `0x` prefixes or separators.
///
/// Used by the rule engine to read hex byte patterns out of rule files.
pub fn parse_hex_pattern(input: &str) -> std::result::Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut high: Option<u8> = None;
    for ch in input.chars() {
        if ch.is_whitespace() || ch == ':' || ch == '-' || ch == '_' || ch == ',' {
            continue;
        }
        if ch == '?' {
            return Err("wildcards are not supported in hex patterns".into());
        }
        let v = ch
            .to_digit(16)
            .ok_or_else(|| format!("`{ch}` is not a hex digit"))? as u8;
        match high.take() {
            Some(h) => out.push((h << 4) | v),
            None => high = Some(v),
        }
    }
    if high.is_some() {
        return Err("hex pattern has an odd number of digits".into());
    }
    Ok(out)
}

/// Render a count with the correctly inflected noun.
///
/// `plural(1, "finding")` → `"1 finding"`; `plural(3, "finding")` →
/// `"3 findings"`. Irregular forms are passed explicitly:
/// `plural(2, "library", "libraries")`.
pub fn plural(count: usize, singular: &str, plural_form: Option<&str>) -> String {
    if count == 1 {
        format!("{count} {singular}")
    } else {
        let word = plural_form
            .map(str::to_string)
            .unwrap_or_else(|| pluralise(singular));
        format!("{count} {word}")
    }
}

/// Append the English plural suffix.
///
/// `format!("{singular}s")` is wrong often enough to be worth four lines: it
/// produced "2 executable or script entrys" the first time a noun ended in `y`.
/// This handles the two rules that actually occur in this codebase's vocabulary
/// — consonant + `y` → `ies`, and a sibilant ending → `es` — and leaves
/// irregular words to the explicit `plural_form` argument.
fn pluralise(singular: &str) -> String {
    let lower = singular.to_ascii_lowercase();
    let consonant_y = lower.ends_with('y')
        && lower
            .chars()
            .rev()
            .nth(1)
            .is_some_and(|c| !"aeiou".contains(c));
    if consonant_y {
        format!("{}ies", &singular[..singular.len() - 1])
    } else if lower.ends_with('s')
        || lower.ends_with('x')
        || lower.ends_with('z')
        || lower.ends_with("ch")
        || lower.ends_with("sh")
    {
        format!("{singular}es")
    } else {
        format!("{singular}s")
    }
}

/// Pad `n` to the next multiple of `align` (no-op when already aligned).
pub fn align_up(n: usize, align: usize) -> usize {
    if align == 0 {
        return n;
    }
    n.div_ceil(align) * align
}

#[cfg(test)]
mod tests {
    #[test]
    fn pluralises_irregular_endings() {
        use super::plural;
        assert_eq!(plural(1, "entry", None), "1 entry");
        assert_eq!(plural(2, "entry", None), "2 entries");
        assert_eq!(plural(2, "match", None), "2 matches");
        assert_eq!(plural(3, "box", None), "3 boxes");
        assert_eq!(plural(2, "class", None), "2 classes");
        assert_eq!(plural(2, "section", None), "2 sections");
        // A vowel before `y` keeps the `y`.
        assert_eq!(plural(2, "key", None), "2 keys");
        assert_eq!(plural(2, "day", None), "2 days");
        // An explicit form still wins.
        assert_eq!(plural(2, "library", Some("libraries")), "2 libraries");
    }

    use super::*;

    #[test]
    fn reads_little_endian() {
        let data = [0x01, 0x02, 0x03, 0x04];
        let mut r = Reader::at(&data);
        assert_eq!(r.u16_le().unwrap(), 0x0201);
        assert_eq!(r.u16_le().unwrap(), 0x0403);
        assert!(r.is_empty());
    }

    #[test]
    fn reads_big_endian() {
        let data = [0xde, 0xad, 0xbe, 0xef];
        let mut r = Reader::at(&data);
        assert_eq!(r.u32_be().unwrap(), 0xdead_beef);
    }

    #[test]
    fn truncation_reports_absolute_offset() {
        let data = [0u8; 4];
        let mut r = Reader::new(&data, 0x1000);
        assert_eq!(r.u32_le().unwrap(), 0);
        let err = r.u32_le().unwrap_err();
        match err {
            AssayError::Truncated { offset, .. } => assert_eq!(offset, 0x1004),
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn cstring_stops_at_nul_and_consumes_it() {
        let data = b"hello\0world";
        let mut r = Reader::at(data);
        assert_eq!(r.cstring(64).unwrap(), "hello");
        assert_eq!(r.remaining(), 5);
    }

    #[test]
    fn cstring_respects_cap() {
        let data = b"abcdefghij";
        let mut r = Reader::at(data);
        assert_eq!(r.cstring(4).unwrap(), "abcd");
    }

    #[test]
    fn uleb128_decodes_multi_byte() {
        // 624485 == 0xE5 0x8E 0x26
        let data = [0xe5, 0x8e, 0x26];
        let mut r = Reader::at(&data);
        assert_eq!(r.uleb128().unwrap(), 624_485);
    }

    #[test]
    fn sleb128_decodes_negative() {
        // -123456 == 0xC0 0xBB 0x78
        let data = [0xc0, 0xbb, 0x78];
        let mut r = Reader::at(&data);
        assert_eq!(r.sleb128().unwrap(), -123_456);
    }

    #[test]
    fn hex_pattern_accepts_separators() {
        assert_eq!(
            parse_hex_pattern("4D 5A 90:00-03").unwrap(),
            vec![0x4d, 0x5a, 0x90, 0x00, 0x03]
        );
    }

    #[test]
    fn hex_pattern_rejects_odd_length() {
        assert!(parse_hex_pattern("4D5").is_err());
    }

    #[test]
    fn align_up_rounds() {
        assert_eq!(align_up(0, 16), 0);
        assert_eq!(align_up(1, 16), 16);
        assert_eq!(align_up(16, 16), 16);
        assert_eq!(align_up(17, 16), 32);
    }

    #[test]
    fn fixed_str_trims_at_nul() {
        assert_eq!(fixed_str(b"text\0\0\0"), "text");
        assert_eq!(fixed_str(b"text"), "text");
        assert_eq!(fixed_str(b"\0\0\0"), "");
    }
}

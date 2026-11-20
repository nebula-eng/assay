//! Minimal DER/ASN.1 traversal, enough to read Authenticode (PKCS#7) and
//! X.509 fields that matter to an analyst.
//!
//! Scope is deliberate. This module **reads** structures; it does not verify
//! signatures, and it says so in the output. Cryptographic verification of
//! Authenticode requires implementing RSA/ECDSA signature checks plus the
//! Windows trust-chain policy, which is a job for the platform verifier, not for
//! a static analyser that must run offline on Linux. What the engine *can* do
//! honestly — and does — is report which digest algorithm a signature names,
//! whether a countersignature exists, and which identity the embedded
//! certificate claims, all of which are strong signals on their own.

use crate::format::SignatureInfo;

/// ASN.1 universal tag numbers used here.
pub mod tag {
    /// `BOOLEAN`.
    pub const BOOLEAN: u8 = 0x01;
    /// `INTEGER`.
    pub const INTEGER: u8 = 0x02;
    /// `BIT STRING`.
    pub const BIT_STRING: u8 = 0x03;
    /// `OCTET STRING`.
    pub const OCTET_STRING: u8 = 0x04;
    /// `NULL`.
    pub const NULL: u8 = 0x05;
    /// `OBJECT IDENTIFIER`.
    pub const OID: u8 = 0x06;
    /// `UTF8String`.
    pub const UTF8_STRING: u8 = 0x0C;
    /// `SEQUENCE` (constructed).
    pub const SEQUENCE: u8 = 0x30;
    /// `SET` (constructed).
    pub const SET: u8 = 0x31;
    /// `PrintableString`.
    pub const PRINTABLE_STRING: u8 = 0x13;
    /// `UTCTime`.
    pub const UTC_TIME: u8 = 0x17;
    /// `GeneralizedTime`.
    pub const GENERALIZED_TIME: u8 = 0x18;
}

/// One decoded TLV.
#[derive(Debug, Clone, Copy)]
pub struct Tlv<'a> {
    /// Combined class/constructed/tag-number byte(s) start.
    pub tag_byte: u8,
    /// Full tag number, including the high-tag-number form.
    pub tag_number: u32,
    /// Value bytes.
    pub value: &'a [u8],
    /// Absolute offset of the identifier byte, for diagnostics.
    pub offset: usize,
}

impl<'a> Tlv<'a> {
    /// True when the constructed bit is set.
    pub fn is_constructed(&self) -> bool {
        self.tag_byte & 0x20 != 0
    }

    /// ASN.1 class: 0 universal, 1 application, 2 context, 3 private.
    pub fn class(&self) -> u8 {
        self.tag_byte >> 6
    }
    /// Decode an OID into dotted form.
    pub fn as_oid(&self) -> Option<String> {
        if self.tag_byte & 0x1F != tag::OID {
            return None;
        }
        decode_oid(self.value)
    }

    /// Decode a string-ish value (UTF-8, Printable, IA5, BMP).
    pub fn as_string(&self) -> Option<String> {
        match self.tag_byte & 0x1F {
            tag::UTF8_STRING | tag::PRINTABLE_STRING | 0x16 => {
                Some(String::from_utf8_lossy(self.value).into_owned())
            }
            // BMPString: UTF-16BE
            0x1E => {
                let mut s = String::new();
                for chunk in self.value.chunks_exact(2) {
                    s.push(char::from_u32(u32::from(u16::from_be_bytes([
                        chunk[0], chunk[1],
                    ])))?);
                }
                Some(s)
            }
            _ => None,
        }
    }

    /// Iterate the child TLVs of a constructed value.
    pub fn children(&self) -> TlvIter<'a> {
        TlvIter {
            data: self.value,
            pos: 0,
            base: self.offset + (self.value.len() - self.value.len()),
        }
    }
}

/// Iterator over sibling TLVs inside a constructed value.
pub struct TlvIter<'a> {
    data: &'a [u8],
    pos: usize,
    base: usize,
}

impl<'a> Iterator for TlvIter<'a> {
    type Item = Tlv<'a>;

    fn next(&mut self) -> Option<Tlv<'a>> {
        if self.pos >= self.data.len() {
            return None;
        }
        let (tlv, consumed) = read_tlv(self.data, self.pos, self.base)?;
        self.pos += consumed;
        Some(tlv)
    }
}

/// Read one TLV starting at `pos` inside `data`.
///
/// Returns the TLV and the number of bytes consumed. `None` on malformed input —
/// callers treat that as "stop here", never as an error worth aborting the run.
pub fn read_tlv(data: &[u8], pos: usize, base: usize) -> Option<(Tlv<'_>, usize)> {
    if pos >= data.len() {
        return None;
    }
    let tag_byte = data[pos];
    let mut cursor = pos + 1;

    // High-tag-number form: low 5 bits all set.
    let tag_number = if tag_byte & 0x1F == 0x1F {
        let mut num: u32 = 0;
        let mut count = 0;
        loop {
            let b = *data.get(cursor)?;
            cursor += 1;
            num = (num << 7) | u32::from(b & 0x7F);
            count += 1;
            if b & 0x80 == 0 || count > 4 {
                break;
            }
        }
        num
    } else {
        u32::from(tag_byte & 0x1F)
    };

    let first_len = *data.get(cursor)?;
    cursor += 1;
    let length = if first_len & 0x80 == 0 {
        usize::from(first_len)
    } else {
        let n = usize::from(first_len & 0x7F);
        if n == 0 || n > 4 {
            return None;
        }
        let mut len: usize = 0;
        for _ in 0..n {
            let b = *data.get(cursor)?;
            cursor += 1;
            len = (len << 8) | usize::from(b);
        }
        len
    };

    let end = cursor.checked_add(length)?;
    if end > data.len() {
        return None;
    }

    Some((
        Tlv {
            tag_byte,
            tag_number,
            value: &data[cursor..end],
            offset: base + pos,
        },
        end - pos,
    ))
}

/// Decode a DER OBJECT IDENTIFIER into dotted decimal.
pub fn decode_oid(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() {
        return None;
    }
    let mut parts: Vec<u64> = Vec::with_capacity(8);
    let first = u64::from(bytes[0]);
    parts.push(first / 40);
    parts.push(first % 40);

    let mut acc: u64 = 0;
    for &b in &bytes[1..] {
        acc = (acc << 7) | u64::from(b & 0x7F);
        if b & 0x80 == 0 {
            parts.push(acc);
            acc = 0;
        }
    }
    Some(
        parts
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join("."),
    )
}

/// Map a digest/encryption OID to a short algorithm name.
pub fn oid_algorithm_name(oid: &str) -> &'static str {
    match oid {
        "1.2.840.113549.1.1.4" => "md5WithRSA",
        "1.2.840.113549.1.1.5" => "sha1WithRSA",
        "1.2.840.113549.1.1.11" => "sha256WithRSA",
        "1.2.840.113549.1.1.12" => "sha384WithRSA",
        "1.2.840.113549.1.1.13" => "sha512WithRSA",
        "1.2.840.10045.4.1" => "sha1WithECDSA",
        "1.2.840.10045.4.3.2" => "sha256WithECDSA",
        "1.2.840.10045.4.3.3" => "sha384WithECDSA",
        "1.2.840.10045.4.3.4" => "sha512WithECDSA",
        // Digest-only OIDs.
        "1.2.840.113549.2.5" => "md5",
        "1.3.14.3.2.26" => "sha1",
        "2.16.840.1.101.3.4.2.1" => "sha256",
        "2.16.840.1.101.3.4.2.2" => "sha384",
        "2.16.840.1.101.3.4.2.3" => "sha512",
        // PKCS#7 / SPC.
        "1.2.840.113549.1.7.2" => "pkcs7-signedData",
        "1.3.6.1.4.1.311.2.1.4" => "spcIndirectDataContent",
        "1.3.6.1.4.1.311.2.1.15" => "spcPeImageData",
        "1.3.6.1.4.1.311.3.3.1" => "spcRelaxedPeMarker",
        "1.2.840.113549.1.9.3" => "contentType",
        "1.2.840.113549.1.9.4" => "messageDigest",
        "1.2.840.113549.1.9.5" => "signingTime",
        "1.2.840.113549.1.9.6" => "counterSignature",
        "1.3.6.1.4.1.311.2.4.1" => "spcNestedSignature",
        "1.3.6.1.4.1.311.3.2.1" => "timestampToken",
        _ => "",
    }
}

/// Common Name OID.
const OID_CN: &str = "2.5.4.3";

/// Pull the first CN out of an X.501 `Name`.
pub fn name_common_name(name: &Tlv<'_>) -> Option<String> {
    // Name ::= SEQUENCE OF SET OF SEQUENCE { OID, value }
    for rdn in name.children() {
        for atv in rdn.children() {
            let mut kids = atv.children();
            let Some(oid_tlv) = kids.next() else { continue };
            let Some(oid) = oid_tlv.as_oid() else {
                continue;
            };
            if oid == OID_CN {
                if let Some(value) = kids.next().and_then(|v| v.as_string()) {
                    return Some(value);
                }
            }
        }
    }
    None
}
/// Decode a DER `Time` (UTCTime or GeneralizedTime) into Unix seconds.
pub fn time_to_unix(tlv: &Tlv<'_>) -> Option<i64> {
    let raw = std::str::from_utf8(tlv.value).ok()?;
    let digits: Vec<u8> = raw
        .bytes()
        .take_while(|b| b.is_ascii_digit())
        .map(|b| b - b'0')
        .collect();

    let (year, rest) = match tlv.tag_byte & 0x1F {
        tag::UTC_TIME => {
            if digits.len() < 12 {
                return None;
            }
            let yy = i64::from(digits[0]) * 10 + i64::from(digits[1]);
            // RFC 5280 §4.1.2.5.1: YY >= 50 means 19YY, otherwise 20YY.
            let year = if yy >= 50 { 1900 + yy } else { 2000 + yy };
            (year, 2)
        }
        tag::GENERALIZED_TIME => {
            if digits.len() < 14 {
                return None;
            }
            let y = digits[0..4]
                .iter()
                .fold(0i64, |acc, &d| acc * 10 + i64::from(d));
            (y, 4)
        }
        _ => return None,
    };

    let num = |start: usize, len: usize| -> Option<i64> {
        if digits.len() < start + len {
            return None;
        }
        Some(
            digits[start..start + len]
                .iter()
                .fold(0i64, |acc, &d| acc * 10 + i64::from(d)),
        )
    };

    let month = num(rest, 2)?;
    let day = num(rest + 2, 2)?;
    let hour = num(rest + 4, 2)?;
    let minute = num(rest + 6, 2)?;
    let second = num(rest + 8, 2).unwrap_or(0);

    Some(days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second)
}

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's
/// `days_from_civil`). Correct for the 1970–2100 range certificates use.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Walk an Authenticode `SignedData` blob and fill in what we can read.
///
/// The structure is:
/// ```text
/// ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT SignedData }
/// SignedData  ::= SEQUENCE {
///                   version, digestAlgorithms SET, contentInfo,
///                   certificates [0] IMPLICIT SET OF Certificate OPTIONAL,
///                   signerInfos SET }
/// ```
pub fn inspect_authenticode(blob: &[u8], info: &mut SignatureInfo) {
    let Some((root, _)) = read_tlv(blob, 0, 0) else {
        info.issues.push("signature blob is not valid DER".into());
        return;
    };
    if root.tag_byte != tag::SEQUENCE {
        info.issues
            .push("signature blob does not start with a SEQUENCE".into());
        return;
    }

    // ContentInfo: OID then [0] wrapping SignedData.
    let mut ci = root.children();
    let content_type = ci.next().and_then(|t| t.as_oid());
    if content_type.as_deref() != Some("1.2.840.113549.1.7.2") {
        info.issues.push(format!(
            "unexpected PKCS#7 content type {:?}",
            content_type.unwrap_or_else(|| "<none>".into())
        ));
    }

    let Some(wrapper) = ci.next() else {
        info.issues.push("no SignedData wrapper".into());
        return;
    };
    let Some(signed_data) = wrapper.children().next() else {
        info.issues.push("SignedData is empty".into());
        return;
    };

    let mut sd = signed_data.children();

    // version
    let _version = sd.next();
    // digestAlgorithms SET
    if let Some(digest_set) = sd.next() {
        for alg in digest_set.children() {
            if let Some(oid_tlv) = alg.children().next() {
                if let Some(oid) = oid_tlv.as_oid() {
                    let name = oid_algorithm_name(&oid);
                    if !name.is_empty() {
                        info.digest_algorithm = Some(name.to_string());
                        if name == "md5" || name == "sha1" {
                            info.issues.push(format!(
                                "signature uses {name}, which is cryptographically broken"
                            ));
                        }
                    }
                }
            }
        }
    }

    // contentInfo — carries the SPC indirect data; we only need its presence.
    let _content_info = sd.next();

    // Walk the remaining children: [0] certificates and the SET of signerInfos.
    let mut signer_cert_subject: Option<String> = None;
    let mut signer_cert_issuer: Option<String> = None;
    let mut saw_signer_info = false;

    for node in sd {
        match (node.class(), node.tag_number) {
            // [0] IMPLICIT certificates.
            (2, 0) => {
                for cert in node.children() {
                    if cert.tag_byte != tag::SEQUENCE {
                        continue;
                    }
                    let Some(fields) = read_certificate(&cert) else {
                        continue;
                    };
                    if signer_cert_subject.is_none() {
                        signer_cert_subject = fields.subject;
                        signer_cert_issuer = fields.issuer;
                        info.valid_from = fields.not_before;
                        info.valid_to = fields.not_after;
                    }
                }
            }
            // signerInfos SET.
            (0, 17) => {
                saw_signer_info = true;
                for signer in node.children() {
                    inspect_signer_info(&signer, info);
                }
            }
            _ => {}
        }
    }

    if !saw_signer_info {
        info.issues.push("no SignerInfo present".into());
    }

    info.signer = signer_cert_subject;
    info.issuer = signer_cert_issuer;

    if !info.timestamped {
        info.issues
            .push("no countersignature timestamp (signature expires with the certificate)".into());
    }
}

/// Identity fields recovered from one X.509 certificate.
struct CertFields {
    subject: Option<String>,
    issuer: Option<String>,
    not_before: Option<i64>,
    not_after: Option<i64>,
}

/// Pull the subject, issuer and validity window out of an X.509 certificate.
fn read_certificate(cert: &Tlv<'_>) -> Option<CertFields> {
    let tbs = cert.children().next()?;
    let mut fields = tbs.children();

    // Optional [0] EXPLICIT version.
    let mut next = fields.next()?;
    if next.class() == 2 && next.tag_number == 0 {
        next = fields.next()?;
    }
    // serialNumber
    let _serial = next;
    // signature AlgorithmIdentifier
    let _sig_alg = fields.next()?;
    // issuer
    let issuer_tlv = fields.next()?;
    // validity
    let validity = fields.next()?;
    // subject
    let subject_tlv = fields.next()?;

    let issuer = name_common_name(&issuer_tlv);
    let subject = name_common_name(&subject_tlv);

    let mut times = validity.children();
    let not_before = times.next().and_then(|t| time_to_unix(&t));
    let not_after = times.next().and_then(|t| time_to_unix(&t));

    Some(CertFields {
        subject,
        issuer,
        not_before,
        not_after,
    })
}

/// Look for a timestamp token or counter-signature inside a `SignerInfo`.
fn inspect_signer_info(signer: &Tlv<'_>, info: &mut SignatureInfo) {
    for node in signer.children() {
        // signedAttrs [0] IMPLICIT
        if node.class() == 2 && node.tag_number == 0 {
            for attr in node.children() {
                let mut kids = attr.children();
                let Some(oid) = kids.next().and_then(|t| t.as_oid()) else {
                    continue;
                };
                match oid.as_str() {
                    // counterSignature
                    "1.2.840.113549.1.9.6" => info.timestamped = true,
                    // RFC 3161 timestamp token
                    "1.3.6.1.4.1.311.3.2.1" => info.timestamped = true,
                    // signingTime
                    "1.2.840.113549.1.9.5" => {
                        if let Some(set) = kids.next() {
                            if let Some(time) = set.children().next() {
                                let _ = time_to_unix(&time);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        // digestAlgorithm
        if node.tag_byte == tag::SEQUENCE && info.digest_algorithm.is_none() {
            if let Some(alg_oid) = node.children().next().and_then(|t| t.as_oid()) {
                let name = oid_algorithm_name(&alg_oid);
                if !name.is_empty() && name != "pkcs7-signedData" {
                    info.digest_algorithm = Some(name.to_string());
                }
            }
        }
    }
}

/// Render a DER blob as a compact structural outline. Used by `assay inspect`
/// for ad-hoc certificate spelunking and by tests.
pub fn outline(blob: &[u8], depth: usize, max_depth: usize, out: &mut Vec<String>) {
    let mut pos = 0usize;
    while pos < blob.len() && out.len() < 512 {
        let Some((tlv, consumed)) = read_tlv(blob, pos, 0) else {
            return;
        };
        let indent = "  ".repeat(depth);
        let label = match tlv.tag_byte & 0x1F {
            0x06 => tlv
                .as_oid()
                .map(|o| {
                    let name = oid_algorithm_name(&o);
                    if name.is_empty() {
                        format!("OID {o}")
                    } else {
                        format!("OID {o} ({name})")
                    }
                })
                .unwrap_or_else(|| "OID ?".into()),
            0x02 => format!(
                "INTEGER {}",
                tlv.value
                    .iter()
                    .fold(0u64, |acc, &b| (acc << 8) | u64::from(b))
            ),
            0x0C | 0x13 | 0x16 => format!("STRING {}", tlv.as_string().unwrap_or_default()),
            0x17 | 0x18 => format!("TIME {}", String::from_utf8_lossy(tlv.value)),
            _ => format!("tag {:#04x} len {}", tlv.tag_byte, tlv.value.len()),
        };
        out.push(format!("{indent}{label} @{}", tlv.offset));

        if tlv.is_constructed() && depth < max_depth {
            outline(tlv.value, depth + 1, max_depth, out);
        }
        pos += consumed;
        if consumed == 0 {
            return;
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_common_oids() {
        // 1.2.840.113549.1.1.11 = sha256WithRSA
        assert_eq!(
            decode_oid(&[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B]).unwrap(),
            "1.2.840.113549.1.1.11"
        );
        // 2.5.4.3 = commonName
        assert_eq!(decode_oid(&[0x55, 0x04, 0x03]).unwrap(), "2.5.4.3");
    }

    #[test]
    fn algorithm_names_resolve() {
        assert_eq!(oid_algorithm_name("2.16.840.1.101.3.4.2.1"), "sha256");
        assert_eq!(oid_algorithm_name("1.2.840.113549.1.1.5"), "sha1WithRSA");
        assert_eq!(oid_algorithm_name("9.9.9"), "");
    }

    #[test]
    fn days_from_civil_matches_known_dates() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 1, 1), 10_957);
        assert_eq!(days_from_civil(2024, 2, 29), 19_782);
    }

    #[test]
    fn parses_utctime() {
        // 240229120000Z → 2024-02-29T12:00:00Z
        let data = b"\x17\x0D240229120000Z";
        let (tlv, _) = read_tlv(data, 0, 0).unwrap();
        assert_eq!(time_to_unix(&tlv).unwrap(), 1_709_208_000);
    }

    #[test]
    fn parses_generalized_time() {
        let data = b"\x18\x0F20240229120000Z";
        let (tlv, _) = read_tlv(data, 0, 0).unwrap();
        assert_eq!(time_to_unix(&tlv).unwrap(), 1_709_208_000);
    }

    #[test]
    fn rejects_truncated_tlv() {
        let data = [0x30, 0x10, 0x00, 0x01];
        assert!(read_tlv(&data, 0, 0).is_none());
    }

    #[test]
    fn outline_walks_nested_sequence() {
        // SEQUENCE { INTEGER 5, OID 1.2.840.113549.1.1.11 }
        let data = [
            0x30, 0x0e, 0x02, 0x01, 0x05, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
            0x01, 0x0b,
        ];
        let mut out = Vec::new();
        outline(&data, 0, 4, &mut out);
        assert!(out.iter().any(|l| l.contains("INTEGER 5")));
        assert!(out.iter().any(|l| l.contains("sha256WithRSA")));
    }

    #[test]
    fn garbage_authenticode_does_not_panic() {
        let mut info = SignatureInfo::absent();
        inspect_authenticode(&[0xFF, 0xFE, 0x00, 0x01, 0x02], &mut info);
        assert!(!info.issues.is_empty() || info.signer.is_none());
    }
}

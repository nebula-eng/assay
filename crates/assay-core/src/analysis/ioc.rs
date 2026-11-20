//! Indicator-of-compromise extraction.
//!
//! Regexes over recovered strings are the cheapest intelligence a static
//! analyser can produce, and also the easiest to pollute. Two rules keep this
//! module honest:
//!
//! 1. **Every indicator carries a confidence, not a verdict.** An IPv4 literal
//!    might be a version string; a domain might be a filename. The caller
//!    decides what to escalate.
//! 2. **Known-benign shapes are filtered at the source.** `kernel32.dll` is not
//!    a domain, `1.2.3.4` inside `.rsrc` version info is not C2, and
//!    `0.0.0.0`/`127.0.0.1` are not interesting. Rejecting them here means the
//!    UI never has to explain noise.

use regex_lite::Regex;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

use crate::analysis::strings::ExtractedString;

/// Kind of indicator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IocKind {
    /// Fully-qualified URL with a scheme.
    Url,
    /// Bare domain name.
    Domain,
    /// Dotted-quad IPv4.
    Ipv4,
    /// Colon-hex IPv6.
    Ipv6,
    /// Email address.
    Email,
    /// Bitcoin address (legacy or bech32).
    Bitcoin,
    /// Ethereum-style 0x address.
    Ethereum,
    /// Tor v3/v2 onion service.
    Onion,
    /// Windows registry path.
    RegistryKey,
    /// UNC path or absolute filesystem path.
    FilePath,
    /// GUID/UUID.
    Guid,
    /// User-Agent header value.
    UserAgent,
    /// Mutex or named object name.
    NamedObject,
}

impl IocKind {
    /// Stable lowercase label for JSON and rule matching.
    pub fn as_str(self) -> &'static str {
        match self {
            IocKind::Url => "url",
            IocKind::Domain => "domain",
            IocKind::Ipv4 => "ipv4",
            IocKind::Ipv6 => "ipv6",
            IocKind::Email => "email",
            IocKind::Bitcoin => "bitcoin",
            IocKind::Ethereum => "ethereum",
            IocKind::Onion => "onion",
            IocKind::RegistryKey => "registry_key",
            IocKind::FilePath => "file_path",
            IocKind::Guid => "guid",
            IocKind::UserAgent => "user_agent",
            IocKind::NamedObject => "named_object",
        }
    }

    /// Priority used when the UI has to pick a handful of indicators to show.
    pub fn weight(self) -> u8 {
        match self {
            IocKind::Onion => 100,
            IocKind::Bitcoin | IocKind::Ethereum => 90,
            IocKind::Url => 85,
            IocKind::Ipv4 | IocKind::Ipv6 => 70,
            IocKind::RegistryKey => 60,
            IocKind::Domain => 55,
            IocKind::Email => 50,
            IocKind::NamedObject => 40,
            IocKind::FilePath => 30,
            IocKind::UserAgent => 20,
            IocKind::Guid => 10,
        }
    }
}

/// One recovered indicator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Indicator {
    /// Indicator kind.
    pub kind: IocKind,
    /// Normalised value (lowercased for domains and URLs' hosts).
    pub value: String,
    /// How many times it appeared.
    pub occurrences: usize,
    /// Offsets of the first few occurrences.
    pub offsets: Vec<u64>,
    /// 0.0–1.0, how much this looks like a real indicator rather than an
    /// artefact of binary data that happened to match a pattern.
    pub confidence: f64,
    /// Why it is worth looking at, in one line.
    pub rationale: String,
}

/// Aggregated IOC set for one artefact.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IocSet {
    /// All indicators, sorted by weight then confidence.
    pub indicators: Vec<Indicator>,
    /// Count per kind, for the summary tiles.
    pub by_kind: Vec<(String, usize)>,
}

impl IocSet {
    /// Indicators of a specific kind.
    pub fn of_kind(&self, kind: IocKind) -> impl Iterator<Item = &Indicator> {
        self.indicators.iter().filter(move |i| i.kind == kind)
    }

    /// The highest-signal indicators, limited to `n`.
    pub fn top(&self, n: usize) -> &[Indicator] {
        &self.indicators[..self.indicators.len().min(n)]
    }

    /// True when nothing was found.
    pub fn is_empty(&self) -> bool {
        self.indicators.is_empty()
    }
}

fn re_url() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)\b(?:https?|wss?|ftp)://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{3,}"#)
            .expect("url regex")
    })
}

fn re_domain() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:com|net|org|edu|gov|mil|int|info|biz|io|co|ai|app|dev|cloud|xyz|top|site|online|store|tech|ru|cn|su|ua|by|kz|de|fr|nl|uk|us|ca|au|jp|kr|in|br|mx|es|it|pl|se|no|fi|dk|ch|at|be|cz|gr|pt|ro|hu|bg|tr|il|ir|sa|ae|za|ng|ke|pk|bd|vn|th|id|my|sg|hk|tw|ph|onion)\b",
        )
        .expect("domain regex")
    })
}

fn re_ipv4() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b")
            .expect("ipv4 regex")
    })
}

fn re_email() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,24}\b").expect("email regex")
    })
}

fn re_bitcoin() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\b(?:bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
            .expect("btc regex")
    })
}

/// Base58 alphabet, as used by Bitcoin and its forks.
const BASE58: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Decode a Base58 string into big-endian bytes, or `None` when a character is
/// outside the alphabet.
fn base58_decode(text: &str) -> Option<Vec<u8>> {
    // Big-endian accumulator: each character multiplies the running value by 58
    // and adds its digit.
    let mut big: Vec<u8> = Vec::with_capacity(text.len());
    for ch in text.bytes() {
        let digit = BASE58.iter().position(|&c| c == ch)? as u32;
        let mut carry = digit;
        for byte in big.iter_mut().rev() {
            let value = u32::from(*byte) * 58 + carry;
            *byte = (value & 0xFF) as u8;
            carry = value >> 8;
        }
        while carry > 0 {
            big.insert(0, (carry & 0xFF) as u8);
            carry >>= 8;
        }
    }
    // A leading '1' is a leading zero byte, which the loop above cannot express.
    let leading_zeros = text.bytes().take_while(|&c| c == b'1').count();
    let mut out = vec![0u8; leading_zeros];
    out.extend_from_slice(&big);
    Some(out)
}

/// Verify a Base58Check string: the trailing four bytes must equal the first
/// four bytes of `SHA-256(SHA-256(payload))`.
///
/// This is the whole reason a wallet address is worth reporting and a random
/// identifier is not. Base58 uses 58 of the 62 alphanumeric characters, so a
/// 26–35 character run beginning with `1` or `3` matches the shape roughly once
/// in every few thousand arbitrary identifiers — `APMon.dll`, a Microsoft
/// performance-monitoring library, carries `3dMPXjCZeBMGVAXdgiZNgsKHRj7FE` and
/// was reported as contacting a ransom wallet because of it.
///
/// A checksum makes that a 1-in-2^32 accident instead.
fn base58check_valid(text: &str) -> bool {
    let Some(bytes) = base58_decode(text) else {
        return false;
    };
    if bytes.len() < 5 {
        return false;
    }
    let (payload, checksum) = bytes.split_at(bytes.len() - 4);
    let first = crate::hash::sha256(payload);
    let second = crate::hash::sha256(&first);
    second[..4] == *checksum
}

fn re_ethereum() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b0x[a-fA-F0-9]{40}\b").expect("eth regex"))
}

fn re_onion() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b[a-z2-7]{16,56}\.onion\b").expect("onion regex"))
}

fn re_registry() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)\b(?:HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)|HKLM|HKCU|HKCR|HKU|HKCC)\\[A-Za-z0-9 _\-\\{}.]+",
        )
        .expect("registry regex")
    })
}

fn re_guid() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
        )
        .expect("guid regex")
    })
}

fn re_user_agent() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"Mozilla/[45]\.0 \([^)\r\n]{5,120}\)[^\r\n\x22]{0,160}").expect("ua regex")
    })
}

fn re_unc_path() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\\\\[A-Za-z0-9._\-]{2,64}\\[A-Za-z0-9._\-\\ ]{2,200}").expect("unc regex")
    })
}

/// File extensions that turn a "domain-looking" token into an obvious filename.
const BENIGN_EXTENSIONS: &[&str] = &[
    "dll", "exe", "sys", "drv", "ocx", "cpl", "scr", "msi", "cab", "mui", "tsp", "efi", "ax", "so",
    "dylib", "a", "o", "obj", "lib", "pdb", "ilk", "exp", "res", "rc", "manifest", "png", "jpg",
    "jpeg", "gif", "bmp", "ico", "svg", "webp", "tif", "tiff", "txt", "log", "ini", "cfg", "conf",
    "xml", "json", "yml", "yaml", "toml", "csv", "html", "htm", "css", "js", "mjs", "ts", "map",
    "pak", "dat", "bin", "tmp", "bak", "nls", "mun", "cat", "inf", "vbs", "ps1", "bat", "cmd",
    "sh", "py", "pl", "rb",
];

/// Addresses that carry no investigative value.
fn is_boring_ipv4(value: &str) -> bool {
    let octets: Vec<u8> = value
        .split('.')
        .filter_map(|p| p.parse::<u8>().ok())
        .collect();
    if octets.len() != 4 {
        return true;
    }
    let first = octets[0];
    let last = octets[3];
    // Loopback, any, broadcast, link-local, documentation, multicast.
    if first == 0 || first == 127 || first >= 224 {
        return true;
    }
    if first == 169 && octets[1] == 254 {
        return true;
    }
    // RFC 1918 private ranges. These matter for lateral movement but they are
    // not external indicators, and mixing them into an IOC list trains the
    // reader to ignore it.
    if first == 10 {
        return true;
    }
    if first == 172 && (16..=31).contains(&octets[1]) {
        return true;
    }
    if first == 192 && octets[1] == 168 {
        return true;
    }
    if first == 192 && octets[1] == 0 && octets[2] == 2 {
        return true;
    }
    if first == 198 && octets[1] == 51 && octets[2] == 100 {
        return true;
    }
    if first == 203 && octets[1] == 0 && octets[2] == 113 {
        return true;
    }
    // Versions like 1.2.3.4 are frequently just that — a version. The tell is
    // a small leading octet plus a strictly increasing sequence; a real address
    // such as 8.8.8.8 or 1.1.1.1 is constant, not monotonic.
    let monotonic_small =
        first <= 10 && octets.windows(2).all(|w| w[0] < w[1]) && octets.iter().all(|&o| o <= 32);
    if monotonic_small {
        return true;
    }
    // A trailing zero is a network or a version component, never a host. This
    // catches the `5.1.0.0` / `6.0.0.0` family of Windows version strings that
    // otherwise pass every other filter.
    if last == 0 {
        return true;
    }
    last == 255
}

fn is_benign_filename(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    if let Some((_, ext)) = lower.rsplit_once('.') {
        return BENIGN_EXTENSIONS.contains(&ext);
    }
    false
}

/// True when a host is an XML namespace or PKI identifier rather than an
/// endpoint.
///
/// These appear in every Windows binary: the manifest declares XML namespaces
/// (`schemas.microsoft.com/SMI/2016/WindowsSettings`), and the embedded
/// certificate carries its issuer's publication points (`www.microsoft.com/pki/...`).
/// Treating them as command-and-control hosts is how a signed system library
/// scored full marks on "network indicators".
fn is_identifier_host(host: &str) -> bool {
    const SUFFIXES: &[&str] = &[
        "w3.org",
        "xmlsoap.org",
        "oasis-open.org",
        "purl.org",
        "openxmlformats.org",
        "iso.org",
        "ietf.org",
        "iana.org",
        "schemas.microsoft.com",
        "schemas.openxmlformats.org",
        "schemas.xmlsoap.org",
        "crl.microsoft.com",
        "ocsp.msocsp.com",
        "www.microsoft.com",
        "go.microsoft.com",
        "ns.adobe.com",
        "apple.com/DTDs",
    ];
    let host = host.trim_end_matches('.');
    SUFFIXES
        .iter()
        .any(|suffix| host == *suffix || host.ends_with(&format!(".{suffix}")))
}

/// True when a path looks like certificate plumbing rather than a request target.
fn is_pki_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    const MARKERS: &[&str] = &["/pki/", "/certs/", "/crl/", ".crl", ".cer", ".p7b", "/ocsp"];
    MARKERS.iter().any(|m| lower.contains(m))
}

/// Extract indicators from an already-recovered string set.
pub fn extract(strings: &[ExtractedString]) -> IocSet {
    let mut acc = IocMap::new();
    for s in strings {
        collect_into(&mut acc, s);
    }

    let mut indicators: Vec<Indicator> = Vec::with_capacity(acc.len());
    for ((kind, value), entry) in acc {
        indicators.push(Indicator {
            kind,
            value,
            occurrences: entry.occurrences,
            offsets: entry.offsets,
            confidence: entry.confidence,
            rationale: entry.rationale,
        });
    }

    // Rank: weight first (what kind of indicator), then confidence, then count.
    indicators.sort_by(|a, b| {
        b.kind
            .weight()
            .cmp(&a.kind.weight())
            .then_with(|| {
                b.confidence
                    .partial_cmp(&a.confidence)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .then_with(|| b.occurrences.cmp(&a.occurrences))
            .then_with(|| a.value.cmp(&b.value))
    });
    indicators.truncate(5000);

    let mut counts: std::collections::HashMap<&'static str, usize> =
        std::collections::HashMap::new();
    for i in &indicators {
        *counts.entry(i.kind.as_str()).or_insert(0) += 1;
    }
    let mut by_kind: Vec<(String, usize)> = counts
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
    by_kind.sort_by_key(|entry| std::cmp::Reverse(entry.1));

    IocSet {
        indicators,
        by_kind,
    }
}

/// Working entry while scanning: counts, sample offsets and the best
/// confidence seen for a given (kind, value) pair.
struct IocAcc {
    occurrences: usize,
    offsets: Vec<u64>,
    confidence: f64,
    rationale: String,
}

/// Keyed accumulator: a value can appear as several kinds (an IPv4 inside a URL
/// is both), so the kind participates in the key.
type IocMap = std::collections::HashMap<(IocKind, String), IocAcc>;

fn collect_into(acc: &mut IocMap, s: &ExtractedString) {
    let text = s.text.as_str();
    let mut push = |kind: IocKind, value: String, conf: f64, why: &str| {
        if value.is_empty() || value.len() > 2048 {
            return;
        }
        let entry = acc.entry((kind, value)).or_insert_with(|| IocAcc {
            occurrences: 0,
            offsets: Vec::new(),
            confidence: conf,
            rationale: why.to_string(),
        });
        entry.occurrences += 1;
        if entry.offsets.len() < 8 {
            entry.offsets.push(s.offset);
        }
        if conf > entry.confidence {
            entry.confidence = conf;
        }
    };

    for m in re_url().find_iter(text) {
        let value = m.as_str().trim_end_matches(['.', ',', ';', ')']);
        let (host, path) = split_url(value);
        if is_identifier_host(host) || is_pki_path(path) {
            continue;
        }
        push(
            IocKind::Url,
            value.to_string(),
            0.95,
            "explicit URL with scheme",
        );
    }
    for m in re_onion().find_iter(text) {
        push(
            IocKind::Onion,
            m.as_str().to_string(),
            0.99,
            "Tor onion service address",
        );
    }
    for m in re_email().find_iter(text) {
        push(
            IocKind::Email,
            m.as_str().to_string(),
            0.85,
            "email address, typical of C2 or registration identifiers",
        );
    }
    for m in re_bitcoin().find_iter(text) {
        let value = m.as_str();
        // A checksum turns "looks like Base58" into "is a Bitcoin address". The
        // reward is worth it: without it, one in a few thousand arbitrary strings
        // qualifies, and every hit claims the sample contacts a ransom wallet.
        if !base58check_valid(value) {
            continue;
        }
        push(
            IocKind::Bitcoin,
            value.to_string(),
            0.97,
            "Bitcoin address with a valid Base58Check checksum",
        );
    }
    for m in re_ethereum().find_iter(text) {
        push(
            IocKind::Ethereum,
            m.as_str().to_string(),
            0.9,
            "Ethereum-style address",
        );
    }
    for m in re_registry().find_iter(text) {
        push(
            IocKind::RegistryKey,
            m.as_str().to_string(),
            0.8,
            "registry path, potential persistence location",
        );
    }
    for m in re_unc_path().find_iter(text) {
        push(
            IocKind::FilePath,
            m.as_str().to_string(),
            0.75,
            "UNC path, potential lateral movement target",
        );
    }
    for m in re_user_agent().find_iter(text) {
        push(
            IocKind::UserAgent,
            m.as_str().to_string(),
            0.7,
            "hard-coded User-Agent, typical of custom HTTP clients",
        );
    }
    for m in re_domain().find_iter(text) {
        let value = m.as_str().to_ascii_lowercase();
        if is_benign_filename(&value) || is_identifier_host(&value) {
            continue;
        }
        push(IocKind::Domain, value, 0.6, "bare domain name");
    }
    for m in re_ipv4().find_iter(text) {
        if is_boring_ipv4(m.as_str()) {
            continue;
        }
        push(
            IocKind::Ipv4,
            m.as_str().to_string(),
            0.65,
            "routable IPv4 literal",
        );
    }
    for m in re_guid().find_iter(text) {
        push(
            IocKind::Guid,
            m.as_str().to_ascii_lowercase(),
            0.5,
            "GUID, often a CLSID or interface identifier",
        );
    }
}

/// Split a URL into its authority and path components.
///
/// Deliberately simple: strip the scheme, take everything up to the first `/`,
/// `?` or `#`, and drop any userinfo. Good enough to classify an identifier
/// namespace, which is the only consumer.
fn split_url(url: &str) -> (&str, &str) {
    let after_scheme = match url.find("://") {
        Some(index) => &url[index + 3..],
        None => url,
    };
    let authority_end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    let authority = &after_scheme[..authority_end];
    let path = &after_scheme[authority_end..];
    let host = authority.rsplit('@').next().unwrap_or(authority);
    let host = host.split(':').next().unwrap_or(host);
    (host, path)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::strings::Encoding;

    fn s(offset: u64, text: &str) -> ExtractedString {
        ExtractedString {
            offset,
            encoding: Encoding::Ascii,
            length: text.len(),
            text: text.to_string(),
        }
    }

    #[test]
    fn finds_url_and_domain() {
        let strings = vec![s(0, "connect to https://c2.evil-example.com/gate.php now")];
        let set = extract(&strings);
        assert!(set
            .of_kind(IocKind::Url)
            .any(|i| i.value.contains("evil-example.com")));
        assert!(set
            .of_kind(IocKind::Domain)
            .any(|i| i.value == "c2.evil-example.com"));
    }

    #[test]
    fn rejects_dll_names_as_domains() {
        let strings = vec![s(0, "kernel32.dll")];
        let set = extract(&strings);
        assert!(set.of_kind(IocKind::Domain).count() == 0);
    }

    #[test]
    fn rejects_boring_ips() {
        let strings = vec![s(0, "127.0.0.1 and 0.0.0.0 and 192.168.1.1 and 8.8.8.8")];
        let set = extract(&strings);
        let ips: Vec<&str> = set
            .of_kind(IocKind::Ipv4)
            .map(|i| i.value.as_str())
            .collect();
        assert!(ips.contains(&"8.8.8.8"));
        assert!(!ips.contains(&"127.0.0.1"));
        assert!(!ips.contains(&"192.168.1.1"));
    }

    #[test]
    fn finds_registry_path() {
        let strings = vec![s(
            0,
            "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        )];
        let set = extract(&strings);
        assert!(set.of_kind(IocKind::RegistryKey).count() >= 1);
    }

    #[test]
    fn finds_onion() {
        let strings = vec![s(0, "http://expyuzz4wqqyqhjn.onion/")];
        let set = extract(&strings);
        assert!(set
            .of_kind(IocKind::Onion)
            .any(|i| i.value.ends_with(".onion")));
    }

    #[test]
    fn finds_bitcoin_address() {
        let strings = vec![s(0, "pay 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa now")];
        let set = extract(&strings);
        assert!(set.of_kind(IocKind::Bitcoin).count() >= 1);
    }

    #[test]
    fn counts_occurrences() {
        let strings = vec![
            s(0, "https://a.example.com/x"),
            s(100, "https://a.example.com/x"),
        ];
        let set = extract(&strings);
        let url = set.of_kind(IocKind::Url).next().unwrap();
        assert_eq!(url.occurrences, 2);
    }

    #[test]
    fn ranking_puts_onion_first() {
        let strings = vec![
            s(0, "https://a.example.com/x"),
            s(10, "abc2def3ghi4jkl5.onion"),
        ];
        let set = extract(&strings);
        assert_eq!(set.indicators[0].kind, IocKind::Onion);
    }

    #[test]
    fn version_like_quads_are_ignored() {
        let strings = vec![s(0, "version 1.2.3.4 build 5.6.7.8")];
        let set = extract(&strings);
        assert_eq!(set.of_kind(IocKind::Ipv4).count(), 0);
    }

    #[test]
    fn base58check_accepts_real_addresses() {
        // Genesis block address, and a P2SH address. Both carry a valid
        // double-SHA-256 checksum in their last four bytes.
        assert!(base58check_valid("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"));
        assert!(base58check_valid("1BoatSLRHtKNngkdXEeobR76b53LETtpyT"));
        assert!(base58check_valid("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"));
    }

    #[test]
    fn base58check_rejects_shape_that_is_not_an_address() {
        // From `APMon.dll`, a Microsoft performance-monitoring library: 31
        // Base58 characters starting with `3`, which the shape regex accepts. The
        // checksum does not. Before this check existed the file was reported as
        // contacting a ransom wallet and scored high.
        assert!(!base58check_valid("3dMPXjCZeBMGVAXdgiZNgsKHRj7FE"));
        // A run of the alphabet in order is the canonical near-miss.
        assert!(!base58check_valid("1111111111111111111111111111"));
        assert!(!base58check_valid(""));
        assert!(!base58check_valid("1"));
        // Characters outside the alphabet (`0`, `O`, `I`, `l`) are not Base58.
        assert!(!base58check_valid("0OIl1111111111111111111111111"));
    }

    #[test]
    fn only_checksummed_wallets_become_indicators() {
        let strings = vec![s(
            0,
            "wallet 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa and noise 3dMPXjCZeBMGVAXdgiZNgsKHRj7FE",
        )];
        let set = extract(&strings);
        let found: Vec<&str> = set
            .of_kind(IocKind::Bitcoin)
            .map(|i| i.value.as_str())
            .collect();
        assert_eq!(found, vec!["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"]);
    }
}

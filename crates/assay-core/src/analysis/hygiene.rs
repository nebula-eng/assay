//! String-hygiene predicates.
//!
//! A string in a binary is evidence of intent only when it names something the
//! code **acts on**. Most strings name something the code merely mentions — a
//! path, a hostname, an XML element, its own symbol file, its own name — and
//! every predicate below exists because a specific signed Microsoft binary was
//! convicted on exactly that kind of string.
//!
//! They live here, rather than inside the ATT&CK inference, because the rule
//! engine reads the same string table and needs the same hygiene: a rule keyed
//! on `eval(` fired on `slmgr.vbs`'s resource-lookup helper, which is a Windows
//! Script Host idiom, not obfuscation.

/// True when a string names a **location** rather than an object the code acts
/// on.
///
/// Paths and hostnames say where something lives. Attackers do embed them — a
/// C2 URL, a drop path — but that is what the indicator layer is for. As ATT&CK
/// evidence they are actively misleading, and twice in this project's own test
/// corpus they were the entire basis for a critical finding:
///
/// * `%programfiles%\windows defender\msmpeng.exe` appears in Task Manager
///   because it draws that process's icon, not because it terminates it.
/// * `vega.ws.symantec.com` appears in certutil because that is a certificate
///   revocation endpoint, not a target.
///
/// Both were read as "names a security product alongside a termination
/// primitive", which labelled two Microsoft-signed system tools as
/// defence-evasion malware.
///
/// Registry hives are deliberately **not** treated as locations: `SOFTWARE\...`
/// is a thing code reads and writes, so it stays available as evidence.
pub(crate) fn is_location(text: &str) -> bool {
    let t = text.trim();
    if t.len() < 4 {
        return false;
    }
    if t.contains("://") {
        return true;
    }
    let bytes = t.as_bytes();
    // `%ProgramFiles%\...` — environment-variable-rooted path.
    if bytes[0] == b'%' {
        return true;
    }
    // `C:\...` and `/usr/...`.
    if bytes.len() > 2 && bytes[1] == b':' && (bytes[2] == b'\\' || bytes[2] == b'/') {
        return true;
    }
    // UNC share.
    if t.starts_with("\\\\") {
        return true;
    }

    let lower = t.to_ascii_lowercase();
    let is_registry = lower.starts_with("software\\")
        || lower.starts_with("system\\")
        || lower.starts_with("hkey_")
        || lower.starts_with("hklm")
        || lower.starts_with("hkcu")
        || lower.starts_with("control\\")
        || lower.starts_with("clsid\\");
    if !is_registry && t.contains('\\') {
        return true;
    }

    is_hostname(t)
}

/// Top-level domains common enough that `evil.com` is a host, while `ntds.dit`
/// is not.
///
/// The list exists to separate a hostname from a filename: both are `label.label`.
/// `ntds.dit` is the Active Directory database and must survive — it is exactly
/// the string a credential-dumping rule wants to see.
const COMMON_TLDS: &[&str] = &[
    "com", "net", "org", "io", "cn", "ru", "ws", "info", "biz", "xyz", "top", "site", "online",
    "club", "shop", "app", "dev", "uk", "de", "fr", "jp", "br", "in", "su", "cc", "tv", "me", "co",
    "eu", "nl", "pl", "kr", "tw", "hk", "sg", "au", "ca", "us", "ir", "vn", "th",
];

/// True when the text is a bare DNS name (`host.tld`, `a.b.tld`, optionally with
/// a path or port).
pub(crate) fn is_hostname(text: &str) -> bool {
    let authority = text.split(['/', '?', '#']).next().unwrap_or(text);
    let host = authority.rsplit('@').next().unwrap_or(authority);
    let host = host.split(':').next().unwrap_or(host);
    if !host.contains('.') {
        return false;
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 2 || labels.iter().any(|label| label.is_empty()) {
        return false;
    }
    let plausible = labels.iter().all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    });
    if !plausible {
        return false;
    }
    // Three or more labels is unambiguous enough; two needs a known TLD so that
    // `ntds.dit` and `system.dat` are not mistaken for hosts.
    let tld = labels[labels.len() - 1].to_ascii_lowercase();
    labels.len() >= 3 || COMMON_TLDS.contains(&tld.as_str())
}

/// True when the string is a data-format declaration rather than a message.
///
/// Appx packaging ships its whole manifest XSD as literal strings, so
/// `<xs:element name="shadowcopyexcludefile">` and
/// `<xs:complexType name="ct_pospaymentconnector">` appear in a legitimate
/// Microsoft library. Substring matching read the first as "deletes shadow
/// copies" and the second as "asks for a ransom payment", and the pair produced
/// a critical ransomware verdict for `AppxPackaging.dll`.
pub(crate) fn is_markup(text: &str) -> bool {
    let t = text.trim_start();
    if t.starts_with('<') && t.contains('>') {
        return true;
    }
    if t.starts_with('<') {
        return true;
    }
    let lower = t.to_ascii_lowercase();
    lower.starts_with("xs:") || lower.starts_with("xsd:") || lower.starts_with("xmlns")
}

/// True when the string is a debug-symbol path.
///
/// The linker embeds `C:\build\...\wbadmin.pdb` in every binary it produces, so
/// the image's own name appears in its own string table. Matching that against a
/// rule keyed on a tool name is self-reference, not evidence: `wbadmin.exe`
/// scored critical for "deletes the recovery catalogue" because it contained
/// `wbadmin.pdb`, the name of its own symbol file.
pub(crate) fn is_debug_symbol(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.ends_with(".pdb")
        || lower.contains(".pdb\\")
        || lower.contains(".pdb/")
        || lower.ends_with(".dbg")
        || lower.ends_with(".ilk")
        || lower.contains("\\obj\\")
}

/// True when the string is the module's own name, with or without a path or
/// extension.
///
/// Every command-line tool prints its own name in its usage text, so
/// `wbadmin.exe` carries the literal string `wbadmin.exe`. A rule keyed on the
/// tool's name then matches the tool itself: `wbadmin.exe` was reported as
/// deleting the recovery catalogue because it documented its own usage.
///
/// Only an exact stem match qualifies. A binary named `locker.exe` still keeps
/// the string "locker encrypted your files", because that whole sentence is not
/// its name.
pub(crate) fn is_self_reference(text: &str, module: &str) -> bool {
    if module.is_empty() {
        return false;
    }
    let trimmed = text.trim();
    let base = trimmed.rsplit(['\\', '/']).next().unwrap_or(trimmed);
    let stem = match base.rsplit_once('.') {
        Some((stem, _)) => stem,
        None => base,
    };
    stem.eq_ignore_ascii_case(module)
}

/// True when the string is the Windows Script Host resource-lookup idiom.
///
/// Every Microsoft `.vbs` that reads localised strings out of a resource DLL
/// carries the same three lines:
///
/// ```vbscript
/// Function GetResource(Name)
///     GetResource = Eval(Name)
/// End Function
/// ```
///
/// `slmgr.vbs` and `winrm.vbs` both ship it, and a rule that treats `eval(` as
/// dynamic execution convicted both of them of being obfuscated stagers. The
/// `Eval` there indexes a resource table; it does not evaluate attacker-supplied
/// code, and calling it obfuscation is reading a verb as a behaviour.
///
/// Only the assignment form qualifies. A script that calls `Eval(` on anything
/// else keeps the marker.
pub(crate) fn is_script_resource_lookup(text: &str) -> bool {
    let compact: String = text
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_ascii_lowercase();
    compact.contains("getresource=eval(")
}

/// The file stem of an artefact name, for [`is_self_reference`].
///
/// `C:/Windows/System32/wbadmin.exe` → `wbadmin`. Passed to string hygiene so a
/// module's own name can be excluded from its evidence; the caller has the path,
/// the predicate only needs the stem.
pub(crate) fn module_stem(name: &str) -> &str {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    match base.rsplit_once('.') {
        Some((stem, _)) => stem,
        None => base,
    }
}

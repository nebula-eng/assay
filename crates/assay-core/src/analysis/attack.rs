//! MITRE ATT&CK technique inference from static evidence.
//!
//! ## The problem this module has to avoid
//!
//! A naive implementation greps the import table for API names and reports a
//! technique per hit. It looks impressive and it is worthless: `CreateRemoteThread`
//! is imported by every debugger, profiler and anti-cheat; `CryptEncrypt` by
//! every application that stores a password; `NtQueryInformationProcess` by
//! essentially everything that needs its own process information.
//!
//! Worse, a naive implementation scores *providers* as *users*. `advapi32.dll`
//! exports `CryptEncrypt` and imports it from `CRYPTSP.dll` — the classic
//! API-forwarding pattern — and a naive analyser concludes that the Windows
//! registry library is ransomware.
//!
//! ## The model used here
//!
//! A technique needs a **combination that has a reason to hold**, expressed as
//! four slots:
//!
//! | Slot | Semantics |
//! |------|-----------|
//! | `all_apis` | Every listed symbol must be present |
//! | `core_apis` | At least `min_core` of these must be present |
//! | `also_apis` | At least one of these must also be present (when non-empty) |
//! | `any_strings` | At least one of these substrings must appear (when non-empty) |
//!
//! and two guards that apply to every rule:
//!
//! * **Exports disqualify.** If the module itself exports a symbol, that symbol
//!   is its product, not its behaviour. Forwarders are implementation detail.
//! * **Two pieces of evidence minimum.** A technique never fires on one matched
//!   symbol. This is enforced centrally so no individual rule can regress.
//!
//! `min_core` is where domain knowledge lives, and it is set deliberately: one
//! for a symbol that is genuinely rare (`GetAsyncKeyState`, `NtLoadDriver`), two
//! for a symbol that is common but meaningful in company
//! (`AdjustTokenPrivileges`, `IsDebuggerPresent`).

use serde::{Deserialize, Serialize};

use crate::analysis::hygiene::{
    is_debug_symbol, is_location, is_markup, is_script_resource_lookup, is_self_reference,
};
use crate::format::BinaryImage;

/// One inferred ATT&CK technique.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Technique {
    /// Technique identifier (`T1055`).
    pub id: String,
    /// Sub-technique when the rule targets one (`T1055.012`).
    pub sub_id: Option<String>,
    /// Technique name as MITRE writes it.
    pub name: String,
    /// Tactic phase (`defense-evasion`, `persistence`, …).
    pub tactic: String,
    /// 0.0–1.0 confidence that the *capability* is present.
    pub confidence: f64,
    /// Symbols and strings that satisfied the rule.
    pub evidence: Vec<String>,
    /// What the combination means, in one sentence.
    pub note: String,
    /// One-line remediation framing for defenders.
    pub detection: String,
}

/// A technique rule.
struct Rule {
    /// Technique identifier.
    id: &'static str,
    /// Sub-technique identifier, when the rule targets one.
    sub_id: Option<&'static str>,
    /// Display name.
    name: &'static str,
    /// Tactic phase.
    tactic: &'static str,
    /// Symbols that must all be present.
    all_apis: &'static [&'static str],
    /// Distinctive symbols, of which `min_core` must be present.
    core_apis: &'static [&'static str],
    /// How many `core_apis` are required. `0` means the slot is unused.
    min_core: usize,
    /// Additional symbols, at least one of which must be present.
    also_apis: &'static [&'static str],
    /// Substrings, at least one of which must appear in a recovered string.
    any_strings: &'static [&'static str],
    /// When true, a module that enumerates processes or services is exempt from
    /// this rule entirely.
    ///
    /// An enumerator's string table necessarily holds the names of everything it
    /// lists. Task Manager carries `lsass.exe` and `msmpeng.exe` because it draws
    /// them in a list, not because it targets them — and reading those names as
    /// evidence of targeting turned the Windows Task Manager into a credential
    /// dumper. A dedicated stealer names its target too, but reaches it with
    /// `OpenProcess` and never enumerates, so enumeration is the discriminator.
    ///
    /// Exempt means **not reported**, not "reported at low confidence": for an
    /// enumerator the name evidence is uninterpretable, and a guess dressed up as
    /// a finding is worse than silence. The report says so in a structural note.
    suppressed_by_enumeration: bool,
    /// Base confidence before corroboration bonus.
    confidence: f64,
    /// What the combination means.
    note: &'static str,
    /// Detection guidance.
    detection: &'static str,
}

/// The rule corpus.
///
/// Ordering is by tactic for readability. Every entry documents *why* its
/// combination holds, because a reviewer must be able to disagree with the
/// reasoning rather than with a black box.
#[rustfmt::skip]
const RULES: &[Rule] = &[
    // ================= Execution =================
    Rule {
        id: "T1059.001", sub_id: Some("T1059.001"),
        name: "Command and Scripting Interpreter: PowerShell",
        tactic: "execution",
        all_apis: &[],
        core_apis: &["ShellExecuteA", "ShellExecuteW", "CreateProcessA", "CreateProcessW", "WinExec"],
        min_core: 1,
        also_apis: &[],
        // The shell-spawning API is table stakes; the PowerShell marker is the
        // discriminator, so it is required rather than optional.
        any_strings: &["powershell", "-encodedcommand", "-enc ", "invoke-expression", "iex("],
        suppressed_by_enumeration: false,
        confidence: 0.88,
        note: "Spawns a process and carries PowerShell invocation material, the shape of a script stager.",
        detection: "Script-block logging (event 4104) records the decoded command.",
    },
    Rule {
        id: "T1059.003", sub_id: Some("T1059.003"),
        name: "Command and Scripting Interpreter: Windows Command Shell",
        tactic: "execution",
        all_apis: &[],
        core_apis: &["WinExec", "CreateProcessA", "CreateProcessW", "ShellExecuteA", "ShellExecuteW"],
        min_core: 1,
        also_apis: &[],
        // Requiring the executable name plus the switch avoids matching the
        // literal "/c " that appears in unrelated formatting strings.
        any_strings: &["cmd.exe /c", "cmd /c", "cmd.exe\\0/c", "\\cmd.exe"],
        suppressed_by_enumeration: false,
        confidence: 0.66,
        note: "Invokes the command interpreter directly, typically to chain a second stage.",
        detection: "Process ancestry: cmd.exe spawned by a document reader or an installer is abnormal.",
    },
    Rule {
        id: "T1047", sub_id: None,
        name: "Windows Management Instrumentation",
        tactic: "execution",
        all_apis: &[],
        core_apis: &["CoCreateInstance", "CoInitializeEx", "CoInitializeSecurity"],
        min_core: 1,
        also_apis: &[],
        any_strings: &["win32_process", "root\\cimv2", "wmic", "win32_shadowcopy"],
        suppressed_by_enumeration: false,
        confidence: 0.72,
        note: "Initialises COM and references WMI namespaces, which are used for local and remote execution.",
        detection: "WMI-Activity/Operational records the consumer, command line and calling process.",
    },
    Rule {
        id: "T1059.005", sub_id: Some("T1059.005"),
        name: "Command and Scripting Interpreter: Visual Basic",
        tactic: "execution",
        all_apis: &[],
        core_apis: &[],
        min_core: 0,
        also_apis: &[],
        // COM automation is resolved by ProgID at runtime, so no import exists
        // to key on. The ProgID strings are the only static signal, and they are
        // specific enough to stand alone.
        any_strings: &["wscript.shell", "scripting.filesystemobject", "shell.application", "msxml2.xmlhttp"],
        suppressed_by_enumeration: false,
        confidence: 0.74,
        note: "Contains VBScript/JScript COM automation ProgIDs, the building blocks of a script dropper.",
        detection: "Block or log wscript.exe and cscript.exe execution on endpoints.",
    },

    // ================= Persistence =================
    Rule {
        id: "T1547.001", sub_id: Some("T1547.001"),
        name: "Boot or Logon Autostart: Registry Run Keys",
        tactic: "persistence",
        all_apis: &[],
        core_apis: &["RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA", "RegCreateKeyExW", "RegSetKeyValueA"],
        min_core: 1,
        also_apis: &[],
        // Writing a value is unremarkable; writing it under a Run key is the
        // technique. The path is required.
        any_strings: &[
            "\\currentversion\\run",
            "\\currentversion\\runonce",
            "\\currentversion\\policies\\explorer\\run",
        ],
        suppressed_by_enumeration: false,
        confidence: 0.86,
        note: "Writes an autorun value: code that starts at every logon without a service or a task.",
        detection: "Baseline Run/RunOnce values; alert on new entries pointing at user-writable paths.",
    },
    Rule {
        id: "T1543.003", sub_id: Some("T1543.003"),
        name: "Create or Modify System Process: Windows Service",
        tactic: "persistence",
        all_apis: &[],
        core_apis: &["CreateServiceA", "CreateServiceW", "ChangeServiceConfigA", "ChangeServiceConfigW", "StartServiceA"],
        min_core: 1,
        also_apis: &["OpenSCManagerA", "OpenSCManagerW"],
        any_strings: &[],
        suppressed_by_enumeration: false,
        confidence: 0.72,
        note: "Registers or reconfigures a service, which survives reboots and can run as SYSTEM.",
        detection: "Event 7045 records every installed service with its image path and account.",
    },
    Rule {
        id: "T1053.005", sub_id: Some("T1053.005"),
        name: "Scheduled Task/Job: Scheduled Task",
        tactic: "persistence",
        all_apis: &[],
        core_apis: &[],
        min_core: 0,
        also_apis: &["CoCreateInstance"],
        any_strings: &["schtasks", "taskschd", "\\tasks\\", "registertaskdefinition"],
        suppressed_by_enumeration: false,
        confidence: 0.70,
        note: "References the task scheduler by name or namespace, the usual delayed-execution primitive.",
        detection: "Event 4698 plus TaskScheduler/Operational gives the action and trigger.",
    },

    // ================= Privilege escalation =================
    Rule {
        id: "T1134", sub_id: None,
        name: "Access Token Manipulation",
        tactic: "privilege-escalation",
        all_apis: &[],
        // OpenProcessToken and LookupPrivilegeValue are deliberately excluded:
        // they are setup calls that appear in ordinary software. Two of the
        // distinctive operations are required, which no incidental code path does.
        core_apis: &[
            "AdjustTokenPrivileges", "DuplicateTokenEx", "ImpersonateLoggedOnUser",
            "SetThreadToken", "ImpersonateNamedPipeClient", "LogonUserA", "LogonUserW",
            "CreateProcessWithTokenW", "CreateProcessAsUserA",
        ],
        min_core: 2,
        also_apis: &[],
        any_strings: &[],
        suppressed_by_enumeration: false,
        confidence: 0.68,
        note: "Performs multiple token operations, the mechanics of running as somebody else.",
        detection: "Audit 4672/4624 type 9; correlate with unexpected SeDebugPrivilege grants.",
    },
    Rule {
        id: "T1548.002", sub_id: Some("T1548.002"),
        name: "Abuse Elevation Control: Bypass User Account Control",
        tactic: "privilege-escalation",
        all_apis: &[],
        core_apis: &["ShellExecuteExA", "ShellExecuteExW", "CreateProcessWithTokenW"],
        min_core: 1,
        also_apis: &[],
        // Generic "runas" is not enough; these are the specific auto-elevating
        // hosts abused by published UAC bypasses.
        any_strings: &["fodhelper", "sdclt", "eventvwr.exe", "computerdefaults", "cmstp"],
        suppressed_by_enumeration: false,
        confidence: 0.74,
        note: "Names a known auto-elevating host, the pivot used by UAC bypass techniques.",
        detection: "Monitor auto-elevating binaries launching children outside their normal role.",
    },
    Rule {
        id: "T1068", sub_id: None,
        name: "Exploitation for Privilege Escalation",
        tactic: "privilege-escalation",
        all_apis: &[],
        core_apis: &["DeviceIoControl", "NtDeviceIoControlFile"],
        min_core: 1,
        also_apis: &[],
        // DeviceIoControl is ubiquitous; opening a raw physical device is not.
        any_strings: &["\\\\.\\physicaldrive", "\\\\.\\globalroot", "\\\\.\\scsi", "\\device\\physicalmemory"],
        suppressed_by_enumeration: false,
        confidence: 0.62,
        note: "Opens a raw device handle, the entry point for driver-based elevation bugs.",
        detection: "Log raw-device access; legitimate applications rarely need PhysicalDrive handles.",
    },

    // ================= Defense evasion =================
    Rule {
        id: "T1055", sub_id: None,
        name: "Process Injection",
        tactic: "defense-evasion",
        all_apis: &["VirtualAllocEx", "WriteProcessMemory"],
        core_apis: &[
            "CreateRemoteThread", "NtCreateThreadEx", "RtlCreateUserThread",
            "QueueUserAPC", "NtQueueApcThread", "SetThreadContext", "NtMapViewOfSection",
        ],
        min_core: 1,
        also_apis: &[],
        any_strings: &[],
        suppressed_by_enumeration: false,
        confidence: 0.90,
        note: "Allocate in another process, write to it, then execute there — the canonical injection triad.",
        detection: "Sysmon 8/10 with a cross-process target from a non-security product.",
    },
    Rule {
        id: "T1055.012", sub_id: Some("T1055.012"),
        name: "Process Injection: Process Hollowing",
        tactic: "defense-evasion",
        all_apis: &[],
        core_apis: &["NtUnmapViewOfSection", "ZwUnmapViewOfSection"],
        min_core: 1,
        // Unmapping alone is a loader detail; hollowing requires putting
        // something back, which is what the second clause demands.
        also_apis: &["WriteProcessMemory", "NtWriteVirtualMemory", "VirtualAllocEx", "SetThreadContext"],
        any_strings: &[],
        suppressed_by_enumeration: false,
        confidence: 0.84,
        note: "Unmaps a section of a process and then writes into it: the defining hollowing sequence.",
        detection: "Sysmon 1 followed by image-base anomalies in the same PID.",
    },
    Rule {
        id: "T1055.003", sub_id: Some("T1055.003"),
        name: "Process Injection: Thread Execution Hijacking",
        tactic: "defense-evasion",
        all_apis: &["SuspendThread", "SetThreadContext"],
        core_apis: &["ResumeThread"],
        min_core: 1,
        also_apis: &[],
        any_strings: &[],
        suppressed_by_enumeration: false,
        confidence: 0.86,
        note: "Suspends a thread, rewrites its context, then resumes it into attacker-chosen code.",
        detection: "Sysmon 8 targeting threads the caller does not own.",
    },
    Rule {
        id: "T1055.004", sub_id: Some("T1055.004"),
        name: "Process Injection: Asynchronous Procedure Call",
        tactic: "defense-evasion",
        all_apis: &[],
        core_apis: &["QueueUserAPC", "NtQueueApcThread"],
        min_core: 1,
        also_apis: &["VirtualAllocEx", "NtAllocateVirtualMemory", "WriteProcessMemory", "OpenProcess"],
        any_strings: &[],
        suppressed_by_enumeration: false,
        confidence: 0.78,
        note: "Queues an APC for another process, delivering code without creating a thread.",
        detection: "ETW threat-intelligence APC events; correlate with remote allocation.",
    },
    Rule {
        id: "T1055.001", sub_id: Some("T1055.001"),
        name: "Process Injection: Dynamic-link Library Injection",
        tactic: "defense-evasion",
        all_apis: &[],
        core_apis: &["LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW", "LdrLoadDll"],
        min_core: 1,
        also_apis: &[],
        // Loading a library is normal; loading one out of a writable staging
        // directory is the side-loading shape.
        any_strings: &["\\appdata\\local\\temp\\", "\\programdata\\", "\\users\\public\\"],
        suppressed_by_enumeration: false,
        confidence: 0.58,
        note: "Loads a library from a user-writable staging directory, the DLL side-loading shape.",
        detection: "Monitor image loads from Temp, ProgramData and Users\\Public (Sysmon 7).",
    },
    Rule {
        id: "T1622", sub_id: None,
        name: "Debugger Evasion",
        tactic: "defense-evasion",
        all_apis: &[],
        // NtQueryInformationProcess is included but needs company: a lone
        // ProcessBasicInformation query is routine and proves nothing.
        core_apis: &[
            "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtSetInformationThread",
            "OutputDebugStringA", "NtQueryInformationProcess",
        ],
        min_core: 2,
        also_apis: &[],
        any_strings: &[],
        suppressed_by_enumeration: false,
        confidence: 0.62,
        note: "Combines multiple debugger-detection or anti-attach operations.",
        detection: "Anti-analysis is not malicious alone, but it raises the cost of triage.",
    },
    Rule {
        id: "T1497.001", sub_id: Some("T1497.001"),
        name: "Virtualization/Sandbox Evasion: System Checks",
        tactic: "defense-evasion",
        all_apis: &[],
        // Volume and memory queries are used by every application; firmware table
        // enumeration and driver enumeration are the sandbox-hunting primitives.
        core_apis: &["GetSystemFirmwareTable", "EnumDeviceDrivers", "SetupDiGetDeviceRegistryPropertyA"],
        min_core: 1,
        also_apis: &[],
        any_strings: &["vmware", "virtualbox", "vbox", "qemu", "sandbox", "cuckoo", "wine_get_unix_file_name"],
        suppressed_by_enumeration: false,
        confidence: 0.72,
        note: "Probes hardware identity for hypervisor or analysis-framework artefacts.",
        detection: "Sandbox-aware samples need a bare-metal or hardened-VM detonation.",
    },
    Rule {
        id: "T1070.004", sub_id: Some("T1070.004"),
        name: "Indicator Removal: File Deletion",
        tactic: "defense-evasion",
        all_apis: &[],
        core_apis: &["DeleteFileA", "DeleteFileW", "MoveFileExA", "MoveFileExW", "SetFileInformationByHandle"],
        min_core: 2,
        also_apis: &[],
        any_strings: &[],
        suppressed_by_enumeration: false,
        confidence: 0.48,
        note: "Performs several file-removal operations, typical cleanup after staging a payload.",
        detection: "Track deletions of files created in the same session under Temp.",
    },
    Rule {
        id: "T1112", sub_id: None,
        name: "Modify Registry",
        tactic: "defense-evasion",
        all_apis: &[],
        // Deletion and restore are the tampering shape; plain value writes are
        // excluded as they are ubiquitous.
        core_apis: &["RegDeleteKeyA", "RegDeleteKeyW", "RegDeleteValueA", "RegDeleteValueW", "RegRestoreKeyA"],
        min_core: 1,
        also_apis: &[],
        any_strings: &[],
        suppressed_by_enumeration: false,
        confidence: 0.52,
        note: "Removes or restores registry keys, which is how configuration and security settings get rolled back.",
        detection: "Baseline security-relevant keys; alert on deletions under Policies branches.",
    },
    Rule {
        id: "T1562.001", sub_id: Some("T1562.001"),
        name: "Impair Defenses: Disable or Modify Tools",
        tactic: "defense-evasion",
        all_apis: &[],
        core_apis: &["ControlService", "DeleteService", "ChangeServiceConfig"],
        min_core: 1,
        also_apis: &["TerminateProcess", "NtTerminateProcess", "RegSetValueExW", "RegSetValueExA"],
        // The discriminator is the *action*, not the product being named.
        //
        // Naming a security product is close to universal on Windows: Task Manager
        // lists `msmpeng.exe` because it draws the process list, `certutil` carries
        // the string `symantec 'vega' log` as a log label for a trust anchor, and
        // the Application Compatibility shims contain a whole error message that
        // reads "calling application request contradicts with the windows defender
        // status". Naming the product was the old rule, and it scored seven
        // Microsoft-signed system binaries as critical defence evasion.
        //
        // Disabling it looks different: the specific knobs Defender exposes, or the
        // service-control and registry writes that turn it off.
        any_strings: &[
            "disablerealtimemonitoring", "disableantispyware", "disableioavprotection",
            "disablebehaviormonitoring", "disableblockatfirstseen",
            "add-mppreference", "set-mppreference", "exclusionpath", "exclusionprocess",
            "tamperprotection", "amsiutils", "amsi.dll", "amsiinitialize",
        ],
        suppressed_by_enumeration: true,
        confidence: 0.88,
        note: "Carries the specific switch that turns a security product off, or the AMSI interface it would have to patch.",
        detection: "Alert on any process terminating AV/EDR components or writing their exclusion lists.",
    },
    Rule {
        id: "T1014", sub_id: None,
        name: "Rootkit",
        tactic: "defense-evasion",
        all_apis: &[],
        core_apis: &["NtLoadDriver", "ZwLoadDriver"],
        min_core: 1,
        also_apis: &[],
        any_strings: &["\\systemroot\\system32\\drivers"],
        suppressed_by_enumeration: false,
        confidence: 0.76,
        note: "Loads a kernel driver at runtime, the standard rootkit delivery path.",
        detection: "Event 7045 with a kernel service type, plus unsigned driver loads.",
    },

    // ================= Credential access =================
    Rule {
        id: "T1003", sub_id: None,
        name: "OS Credential Dumping",
        tactic: "credential-access",
        all_apis: &[],
        // CredRead and CredEnumerate are excluded: they are the supported API for
        // credential-manager applications. Dumping means process memory or LSA/SAM.
        core_apis: &[
            "MiniDumpWriteDump", "LsaEnumerateLogonSessions", "LsaOpenPolicy",
            "SamQueryInformationUser", "SamConnect",
        ],
        min_core: 1,
        also_apis: &["OpenProcess", "OpenProcessToken"],
        // The API pair alone is a *capability*, not a target. Task Manager imports
        // MiniDumpWriteDump and OpenProcess because "Create dump file" is a menu
        // item, and certutil imports LsaOpenPolicy for its policy-backup mode —
        // both Microsoft-signed, both scored as credential theft before this
        // requirement existed. Naming the store being read is what separates a
        // dumper from a tool that can dump.
        //
        // `ntds.dit`, `sam` and `lsass` survive the location filter on purpose:
        // they are objects, not paths.
        any_strings: &[
            "lsass", "lsa secrets", "sekurlsa", "ntds.dit", "sam database",
            "security hive", "minidump of lsass", "credential dump",
        ],
        suppressed_by_enumeration: true,
        confidence: 0.87,
        note: "Reads the LSA/SAM structures or process memory where credential material lives, and names the store.",
        detection: "Sysmon 10 with lsass.exe as the target from a non-approved source is near-certain.",
    },
    Rule {
        id: "T1056.001", sub_id: Some("T1056.001"),
        name: "Input Capture: Keylogging",
        tactic: "credential-access",
        all_apis: &[],
        // GetKeyState/GetKeyboardState are excluded: games, editors and IMEs use
        // them constantly. The five below have almost no other purpose.
        core_apis: &[
            "GetAsyncKeyState", "SetWindowsHookExA", "SetWindowsHookExW",
            "RegisterRawInputDevices", "GetRawInputData",
        ],
        min_core: 1,
        also_apis: &[],
        any_strings: &[],
        suppressed_by_enumeration: false,
        confidence: 0.74,
        note: "Polls or hooks the keyboard through an API whose only common purpose is capturing input.",
        detection: "Global low-level keyboard hooks from a process with no input-method role.",
    },
    Rule {
        id: "T1555", sub_id: None,
        name: "Credentials from Password Stores",
        tactic: "credential-access",
        all_apis: &[],
        core_apis: &["CryptUnprotectData", "VaultEnumerateVaults", "CryptUnprotectMemory"],
        min_core: 1,
        also_apis: &["CryptProtectData"],
        // DPAPI is used by legitimate software to protect its own configuration,
        // so the browser-store path is required to separate theft from routine use.
        any_strings: &["login data", "\\google\\chrome\\user data", "\\microsoft\\edge\\user data", "\\microsoft\\credentials"],
        suppressed_by_enumeration: false,
        confidence: 0.82,
        note: "Decrypts DPAPI-protected blobs while referencing a browser or credential-store path.",
        detection: "Non-browser processes reading Chrome/Edge Login Data files.",
    },

    // ================= Discovery =================
    // Discovery techniques are context, not findings. They are scored at a low
    // tactic weight and never carry a rule, because every program enumerates
    // something.
    Rule {
        id: "T1057", sub_id: None,
        name: "Process Discovery",
        tactic: "discovery",
        all_apis: &[],
        core_apis: &["CreateToolhelp32Snapshot", "Process32First", "Process32FirstW", "EnumProcesses"],
        min_core: 1,
        also_apis: &["Process32Next", "Process32NextW", "EnumProcessModules"],
        any_strings: &[],
        suppressed_by_enumeration: false,
        confidence: 0.50,
        note: "Enumerates running processes, typically to pick an injection target or spot a security product.",
        detection: "Toolhelp snapshots from unsigned binaries shortly after start-up.",
    },
    Rule {
        id: "T1082", sub_id: None,
        name: "System Information Discovery",
        tactic: "discovery",
        all_apis: &[],
        core_apis: &["GetSystemInfo", "GetNativeSystemInfo", "GetComputerNameA", "GetComputerNameW"],
        min_core: 2,
        also_apis: &["GlobalMemoryStatusEx", "GetVolumeInformationA", "GetTickCount64"],
        any_strings: &[],
        suppressed_by_enumeration: false,
        confidence: 0.42,
        note: "Collects host facts, typically for bot identification or virtual-machine checks.",
        detection: "Low signal alone; meaningful alongside exfiltration primitives.",
    },
    Rule {
        id: "T1083", sub_id: None,
        name: "File and Directory Discovery",
        tactic: "discovery",
        all_apis: &[],
        core_apis: &["FindFirstFileA", "FindFirstFileW", "FindFirstFileExA", "FindFirstFileExW"],
        min_core: 1,
        also_apis: &["FindNextFileA", "FindNextFileW"],
        any_strings: &[],
        suppressed_by_enumeration: false,
        confidence: 0.38,
        note: "Walks the filesystem, a prerequisite for collection or encryption.",
        detection: "Mass directory enumeration followed by bulk reads or writes.",
    },
    Rule {
        id: "T1012", sub_id: None,
        name: "Query Registry",
        tactic: "discovery",
        all_apis: &[],
        core_apis: &["RegEnumKeyExA", "RegEnumValueA", "RegEnumValueW", "RegQueryInfoKeyA"],
        min_core: 1,
        also_apis: &["RegOpenKeyExA", "RegQueryValueExA"],
        any_strings: &[],
        suppressed_by_enumeration: false,
        confidence: 0.40,
        note: "Enumerates registry structure to fingerprint the host or locate installed software.",
        detection: "Correlate with subsequent network activity.",
    },

    // ================= Lateral movement =================
    Rule {
        id: "T1021.002", sub_id: Some("T1021.002"),
        name: "Remote Services: SMB/Windows Admin Shares",
        tactic: "lateral-movement",
        all_apis: &[],
        core_apis: &["NetShareEnum", "NetUseAdd", "NetSessionEnum", "WNetAddConnection2A", "WNetAddConnection2W"],
        min_core: 1,
        also_apis: &[],
        any_strings: &["\\admin$", "\\ipc$", "\\c$"],
        suppressed_by_enumeration: false,
        confidence: 0.70,
        note: "Enumerates or mounts SMB shares by administrative name, the primary Windows lateral channel.",
        detection: "5140/5145 with ADMIN$ access from an unexpected workstation.",
    },

    // ================= Collection =================
    // Screen capture was removed from the corpus: BitBlt/GetDC are used by every
    // GDI application, and no static combination separates a screenshot from
    // ordinary drawing. Reporting it produced false positives on text editors.
    Rule {
        id: "T1115", sub_id: None,
        name: "Clipboard Data",
        tactic: "collection",
        all_apis: &[],
        core_apis: &["GetClipboardData", "SetClipboardData"],
        min_core: 1,
        also_apis: &["OpenClipboard"],
        any_strings: &[],
        suppressed_by_enumeration: false,
        confidence: 0.56,
        note: "Reads or replaces clipboard contents, used for data theft and crypto-address substitution.",
        detection: "Clipboard access from a process with no foreground window.",
    },

    // ================= Command and control =================
    Rule {
        id: "T1071.001", sub_id: Some("T1071.001"),
        name: "Application Layer Protocol: Web Protocols",
        tactic: "command-and-control",
        all_apis: &[],
        core_apis: &[
            "HttpSendRequestA", "HttpSendRequestW", "WinHttpSendRequest",
            "InternetConnectA", "WinHttpConnect", "WinHttpOpen",
        ],
        min_core: 2,
        also_apis: &["InternetOpenA", "InternetOpenW", "WinHttpOpenRequest"],
        any_strings: &[],
        suppressed_by_enumeration: false,
        confidence: 0.64,
        note: "Implements an HTTP client through the WinINET or WinHTTP stack, the usual C2 transport.",
        detection: "Beacon-shaped intervals to a single host with uniform body sizes.",
    },
    Rule {
        id: "T1095", sub_id: None,
        name: "Non-Application Layer Protocol",
        tactic: "command-and-control",
        all_apis: &[],
        core_apis: &["socket", "connect", "send", "recv", "WSASocketA", "WSASocketW"],
        min_core: 3,
        also_apis: &["WSAStartup"],
        any_strings: &[],
        suppressed_by_enumeration: false,
        confidence: 0.52,
        note: "Drives raw Winsock directly rather than through an HTTP library, bypassing proxy logging.",
        detection: "Unexpected outbound TCP from a process with no business need.",
    },
    Rule {
        id: "T1105", sub_id: None,
        name: "Ingress Tool Transfer",
        tactic: "command-and-control",
        all_apis: &[],
        core_apis: &["URLDownloadToFileA", "URLDownloadToFileW", "URLDownloadToCacheFileA", "WinHttpReadData"],
        min_core: 1,
        also_apis: &[],
        any_strings: &[],
        suppressed_by_enumeration: false,
        confidence: 0.78,
        note: "Downloads a file to disk, the second stage of most droppers.",
        detection: "Correlate the download URL with the file written immediately afterwards.",
    },

    // ================= Impact =================
    Rule {
        id: "T1486", sub_id: None,
        name: "Data Encrypted for Impact",
        tactic: "impact",
        all_apis: &[],
        core_apis: &["CryptEncrypt", "BCryptEncrypt", "CryptGenKey", "NCryptEncrypt", "CryptDeriveKey"],
        min_core: 1,
        also_apis: &[],
        // A cipher API means nothing on its own — almost every application that
        // stores a secret uses one. What turns it into this technique is a demand
        // or a marker of encrypted output, and the marker has to be a phrase, not
        // a noun from the encryption domain.
        //
        // `payment` was the noun that convicted eight Microsoft components: a
        // billing stack legitimately pairs BCryptEncrypt with strings like
        // "payment required" (`MdmDiagnostics.dll`) and "payment app extension
        // data invalid for package" (`Windows.Payments.dll`). `bitcoin` and
        // `ransom` have the same problem in a wallet or an anti-malware
        // dictionary. Every entry below is either a sentence fragment of an
        // extortion demand or a marker only an encrypting program writes.
        any_strings: &[
            "your files have been encrypted",
            "your files are encrypted",
            "your files have been locked",
            "all your files have been",
            "files have been encrypted",
            "to decrypt your files",
            "decrypt your files",
            "pay to decrypt",
            "payment to decrypt",
            "send bitcoin",
            "pay in bitcoin",
            "pay the ransom",
            "unlock your files",
            ".locked",
            ".encrypted",
        ],
        suppressed_by_enumeration: false,
        confidence: 0.82,
        note: "Combines a symmetric cipher with extortion or file-encryption markers, the impact path.",
        detection: "Mass file writes with high-entropy output plus deletion of the originals.",
    },
    Rule {
        id: "T1489", sub_id: None,
        name: "Service Stop",
        tactic: "impact",
        all_apis: &[],
        core_apis: &["ControlService", "DeleteService", "ChangeServiceConfigA"],
        min_core: 1,
        also_apis: &[],
        any_strings: &["windefend", "vss", "backup", "sqlserver", "sql "],
        suppressed_by_enumeration: false,
        confidence: 0.66,
        note: "Stops services by name, commonly backups and security tooling before encryption.",
        detection: "Bulk service stops within a short window.",
    },
    Rule {
        id: "T1490", sub_id: None,
        name: "Inhibit System Recovery",
        tactic: "impact",
        all_apis: &[],
        core_apis: &["WinExec", "CreateProcessA", "CreateProcessW", "ShellExecuteA", "ShellExecuteW"],
        min_core: 1,
        also_apis: &[],
        // The destructive verb is the technique; the tool name is not enough.
        // `bcdedit` on its own convicted `ResetEngine.dll`, whose string reads
        // "failed to wait for bcdedit -set debug on" — a factory reset enabling a
        // debug flag, not an attacker removing recovery. Each entry below names
        // the deletion, not the utility.
        any_strings: &[
            "vssadmin delete",
            "vssadmin.exe delete",
            "delete shadows",
            "shadowcopy delete",
            "wbadmin delete",
            "delete catalog",
            "recoveryenabled no",
            "bootstatuspolicy ignoreallfailures",
        ],
        suppressed_by_enumeration: false,
        confidence: 0.86,
        note: "Invokes the exact utilities ransomware uses to delete shadow copies and recovery catalogues.",
        detection: "Process creation of vssadmin or wbadmin with `delete` arguments.",
    },
];

/// Pre-computed lookup sets for one artefact.
pub struct Evidence {
    /// Lowercased imported symbols, excluding anything the module exports.
    apis: std::collections::HashSet<String>,
    /// Lowercased exported symbols.
    exports: std::collections::HashSet<String>,
    /// Lowercased recovered strings.
    strings: std::collections::HashSet<String>,
    /// Original casing for readable evidence.
    original: std::collections::HashMap<String, String>,
    /// True when the module provides as large an API surface as it consumes.
    is_library_surface: bool,
}

impl Evidence {
    /// Build the lookup sets from an image plus its recovered strings.
    pub fn new(
        image: &BinaryImage,
        strings: &[crate::analysis::strings::ExtractedString],
        artefact_name: &str,
    ) -> Self {
        // Exports first: a symbol the module provides is not a symbol it uses.
        let mut exports = std::collections::HashSet::new();
        for export in &image.exports {
            if !export.name.is_empty() {
                exports.insert(export.name.to_ascii_lowercase());
            }
        }

        let mut apis = std::collections::HashSet::new();
        let mut original: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        for import in &image.imports {
            if import.symbol.is_empty() {
                continue;
            }
            let lower = import.symbol.to_ascii_lowercase();
            if exports.contains(&lower) {
                // API forwarding: advapi32 imports CryptEncrypt from CRYPTSP and
                // exports it to its own callers. Counting that as "uses crypto"
                // is how a naive analyser calls the registry library ransomware.
                continue;
            }
            original
                .entry(lower.clone())
                .or_insert_with(|| import.symbol.clone());
            apis.insert(lower);
        }

        // The module's own stem, used to drop self-referential strings.
        let module_stem = crate::analysis::hygiene::module_stem(artefact_name);

        // A string only counts as evidence of intent when it names something the
        // code acts on. Locations, format declarations, debug paths and the
        // module's own name all name something the code merely mentions — see
        // each predicate for the signed Microsoft binary it was written for.
        let mut set = std::collections::HashSet::new();
        for s in strings {
            let lower = s.text.to_ascii_lowercase();
            if is_location(&lower)
                || is_markup(&lower)
                || is_debug_symbol(&lower)
                || is_script_resource_lookup(&lower)
                || is_self_reference(&lower, module_stem)
            {
                continue;
            }
            set.insert(lower);
        }

        Evidence {
            apis,
            exports,
            strings: set,
            original,
            is_library_surface: image.is_library_surface(),
        }
    }

    /// How many symbols the module exports.
    pub fn export_count(&self) -> usize {
        self.exports.len()
    }

    /// True when the module lists processes, services or windows.
    ///
    /// Such a module necessarily holds the names of the things it lists, so a
    /// name in its string table is not evidence of intent. This is the single
    /// fact that separates Task Manager from a credential stealer: both import
    /// `OpenProcess`, both can name `lsass.exe`, but only the stealer reaches the
    /// target directly instead of walking a list to find it.
    pub fn enumerates(&self) -> bool {
        const ENUMERATORS: &[&str] = &[
            "enumprocesses",
            "createtoolhelp32snapshot",
            "process32first",
            "process32next",
            "process32firstw",
            "process32nextw",
            "ntquerysysteminformation",
            "enumservicesstatusexw",
            "enumservicesstatusexa",
            "enumservicesstatusw",
            "wtsenumerateprocessesw",
            "wtsscanopenprocess",
            "enumwindows",
            "enumchildwindows",
        ];
        ENUMERATORS.iter().any(|name| self.apis.contains(*name))
    }

    fn has_api(&self, name: &str) -> Option<String> {
        let lower = name.to_ascii_lowercase();
        if self.apis.contains(&lower) {
            Some(
                self.original
                    .get(&lower)
                    .cloned()
                    .unwrap_or_else(|| name.to_string()),
            )
        } else {
            None
        }
    }

    fn find_string(&self, needle: &str) -> Option<String> {
        let lower = needle.to_ascii_lowercase();
        self.strings
            .iter()
            .find(|s| find_on_word_boundary(s, &lower))
            .cloned()
    }
}

/// True when `byte` can appear inside an identifier.
///
/// Used to decide whether a match sits on a word boundary. `_` counts as a word
/// character because `shadow_copy` is one token, not the word `shadow` followed
/// by punctuation.
fn is_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// Does `haystack` contain `needle` as a **word**, rather than as a fragment of a
/// longer identifier?
///
/// A plain `contains` is how `payment` matched `pospaymentconnector` and
/// `shadowcopy` matched `shadowcopyexcludefile` — both are XML schema names
/// inside a signed Microsoft library, and both were read as evidence of
/// extortion.
///
/// A boundary is only required on a side where the needle itself begins or ends
/// with a word character. That keeps `.locked` working inside `file.locked.bak`,
/// where the leading dot is punctuation, not part of an identifier.
fn find_on_word_boundary(haystack: &str, needle: &str) -> bool {
    let h = haystack.as_bytes();
    let n = needle.as_bytes();
    if n.is_empty() || n.len() > h.len() {
        return false;
    }
    let check_head = is_word_byte(n[0]);
    let check_tail = is_word_byte(n[n.len() - 1]);
    for start in 0..=(h.len() - n.len()) {
        if &h[start..start + n.len()] != n {
            continue;
        }
        let end = start + n.len();
        let head_ok = !check_head || start == 0 || !is_word_byte(h[start - 1]);
        let tail_ok = !check_tail || end == h.len() || !is_word_byte(h[end]);
        if head_ok && tail_ok {
            return true;
        }
    }
    false
}

/// Evaluate every rule against the evidence.
///
/// Returns an empty set for platform libraries. A module that both exports and
/// imports a large API surface is infrastructure — asking whether it "has" the
/// capability to inject into a process is not a question that has a useful
/// answer, and the honest response is silence rather than a wrong one. The
/// caller records the reason as a structural note.
///
/// Otherwise a technique is reported only when its combination holds **and** at
/// least two independent observations support it. The second condition is
/// enforced here rather than per rule, so no individual rule can regress into a
/// single-API matcher.
pub fn infer(evidence: &Evidence) -> Vec<Technique> {
    if evidence.is_library_surface {
        return Vec::new();
    }

    let mut out: Vec<Technique> = Vec::with_capacity(RULES.len());

    // Computed once: enumerators are exempt from the rules whose evidence is a
    // name, because their string table holds every name they display.
    let enumerates = evidence.enumerates();

    for rule in RULES {
        if rule.suppressed_by_enumeration && enumerates {
            continue;
        }

        let mut hits: Vec<String> = Vec::new();
        let mut core_matched = 0usize;

        // Slot 1: every one of these must be present.
        let mut all_ok = true;
        for api in rule.all_apis {
            match evidence.has_api(api) {
                Some(name) => push_unique(&mut hits, name),
                None => {
                    all_ok = false;
                    break;
                }
            }
        }
        if !all_ok {
            continue;
        }

        // Slot 2: at least `min_core` of the distinctive symbols.
        for api in rule.core_apis {
            if let Some(name) = evidence.has_api(api) {
                push_unique(&mut hits, name);
                core_matched += 1;
            }
        }
        if core_matched < rule.min_core {
            continue;
        }

        // Slot 3: at least one supporting symbol, when the slot is used.
        if !rule.also_apis.is_empty() {
            let mut matched = false;
            for api in rule.also_apis {
                if let Some(name) = evidence.has_api(api) {
                    push_unique(&mut hits, name);
                    matched = true;
                }
            }
            if !matched {
                continue;
            }
        }

        // Slot 4: at least one string, when the slot is used.
        if !rule.any_strings.is_empty() {
            let mut matched = false;
            for needle in rule.any_strings {
                if let Some(found) = evidence.find_string(needle) {
                    push_unique(&mut hits, format!("string:{}", truncate(&found, 72)));
                    matched = true;
                    break;
                }
            }
            if !matched {
                continue;
            }
        }

        // Central guard: a technique needs corroboration. One symbol is not a
        // capability, however distinctive the symbol looks.
        if hits.len() < 2 {
            continue;
        }

        // Additional corroboration raises confidence, with a hard ceiling so a
        // wide import table never produces a ~100% verdict.
        let bonus = ((hits.len().saturating_sub(2)) as f64 * 0.02).min(0.08);
        let confidence = (rule.confidence + bonus).min(0.97);

        out.push(Technique {
            id: rule.id.to_string(),
            sub_id: rule.sub_id.map(String::from),
            name: rule.name.to_string(),
            tactic: rule.tactic.to_string(),
            confidence,
            evidence: hits,
            note: rule.note.to_string(),
            detection: rule.detection.to_string(),
        });
    }

    out.sort_by(|a, b| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.id.cmp(&b.id))
    });
    out
}

fn push_unique(hits: &mut Vec<String>, value: String) {
    if !hits.iter().any(|existing| existing == &value) {
        hits.push(value);
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        s.chars().take(max).collect::<String>() + "…"
    }
}

/// Tactic ordering used by the kill-chain view. Index is the display order.
pub fn tactic_order(tactic: &str) -> u8 {
    match tactic {
        "reconnaissance" => 0,
        "resource-development" => 1,
        "initial-access" => 2,
        "execution" => 3,
        "persistence" => 4,
        "privilege-escalation" => 5,
        "defense-evasion" => 6,
        "credential-access" => 7,
        "discovery" => 8,
        "lateral-movement" => 9,
        "collection" => 10,
        "command-and-control" => 11,
        "exfiltration" => 12,
        "impact" => 13,
        _ => 14,
    }
}

/// Group techniques by tactic, preserving kill-chain order.
pub fn by_tactic(techniques: &[Technique]) -> Vec<(String, Vec<&Technique>)> {
    let mut sorted: Vec<&Technique> = techniques.iter().collect();
    sorted.sort_by_key(|t| (tactic_order(&t.tactic), t.id.clone()));

    let mut groups: Vec<(String, Vec<&Technique>)> = Vec::new();
    for t in sorted {
        match groups.last_mut() {
            Some((tactic, list)) if *tactic == t.tactic => list.push(t),
            _ => groups.push((t.tactic.clone(), vec![t])),
        }
    }
    groups
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::strings::Encoding;
    use crate::format::{BinaryImage, ExportEntry, ImportEntry};

    fn image_with(imports: &[&str], exports: &[&str]) -> BinaryImage {
        let mut image = BinaryImage::placeholder(crate::format::Format::Pe);
        image.imports = imports
            .iter()
            .map(|s| ImportEntry {
                library: "kernel32.dll".into(),
                symbol: (*s).to_string(),
                ordinal: None,
                hint: None,
                delayed: false,
            })
            .collect();
        image.exports = exports
            .iter()
            .map(|s| ExportEntry {
                name: (*s).to_string(),
                ordinal: Some(1),
                address: 0x1000,
                forwarded_to: None,
            })
            .collect();
        image
    }

    fn strings(items: &[&str]) -> Vec<crate::analysis::strings::ExtractedString> {
        items
            .iter()
            .map(|s| crate::analysis::strings::ExtractedString {
                offset: 0,
                encoding: Encoding::Ascii,
                length: s.len(),
                text: (*s).to_string(),
            })
            .collect()
    }

    // ---- The false positives this module exists to avoid ----

    #[test]
    fn api_forwarder_symbol_is_never_cited() {
        // advapi32 exports CryptEncrypt and imports it from CRYPTSP.
        let image = image_with(
            &["CryptEncrypt", "CryptGenKey", "BCryptEncrypt"],
            &["CryptEncrypt"],
        );
        let ev = Evidence::new(
            &image,
            &strings(&["your files have been encrypted"]),
            "sample.exe",
        );
        for t in infer(&ev) {
            assert!(
                !t.evidence.iter().any(|e| e == "CryptEncrypt"),
                "an exported symbol must never be cited as capability evidence"
            );
        }
    }

    #[test]
    fn single_api_never_fires() {
        // Every one of these is distinctive. None may produce a technique alone.
        for api in [
            "NtUnmapViewOfSection",
            "QueueUserAPC",
            "MiniDumpWriteDump",
            "NtLoadDriver",
            "GetClipboardData",
            "GetAsyncKeyState",
        ] {
            let image = image_with(&[api], &[]);
            let ev = Evidence::new(&image, &[], "sample.exe");
            assert!(
                infer(&ev).is_empty(),
                "{api} alone must not produce a technique"
            );
        }
    }

    #[test]
    fn token_manipulation_needs_two_operations() {
        // Enabling a privilege is what ordinary software does.
        let image = image_with(&["OpenProcessToken", "AdjustTokenPrivileges"], &[]);
        let ev = Evidence::new(&image, &[], "sample.exe");
        assert!(!infer(&ev).iter().any(|t| t.id == "T1134"));

        // Two distinct impersonation primitives is a different story.
        let image = image_with(&["AdjustTokenPrivileges", "ImpersonateLoggedOnUser"], &[]);
        let ev = Evidence::new(&image, &[], "sample.exe");
        assert!(infer(&ev).iter().any(|t| t.id == "T1134"));
    }

    #[test]
    fn debugger_evasion_needs_two_checks() {
        let image = image_with(&["IsDebuggerPresent"], &[]);
        let ev = Evidence::new(&image, &[], "sample.exe");
        assert!(!infer(&ev).iter().any(|t| t.id == "T1622"));

        let image = image_with(&["IsDebuggerPresent", "CheckRemoteDebuggerPresent"], &[]);
        let ev = Evidence::new(&image, &[], "sample.exe");
        assert!(infer(&ev).iter().any(|t| t.id == "T1622"));
    }

    #[test]
    fn ransomware_needs_extortion_context() {
        // Crypto alone is not ransomware.
        let image = image_with(&["CryptEncrypt", "CryptGenKey"], &[]);
        let ev = Evidence::new(&image, &[], "sample.exe");
        assert!(!infer(&ev).iter().any(|t| t.id == "T1486"));

        // Crypto plus extortion material is.
        let ev = Evidence::new(
            &image,
            &strings(&["pay in bitcoin to unlock"]),
            "sample.exe",
        );
        assert!(infer(&ev).iter().any(|t| t.id == "T1486"));

        // A payments noun is not extortion material. `Windows.Payments.dll` and
        // seven other Microsoft components carried "payment required" or
        // "payment app extension data invalid" next to BCryptEncrypt, and a
        // marker list containing the bare word `payment` made all of them
        // critical ransomware.
        let ev = Evidence::new(
            &image,
            &strings(&["payment required", "payment app extension data invalid"]),
            "sample.exe",
        );
        assert!(!infer(&ev).iter().any(|t| t.id == "T1486"));
    }

    #[test]
    fn run_key_persistence_needs_the_path() {
        let image = image_with(&["RegSetValueExA"], &[]);
        let ev = Evidence::new(&image, &[], "sample.exe");
        assert!(!infer(&ev).iter().any(|t| t.id == "T1547.001"));

        let ev = Evidence::new(
            &image,
            &strings(&["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"]),
            "sample.exe",
        );
        assert!(infer(&ev).iter().any(|t| t.id == "T1547.001"));
    }

    // ---- True positives that must still fire ----

    #[test]
    fn injection_triad_is_detected() {
        let image = image_with(
            &["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
            &[],
        );
        let ev = Evidence::new(&image, &[], "sample.exe");
        let t = infer(&ev)
            .into_iter()
            .find(|t| t.id == "T1055")
            .expect("T1055 should fire on the triad");
        assert!(t.confidence > 0.85);
        assert_eq!(t.evidence.len(), 3);
    }

    #[test]
    fn hollowing_needs_unmap_plus_write() {
        let image = image_with(&["NtUnmapViewOfSection"], &[]);
        let ev = Evidence::new(&image, &[], "sample.exe");
        assert!(!infer(&ev).iter().any(|t| t.id == "T1055.012"));

        let image = image_with(&["NtUnmapViewOfSection", "WriteProcessMemory"], &[]);
        let ev = Evidence::new(&image, &[], "sample.exe");
        assert!(infer(&ev).iter().any(|t| t.id == "T1055.012"));
    }

    #[test]
    fn credential_dumping_detected() {
        // Dumping needs a named target: the API pair alone is also Task Manager's
        // "Create dump file" menu item.
        let image = image_with(&["MiniDumpWriteDump", "OpenProcess"], &[]);
        let ev = Evidence::new(&image, &strings(&["lsass.exe"]), "sample.exe");
        assert!(infer(&ev).iter().any(|t| t.id == "T1003"));
    }

    #[test]
    fn keylogging_detected() {
        let image = image_with(&["GetAsyncKeyState", "RegisterRawInputDevices"], &[]);
        let ev = Evidence::new(&image, &[], "sample.exe");
        assert!(infer(&ev).iter().any(|t| t.id == "T1056.001"));
    }

    #[test]
    fn shadow_copy_deletion_detected() {
        let image = image_with(&["CreateProcessA"], &[]);
        let ev = Evidence::new(
            &image,
            &strings(&["vssadmin delete shadows /all /quiet"]),
            "sample.exe",
        );
        assert!(infer(&ev).iter().any(|t| t.id == "T1490"));
    }

    #[test]
    fn defense_tampering_detected() {
        // The switch that turns real-time protection off is the evidence, and it
        // has to arrive with a second action: stopping a service is routine
        // administration on its own.
        let image = image_with(&["ControlService", "RegSetValueExW"], &[]);
        let ev = Evidence::new(
            &image,
            &strings(&["Set-MpPreference -DisableRealtimeMonitoring $true"]),
            "sample.exe",
        );
        assert!(infer(&ev).iter().any(|t| t.id == "T1562.001"));
    }

    #[test]
    fn naming_a_security_product_is_not_tampering() {
        // Regression: `SystemSettingsAdminFlows.exe` and six other signed system
        // binaries scored critical because their string tables held a path to a
        // Defender component next to a termination primitive. Naming a product is
        // not disabling it — the path is where the program looks, not a target.
        let image = image_with(&["TerminateProcess", "ControlService"], &[]);
        let ev = Evidence::new(
            &image,
            &strings(&["C:\\Program Files\\Windows Defender\\MsMpEng.exe"]),
            "sample.exe",
        );
        assert!(
            !infer(&ev).iter().any(|t| t.id == "T1562.001"),
            "a path to a security product must not be read as an attack on it"
        );
    }

    #[test]
    fn an_enumerator_is_not_a_dumper() {
        // Regression: Task Manager imports MiniDumpWriteDump and OpenProcess, and
        // lists `lsass.exe` because it draws the process table. Enumeration is the
        // discriminator — a stealer opens the target without listing anything.
        let enumerator = image_with(
            &[
                "NtQuerySystemInformation",
                "MiniDumpWriteDump",
                "OpenProcess",
            ],
            &[],
        );
        let ev = Evidence::new(&enumerator, &strings(&["lsass.exe"]), "sample.exe");
        assert!(
            !infer(&ev).iter().any(|t| t.id == "T1003"),
            "an enumerator's string table holds whatever it displays"
        );

        // The same APIs without enumeration stay reportable.
        let stealer = image_with(&["MiniDumpWriteDump", "OpenProcess"], &[]);
        let ev = Evidence::new(&stealer, &strings(&["lsass.exe"]), "sample.exe");
        assert!(
            infer(&ev).iter().any(|t| t.id == "T1003"),
            "a direct read of lsass is still credential access"
        );
    }

    #[test]
    fn a_tool_naming_itself_is_not_evidence() {
        // Regression: `wbadmin.exe` was reported as deleting the recovery
        // catalogue because its usage text contains its own name, and because the
        // linker embeds `wbadmin.pdb`.
        let image = image_with(&["CreateProcessW"], &[]);
        let ev = Evidence::new(
            &image,
            &strings(&["wbadmin.exe", "C:\\build\\amd64\\wbadmin.pdb"]),
            "wbadmin.exe",
        );
        assert!(
            !infer(&ev).iter().any(|t| t.id == "T1490"),
            "self-reference is not evidence of intent"
        );
    }

    #[test]
    fn recovery_inhibition_needs_the_deletion() {
        // Regression: `ResetEngine.dll` was critical for ransomware because it
        // carries "failed to wait for bcdedit -set debug on" — a factory reset
        // enabling a debug flag. The tool name is not the technique; the deletion
        // is.
        let image = image_with(&["CreateProcessW"], &[]);
        let ev = Evidence::new(
            &image,
            &strings(&["failed to wait for bcdedit -set debug on"]),
            "ResetEngine.dll",
        );
        assert!(
            !infer(&ev).iter().any(|t| t.id == "T1490"),
            "`bcdedit /set debug` is not recovery inhibition"
        );

        let ev = Evidence::new(
            &image,
            &strings(&["vssadmin delete shadows /all /quiet"]),
            "sample.exe",
        );
        assert!(infer(&ev).iter().any(|t| t.id == "T1490"));
    }

    #[test]
    fn clean_binary_yields_nothing() {
        let image = image_with(
            &["GetStdHandle", "WriteConsoleA", "ExitProcess", "Sleep"],
            &[],
        );
        let ev = Evidence::new(&image, &[], "sample.exe");
        assert!(infer(&ev).is_empty());
    }

    #[test]
    fn system_library_profile_yields_nothing() {
        // A synthetic stand-in for kernel32: broad API surface where every
        // capability-relevant symbol is both imported and exported.
        let imports = [
            "NtUnmapViewOfSection",
            "IsDebuggerPresent",
            "GetAsyncKeyState",
            "QueueUserAPC",
            "AdjustTokenPrivileges",
            "RegSetValueExA",
            "CryptEncrypt",
            "DeviceIoControl",
            "GetClipboardData",
        ];
        let exports = [
            "IsDebuggerPresent",
            "GetAsyncKeyState",
            "QueueUserAPC",
            "AdjustTokenPrivileges",
            "RegSetValueExA",
            "CryptEncrypt",
            "DeviceIoControl",
            "GetClipboardData",
        ];
        let image = image_with(&imports, &exports);
        let ev = Evidence::new(&image, &[], "sample.exe");
        assert!(
            infer(&ev).is_empty(),
            "a module that provides these APIs must not be reported as using them"
        );
    }

    #[test]
    fn techniques_sorted_by_confidence() {
        let image = image_with(
            &[
                "VirtualAllocEx",
                "WriteProcessMemory",
                "CreateRemoteThread",
                "MiniDumpWriteDump",
                "OpenProcess",
            ],
            &[],
        );
        let ev = Evidence::new(&image, &[], "sample.exe");
        let confidences: Vec<f64> = infer(&ev).iter().map(|t| t.confidence).collect();
        let mut sorted = confidences.clone();
        sorted.sort_by(|a, b| b.partial_cmp(a).unwrap());
        assert_eq!(confidences, sorted);
    }

    #[test]
    fn confidence_never_reaches_certainty() {
        let image = image_with(
            &[
                "VirtualAllocEx",
                "WriteProcessMemory",
                "CreateRemoteThread",
                "NtCreateThreadEx",
                "RtlCreateUserThread",
                "QueueUserAPC",
                "SetThreadContext",
            ],
            &[],
        );
        let ev = Evidence::new(&image, &[], "sample.exe");
        for t in infer(&ev) {
            assert!(
                t.confidence <= 0.97,
                "confidence {} exceeds the ceiling",
                t.confidence
            );
        }
    }

    #[test]
    fn tactic_ordering_is_kill_chain_order() {
        assert!(tactic_order("execution") < tactic_order("persistence"));
        assert!(tactic_order("persistence") < tactic_order("impact"));
        assert!(tactic_order("reconnaissance") < tactic_order("execution"));
    }

    #[test]
    fn groups_preserve_order() {
        let image = image_with(
            &[
                "VirtualAllocEx",
                "WriteProcessMemory",
                "CreateRemoteThread",
                "GetAsyncKeyState",
                "RegisterRawInputDevices",
            ],
            &[],
        );
        let ev = Evidence::new(&image, &[], "sample.exe");
        let techniques = infer(&ev);
        let groups = by_tactic(&techniques);
        let order: Vec<u8> = groups.iter().map(|(t, _)| tactic_order(t)).collect();
        let mut sorted = order.clone();
        sorted.sort_unstable();
        assert_eq!(order, sorted);
    }

    #[test]
    fn every_rule_can_fire_in_principle() {
        for rule in RULES {
            let has_slot = !rule.all_apis.is_empty()
                || rule.min_core > 0
                || !rule.also_apis.is_empty()
                || !rule.any_strings.is_empty();
            assert!(has_slot, "rule {} has no condition", rule.id);
            assert!(
                rule.min_core <= rule.core_apis.len(),
                "rule {} requires more core APIs than it lists",
                rule.id
            );
        }
    }

    #[test]
    fn rule_ids_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for rule in RULES {
            assert!(seen.insert(rule.id), "duplicate rule id {}", rule.id);
        }
    }

    #[test]
    fn library_surface_suppresses_inference() {
        // 200 exports and 200 imports is the shape of a platform library.
        let export_names: Vec<String> = (0..200).map(|i| format!("Exported{i}")).collect();
        let import_names: Vec<String> = (0..200).map(|i| format!("Imported{i}")).collect();
        let mut image = image_with(&[], &[]);
        image.exports = export_names
            .iter()
            .map(|n| ExportEntry {
                name: n.clone(),
                ordinal: Some(1),
                address: 0x1000,
                forwarded_to: None,
            })
            .collect();
        image.imports = import_names
            .iter()
            .map(|n| ImportEntry {
                library: "ntdll.dll".into(),
                symbol: n.clone(),
                ordinal: None,
                hint: None,
                delayed: false,
            })
            .collect();
        // Even with a genuine injection triad present, the answer is silence.
        image.imports.push(ImportEntry {
            library: "kernel32.dll".into(),
            symbol: "VirtualAllocEx".into(),
            ordinal: None,
            hint: None,
            delayed: false,
        });
        image.imports.push(ImportEntry {
            library: "kernel32.dll".into(),
            symbol: "WriteProcessMemory".into(),
            ordinal: None,
            hint: None,
            delayed: false,
        });
        image.imports.push(ImportEntry {
            library: "kernel32.dll".into(),
            symbol: "CreateRemoteThread".into(),
            ordinal: None,
            hint: None,
            delayed: false,
        });

        assert!(image.is_library_surface());
        let ev = Evidence::new(&image, &[], "sample.exe");
        assert!(
            infer(&ev).is_empty(),
            "a platform library must not be profiled for offensive capability"
        );
    }

    #[test]
    fn export_count_is_reported() {
        let image = image_with(&[], &["A", "B", "C"]);
        let ev = Evidence::new(&image, &[], "sample.exe");
        assert_eq!(ev.export_count(), 3);
    }

    // ---- String evidence hygiene -----------------------------------------
    //
    // Each of these locked in a false positive that shipped: a signed Microsoft
    // binary scored critical for ransomware or credential theft because an
    // unrelated string happened to contain the needle as a substring. They are
    // grouped here so the shared predicate is tested once per shape.

    #[test]
    fn word_boundary_prevents_fragment_matches() {
        // `payment` inside `pospaymentconnector` and `shadowcopy` inside
        // `shadowcopyexcludefile` are how `AppxPackaging.dll` — a signed
        // packaging library — became a critical ransomware finding.
        assert!(!find_on_word_boundary("ct_pospaymentconnector", "payment"));
        assert!(!find_on_word_boundary(
            "shadowcopyexcludefile",
            "shadowcopy"
        ));
        // Real occurrences still match, including a leading dot that is
        // punctuation rather than part of an identifier.
        assert!(find_on_word_boundary("pay in bitcoin to unlock", "bitcoin"));
        assert!(find_on_word_boundary("invoice.pdf.locked", ".locked"));
        assert!(find_on_word_boundary("vssadmin delete shadows", "vssadmin"));
    }

    #[test]
    fn locations_are_not_intent() {
        assert!(is_location(r"%programfiles%\windows defender\msmpeng.exe"));
        assert!(is_location("vega.ws.symantec.com"));
        assert!(is_location("http://185.220.101.42/beacon"));
        assert!(is_location("C:\\Windows\\System32\\cmd.exe"));
        assert!(is_location(r"\\server\share\payload.bin"));
        // The Active Directory database and a SAM key are targets, not paths.
        assert!(!is_location("ntds.dit"));
        assert!(!is_location("lsass"));
        assert!(!is_location("vssadmin"));
        // A registry key is an object code reads and writes, not a place it lives,
        // so it stays available as evidence — `T1547.001` depends on that.
        assert!(!is_location(
            "software\\microsoft\\windows\\currentversion\\run"
        ));
        assert!(!is_location(
            "hkey_local_machine\\system\\currentcontrolset"
        ));
    }

    #[test]
    fn markup_is_not_a_message() {
        // The Appx manifest XSD ships inside the packaging library, so its element
        // names appear as literal strings.
        assert!(is_markup(
            r#"<xs:element name="shadowcopyexcludefile" type="ct_shadowcopyexcludefile"/>"#
        ));
        assert!(is_markup("xmlns:xs=\"http://www.w3.org/2001/XMLSchema\""));
        assert!(!is_markup("vssadmin delete shadows /all /quiet"));
        assert!(!is_markup("pay in bitcoin to unlock your files"));
    }

    #[test]
    fn debug_paths_are_not_tool_names() {
        // The linker embeds its own output path, so `wbadmin.exe` contains
        // `C:\build\...\wbadmin.pdb`.
        assert!(is_debug_symbol(r"c:\build\amd64\wbadmin.pdb"));
        assert!(is_debug_symbol("out.exe.pdb"));
        assert!(!is_debug_symbol("wbadmin.exe"));
    }

    #[test]
    fn a_modules_own_name_is_not_evidence() {
        assert!(is_self_reference("wbadmin.exe", "wbadmin"));
        assert!(is_self_reference("wbadmin", "wbadmin"));
        assert!(is_self_reference(
            r"c:\windows\system32\wbadmin.exe",
            "wbadmin"
        ));
        // A different name in the same string is still evidence.
        assert!(!is_self_reference("vssadmin delete shadows", "wbadmin"));
        assert!(!is_self_reference("wbadmin.exe /delete", "wbadmin"));
    }
}

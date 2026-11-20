/**
 * Type definitions mirroring the JSON that `assay-core` serialises.
 *
 * These are hand-written rather than generated so that every field carries the
 * reason it exists. Any change here must be mirrored in
 * `crates/assay-core/src/report.rs`; the `schema_version` field is the contract
 * that lets the UI detect a mismatch instead of silently misrendering.
 */

export type SchemaVersion = "1.0";

export type Severity = "info" | "low" | "medium" | "high" | "critical";

export type Grade = "clean" | "low" | "medium" | "high" | "critical";

export type ContainerFormat =
  | "pe"
  | "elf"
  | "macho"
  | "ar"
  | "zip"
  | "gzip"
  | "tar"
  | "script"
  | "unknown";

export type BinaryKind =
  | "executable"
  | "shared_library"
  | "object"
  | "managed_assembly"
  | "installer"
  | "driver"
  | "script"
  | "package"
  | "other";

export interface ToolInfo {
  name: string;
  version: string;
  build: string;
}

export interface ArtefactInfo {
  path: string;
  name: string;
  size: number;
  sha256: string;
  sha1: string;
  md5: string;
  fuzzy: string;
  detected_format: ContainerFormat;
  detection_confidence: "certain" | "structural" | "weak";
  magic: string;
  detection_reason: string;
}

export interface Permissions {
  read: boolean;
  write: boolean;
  execute: boolean;
}

export interface SectionInfo {
  name: string;
  virtual_address: number;
  virtual_size: number;
  file_offset: number;
  file_size: number;
  entropy: number;
  permissions: Permissions;
  sha256: string;
  raw_characteristics: number;
}

export interface ImportEntry {
  library: string;
  symbol: string;
  ordinal: number | null;
  hint: number | null;
  delayed: boolean;
}

export interface ExportEntry {
  name: string;
  ordinal: number | null;
  address: number;
  forwarded_to: string | null;
}

export interface ResourceEntry {
  kind: string;
  name: string;
  language: string | null;
  file_offset: number;
  size: number;
  sha256: string;
}

export interface DebugArtifact {
  kind: string;
  value: string;
  trusted: boolean;
}

export interface SignatureInfo {
  scheme: string;
  present: boolean;
  signer: string | null;
  issuer: string | null;
  digest_algorithm: string | null;
  valid_from: number | null;
  valid_to: number | null;
  timestamped: boolean;
  issues: string[];
  blob_sha256: string;
}

/** The PE-specific block; `format` is the discriminant written by serde. */
export interface PeMetadata {
  format: "pe";
  machine: number;
  machine_name: string;
  declared_sections: number;
  timestamp: number;
  characteristics: number;
  dll_characteristics: number;
  subsystem: number;
  linker_version: string;
  declared_checksum: number;
  computed_checksum: number;
  checksum_valid: boolean;
  size_of_image: number;
  size_of_headers: number;
  file_alignment: number;
  section_alignment: number;
  num_directories: number;
  is_dotnet: boolean;
  clr_version: string | null;
  metadata_version: string | null;
  tls_callbacks: number[];
  has_tls: boolean;
  rich_key: number | null;
  rich_entries: { product_id: number; build: number; count: number }[];
  pdb_path: string | null;
  debug_types: string[];
  import_hash: string | null;
  base_of_code: number;
  is_dll: boolean;
}

export interface ElfMetadata {
  format: "elf";
  e_type: number;
  e_type_name: string;
  machine: number;
  machine_name: string;
  osabi: string;
  elf_version: number;
  interpreter: string | null;
  soname: string | null;
  rpath: string[];
  runpath: string[];
  build_id: string | null;
  compiler_comments: string[];
  nx_stack: boolean;
  relro: boolean;
  pie: boolean;
  bind_now: boolean;
  has_symtab: boolean;
  dynsym_exports: number;
}

export interface MachOMetadata {
  format: "macho";
  cputype: number;
  cpusubtype: number;
  filetype: number;
  filetype_name: string;
  uuid: string | null;
  min_os: string | null;
  sdk: string | null;
  platform: string | null;
  install_name: string | null;
  rpaths: string[];
  has_code_signature: boolean;
  code_signature_size: number;
  encrypted: boolean;
  main_offset: number | null;
  slices: { cputype: number; arch: string; offset: number; size: number }[];
  is_fat: boolean;
  symbol_count: number;
}

export interface ArchiveMetadata {
  format: "archive";
  container: string;
  entry_count: number;
  declared_uncompressed: number;
  declared_compressed: number;
  suspicious_ratio_entries: string[];
  executable_entries: string[];
  setuid_or_exec_entries: string[];
  top_level: string[];
  inferred_purpose: string | null;
  gzip_original_name: string | null;
  gzip_mtime: number | null;
  has_signature_files: boolean;
}

export type FormatMetadata =
  | PeMetadata
  | ElfMetadata
  | MachOMetadata
  | ArchiveMetadata
  | { format: "none" };

export interface BinaryImage {
  format: ContainerFormat;
  kind: BinaryKind;
  arch: string;
  endian: "little" | "big";
  bitness: number;
  entry_point: number | null;
  image_base: number;
  sections: SectionInfo[];
  imports: ImportEntry[];
  exports: ExportEntry[];
  resources: ResourceEntry[];
  debug_artifacts: DebugArtifact[];
  signature: SignatureInfo;
  structural_notes: string[];
  metadata: FormatMetadata;
}

export interface EntropyWindow {
  offset: number;
  length: number;
  entropy: number;
}

export interface EntropyProfile {
  overall: number;
  mean_windowed: number;
  stdev_windowed: number;
  window: number;
  windows: EntropyWindow[];
  longest_high_run: EntropyWindow;
  peak_offset: number;
  peak_entropy: number;
  high_entropy_fraction: number;
}

export type StringEncoding = "ascii" | "utf16le" | "utf16be";

export interface ExtractedString {
  offset: number;
  encoding: StringEncoding;
  text: string;
  length: number;
}

export interface StringStats {
  total: number;
  unique: number;
  ascii: number;
  utf16le: number;
  utf16be: number;
  longest: number;
}

export type IocKind =
  | "url"
  | "domain"
  | "ipv4"
  | "ipv6"
  | "email"
  | "bitcoin"
  | "ethereum"
  | "onion"
  | "registry_key"
  | "file_path"
  | "guid"
  | "user_agent"
  | "named_object";

export interface Indicator {
  kind: IocKind;
  value: string;
  occurrences: number;
  offsets: number[];
  confidence: number;
  rationale: string;
}

export interface IocSet {
  indicators: Indicator[];
  by_kind: [string, number][];
}

/** Convenience accessor mirroring `IocSet::top` in the engine. */
export function topIndicators(set: IocSet, limit: number): Indicator[] {
  return set.indicators.slice(0, limit);
}

export interface PackerEvidence {
  key: string;
  detail: string;
  weight: number;
}

export interface PackerVerdict {
  likelihood: number;
  signatures: string[];
  evidence: PackerEvidence[];
  summary: string;
}

export interface Technique {
  id: string;
  sub_id: string | null;
  name: string;
  tactic: string;
  confidence: number;
  evidence: string[];
  note: string;
  detection: string;
}

export interface Factor {
  key: string;
  name: string;
  points: number;
  max_points: number;
  detail: string;
  evidence: string[];
}

export interface RiskScore {
  score: number;
  grade: Grade;
  factors: Factor[];
  verdict: string;
}

export interface Finding {
  rule_id: string;
  rule_name: string;
  severity: Severity;
  description: string;
  evidence: string[];
  tags: string[];
}

export interface Diagnostic {
  stage: string;
  severity: "error" | "warning";
  kind: string;
  message: string;
}

export interface Timing {
  detect_ms: number;
  parse_ms: number;
  strings_ms: number;
  analysis_ms: number;
  rules_ms: number;
  total_ms: number;
}

export interface Report {
  schema_version: SchemaVersion;
  tool: ToolInfo;
  artefact: ArtefactInfo;
  image: BinaryImage;
  entropy: EntropyProfile;
  strings: ExtractedString[];
  string_stats: StringStats;
  indicators: IocSet;
  packer: PackerVerdict;
  techniques: Technique[];
  score: RiskScore;
  findings: Finding[];
  /** Number of rules evaluated. Zero means rule checking was disabled. */
  rules_evaluated: number;
  diagnostics: Diagnostic[];
  timing: Timing;
}

/** A report plus the UI-side bookkeeping that never leaves the client. */
export interface WorkbenchEntry {
  id: string;
  report: Report;
  addedAt: number;
  /** Present only when the entry was synthesised in the browser demo mode. */
  demo?: boolean;
}

export const GRADE_ORDER: Record<Grade, number> = {
  clean: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export const SEVERITY_ORDER: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

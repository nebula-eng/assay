import type { Grade, Severity } from "../types";

/** Human byte size with binary units, matching what the CLI prints. */
export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return "—";
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KiB", "MiB", "GiB", "TiB"];
  let value = bytes;
  let unit = -1;
  do {
    value /= 1024;
    unit += 1;
  } while (value >= 1024 && unit < units.length - 1);
  // Three significant digits keeps 1.5 KiB and 998 KiB both readable without
  // rounding 1023.9 up into a unit that no longer applies.
  return `${value.toFixed(value >= 100 ? 0 : 1)} ${units[unit]}`;
}

/** Zero-padded hex with a `0x` prefix, sized for the bit width given. */
export function hex(value: number | null | undefined, width = 0): string {
  if (value === null || value === undefined) return "—";
  const raw = Math.max(0, Math.trunc(value)).toString(16);
  return `0x${width > 0 ? raw.padStart(width, "0") : raw}`;
}

/** Zero-padded file offset, aligned so a column of them is scannable. */
export function offset(value: number, width = 8): string {
  return `0x${Math.max(0, Math.trunc(value)).toString(16).padStart(width, "0")}`;
}

/** Abbreviate a long hash for a header, keeping both ends recognisable. */
export function shortHash(hash: string, keep = 12): string {
  if (hash.length <= keep * 2 + 1) return hash;
  return `${hash.slice(0, keep)}…${hash.slice(-keep)}`;
}

/** Fixed-decimal rendering that never shows `NaN`. */
export function fixed(value: number, digits = 2): string {
  return Number.isFinite(value) ? value.toFixed(digits) : "—";
}

/** Percentage with no decimals, for confidence and ratio displays. */
export function pct(value: number): string {
  return `${Math.round(value * 100)}%`;
}

/** Count with a correctly pluralised noun (`1 finding`, `3 findings`). */
export function plural(count: number, singular: string, pluralForm?: string): string {
  return `${count} ${count === 1 ? singular : pluralForm ?? `${singular}s`}`;
}

/** `1700000000` → `14 Nov 2023`. Used for embedded timestamps. */
export function formatUnixDate(seconds: number | null | undefined): string {
  if (!seconds || seconds <= 0) return "—";
  const date = new Date(seconds * 1000);
  if (Number.isNaN(date.getTime())) return "—";
  return date.toLocaleDateString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
  });
}

/** `1700000000` → `14 Nov 2023, 22:13`. */
export function formatUnixDateTime(seconds: number | null | undefined): string {
  if (!seconds || seconds <= 0) return "—";
  const date = new Date(seconds * 1000);
  if (Number.isNaN(date.getTime())) return "—";
  return date.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

/** CSS custom-property colour for a risk band. */
export function gradeColor(grade: Grade): string {
  switch (grade) {
    case "critical":
      return "var(--critical)";
    case "high":
      return "var(--high)";
    case "medium":
      return "var(--medium)";
    case "low":
      return "var(--low)";
    case "clean":
      return "var(--clean)";
  }
}

/** CSS custom-property colour for a finding severity. */
export function severityColor(severity: Severity): string {
  switch (severity) {
    case "critical":
      return "var(--critical)";
    case "high":
      return "var(--high)";
    case "medium":
      return "var(--medium)";
    case "low":
      return "var(--low)";
    case "info":
      return "var(--info)";
  }
}

/**
 * Colour for an entropy reading, using the same thresholds as the engine
 * (`HIGH_THRESHOLD = 7.2`, `VERY_HIGH_THRESHOLD = 7.6`).
 *
 * The band table lives in `EntropyChart` and this function must agree with it;
 * the chart derives its legend from the same list, so the two cannot drift.
 */
export function entropyColor(entropy: number): string {
  if (entropy >= 7.6) return "var(--critical)";
  if (entropy >= 7.2) return "var(--high)";
  if (entropy >= 5.0) return "var(--medium)";
  if (entropy >= 3.0) return "var(--low)";
  return "var(--text-faint)";
}

/** Render `rwx`, flagging the combination that breaks W^X. */
export function permissionBits(perm: {
  read: boolean;
  write: boolean;
  execute: boolean;
}): { text: string; wx: boolean } {
  const text = `${perm.read ? "r" : "-"}${perm.write ? "w" : "-"}${perm.execute ? "x" : "-"}`;
  return { text, wx: perm.write && perm.execute };
}

/** "3 minutes ago" style stamp for the sample list. */
export function relativeTime(timestamp: number): string {
  const delta = Math.max(0, Date.now() - timestamp);
  const seconds = Math.floor(delta / 1000);
  if (seconds < 10) return "just now";
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

/** Human label for a container format, e.g. `pe` → `PE`. */
export function formatLabel(format: string): string {
  const special: Record<string, string> = {
    pe: "PE",
    elf: "ELF",
    macho: "Mach-O",
    ar: "ar",
    zip: "ZIP",
    gzip: "gzip",
    tar: "tar",
    script: "script",
    unknown: "unknown",
  };
  return special[format] ?? format;
}

/** Human label for an artefact kind, e.g. `shared_library` → `shared library`. */
export function kindLabel(kind: string): string {
  return kind.replace(/_/g, " ");
}

/** Encoding label, e.g. `utf16le` → `UTF-16 LE`. */
export function encodingLabel(encoding: string): string {
  switch (encoding) {
    case "ascii":
      return "ASCII";
    case "utf16le":
      return "UTF-16 LE";
    case "utf16be":
      return "UTF-16 BE";
    default:
      return encoding;
  }
}

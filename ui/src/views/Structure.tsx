import { useMemo, useState } from "react";
import type { Report, SectionInfo } from "../types";
import { EntropyChart } from "../components/EntropyChart";
import { Card, Check, Empty, Explainer, KeyValues, SearchInput } from "../components/Primitives";
import {
  entropyColor,
  fixed,
  formatBytes,
  formatUnixDateTime,
  hex,
  permissionBits,
  shortHash,
} from "../lib/format";

function PermCell({ perm }: { perm: SectionInfo["permissions"] }) {
  const { text, wx } = permissionBits(perm);
  if (wx) {
    return (
      <span className="perm" title="writable and executable — breaks W^X">
        <span className="wx">{text}</span>
      </span>
    );
  }
  return (
    <span className="perm" title={`${text} (read/write/execute)`}>
      <span className={perm.read ? "on" : "off"}>{text[0]}</span>
      <span className={perm.write ? "on" : "off"}>{text[1]}</span>
      <span className={perm.execute ? "on" : "off"}>{text[2]}</span>
    </span>
  );
}

/** Map a Rich-header product id to the tool MSVC records for it. */
function richProductName(productId: number): string {
  // The low byte identifies the tool; the high byte the language. Only the
  // common values are named — inventing a name for an unknown id would be worse
  // than printing the number.
  const known: Record<number, string> = {
    0x00: "Unknown",
    0x01: "Import0",
    0x02: "Linker510",
    0x03: "Cvtomf510",
    0x04: "Linker600",
    0x05: "Cvtomf600",
    0x06: "Cvtres500",
    0x07: "Utc11_Basic",
    0x08: "Utc11_C",
    0x09: "Utc12_Basic",
    0x0a: "Utc12_C",
    0x0b: "Utc12_CPP",
    0x0c: "AliasObj60",
    0x0d: "VisualBasic60",
    0x0e: "Masm613",
    0x0f: "Masm710",
    0x10: "Linker511",
    0x11: "Cvtomf511",
    0x12: "Masm614",
    0x13: "Linker512",
    0x14: "Cvtomf512",
    0x15: "Utc12_C_Std",
    0x16: "Utc12_CPP_Std",
    0x17: "Utc12_C_Book",
    0x18: "Utc12_CPP_Book",
    0x19: "Implib700",
    0x1a: "Cvtomf700",
    0x1b: "Utc13_Basic",
    0x1c: "Utc13_C",
    0x1d: "Utc13_CPP",
    0x1e: "Linker610",
    0x1f: "Cvtomf610",
    0x20: "Linker601",
    0x21: "Cvtomf601",
    0x22: "Utc12_1_Basic",
    0x23: "Utc12_1_C",
    0x24: "Utc12_1_CPP",
    0x25: "Linker620",
    0x26: "Cvtomf620",
    0x27: "AliasObj70",
    0x28: "Linker621",
    0x29: "Cvtomf621",
    0x2a: "Masm615",
    0x2b: "Utc13_LTCG_C",
    0x2c: "Utc13_LTCG_CPP",
    0x2d: "Masm620",
    0x2e: "ILAsm100",
    0x2f: "Utc12_2_Basic",
    0x30: "Utc12_2_C",
    0x31: "Utc12_2_CPP",
    0x32: "Utc12_2_C_Std",
    0x33: "Utc12_2_CPP_Std",
    0x34: "Utc12_2_C_Book",
    0x35: "Utc12_2_CPP_Book",
    0x36: "Implib622",
    0x37: "Cvtomf622",
    0x38: "Cvtres501",
    0x39: "Utc13_C_Std",
    0x3a: "Utc13_CPP_Std",
    0x3b: "Cvtpgd1300",
    0x3c: "Linker622",
    0x3d: "Linker700",
    0x3e: "Export622",
    0x3f: "Export700",
    0x40: "Masm700",
    0x41: "Utc13_POGO_I_C",
    0x42: "Utc13_POGO_I_CPP",
    0x43: "Utc13_POGO_O_C",
    0x44: "Utc13_POGO_O_CPP",
    0x45: "Cvtres700",
    0x46: "Cvtres710p",
    0x47: "Linker710p",
    0x48: "Cvtomf710p",
    0x49: "Export710p",
    0x4a: "Implib710p",
    0x4b: "Masm710p",
    0x4c: "Utc1310p_C",
    0x4d: "Utc1310p_CPP",
    0x4e: "Utc1310p_C_Std",
    0x4f: "Utc1310p_CPP_Std",
    0x50: "Utc1310p_LTCG_C",
    0x51: "Utc1310p_LTCG_CPP",
    0x52: "Utc1310p_POGO_I_C",
    0x53: "Utc1310p_POGO_I_CPP",
    0x54: "Utc1310p_POGO_O_C",
    0x55: "Utc1310p_POGO_O_CPP",
    0x56: "Linker624",
    0x57: "Cvtomf624",
    0x58: "Export624",
    0x59: "Implib624",
    0x5a: "Linker710",
    0x5b: "Cvtomf710",
    0x5c: "Export710",
    0x5d: "Implib710",
    0x5e: "Cvtres710",
    0x5f: "Utc1310_C",
    0x60: "Utc1310_CPP",
    0x61: "Utc1310_C_Std",
    0x62: "Utc1310_CPP_Std",
    0x63: "Utc1310_LTCG_C",
    0x64: "Utc1310_LTCG_CPP",
    0x65: "Utc1310_POGO_I_C",
    0x66: "Utc1310_POGO_I_CPP",
    0x67: "Utc1310_POGO_O_C",
    0x68: "Utc1310_POGO_O_CPP",
    0x69: "AliasObj710",
    0x6a: "AliasObj710p",
    0x6b: "Cvtpgd1310",
    0x6c: "Cvtpgd1310p",
    0x6d: "Utc1400_C",
    0x6e: "Utc1400_CPP",
    0x6f: "Utc1400_C_Std",
    0x70: "Utc1400_CPP_Std",
    0x71: "Utc1400_LTCG_C",
    0x72: "Utc1400_LTCG_CPP",
    0x73: "Utc1400_POGO_I_C",
    0x74: "Utc1400_POGO_I_CPP",
    0x75: "Utc1400_POGO_O_C",
    0x76: "Utc1400_POGO_O_CPP",
    0x77: "Cvtpgd1400",
    0x78: "Linker800",
    0x79: "Cvtomf800",
    0x7a: "Export800",
    0x7b: "Implib800",
    0x7c: "Cvtres800",
    0x7d: "Masm800",
    0x7e: "AliasObj800",
    0x7f: "PhoenixPrerelease",
    0x80: "Utc1400_CVTCIL_C",
    0x81: "Utc1400_CVTCIL_CPP",
    0x82: "Utc1400_LTCG_MSIL",
    0x83: "Utc1500_C",
    0x84: "Utc1500_CPP",
    0x85: "Utc1500_C_Std",
    0x86: "Utc1500_CPP_Std",
    0x87: "Utc1500_CVTCIL_C",
    0x88: "Utc1500_CVTCIL_CPP",
    0x89: "Utc1500_LTCG_C",
    0x8a: "Utc1500_LTCG_CPP",
    0x8b: "Utc1500_LTCG_MSIL",
    0x8c: "Utc1500_POGO_I_C",
    0x8d: "Utc1500_POGO_I_CPP",
    0x8e: "Utc1500_POGO_O_C",
    0x8f: "Utc1500_POGO_O_CPP",
    0x90: "Cvtpgd1500",
    0x91: "Linker900",
    0x92: "Export900",
    0x93: "Implib900",
    0x94: "Cvtres900",
    0x95: "Masm900",
    0x96: "AliasObj900",
    0x97: "Resource900",
    0x98: "AliasObj1000",
    0x99: "Cvtpgd1600",
    0x9a: "Cvtres1000",
    0x9b: "Export1000",
    0x9c: "Implib1000",
    0x9d: "Linker1000",
    0x9e: "Masm1000",
    0x9f: "Utc1600_C",
    0xa0: "Utc1600_CPP",
    0xa1: "Utc1600_CVTCIL_C",
    0xa2: "Utc1600_CVTCIL_CPP",
    0xa3: "Utc1600_LTCG_C",
    0xa4: "Utc1600_LTCG_CPP",
    0xa5: "Utc1600_LTCG_MSIL",
    0xa6: "Utc1600_POGO_I_C",
    0xa7: "Utc1600_POGO_I_CPP",
    0xa8: "Utc1600_POGO_O_C",
    0xa9: "Utc1600_POGO_O_CPP",
    0xaa: "Utc1700_C",
    0xab: "Utc1700_CPP",
    0xac: "Utc1700_CVTCIL_C",
    0xad: "Utc1700_CVTCIL_CPP",
    0xae: "Utc1700_LTCG_C",
    0xaf: "Utc1700_LTCG_CPP",
    0xb0: "Utc1700_LTCG_MSIL",
    0xb1: "Utc1700_POGO_I_C",
    0xb2: "Utc1700_POGO_I_CPP",
    0xb3: "Utc1700_POGO_O_C",
    0xb4: "Utc1700_POGO_O_CPP",
    0xb5: "Utc1800_C",
    0xb6: "Utc1800_CPP",
    0xb7: "Utc1800_CVTCIL_C",
    0xb8: "Utc1800_CVTCIL_CPP",
    0xb9: "Utc1800_LTCG_C",
    0xba: "Utc1800_LTCG_CPP",
    0xbb: "Utc1800_LTCG_MSIL",
    0xbc: "Utc1800_POGO_I_C",
    0xbd: "Utc1800_POGO_I_CPP",
    0xbe: "Utc1800_POGO_O_C",
    0xbf: "Utc1800_POGO_O_CPP",
    0xc0: "Utc1900_C",
    0xc1: "Utc1900_CPP",
    0xc2: "Utc1900_CVTCIL_C",
    0xc3: "Utc1900_CVTCIL_CPP",
    0xc4: "Utc1900_LTCG_C",
    0xc5: "Utc1900_LTCG_CPP",
    0xc6: "Utc1900_LTCG_MSIL",
    0xc7: "Utc1900_POGO_I_C",
    0xc8: "Utc1900_POGO_I_CPP",
    0xc9: "Utc1900_POGO_O_C",
    0xca: "Utc1900_POGO_O_CPP",
  };
  // The tool id lives in the low byte of the full comp.id; the parser already
  // split the product id, so match on that.
  const toolId = productId & 0xffff;
  return known[toolId] ?? "unrecognised";
}

export function StructureView({ report }: { report: Report }) {
  const { image, entropy } = report;
  const meta = image.metadata;
  const [query, setQuery] = useState("");
  const [onlyHighEntropy, setOnlyHighEntropy] = useState(false);

  const sections = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return image.sections.filter((section) => {
      if (needle && !section.name.toLowerCase().includes(needle)) return false;
      if (onlyHighEntropy && section.entropy < 7.2) return false;
      return true;
    });
  }, [image.sections, query, onlyHighEntropy]);

  return (
    <div className="stack">
      <Card
        title="Entropy profile"
        sub={`${entropy.window}-byte windows · ${entropy.windows.length} sampled`}
      >
        <EntropyChart profile={entropy} fileSize={report.artefact.size} />
      </Card>

      <Card
        title="Sections"
        sub={`${sections.length} of ${image.sections.length}`}
        bodyClass="flush"
        actions={
          <div style={{ marginLeft: "auto", display: "flex", gap: 10, alignItems: "center" }}>
            <Check checked={onlyHighEntropy} onChange={setOnlyHighEntropy}>
              ≥ 7.2 only
            </Check>
            <SearchInput
              value={query}
              onChange={setQuery}
              placeholder="Filter by name…"
              label="Filter sections by name"
            />
          </div>
        }
      >
        <div className="table-wrap" style={{ maxHeight: "min(58vh, 520px)" }}>
          <table className="data">
            <thead>
              <tr>
                <th>Name</th>
                <th className="mono num">Virtual address</th>
                <th className="mono num">Virtual size</th>
                <th className="mono num">Raw size</th>
                <th>Perm</th>
                <th className="num">Entropy</th>
                <th className="mono">SHA-256</th>
              </tr>
            </thead>
            <tbody>
              {sections.map((section, index) => (
                <tr key={`${section.name}-${section.file_offset}-${index}`}>
                  <td className="mono" style={{ color: "var(--text)" }}>
                    {section.name || "<unnamed>"}
                  </td>
                  <td className="mono num">{hex(section.virtual_address)}</td>
                  <td className="mono num">{formatBytes(section.virtual_size)}</td>
                  <td className="mono num">
                    {section.file_size > 0 ? formatBytes(section.file_size) : "—"}
                  </td>
                  <td>
                    <PermCell perm={section.permissions} />
                  </td>
                  <td className="num">
                    <span
                      className="entropy-value"
                      style={{ color: entropyColor(section.entropy) }}
                    >
                      {fixed(section.entropy)}
                    </span>
                  </td>
                  <td className="mono dim" title={section.sha256}>
                    {section.sha256 ? shortHash(section.sha256, 6) : "—"}
                  </td>
                </tr>
              ))}
              {sections.length === 0 && (
                <tr>
                  <td colSpan={7} className="empty-row">
                    {image.sections.length === 0
                      ? "No sections were recovered. See the diagnostics on the overview tab."
                      : "No section matches the current filter."}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </Card>

      {meta.format === "pe" && (
        <div className="grid cols-2">
          <Card title="PE header">
            <KeyValues
              rows={[
                ["Machine", `${meta.machine_name} (${hex(meta.machine, 4)})`],
                ["Linker version", meta.linker_version],
                ["Build stamp", `${formatUnixDateTime(meta.timestamp)} (frequently forged)`],
                [
                  "Checksum",
                  meta.checksum_valid ? (
                    <span style={{ color: "var(--clean)" }}>valid</span>
                  ) : (
                    <span style={{ color: "var(--high)" }}>
                      mismatch {hex(meta.declared_checksum)} ≠ {hex(meta.computed_checksum)}
                    </span>
                  ),
                ],
                [
                  "Alignment",
                  `file ${hex(meta.file_alignment)} · section ${hex(meta.section_alignment)}`,
                ],
                ["SizeOfImage", formatBytes(meta.size_of_image)],
                ["SizeOfHeaders", formatBytes(meta.size_of_headers)],
                ["Import hash", meta.import_hash ?? "—"],
                [
                  "TLS callbacks",
                  meta.tls_callbacks.length === 0
                    ? "none"
                    : meta.tls_callbacks.map((callback) => hex(callback)).join(", "),
                ],
              ]}
            />
          </Card>

          <Card
            title="Rich header"
            sub={meta.rich_entries.length > 0 ? `key ${hex(meta.rich_key)}` : "absent"}
            bodyClass="flush"
          >
            <div className="table-wrap" style={{ maxHeight: 280 }}>
              <table className="data">
                <thead>
                  <tr>
                    <th className="mono">Product</th>
                    <th>Tool</th>
                    <th className="num">Build</th>
                    <th className="num">Count</th>
                  </tr>
                </thead>
                <tbody>
                  {meta.rich_entries.map((entry, index) => (
                    <tr key={`${entry.product_id}-${entry.build}-${index}`}>
                      <td className="mono">{hex(entry.product_id, 4)}</td>
                      <td>{richProductName(entry.product_id)}</td>
                      <td className="num">{entry.build}</td>
                      <td className="num">{entry.count}</td>
                    </tr>
                  ))}
                  {meta.rich_entries.length === 0 && (
                    <tr>
                      <td colSpan={4} className="empty-row">
                        No Rich header. Normal for non-MSVC builds, managed assemblies and packed
                        stubs.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
            {meta.rich_entries.length > 0 && (
              <div className="card-foot">
                The Rich header records which MSVC tools built the file and how many times each
                ran. It is a toolchain fingerprint, and it is hard to forge convincingly.
              </div>
            )}
          </Card>
        </div>
      )}

      {meta.format === "elf" && (
        <Card title="ELF properties">
          <KeyValues
            rows={[
              ["Type", `${meta.e_type_name}${meta.pie ? " (PIE)" : ""}`],
              ["Machine", `${meta.machine_name} (${hex(meta.machine, 4)})`],
              ["Interpreter", meta.interpreter ?? "none (static or library)"],
              ["SONAME", meta.soname ?? "—"],
              ["RPATH", meta.rpath.length > 0 ? meta.rpath.join(":") : "—"],
              ["RUNPATH", meta.runpath.length > 0 ? meta.runpath.join(":") : "—"],
              ["Build ID", meta.build_id ?? "—"],
              [
                "Hardening",
                `NX stack ${meta.nx_stack ? "on" : "off"} · RELRO ${meta.relro ? "on" : "off"} · BIND_NOW ${meta.bind_now ? "on" : "off"}`,
              ],
              ["Symbols", meta.has_symtab ? "symtab present (not stripped)" : "stripped"],
              [
                "Compiler",
                meta.compiler_comments.length > 0 ? meta.compiler_comments.join(" · ") : "—",
              ],
            ]}
          />
        </Card>
      )}

      {meta.format === "macho" && (
        <Card title="Mach-O properties" sub={meta.is_fat ? "universal" : "thin"}>
          <KeyValues
            rows={[
              ["File type", meta.filetype_name],
              ["UUID", meta.uuid ?? "—"],
              ["Platform", meta.platform ?? "—"],
              ["Minimum OS", meta.min_os ?? "—"],
              ["Built against SDK", meta.sdk ?? "—"],
              ["Install name", meta.install_name ?? "—"],
              ["RPATHs", meta.rpaths.length > 0 ? meta.rpaths.join(", ") : "—"],
              [
                "Code signature",
                meta.has_code_signature
                  ? `present (${formatBytes(meta.code_signature_size)})`
                  : "absent",
              ],
              [
                "Slices",
                meta.slices.length === 0
                  ? "—"
                  : meta.slices
                      .map((slice) => `${slice.arch} @ ${hex(slice.offset)} +${formatBytes(slice.size)}`)
                      .join(", "),
              ],
            ]}
          />
          {meta.is_fat && meta.slices.length > 1 && (
            <Explainer>
              Only the first slice was analysed in depth. A universal binary whose other slices
              differ is a known evasion shape, so treat the unanalysed slices as unknown.
            </Explainer>
          )}
        </Card>
      )}

      {meta.format === "archive" && (
        <Card title="Package properties" sub={meta.container}>
          <KeyValues
            rows={[
              ["Entries", String(meta.entry_count)],
              ["Declared compressed", formatBytes(meta.declared_compressed)],
              ["Declared uncompressed", formatBytes(meta.declared_uncompressed)],
              ["Signature files", meta.has_signature_files ? "META-INF present" : "none"],
              ["Top level", meta.top_level.join(", ") || "—"],
              ["Executables", meta.executable_entries.slice(0, 8).join(", ") || "none"],
              ["Ratio outliers", meta.suspicious_ratio_entries.join(", ") || "none"],
            ]}
          />
          <Explainer>
            Member sizes are as declared in the archive catalogue. Nothing was decompressed, so a
            bomb would be reported here rather than expanded.
          </Explainer>
        </Card>
      )}

      {(image.resources.length > 0 || image.debug_artifacts.length > 0) && (
        <div className="grid cols-2">
          {image.resources.length > 0 && (
            <Card
              title="Resources"
              sub={`${image.resources.length}${image.resources.length > 80 ? " (first 80)" : ""}`}
              bodyClass="flush"
            >
              <div className="table-wrap" style={{ maxHeight: 300 }}>
                <table className="data">
                  <thead>
                    <tr>
                      <th>Type</th>
                      <th>Name</th>
                      <th>Language</th>
                      <th className="num">Size</th>
                    </tr>
                  </thead>
                  <tbody>
                    {image.resources.slice(0, 80).map((resource, index) => (
                      <tr key={`${resource.kind}-${resource.name}-${index}`}>
                        <td className="mono">{resource.kind}</td>
                        <td className="mono">{resource.name}</td>
                        <td className="dim">{resource.language ?? "—"}</td>
                        <td className="num">{formatBytes(resource.size)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Card>
          )}

          {image.debug_artifacts.length > 0 && (
            <Card title="Build artefacts" sub={String(image.debug_artifacts.length)}>
              <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                {image.debug_artifacts.slice(0, 24).map((artifact, index) => (
                  <div
                    key={`${artifact.kind}-${index}`}
                    style={{ display: "flex", gap: 8, alignItems: "flex-start", minWidth: 0 }}
                  >
                    <span className="chip soft" style={{ flex: "none" }}>
                      {artifact.kind}
                    </span>
                    <span
                      className="mono"
                      style={{
                        fontSize: "var(--text-xs)",
                        color: "var(--text-dim)",
                        overflowWrap: "anywhere",
                        minWidth: 0,
                      }}
                    >
                      {artifact.value}
                    </span>
                    {artifact.trusted && (
                      <span className="chip soft" style={{ flex: "none" }} title="plausible build path">
                        provenance
                      </span>
                    )}
                  </div>
                ))}
              </div>
            </Card>
          )}
        </div>
      )}

      {image.signature.present ? (
        <Card title="Signature" sub={image.signature.scheme}>
          <KeyValues
            rows={[
              ["Signer", image.signature.signer ?? "—"],
              ["Issuer", image.signature.issuer ?? "—"],
              ["Digest algorithm", image.signature.digest_algorithm ?? "—"],
              [
                "Validity",
                `${formatUnixDateTime(image.signature.valid_from)} → ${formatUnixDateTime(image.signature.valid_to)}`,
              ],
              ["Timestamped", image.signature.timestamped ? "yes" : "no"],
              ["Blob SHA-256", image.signature.blob_sha256 || "—"],
            ]}
          />
          {image.signature.issues.length > 0 && (
            <div className="note-list" style={{ marginTop: 12 }}>
              {image.signature.issues.map((issue, index) => (
                <div className="note" key={`${issue}-${index}`}>
                  <span>{issue}</span>
                </div>
              ))}
            </div>
          )}
          <Explainer>
            These fields are read from the signature blob; the signature is not cryptographically
            verified. Verifying it needs the platform trust store, which this tool never touches —
            use <span className="mono">signtool verify</span> or{" "}
            <span className="mono">codesign -v</span> when trust matters.
          </Explainer>
        </Card>
      ) : (
        <Card title="Signature">
          <Empty>
            No embedded Authenticode signature. Many Windows binaries are signed through a
            security catalog instead, which this tool does not check — so this is an observation,
            not a verdict.
          </Empty>
        </Card>
      )}

      {image.exports.length > 0 && (
        <Card
          title="Exports"
          sub={(() => {
            const forwarded = image.exports.filter((entry) => entry.forwarded_to).length;
            return forwarded > 0
              ? `${image.exports.length} · ${forwarded} forwarded`
              : String(image.exports.length);
          })()}
          bodyClass="flush"
        >
          <div className="table-wrap" style={{ maxHeight: 320 }}>
            <table className="data">
              <thead>
                <tr>
                  <th>Name</th>
                  <th className="num">Ordinal</th>
                  <th className="mono num">Address</th>
                  <th>Forwarded to</th>
                </tr>
              </thead>
              <tbody>
                {image.exports.slice(0, 400).map((entry, index) => (
                  <tr key={`${entry.name}-${entry.ordinal}-${index}`}>
                    <td className="mono">{entry.name || "<ordinal only>"}</td>
                    <td className="num">{entry.ordinal ?? "—"}</td>
                    <td className="mono num">{hex(entry.address)}</td>
                    <td className="mono dim">{entry.forwarded_to ?? ""}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {image.sections.length > 0 && (
        <Explainer>
          A section that is both writable and executable breaks W^X; it is marked in orange. The
          section table shows virtual size and raw size separately because the gap between them is
          where unpacking stubs hide their scratch space.
        </Explainer>
      )}
    </div>
  );
}

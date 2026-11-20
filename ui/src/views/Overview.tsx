import { useState } from "react";
import type { Report } from "../types";
import { topIndicators } from "../types";
import { Badge, FactorBars, ScoreRing } from "../components/Visuals";
import { EntropyMeter } from "../components/EntropyChart";
import { Card, Empty, Explainer, KeyValues, Metric } from "../components/Primitives";
import {
  fixed,
  formatBytes,
  formatLabel,
  formatUnixDateTime,
  hex,
  kindLabel,
  pct,
} from "../lib/format";

/** Format-specific facts, flattened for the identity card. */
function identityRows(report: Report): [string, React.ReactNode][] {
  const image = report.image;
  const meta = image.metadata;
  const rows: [string, React.ReactNode][] = [
    ["Format", formatLabel(image.format)],
    ["Kind", kindLabel(image.kind)],
    ["Architecture", image.arch],
  ];

  if (image.bitness > 0) rows.push(["Bitness", `${image.bitness}-bit`]);
  rows.push(["Endianness", image.endian]);
  if (image.entry_point !== null) rows.push(["Entry point", hex(image.entry_point)]);
  if (image.image_base > 0) rows.push(["Image base", hex(image.image_base)]);

  if (meta.format === "pe") {
    rows.push(["Linker", `MSVC ${meta.linker_version}`]);
    rows.push([
      "Subsystem",
      meta.subsystem === 2 ? "GUI" : meta.subsystem === 3 ? "Console" : String(meta.subsystem),
    ]);
    rows.push(["Build stamp", `${formatUnixDateTime(meta.timestamp)} (frequently forged)`]);
    if (meta.is_dotnet) rows.push(["CLR", meta.clr_version ?? "present"]);
    if (meta.pdb_path) rows.push(["PDB", meta.pdb_path]);
  } else if (meta.format === "elf") {
    rows.push(["ELF type", meta.e_type_name]);
    rows.push(["OS ABI", meta.osabi]);
    if (meta.interpreter) rows.push(["Interpreter", meta.interpreter]);
    if (meta.build_id) rows.push(["Build ID", meta.build_id]);
    if (meta.soname) rows.push(["SONAME", meta.soname]);
  } else if (meta.format === "macho") {
    rows.push(["Mach-O type", meta.filetype_name]);
    if (meta.uuid) rows.push(["UUID", meta.uuid]);
    if (meta.platform) rows.push(["Platform", meta.platform]);
    if (meta.min_os) rows.push(["Minimum OS", meta.min_os]);
    if (meta.is_fat) rows.push(["Slices", String(meta.slices.length)]);
  } else if (meta.format === "archive") {
    rows.push(["Container", meta.container]);
    rows.push(["Entries", String(meta.entry_count)]);
    rows.push(["Declared size", formatBytes(meta.declared_uncompressed)]);
    if (meta.inferred_purpose) rows.push(["Purpose", meta.inferred_purpose]);
  }

  return rows;
}

export function OverviewView({ report }: { report: Report }) {
  const [factorKey, setFactorKey] = useState<string | null>(null);
  const { image, entropy, score, packer, indicators } = report;

  const selectedFactor = score.factors.find((factor) => factor.key === factorKey) ?? null;

  const executable = image.sections.filter((section) => section.permissions.execute).length;
  const writableExecutable = image.sections.filter(
    (section) => section.permissions.write && section.permissions.execute,
  ).length;

  const signature = image.signature;
  const signatureValue = signature.present ? "signed" : "no embedded signature";

  return (
    <div className="stack">
      <Card
        title="Composite risk"
        sub={`${report.rules_evaluated} rules evaluated`}
      >
        <div className="score-hero">
          <ScoreRing score={score.score} grade={score.grade} />
          <div style={{ flex: 1, minWidth: 0, display: "flex", flexDirection: "column", gap: 10 }}>
            <p className="lede">{score.verdict}</p>
            <FactorBars
              factors={score.factors}
              selected={factorKey}
              onSelect={setFactorKey}
            />
            <p style={{ margin: 0, fontSize: "var(--text-xs)", color: "var(--text-faint)" }}>
              Select a factor to see the evidence behind its points.
            </p>
          </div>
        </div>
        {selectedFactor && (
          <div className="card-foot">
            <div className="section-label">{selectedFactor.name} — evidence</div>
            <p style={{ margin: "0 0 8px", color: "var(--text-dim)", lineHeight: 1.65 }}>
              {selectedFactor.detail}
            </p>
            {selectedFactor.evidence.length === 0 ? (
              <span className="dim">This factor recorded no individual observations.</span>
            ) : (
              <div className="finding-evidence">
                {selectedFactor.evidence.map((line, index) => (
                  <div className="evidence-line" key={`${line}-${index}`}>
                    {line}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </Card>

      <div className="grid cols-4">
        <Metric
          label="Sections"
          value={image.sections.length}
          hint={`${executable} executable · ${writableExecutable} writable+executable`}
        />
        <Metric
          label="Peak entropy"
          value={fixed(entropy.peak_entropy)}
          unit="bits/byte"
          hint={`mean ${fixed(entropy.mean_windowed)} · σ ${fixed(entropy.stdev_windowed)}`}
        >
          <EntropyMeter fraction={entropy.high_entropy_fraction} />
        </Metric>
        <Metric
          label="Packer likelihood"
          value={packer.likelihood}
          unit="%"
          hint={packer.summary}
          tone={packer.likelihood >= 45 ? "var(--high)" : undefined}
        />
        <Metric
          label="Code signing"
          value={signatureValue}
          tone={signature.present ? "var(--low)" : "var(--medium)"}
          hint={
            signature.present
              ? signature.signer ?? "identity unresolved"
              : "catalog signing is not checked"
          }
        />
      </div>

      <div className="grid cols-2">
        <Card title="Identity" sub={`${image.imports.length} imports`}>
          <KeyValues rows={identityRows(report)} />
        </Card>

        <div className="stack">
          <Card title="Extraction summary" sub={`${report.string_stats.total} strings`}>
            <KeyValues
              rows={[
                ["Unique strings", String(report.string_stats.unique)],
                ["ASCII", String(report.string_stats.ascii)],
                ["UTF-16 LE", String(report.string_stats.utf16le)],
                ["UTF-16 BE", String(report.string_stats.utf16be)],
                ["Longest", `${report.string_stats.longest} chars`],
                ["Indicators", String(indicators.indicators.length)],
                ["Techniques", String(report.techniques.length)],
                ["Findings", String(report.findings.length)],
              ]}
            />
          </Card>
          {indicators.indicators.length > 0 && (
            <Card title="Top indicators" sub={`${indicators.indicators.length} total`}>
              <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                {topIndicators(indicators, 4).map((indicator, index) => (
                  <div
                    key={`${indicator.kind}-${indicator.value}-${index}`}
                    style={{ display: "flex", alignItems: "baseline", gap: 8, minWidth: 0 }}
                  >
                    <span className="chip soft" style={{ minWidth: 68, justifyContent: "center" }}>
                      {indicator.kind.replace(/_/g, " ")}
                    </span>
                    <span
                      className="mono truncate"
                      style={{ fontSize: "var(--text-xs)", color: "var(--text-dim)" }}
                      title={indicator.value}
                    >
                      {indicator.value}
                    </span>
                  </div>
                ))}
              </div>
            </Card>
          )}
        </div>
      </div>

      {packer.evidence.length > 0 && (
        <Card title="Packing evidence" sub={`${packer.evidence.length} signals`}>
          <div style={{ display: "flex", flexDirection: "column", gap: 7 }}>
            {packer.evidence.map((item) => (
              <div key={item.key} style={{ display: "flex", gap: 10, alignItems: "flex-start" }}>
                <span
                  className="chip"
                  style={{
                    flex: "none",
                    width: 40,
                    justifyContent: "center",
                    color: item.weight >= 20 ? "var(--high)" : "var(--text-faint)",
                  }}
                  title={`contributes ${item.weight} points to the likelihood`}
                >
                  +{item.weight}
                </span>
                <span style={{ fontSize: "var(--text-sm)", color: "var(--text-dim)", lineHeight: 1.6 }}>
                  {item.detail}
                </span>
              </div>
            ))}
          </div>
          <Explainer>
            Packing likelihood is the sum of these weights, capped at 100. A signature match
            alone is enough to reach the review band; heuristics need to agree with each other
            before the score reacts.
          </Explainer>
        </Card>
      )}

      {image.structural_notes.length > 0 && (
        <Card title="Structural notes" sub={String(image.structural_notes.length)}>
          <div className="note-list">
            {image.structural_notes.map((note, index) => (
              <div className="note" key={`${note}-${index}`}>
                <span>{note}</span>
              </div>
            ))}
          </div>
        </Card>
      )}

      {report.diagnostics.length > 0 && (
        <Card title="Diagnostics" sub={String(report.diagnostics.length)}>
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {report.diagnostics.map((diagnostic, index) => (
              <div
                key={`${diagnostic.stage}-${index}`}
                style={{ display: "flex", gap: 8, alignItems: "flex-start", flexWrap: "wrap" }}
              >
                <Badge level={diagnostic.severity === "error" ? "high" : "medium"} icon>
                  {diagnostic.severity}
                </Badge>
                <span className="chip">{diagnostic.stage}</span>
                <span
                  style={{
                    fontSize: "var(--text-sm)",
                    color: "var(--text-dim)",
                    lineHeight: 1.6,
                    flex: 1,
                    minWidth: 200,
                  }}
                >
                  {diagnostic.message}
                </span>
              </div>
            ))}
          </div>
          <Explainer>
            A warning means part of the file could not be decoded. The rest of the report is
            still valid, but treat the missing structure as unknown rather than absent.
          </Explainer>
        </Card>
      )}

      {report.findings.length === 0 && report.diagnostics.length === 0 && (
        <Card title="No rule matched">
          <Empty>
            None of the {report.rules_evaluated} loaded rules described what this file does. That
            is not a clean bill of health — it means no rule covered this shape. The score above
            is a separate, additive judgement.
          </Empty>
        </Card>
      )}

      <div className="grid cols-2">
        <Card title="Analysis cost" sub={`${report.timing.total_ms} ms`}>
          <div
            style={{
              display: "flex",
              gap: 16,
              flexWrap: "wrap",
              fontSize: "var(--text-xs)",
              color: "var(--text-faint)",
            }}
          >
            {(
              [
                ["detect", report.timing.detect_ms],
                ["parse", report.timing.parse_ms],
                ["strings", report.timing.strings_ms],
                ["infer", report.timing.analysis_ms],
                ["rules", report.timing.rules_ms],
              ] as const
            ).map(([label, ms]) => (
              <span key={label}>
                {label}{" "}
                <b className="mono" style={{ color: "var(--text-dim)", fontWeight: 500 }}>
                  {ms}
                </b>{" "}
                ms
              </span>
            ))}
          </div>
        </Card>

        <Card title="Hashes" sub="identity, not reputation">
          <KeyValues
            rows={[
              ["SHA-256", report.artefact.sha256],
              ["SHA-1", report.artefact.sha1],
              ["MD5", report.artefact.md5],
              ["Fuzzy (CTPH)", report.artefact.fuzzy || "—"],
            ]}
          />
        </Card>
      </div>

      <Explainer>
        High-entropy regions cover {pct(entropy.high_entropy_fraction)} of the file; the longest
        contiguous run is {formatBytes(entropy.longest_high_run.length)} starting at{" "}
        <span className="mono">{hex(entropy.longest_high_run.offset)}</span>. Entropy alone never
        condemns a file — packed content and compressed resources are indistinguishable by this
        measure, which is why the packing evidence above lists its reasons.
      </Explainer>
    </div>
  );
}

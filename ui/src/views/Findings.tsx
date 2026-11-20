import { useMemo, useState } from "react";
import type { Report, Severity } from "../types";
import { SEVERITY_ORDER } from "../types";
import { Badge, SeverityRail } from "../components/Visuals";
import { Card, Empty, Explainer, Segmented } from "../components/Primitives";
import { plural } from "../lib/format";

type Filter = "all" | Severity;

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

export function FindingsView({ report }: { report: Report }) {
  const [filter, setFilter] = useState<Filter>("all");

  const counts = useMemo(() => {
    const map: Partial<Record<Severity, number>> = {};
    for (const finding of report.findings) {
      map[finding.severity] = (map[finding.severity] ?? 0) + 1;
    }
    return map;
  }, [report.findings]);

  const visible = useMemo(() => {
    const list =
      filter === "all"
        ? report.findings
        : report.findings.filter((finding) => finding.severity === filter);
    return [...list].sort((a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity]);
  }, [report.findings, filter]);

  if (report.findings.length === 0) {
    return (
      <div className="stack">
        <Card title="Findings">
          <Empty>
            No rule matched. That is not a clean bill of health — it means none of the{" "}
            {report.rules_evaluated} loaded rules described what this file does. The composite
            score on the overview tab is a separate judgement, and the ATT&amp;CK tab shows what
            capability could be inferred.
          </Empty>
        </Card>
        <Explainer>
          A rule fires on a combination of conditions; its severity is the author&apos;s statement
          about how bad a match would be. The score is an additive judgement over different
          evidence. When a high or critical finding exists, it sets a floor under the score so the
          number cannot contradict the finding — and the score&apos;s verdict sentence names the
          rule responsible.
        </Explainer>
      </div>
    );
  }

  const order: Filter[] = ["all", "critical", "high", "medium", "low", "info"];
  const options = order
    .map((value) => {
      const count = value === "all" ? report.findings.length : counts[value] ?? 0;
      return {
        value,
        label: value === "all" ? "All" : SEVERITY_LABEL[value],
        count,
      };
    })
    // Hide severities with no findings; an empty tab is noise.
    .filter((option) => option.value === "all" || option.count > 0);

  return (
    <div className="stack">
      <div className="spread">
        <Segmented<Filter> label="Filter by severity" value={filter} onChange={setFilter} options={options} />
        <span className="dim" style={{ fontSize: "var(--text-xs)" }}>
          {plural(visible.length, "finding")}
        </span>
      </div>

      <Card title="Rule matches" sub={plural(report.findings.length, "finding")} bodyClass="flush">
        {visible.map((finding, index) => (
          <article className="finding" key={`${finding.rule_id}-${index}`}>
            <SeverityRail severity={finding.severity} />
            <div className="finding-main">
              <div className="finding-title">
                <Badge level={finding.severity} icon>
                  {SEVERITY_LABEL[finding.severity]}
                </Badge>
                <span className="finding-name">{finding.rule_name}</span>
                <span className="finding-id mono">{finding.rule_id}</span>
              </div>
              {finding.description && <p className="finding-desc">{finding.description}</p>}
              <div className="finding-evidence">
                {finding.evidence.map((line, lineIndex) => (
                  <div className="evidence-line" key={`${line}-${lineIndex}`}>
                    {line}
                  </div>
                ))}
              </div>
              {finding.tags.length > 0 && (
                <div className="tag-row">
                  {finding.tags.map((tag) => (
                    <span className="chip soft" key={tag}>
                      {tag}
                    </span>
                  ))}
                </div>
              )}
            </div>
          </article>
        ))}
        {visible.length === 0 && <Empty>No finding at this severity.</Empty>}
      </Card>

      <Explainer>
        Severity is the rule author&apos;s statement about how bad a match would be. The composite
        score is a separate, additive judgement. A critical finding pins the score to the critical
        band, and the uplift is recorded as its own factor — so the two never disagree silently.
        Rules you write yourself can be loaded with <span className="mono">--rules</span>, and each
        one is listed here by its id.
      </Explainer>
    </div>
  );
}

import { useMemo, useState } from "react";
import type { IocKind, Report } from "../types";
import { Badge, ConfidenceMeter } from "../components/Visuals";
import { Card, Check, Empty, Explainer, SearchInput } from "../components/Primitives";
import { pct, plural } from "../lib/format";

const KIND_LABEL: Record<IocKind, string> = {
  url: "URL",
  domain: "Domain",
  ipv4: "IPv4",
  ipv6: "IPv6",
  email: "Email",
  bitcoin: "Bitcoin",
  ethereum: "Ethereum",
  onion: "Onion service",
  registry_key: "Registry key",
  file_path: "File path",
  guid: "GUID",
  user_agent: "User agent",
  named_object: "Named object",
};

/**
 * Kinds promoted above the fold. Everything else is context: a GUID or a file
 * path appears in every binary and burying the reader in them is how an IOC list
 * loses its audience.
 */
const HIGH_SIGNAL: readonly IocKind[] = [
  "onion",
  "bitcoin",
  "ethereum",
  "url",
  "ipv4",
  "ipv6",
  "domain",
  "registry_key",
];

export function IndicatorsView({ report }: { report: Report }) {
  const [showAll, setShowAll] = useState(false);
  const [query, setQuery] = useState("");

  const indicators = report.indicators.indicators;

  const visible = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return indicators.filter((item) => {
      if (!showAll && !HIGH_SIGNAL.includes(item.kind)) return false;
      if (needle && !item.value.toLowerCase().includes(needle)) return false;
      return true;
    });
  }, [indicators, showAll, query]);

  if (indicators.length === 0) {
    return (
      <Card title="Indicators of compromise">
        <Empty>
          No indicators were recovered. For a binary that clearly talks to the network, that absence
          is itself worth explaining — it usually means the strings are decoded at runtime rather
          than stored.
        </Empty>
      </Card>
    );
  }

  const hidden = indicators.length - indicators.filter((i) => HIGH_SIGNAL.includes(i.kind)).length;

  return (
    <div className="stack">
      <Card
        title="Indicators of compromise"
        sub={
          visible.length === indicators.length
            ? plural(indicators.length, "indicator")
            : `${visible.length} of ${indicators.length}`
        }
      >
        <div className="row" style={{ flexWrap: "wrap", gap: 12 }}>
          <SearchInput
            value={query}
            onChange={setQuery}
            placeholder="Filter indicators…"
            label="Filter indicators"
          />
          {hidden > 0 && (
            <Check checked={showAll} onChange={setShowAll}>
              include {hidden} low-signal (paths, GUIDs, user agents)
            </Check>
          )}
          <div
            style={{
              marginLeft: "auto",
              display: "flex",
              gap: 5,
              flexWrap: "wrap",
            }}
          >
            {report.indicators.by_kind.map(([kind, count]) => (
              <span className="chip soft" key={kind} title={`${count} ${kind}`}>
                {KIND_LABEL[kind as IocKind] ?? kind} <b style={{ color: "var(--text-dim)" }}>{count}</b>
              </span>
            ))}
          </div>
        </div>

        {visible.length === 0 ? (
          <Empty>
            No indicator matches the current filter. Enable low-signal kinds to include file paths,
            GUIDs and user-agent strings.
          </Empty>
        ) : (
          <div
            className="table-wrap"
            style={{
              maxHeight: "min(56vh, 540px)",
              margin: "0 -16px -16px",
              borderTop: "1px solid var(--border)",
            }}
          >
            <table className="data">
              <thead>
                <tr>
                  <th style={{ width: 110 }}>Kind</th>
                  <th>Value</th>
                  <th className="num" style={{ width: 62 }}>
                    Seen
                  </th>
                  <th style={{ width: 118 }}>Confidence</th>
                  <th style={{ width: 240 }}>Why it counts</th>
                </tr>
              </thead>
              <tbody>
                {visible.map((item, index) => (
                  <tr key={`${item.kind}-${item.value}-${index}`}>
                    <td>
                      <span className="chip soft">{KIND_LABEL[item.kind] ?? item.kind}</span>
                    </td>
                    <td
                      className="mono"
                      style={{
                        color: "var(--text)",
                        wordBreak: "break-all",
                        userSelect: "text",
                      }}
                    >
                      {item.value}
                    </td>
                    <td className="num">{item.occurrences}</td>
                    <td>
                      <ConfidenceMeter value={item.confidence} />
                    </td>
                    <td className="dim" style={{ fontSize: "var(--text-xs)", lineHeight: 1.55 }}>
                      {item.rationale}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <Explainer>
        Confidence measures how strongly the surrounding bytes support the reading — an IPv4
        literal inside a version resource is weaker evidence than one inside an HTTP request
        template. Nothing here has been checked against a reputation service; Assay makes no
        network calls. XML namespaces and certificate-publication URLs are filtered out at
        extraction, because they are identifiers rather than endpoints.
      </Explainer>
    </div>
  );
}

const TACTIC_LABEL: Record<string, string> = {
  reconnaissance: "Recon",
  "resource-development": "Resource Dev",
  "initial-access": "Initial Access",
  execution: "Execution",
  persistence: "Persistence",
  "privilege-escalation": "Priv Esc",
  "defense-evasion": "Defense Evasion",
  "credential-access": "Credential Access",
  discovery: "Discovery",
  "lateral-movement": "Lateral Movement",
  collection: "Collection",
  "command-and-control": "Command & Control",
  exfiltration: "Exfiltration",
  impact: "Impact",
};

/**
 * Kill-chain order. Must list every tactic the engine can emit: a missing entry
 * previously sorted to index -1 and jumped to the front of the matrix.
 */
const TACTIC_ORDER: string[] = [
  "reconnaissance",
  "resource-development",
  "initial-access",
  "execution",
  "persistence",
  "privilege-escalation",
  "defense-evasion",
  "credential-access",
  "discovery",
  "lateral-movement",
  "collection",
  "command-and-control",
  "exfiltration",
  "impact",
];

function tacticIndex(tactic: string): number {
  const index = TACTIC_ORDER.indexOf(tactic);
  return index === -1 ? TACTIC_ORDER.length : index;
}

function tacticLabel(tactic: string): string {
  return TACTIC_LABEL[tactic] ?? tactic.replace(/-/g, " ");
}

export function AttackView({ report }: { report: Report }) {
  const [selected, setSelected] = useState<string | null>(null);

  const byTactic = useMemo(() => {
    const map = new Map<string, typeof report.techniques>();
    for (const technique of report.techniques) {
      const list = map.get(technique.tactic) ?? [];
      list.push(technique);
      map.set(technique.tactic, list);
    }
    return [...map.entries()].sort((a, b) => tacticIndex(a[0]) - tacticIndex(b[0]));
  }, [report.techniques]);

  if (report.techniques.length === 0) {
    return (
      <Card title="ATT&CK techniques">
        <Empty>
          No technique could be inferred. The usual reasons are an empty import table (packed), a
          non-native artefact, or a platform library where capability inference is deliberately
          withheld — check the structural notes on the overview tab.
        </Empty>
      </Card>
    );
  }

  // Key by sub-technique when present, so T1055 and T1055.012 are distinguishable.
  const keyOf = (id: string, subId: string | null) => subId ?? id;
  const active = selected
    ? report.techniques.find((technique) => keyOf(technique.id, technique.sub_id) === selected) ?? null
    : null;

  return (
    <div className="stack">
      <div className="attack-layout">
        <Card title="Kill chain" sub={plural(report.techniques.length, "technique")}>
          <div className="attack-grid">
            {byTactic.map(([tactic, techniques]) => (
              <div className="tactic-col" key={tactic}>
                <div className="tactic-head" title={tacticLabel(tactic)}>
                  <span
                    style={{ overflow: "hidden", textOverflow: "ellipsis" }}
                  >
                    {tacticLabel(tactic)}
                  </span>
                  <span className="tactic-count">{techniques.length}</span>
                </div>
                {techniques.map((technique) => {
                  const key = keyOf(technique.id, technique.sub_id);
                  const isActive = selected === key;
                  return (
                    <button
                      type="button"
                      key={key}
                      className="technique-card"
                      aria-current={isActive}
                      onClick={() => setSelected(isActive ? null : key)}
                    >
                      <div className="technique-id">{key}</div>
                      <div className="technique-name">{technique.name}</div>
                      <ConfidenceMeter value={technique.confidence} />
                    </button>
                  );
                })}
              </div>
            ))}
          </div>
          <div className="card-foot">
            Techniques are ordered along the kill chain. Select one to see the symbols that
            satisfied its rule and how to detect the behaviour.
          </div>
        </Card>

        {active ? (
          <Card title={`${keyOf(active.id, active.sub_id)} · ${active.name}`} sub={tacticLabel(active.tactic)}>
            <div className="row" style={{ gap: 8, marginBottom: 12, flexWrap: "wrap" }}>
              <Badge level="info">{pct(active.confidence)} confidence</Badge>
              <span className="chip soft">{tacticLabel(active.tactic)}</span>
            </div>
            <p
              style={{
                margin: "0 0 14px",
                fontSize: "var(--text-sm)",
                color: "var(--text-dim)",
                lineHeight: 1.7,
              }}
            >
              {active.note}
            </p>

            <div className="section-label">Evidence</div>
            <div className="finding-evidence" style={{ marginBottom: 14 }}>
              {active.evidence.map((line, index) => (
                <div className="evidence-line" key={`${line}-${index}`}>
                  {line}
                </div>
              ))}
            </div>

            <div className="section-label">Detection</div>
            <p
              style={{
                margin: 0,
                fontSize: "var(--text-sm)",
                color: "var(--text-dim)",
                lineHeight: 1.7,
              }}
            >
              {active.detection}
            </p>
          </Card>
        ) : (
          <Card title="Technique detail">
            <p
              style={{
                margin: 0,
                fontSize: "var(--text-sm)",
                color: "var(--text-faint)",
                lineHeight: 1.75,
              }}
            >
              Select a technique to see which symbols satisfied its rule, why the combination is
              meaningful, and what to monitor for it.
            </p>
            <div className="section-label" style={{ marginTop: 14 }}>
              How a technique is inferred
            </div>
            <p
              style={{
                margin: 0,
                fontSize: "var(--text-sm)",
                color: "var(--text-faint)",
                lineHeight: 1.75,
              }}
            >
              Each rule requires a combination — for process injection, allocating memory in
              another process, writing to it, and then executing there. A single imported API is
              never enough, and a symbol the module exports is excluded because a provider is not
              a user.
            </p>
          </Card>
        )}
      </div>

      <Explainer>
        Techniques are inferred from <em>combinations</em> of imported symbols and embedded
        strings, never from a single API name, and a symbol the module exports never counts as one
        it uses. A hit means the capability is present in the binary — not that this sample
        exercised it.
      </Explainer>
    </div>
  );
}

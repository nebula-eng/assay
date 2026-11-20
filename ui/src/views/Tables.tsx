import { useMemo, useState } from "react";
import type { Report } from "../types";
import { Card, Check, Empty, Explainer, SearchInput, Segmented } from "../components/Primitives";
import { encodingLabel, offset, plural } from "../lib/format";

/**
 * Imports grouped by supplying library.
 *
 * Grouping matters because the question is "does this link against something it
 * has no business linking against", and that question is per-library. The
 * previous implementation rendered one card per library, which on a real binary
 * meant forty stacked cards and a page you had to scroll for a minute. This
 * version keeps one card and lays the groups out as rows, so the whole import
 * surface fits on a screen or two.
 */
export function ImportsView({ report }: { report: Report }) {
  const [query, setQuery] = useState("");
  const [showDelayed, setShowDelayed] = useState(true);

  const groups = useMemo(() => {
    const needle = query.trim().toLowerCase();
    const map = new Map<string, { symbol: string; delayed: boolean }[]>();

    for (const entry of report.image.imports) {
      if (!showDelayed && entry.delayed) continue;
      const label = entry.symbol || (entry.ordinal !== null ? `#${entry.ordinal}` : "<unnamed>");
      if (
        needle &&
        !label.toLowerCase().includes(needle) &&
        !entry.library.toLowerCase().includes(needle)
      ) {
        continue;
      }
      const list = map.get(entry.library) ?? [];
      list.push({ symbol: label, delayed: entry.delayed });
      map.set(entry.library, list);
    }

    return [...map.entries()].sort((a, b) => b[1].length - a[1].length);
  }, [report.image.imports, query, showDelayed]);

  const shown = groups.reduce((sum, [, list]) => sum + list.length, 0);
  const delayedCount = report.image.imports.filter((entry) => entry.delayed).length;
  const isEmpty = report.image.imports.length === 0;

  return (
    <div className="stack">
      {isEmpty ? (
        <Card title="Imports" sub="0 symbols">
          <Empty>
            This image imports nothing. For a PE that is itself a finding: a binary that resolves
            every symbol at runtime is either packed or deliberately avoiding the loader. See the
            packing evidence on the overview tab.
          </Empty>
        </Card>
      ) : groups.length === 0 ? (
        <Card title="Imports">
          <Empty>No symbol matches the filter.</Empty>
        </Card>
      ) : (
        <Card
          title="Imports"
          sub={
            query
              ? `${shown} of ${report.image.imports.length} symbols`
              : `${plural(shown, "symbol")} · ${plural(groups.length, "library", "libraries")}`
          }
        >
          <div
            className="row"
            style={{ flexWrap: "wrap", gap: 12, paddingBottom: 12, marginBottom: 4 }}
          >
            <SearchInput
              value={query}
              onChange={setQuery}
              placeholder="Filter by library or symbol…"
              label="Filter imports"
            />
            <Check checked={showDelayed} onChange={setShowDelayed}>
              include delay-load
            </Check>
            {delayedCount > 0 && (
              <span className="chip soft" title="resolved lazily on first call">
                {delayedCount} delayed
              </span>
            )}
          </div>
          <div style={{ display: "flex", flexDirection: "column" }}>
            {groups.map(([library, symbols], groupIndex) => (
              <div
                key={library}
                style={{
                  padding: "10px 0",
                  borderTop: groupIndex === 0 ? "none" : "1px solid var(--border)",
                }}
              >
                <div className="spread" style={{ marginBottom: 7 }}>
                  <span
                    className="mono"
                    style={{ fontSize: "var(--text-sm)", color: "var(--text)" }}
                  >
                    {library}
                  </span>
                  <span
                    className="mono"
                    style={{ fontSize: "var(--text-2xs)", color: "var(--text-faint)" }}
                  >
                    {symbols.length}
                  </span>
                </div>
                <div style={{ display: "flex", flexWrap: "wrap", gap: 5 }}>
                  {symbols.map((symbol, index) => (
                    <span
                      key={`${symbol.symbol}-${index}`}
                      className={`chip symbol${symbol.delayed ? " delayed" : ""}`}
                      title={
                        symbol.delayed
                          ? "resolved lazily through a delay-load thunk"
                          : "resolved by the loader at start-up"
                      }
                    >
                      {symbol.symbol}
                    </span>
                  ))}
                </div>
              </div>
            ))}
          </div>
          <div className="card-foot">
            Delay-load imports are shown in amber: the symbol is only resolved when it is first
            called, which is a common way to keep a capability out of the start-up path.
          </div>
        </Card>
      )}

      {report.image.exports.length > 0 && (
        <Card
          title="Exports"
          sub={plural(report.image.exports.length, "symbol")}
          bodyClass="flush"
        >
          <div className="table-wrap" style={{ maxHeight: 360 }}>
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
                {report.image.exports.slice(0, 400).map((entry, index) => (
                  <tr key={`${entry.name}-${entry.ordinal}-${index}`}>
                    <td className="mono">{entry.name || "<ordinal only>"}</td>
                    <td className="num">{entry.ordinal ?? "—"}</td>
                    <td className="mono num">0x{entry.address.toString(16)}</td>
                    <td className="mono dim">{entry.forwarded_to ?? ""}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      <Explainer>
        A module that both exports and imports a symbol is usually forwarding it — Windows shims do
        this constantly. Assay excludes such symbols from capability inference, because a module
        that provides an API is not a module that uses it.
      </Explainer>
    </div>
  );
}

type EncodingFilter = "all" | "ascii" | "utf16le" | "utf16be";

/**
 * Recovered strings.
 *
 * The list is capped and filtered client-side rather than virtualised: the
 * engine already bounds the sample to a few thousand entries, so a slice is
 * faster and easier to reason about than a windowing library.
 */
export function StringsView({ report }: { report: Report }) {
  const [query, setQuery] = useState("");
  const [encoding, setEncoding] = useState<EncodingFilter>("all");

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return report.strings.filter((entry) => {
      if (encoding !== "all" && entry.encoding !== encoding) return false;
      if (needle && !entry.text.toLowerCase().includes(needle)) return false;
      return true;
    });
  }, [report.strings, query, encoding]);

  // Bounded because the table is not virtualised; narrowing the filter is the
  // affordance for reaching beyond the cap.
  const LIMIT = 1500;
  const shown = filtered.slice(0, LIMIT);

  const stats = report.string_stats;

  return (
    <div className="stack">
      <Card
        title="Strings"
        sub={
          query || encoding !== "all"
            ? `${shown.length} of ${filtered.length} match`
            : plural(stats.total, "string")
        }
      >
        <div className="row" style={{ flexWrap: "wrap", gap: 12, paddingBottom: 12 }}>
          <SearchInput
            value={query}
            onChange={setQuery}
            placeholder="Search recovered text…"
            label="Search strings"
          />
          <Segmented<EncodingFilter>
            label="Encoding filter"
            value={encoding}
            onChange={setEncoding}
            options={[
              { value: "all", label: "All" },
              { value: "ascii", label: "ASCII", count: stats.ascii },
              { value: "utf16le", label: "UTF-16 LE", count: stats.utf16le },
              { value: "utf16be", label: "UTF-16 BE", count: stats.utf16be },
            ]}
          />
        </div>
        <div
          className="table-wrap"
          style={{
            maxHeight: "min(58vh, 600px)",
            margin: "0 -16px -16px",
            borderTop: "1px solid var(--border)",
          }}
        >
          <table className="data">
            <thead>
              <tr>
                <th className="mono" style={{ width: 108 }}>
                  Offset
                </th>
                <th style={{ width: 84 }}>Encoding</th>
                <th className="num" style={{ width: 56 }}>
                  Length
                </th>
                <th>Text</th>
              </tr>
            </thead>
            <tbody>
              {shown.map((entry, index) => (
                <tr key={`${entry.offset}-${index}`}>
                  <td className="mono dim">{offset(entry.offset)}</td>
                  <td>
                    <span className="chip soft">{encodingLabel(entry.encoding)}</span>
                  </td>
                  <td className="num">{entry.length}</td>
                  <td
                    className="mono"
                    style={{ color: "var(--text-dim)", wordBreak: "break-all", userSelect: "text" }}
                  >
                    {entry.text}
                  </td>
                </tr>
              ))}
              {shown.length === 0 && (
                <tr>
                  <td colSpan={4} className="empty-row">
                    {report.strings.length === 0
                      ? "No strings were recovered from this artefact."
                      : "No string matches the current filter."}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        {filtered.length > LIMIT && (
          <div className="card-foot">
            Showing the first {LIMIT} of {filtered.length} matches. The report embeds a bounded
            sample by design; narrow the filter to reach the rest.
          </div>
        )}
      </Card>

      <Explainer>
        Three encodings are scanned independently. A UTF-16 string is not silently split into
        one-character ASCII “strings”, which is why this list is readable on Windows binaries where
        a naive extractor is not.
      </Explainer>
    </div>
  );
}

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { Report, WorkbenchEntry } from "./types";
import { GRADE_ORDER } from "./types";
import { analyzePath, demo, isDesktop, onFileDrop, pickFiles, revealInFolder } from "./lib/api";
import { formatBytes, gradeColor, relativeTime, shortHash } from "./lib/format";
import { BrandMark, IconAlert, IconLayers, IconPlus, IconSearch, IconTrash, IconX } from "./components/Icons";
import { Badge, GradeDot } from "./components/Visuals";
import { SearchInput } from "./components/Primitives";
import { OverviewView } from "./views/Overview";
import { StructureView } from "./views/Structure";
import { ImportsView, StringsView } from "./views/Tables";
import { AttackView, IndicatorsView } from "./views/Indicators";
import { FindingsView } from "./views/Findings";

type TabId =
  | "overview"
  | "structure"
  | "imports"
  | "strings"
  | "indicators"
  | "attack"
  | "findings";

interface TabDef {
  id: TabId;
  label: string;
  count?: (report: Report) => number;
}

const TABS: TabDef[] = [
  { id: "overview", label: "Overview" },
  { id: "structure", label: "Structure", count: (r) => r.image.sections.length },
  { id: "imports", label: "Imports", count: (r) => r.image.imports.length },
  { id: "strings", label: "Strings", count: (r) => r.string_stats.total },
  { id: "indicators", label: "Indicators", count: (r) => r.indicators.indicators.length },
  { id: "attack", label: "ATT&CK", count: (r) => r.techniques.length },
  { id: "findings", label: "Findings", count: (r) => r.findings.length },
];

/** The app's own version, independent of whatever a report was produced with. */
const APP_VERSION = "0.1.0";

interface Toast {
  id: number;
  message: string;
  error?: boolean;
}

export default function App() {
  const desktop = isDesktop();

  // In the desktop shell the workbench starts empty: showing a synthetic sample
  // as if the user had opened it is a lie that costs trust on first launch. The
  // demo entry exists only in the browser preview, where there is no filesystem
  // and an empty window would teach a visitor nothing.
  const [entries, setEntries] = useState<WorkbenchEntry[]>(() =>
    desktop ? [] : [{ id: "demo", report: demo(), addedAt: Date.now(), demo: true }],
  );
  const [activeId, setActiveId] = useState<string | null>(desktop ? null : "demo");
  const [tab, setTab] = useState<TabId>("overview");
  const [sampleFilter, setSampleFilter] = useState("");
  const [busy, setBusy] = useState(false);
  const [dragHot, setDragHot] = useState(false);
  const [toasts, setToasts] = useState<Toast[]>([]);

  const toastSeq = useRef(0);
  const entrySeq = useRef(0);
  const searchRef = useRef<HTMLInputElement>(null);
  const tabListRef = useRef<HTMLDivElement>(null);

  const nextId = useCallback(() => {
    entrySeq.current += 1;
    return `e${entrySeq.current}`;
  }, []);

  /**
   * Resolve the active entry.
   *
   * The previous implementation fell back to `entries[0]`, while the sidebar
   * rendered a *sorted* list — so the highlighted row and the displayed report
   * could be different files. Falling back through the same sorted order keeps
   * the two in agreement.
   */
  const sorted = useMemo(
    () =>
      [...entries].sort(
        (a, b) => GRADE_ORDER[b.report.score.grade] - GRADE_ORDER[a.report.score.grade],
      ),
    [entries],
  );

  const active = useMemo(() => {
    if (entries.length === 0) return null;
    return entries.find((entry) => entry.id === activeId) ?? sorted[0] ?? null;
  }, [entries, activeId, sorted]);

  const pushToast = useCallback((message: string, error = false) => {
    toastSeq.current += 1;
    const id = toastSeq.current;
    setToasts((current) => [...current, { id, message, error }]);
    window.setTimeout(
      () => setToasts((current) => current.filter((toast) => toast.id !== id)),
      error ? 9000 : 3200,
    );
  }, []);

  const ingest = useCallback(
    async (paths: string[]) => {
      if (!desktop) {
        pushToast(
          "Importing needs the desktop app. This browser preview runs on a bundled report and cannot read your files.",
          true,
        );
        return;
      }
      if (paths.length === 0) return;

      setBusy(true);
      let focusId: string | null = null;

      for (const path of paths) {
        try {
          const report = await analyzePath(path);
          const id = nextId();
          focusId = id;
          setEntries((current) => {
            const existing = current.find(
              (entry) => entry.report.artefact.sha256 === report.artefact.sha256,
            );
            if (existing) {
              // Re-analysing the same bytes refreshes the report in place and
              // keeps the existing id, so the selection does not jump to a row
              // that no longer exists.
              focusId = existing.id;
              return current.map((entry) =>
                entry.id === existing.id ? { ...entry, report, addedAt: Date.now() } : entry,
              );
            }
            return [...current, { id, report, addedAt: Date.now() }];
          });
        } catch (error) {
          const message = error instanceof Error ? error.message : String(error);
          pushToast(`Could not analyse ${path}: ${message}`, true);
        }
      }

      setBusy(false);
      if (focusId) {
        setActiveId(focusId);
        setTab("overview");
      }
    },
    [desktop, nextId, pushToast],
  );

  const handlePick = useCallback(async () => {
    try {
      await ingest(await pickFiles());
    } catch (error) {
      pushToast(error instanceof Error ? error.message : String(error), true);
    }
  }, [ingest, pushToast]);

  const removeEntry = useCallback(
    (id: string) => {
      setEntries((current) => {
        const next = current.filter((entry) => entry.id !== id);
        if (activeId === id) {
          setActiveId(next[0]?.id ?? null);
        }
        return next;
      });
    },
    [activeId],
  );

  // Drag and drop is the primary way files arrive; the button is the fallback.
  useEffect(() => {
    if (!desktop) return;
    const stop = onFileDrop((paths) => {
      setDragHot(false);
      void ingest(paths);
    });

    const onOver = (event: DragEvent) => {
      event.preventDefault();
      setDragHot(true);
    };
    const onLeave = (event: DragEvent) => {
      // Only clear when the pointer leaves the window, not when it crosses an
      // element boundary inside it.
      if (event.relatedTarget === null) setDragHot(false);
    };
    window.addEventListener("dragover", onOver);
    window.addEventListener("dragleave", onLeave);
    window.addEventListener("drop", () => setDragHot(false));
    return () => {
      stop();
      window.removeEventListener("dragover", onOver);
      window.removeEventListener("dragleave", onLeave);
    };
  }, [desktop, ingest]);

  // Keyboard: the whole workbench is operable without a mouse.
  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      const meta = event.ctrlKey || event.metaKey;

      if (meta && event.key.toLowerCase() === "o") {
        event.preventDefault();
        void handlePick();
        return;
      }
      if (meta && event.key.toLowerCase() === "k") {
        event.preventDefault();
        searchRef.current?.focus();
        searchRef.current?.select();
        return;
      }
      // Alt+1..7 or plain 1..7 when focus is not in a text field.
      const target = event.target as HTMLElement | null;
      const typing =
        target instanceof HTMLInputElement ||
        target instanceof HTMLTextAreaElement ||
        target?.isContentEditable === true;
      if (!meta && !typing && /^[1-7]$/.test(event.key) && active) {
        const index = Number(event.key) - 1;
        const definition = TABS[index];
        if (definition) setTab(definition.id);
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [active, handlePick]);

  const filteredEntries = useMemo(() => {
    const needle = sampleFilter.trim().toLowerCase();
    if (!needle) return sorted;
    return sorted.filter(
      (entry) =>
        entry.report.artefact.name.toLowerCase().includes(needle) ||
        entry.report.artefact.sha256.startsWith(needle),
    );
  }, [sorted, sampleFilter]);

  const worst = useMemo(() => {
    if (entries.length === 0) return null;
    return entries.reduce(
      (worstSoFar, entry) =>
        GRADE_ORDER[entry.report.score.grade] > GRADE_ORDER[worstSoFar]
          ? entry.report.score.grade
          : worstSoFar,
      "clean" as Report["score"]["grade"],
    );
  }, [entries]);

  return (
    <div className="app">
      <a className="skip-link" href="#report-body">
        Skip to report
      </a>

      <header className="topbar">
        <div className="brand">
          <BrandMark className="brand-mark" />
          <span className="brand-name">Assay</span>
          <span className="brand-version">v{APP_VERSION}</span>
          {!desktop && <span className="mode-chip demo">demo</span>}
        </div>

        <SearchInput
          inputRef={searchRef}
          value={sampleFilter}
          onChange={setSampleFilter}
          placeholder="Filter samples by name or SHA-256…"
          label="Filter the workbench"
        />

        <div className="topbar-spacer" />

        {worst && (
          <span className="topbar-worst">
            worst
            <Badge level={worst}>{worst}</Badge>
          </span>
        )}

        <button
          type="button"
          className="btn primary"
          onClick={handlePick}
          disabled={busy || !desktop}
          title={desktop ? "Import artefacts (Ctrl+O)" : "Available in the desktop app"}
        >
          {busy ? <span className="spinner" /> : <IconPlus size={13} />}
          {busy ? "Analysing" : "Import"}
        </button>
      </header>

      <aside className="sidebar">
        <div className="sidebar-head">
          <span className="sidebar-title">Workbench</span>
          <span className="sidebar-count">{entries.length}</span>
        </div>

        <div className="sample-list">
          {filteredEntries.map((entry) => {
            const report = entry.report;
            const isActive = active?.id === entry.id;
            return (
              <div key={entry.id} className={`sample-item${isActive ? " active" : ""}`}>
                <button
                  type="button"
                  className="sample-main"
                  onClick={() => setActiveId(entry.id)}
                  onDoubleClick={() => {
                    if (desktop && !entry.demo) void revealInFolder(report.artefact.path);
                  }}
                  aria-current={isActive}
                  title={desktop && !entry.demo ? `${report.artefact.path} — double-click to reveal` : report.artefact.name}
                >
                  <span className="sample-row">
                    <GradeDot grade={report.score.grade} />
                    <span className="sample-name">{report.artefact.name}</span>
                  </span>
                  <span className="sample-meta">
                    <span>{report.image.format}</span>
                    <span>{formatBytes(report.artefact.size)}</span>
                    <span className="sample-score" style={{ color: gradeColor(report.score.grade) }}>
                      {report.score.score}
                    </span>
                  </span>
                  <span className="sample-meta" style={{ marginTop: 2 }}>
                    <span>{relativeTime(entry.addedAt)}</span>
                    <span className="truncate" style={{ maxWidth: 140 }}>
                      {shortHash(report.artefact.sha256, 5)}
                    </span>
                  </span>
                </button>
                {!entry.demo && (
                  <button
                    type="button"
                    className="sample-remove"
                    onClick={() => removeEntry(entry.id)}
                    aria-label={`Remove ${report.artefact.name} from the workbench`}
                    title="Remove from workbench"
                  >
                    <IconX size={10} strokeWidth={2.2} />
                  </button>
                )}
              </div>
            );
          })}

          {filteredEntries.length === 0 && entries.length > 0 && (
            <div className="sidebar-empty">No sample matches the filter.</div>
          )}

          {entries.length === 0 && (
            <div className="sidebar-empty">
              Nothing analysed yet.
              <br />
              Drop a file anywhere in this window.
            </div>
          )}
        </div>

        <div className={`dropzone${dragHot ? " hot" : ""}`}>
          {desktop ? (
            <>
              <strong>Drop files to analyse</strong>
              PE · ELF · Mach-O · packages · scripts
            </>
          ) : (
            <>
              <strong>Browser preview</strong>
              Import is disabled outside the desktop app
            </>
          )}
        </div>
      </aside>

      <main className="main" id="report-body">
        {!active ? (
          <div className="empty-state">
            <IconLayers className="empty-mark" size={52} />
            <h2>Nothing analysed yet</h2>
            <p>
              Drop a binary, package or script anywhere in this window. Assay parses the container,
              infers capability from the import surface, and scores the result — without executing
              the file and without touching the network.
            </p>
            <div className="row" style={{ gap: 14, marginTop: 4, flexWrap: "wrap", justifyContent: "center" }}>
              <span className="dim" style={{ fontSize: "var(--text-xs)" }}>
                <kbd>Ctrl</kbd> <kbd>O</kbd> import
              </span>
              <span className="dim" style={{ fontSize: "var(--text-xs)" }}>
                <kbd>Ctrl</kbd> <kbd>K</kbd> filter
              </span>
              <span className="dim" style={{ fontSize: "var(--text-xs)" }}>
                <kbd>1</kbd>–<kbd>7</kbd> switch tabs
              </span>
            </div>
          </div>
        ) : (
          <>
            <div className="report-head">
              <div className="report-title-row">
                <div className="report-identity">
                  <div className="report-name">
                    <span className="report-filename" title={active.report.artefact.path}>
                      {active.report.artefact.name}
                    </span>
                    <Badge level={active.report.score.grade}>
                      {active.report.score.grade} {active.report.score.score}
                    </Badge>
                    <span className="chip">{active.report.image.format}</span>
                    <span className="chip">{active.report.image.arch}</span>
                    {active.report.image.bitness > 0 && (
                      <span className="chip">{active.report.image.bitness}-bit</span>
                    )}
                  </div>
                  <div className="report-hashes">
                    <span className="hash-item">
                      <span className="hash-label">SHA-256</span>
                      <span className="hash-value" title={active.report.artefact.sha256}>
                        {active.report.artefact.sha256}
                      </span>
                    </span>
                    <span
                      className="hash-item"
                      title="SSDeep-compatible CTPH, for family clustering"
                    >
                      <span className="hash-label">fuzzy</span>
                      <span className="hash-value">{active.report.artefact.fuzzy || "—"}</span>
                    </span>
                  </div>
                </div>
                <div className="report-facts">
                  <span className="chip">{formatBytes(active.report.artefact.size)}</span>
                  <span className="chip">{active.report.timing.total_ms} ms</span>
                  {desktop && !active.demo && (
                    <button
                      type="button"
                      className="icon-btn"
                      onClick={() => void revealInFolder(active.report.artefact.path)}
                      title="Show in file manager"
                      aria-label="Show file in file manager"
                    >
                      <IconSearch size={13} />
                    </button>
                  )}
                  {!active.demo && (
                    <button
                      type="button"
                      className="icon-btn"
                      onClick={() => removeEntry(active.id)}
                      title="Remove from workbench"
                      aria-label="Remove from workbench"
                    >
                      <IconTrash size={13} />
                    </button>
                  )}
                </div>
              </div>

              <p className="verdict">{active.report.score.verdict}</p>

              <div className="tabs" role="tablist" aria-label="Report sections" ref={tabListRef}>
                {TABS.map((definition) => {
                  const count = definition.count?.(active.report);
                  const isActive = tab === definition.id;
                  return (
                    <button
                      type="button"
                      key={definition.id}
                      role="tab"
                      id={`tab-${definition.id}`}
                      aria-selected={isActive}
                      aria-controls={`panel-${definition.id}`}
                      tabIndex={isActive ? 0 : -1}
                      className="tab"
                      onClick={() => setTab(definition.id)}
                      onKeyDown={(event) => {
                        // Arrow-key navigation between tabs, as the ARIA pattern
                        // specifies; Home/End jump to the ends.
                        const index = TABS.findIndex((t) => t.id === definition.id);
                        let nextIndex: number | null = null;
                        if (event.key === "ArrowRight") nextIndex = (index + 1) % TABS.length;
                        if (event.key === "ArrowLeft") nextIndex = (index - 1 + TABS.length) % TABS.length;
                        if (event.key === "Home") nextIndex = 0;
                        if (event.key === "End") nextIndex = TABS.length - 1;
                        if (nextIndex !== null) {
                          event.preventDefault();
                          const next = TABS[nextIndex];
                          if (next) {
                            setTab(next.id);
                            const button = tabListRef.current?.querySelector<HTMLButtonElement>(
                              `#tab-${next.id}`,
                            );
                            button?.focus();
                          }
                        }
                      }}
                    >
                      {definition.label}
                      {count !== undefined && count > 0 && (
                        <span className="tab-badge">{count > 999 ? "999+" : count}</span>
                      )}
                    </button>
                  );
                })}
              </div>
            </div>

            <div
              className="tab-body"
              role="tabpanel"
              id={`panel-${tab}`}
              aria-labelledby={`tab-${tab}`}
            >
              {tab === "overview" && <OverviewView report={active.report} />}
              {tab === "structure" && <StructureView report={active.report} />}
              {tab === "imports" && <ImportsView report={active.report} />}
              {tab === "strings" && <StringsView report={active.report} />}
              {tab === "indicators" && <IndicatorsView report={active.report} />}
              {tab === "attack" && <AttackView report={active.report} />}
              {tab === "findings" && <FindingsView report={active.report} />}
            </div>
          </>
        )}
      </main>

      <div className="toast-stack" role="status" aria-live="polite">
        {toasts.map((toast) => (
          <div className={`toast${toast.error ? " error" : ""}`} key={toast.id}>
            {toast.error && <IconAlert size={13} style={{ flex: "none", marginTop: 2 }} />}
            <span>{toast.message}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

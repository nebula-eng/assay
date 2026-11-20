import { useId } from "react";
import { IconSearch, IconX } from "./Icons";

/**
 * Search field.
 *
 * Extracted because the same control appeared five times with three different
 * widths and two different focus treatments. One component means one behaviour:
 * a clear button appears only when there is something to clear, and Escape
 * restores the unfiltered view.
 */
export function SearchInput({
  value,
  onChange,
  placeholder,
  label,
  autoFocus,
  inputRef,
}: {
  value: string;
  onChange: (next: string) => void;
  placeholder: string;
  label: string;
  autoFocus?: boolean;
  inputRef?: React.Ref<HTMLInputElement>;
}) {
  const id = useId();
  return (
    <div className="search">
      <IconSearch className="search-icon" />
      <input
        ref={inputRef}
        id={id}
        type="search"
        value={value}
        onChange={(event) => onChange(event.target.value)}
        onKeyDown={(event) => {
          if (event.key === "Escape" && value !== "") {
            event.stopPropagation();
            onChange("");
          }
        }}
        placeholder={placeholder}
        aria-label={label}
        autoComplete="off"
        autoCorrect="off"
        spellCheck={false}
        autoFocus={autoFocus}
      />
      {value !== "" && (
        <button
          type="button"
          className="search-clear"
          onClick={() => onChange("")}
          aria-label="Clear filter"
          title="Clear filter"
        >
          <IconX size={11} />
        </button>
      )}
    </div>
  );
}

export type SegmentedOption<T extends string> = {
  value: T;
  label: string;
  count?: number;
};

/**
 * Segmented control.
 *
 * Used for every category filter in the app. `aria-pressed` rather than a
 * class-only state so a screen reader can report the selection; the visual
 * style keys off the same attribute.
 */
export function Segmented<T extends string>({
  options,
  value,
  onChange,
  label,
}: {
  options: SegmentedOption<T>[];
  value: T;
  onChange: (next: T) => void;
  label: string;
}) {
  return (
    <div className="segmented" role="group" aria-label={label}>
      {options.map((option) => (
        <button
          key={option.value}
          type="button"
          aria-pressed={value === option.value}
          onClick={() => onChange(option.value)}
        >
          {option.label}
          {option.count !== undefined && (
            <span className="mono" style={{ marginLeft: 4, opacity: 0.7 }}>
              {option.count}
            </span>
          )}
        </button>
      ))}
    </div>
  );
}

/** Labelled checkbox. */
export function Check({
  checked,
  onChange,
  children,
}: {
  checked: boolean;
  onChange: (next: boolean) => void;
  children: React.ReactNode;
}) {
  return (
    <label className="check">
      <input
        type="checkbox"
        checked={checked}
        onChange={(event) => onChange(event.target.checked)}
      />
      {children}
    </label>
  );
}

/** Card with an optional right-aligned subtitle in the header. */
export function Card({
  title,
  sub,
  children,
  bodyClass,
  actions,
}: {
  title: React.ReactNode;
  sub?: React.ReactNode;
  children: React.ReactNode;
  bodyClass?: string;
  actions?: React.ReactNode;
}) {
  return (
    <section className="card">
      <header className="card-head">
        <h2 className="card-title">{title}</h2>
        {sub !== undefined && <span className="card-sub">{sub}</span>}
        {actions}
      </header>
      <div className={bodyClass ? `card-body ${bodyClass}` : "card-body"}>{children}</div>
    </section>
  );
}

/** Metric tile. `text` switches to the proportional type variant. */
export function Metric({
  label,
  value,
  unit,
  hint,
  tone,
  children,
}: {
  label: string;
  value: React.ReactNode;
  unit?: string;
  hint?: React.ReactNode;
  tone?: string;
  children?: React.ReactNode;
}) {
  const isText = typeof value === "string" && !/^[\d.,]+$/.test(value);
  return (
    <div className="metric">
      <div className="metric-label">{label}</div>
      <div
        className={`metric-value${isText ? " is-text" : ""}`}
        style={tone ? { color: tone } : undefined}
      >
        {value}
        {unit && <span className="metric-unit">{unit}</span>}
      </div>
      {hint !== undefined && <div className="metric-hint" title={typeof hint === "string" ? hint : undefined}>{hint}</div>}
      {children}
    </div>
  );
}

/** Definition list from label/value pairs. */
export function KeyValues({ rows }: { rows: [string, React.ReactNode][] }) {
  return (
    <dl className="kv">
      {rows.map(([label, value], index) => (
        <div key={`${label}-${index}`} style={{ display: "contents" }}>
          <dt>{label}</dt>
          <dd>{value}</dd>
        </div>
      ))}
    </dl>
  );
}

/** Empty state inside a card. */
export function Empty({ children }: { children: React.ReactNode }) {
  return <p className="empty-row">{children}</p>;
}

/** Explanatory paragraph below a view. Used instead of ad-hoc styled divs. */
export function Explainer({ children }: { children: React.ReactNode }) {
  return <p className="explainer">{children}</p>;
}

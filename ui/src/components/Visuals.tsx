import type { Factor, Grade, Severity } from "../types";
import { gradeColor, severityColor } from "../lib/format";
import { IconSeverity } from "./Icons";

/**
 * Severity / grade pill.
 *
 * Renders the level name in small caps. `children` lets a caller show adjacent
 * context (`high · 55`) without a second element, which keeps the header from
 * filling with loose text.
 */
export function Badge({
  level,
  children,
  icon,
}: {
  level: Grade | Severity;
  children?: React.ReactNode;
  icon?: boolean;
}) {
  return (
    <span className={`badge ${level}`}>
      {icon && <IconSeverity level={level as Severity} size={10} strokeWidth={2.2} />}
      {children ?? level}
    </span>
  );
}

/**
 * Circular gauge for the composite score.
 *
 * The arc is drawn with `stroke-dasharray` so the animation is a single CSS
 * property and the geometry stays exact at any size. A faint track behind the
 * arc keeps the scale readable when the score is low.
 *
 * `role="img"` and the label sit on the *outer* element: the previous version
 * put them on an empty sibling div, which produced a nameless graphic followed
 * by an unlabelled one.
 */
export function ScoreRing({
  score,
  grade,
  size = 116,
  thickness = 8,
}: {
  score: number;
  grade: Grade;
  size?: number;
  thickness?: number;
}) {
  const radius = (size - thickness) / 2;
  const circumference = 2 * Math.PI * radius;
  // 25% of the circle is left open at the bottom so the shape reads as a gauge
  // rather than a pie chart that happens to be nearly empty.
  const sweep = 0.75;
  const arc = circumference * sweep;
  const filled = (arc * Math.min(100, Math.max(0, score))) / 100;
  const colour = gradeColor(grade);

  return (
    <div
      className="score-ring"
      style={{ width: size, height: size, position: "relative" }}
      role="img"
      aria-label={`Composite risk score ${score} out of 100, graded ${grade}`}
    >
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} aria-hidden="true">
        <g transform={`rotate(135 ${size / 2} ${size / 2})`}>
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke="var(--surface-3)"
            strokeWidth={thickness}
            strokeDasharray={`${arc} ${circumference}`}
            strokeLinecap="round"
          />
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke={colour}
            strokeWidth={thickness}
            strokeDasharray={`${filled} ${circumference}`}
            strokeLinecap="round"
            style={{ transition: "stroke-dasharray var(--transition-slow)" }}
          />
        </g>
      </svg>
      <div
        style={{
          position: "absolute",
          inset: 0,
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          gap: 0,
        }}
      >
        <div
          style={{
            fontFamily: "var(--font-mono)",
            fontSize: size * 0.29,
            fontWeight: 640,
            lineHeight: 1,
            color: colour,
            letterSpacing: "-0.03em",
            fontVariantNumeric: "tabular-nums",
          }}
        >
          {score}
        </div>
        <div
          style={{
            fontSize: 10,
            fontWeight: 640,
            letterSpacing: "0.14em",
            textTransform: "uppercase",
            color: "var(--text-faint)",
            marginTop: 2,
          }}
        >
          of 100
        </div>
      </div>
    </div>
  );
}

/**
 * One horizontal bar per scoring factor.
 *
 * The bar is normalised against the factor's own ceiling, not against 100, so a
 * factor that is maxed out reads as maxed out even when its ceiling is small.
 *
 * Each row is a `<button>` that reveals the evidence behind the score. The
 * engine has always produced `factor.evidence`; the previous UI never showed
 * it, which meant the "every point is attributable" claim was unverifiable from
 * the interface.
 */
export function FactorBars({
  factors,
  selected,
  onSelect,
}: {
  factors: Factor[];
  selected?: string | null;
  onSelect?: (key: string | null) => void;
}) {
  if (factors.length === 0) {
    return <p className="dim" style={{ margin: 0, fontSize: "var(--text-sm)" }}>No scoring factors recorded.</p>;
  }

  return (
    <div className="factor-list">
      {factors.map((factor) => {
        const ratio = factor.max_points > 0 ? Math.min(1, factor.points / factor.max_points) : 0;
        const colour =
          ratio >= 0.8
            ? "var(--critical)"
            : ratio >= 0.5
              ? "var(--high)"
              : ratio > 0
                ? "var(--medium)"
                : "var(--surface-4)";
        const isSelected = selected === factor.key;
        const interactive = Boolean(onSelect) && factor.points > 0;

        const content = (
          <>
            <span className="factor-name" title={factor.name}>
              {factor.name}
            </span>
            <span className="factor-track">
              <span
                className="factor-fill"
                style={{ width: `${Math.round(ratio * 100)}%`, background: colour, display: "block" }}
              />
            </span>
            <span className="factor-points">
              {factor.points}/{factor.max_points}
            </span>
          </>
        );

        if (!interactive) {
          return (
            <div className="factor" key={factor.key}>
              {content}
            </div>
          );
        }

        return (
          <button
            type="button"
            className="factor"
            key={factor.key}
            onClick={() => onSelect?.(isSelected ? null : factor.key)}
            aria-expanded={isSelected}
            style={{
              width: "100%",
              background: isSelected ? "var(--surface-2)" : "transparent",
              borderRadius: "var(--radius-sm)",
              padding: isSelected ? "3px 6px" : "3px 6px",
              margin: "0 -6px",
              cursor: "pointer",
            }}
            title={`${factor.detail} — click for evidence`}
          >
            {content}
          </button>
        );
      })}
    </div>
  );
}

/** Small dot used in the sample list to encode grade without a word. */
export function GradeDot({ grade }: { grade: Grade }) {
  return <span className="dot" style={{ background: gradeColor(grade) }} aria-hidden="true" />;
}

/** Coloured rail for a finding. */
export function SeverityRail({ severity }: { severity: Severity }) {
  return (
    <div
      className="finding-rail"
      style={{ background: severityColor(severity) }}
      aria-hidden="true"
    />
  );
}

/**
 * Confidence meter.
 *
 * Deliberately *not* coloured by risk band. Confidence answers "how sure are
 * we", severity answers "how bad is it"; painting a 95%-certain low-impact
 * observation in critical red collapses the two axes and makes every populated
 * panel look alarming. The bar is brand-coloured and the number carries the
 * precision.
 */
export function ConfidenceMeter({ value }: { value: number }) {
  const percent = Math.round(Math.min(1, Math.max(0, value)) * 100);
  return (
    <div className="technique-conf" aria-label={`${percent}% confidence`}>
      <span className="conf-track">
        <span className="conf-fill" style={{ width: `${percent}%`, display: "block" }} />
      </span>
      <span className="conf-value">{percent}%</span>
    </div>
  );
}

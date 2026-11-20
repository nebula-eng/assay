import type { EntropyProfile } from "../types";
import { entropyColor, fixed } from "../lib/format";

/**
 * Entropy bands, defined once and used by both the chart and its legend.
 *
 * The previous version had the legend hard-coded in JSX while the bar colours
 * came from `entropyColor`, and the two disagreed: the 3.0–5.0 range rendered
 * blue but the legend lumped it into "structured" grey. Deriving both from one
 * table makes that class of bug impossible.
 */
const BANDS: { min: number; label: string; colour: string }[] = [
  { min: 7.6, label: "encrypted", colour: "var(--critical)" },
  { min: 7.2, label: "dense or packed", colour: "var(--high)" },
  { min: 5.0, label: "compiled code", colour: "var(--medium)" },
  { min: 3.0, label: "structured data", colour: "var(--low)" },
  { min: 0, label: "sparse or padded", colour: "var(--text-faint)" },
];

/**
 * Windowed entropy profile.
 *
 * Why a bar per window rather than a smoothed line: the question this chart
 * answers is "is there a *contiguous region* of high entropy", and bars keep the
 * boundaries honest. A spline would interpolate across the boundary and make a
 * 4 KiB packed stub look like a gradual slope.
 *
 * The y-axis is fixed at 0–8 bits/byte rather than auto-scaled. Auto-scaling
 * would make a file that peaks at 5.0 look identical to one that peaks at 7.9,
 * which inverts the only judgement the chart exists to support.
 */
export function EntropyChart({
  profile,
  height = 132,
  fileSize,
}: {
  profile: EntropyProfile;
  height?: number;
  /** Total artefact size, used to label the x-axis in file offsets. */
  fileSize?: number;
}) {
  const windows = profile.windows;
  if (windows.length === 0) {
    return <p className="dim" style={{ margin: 0 }}>No entropy windows recorded for this artefact.</p>;
  }

  // One viewBox unit per window horizontally, so bars never overlap and never
  // leave a gap regardless of how many the engine sampled.
  const width = windows.length;
  const peak = windows.reduce(
    (best, window) => (window.entropy > best.entropy ? window : best),
    windows[0]!,
  );
  const total = fileSize ?? windows[windows.length - 1]!.offset + windows[windows.length - 1]!.length;

  const xTicks = [0, 0.5, 1].map((fraction) => ({
    fraction,
    offset: Math.round(total * fraction),
  }));

  return (
    <div>
      <svg
        className="entropy-chart"
        viewBox={`0 0 ${width} 100`}
        preserveAspectRatio="none"
        style={{ height }}
        role="img"
        aria-label={`Entropy across ${windows.length} windows; peak ${fixed(profile.peak_entropy)} bits per byte at offset ${peak.offset}`}
      >
        {BANDS.filter((band) => band.min > 0).map((band) => (
          <line
            key={band.min}
            x1={0}
            x2={width}
            y1={100 - (band.min / 8) * 100}
            y2={100 - (band.min / 8) * 100}
            stroke="var(--border-strong)"
            strokeWidth={1}
            strokeDasharray="3 4"
            vectorEffect="non-scaling-stroke"
          />
        ))}
        {windows.map((window, index) => {
          const barHeight = Math.max((window.entropy / 8) * 100, 0.5);
          return (
            <rect
              key={`${window.offset}-${index}`}
              x={index}
              y={100 - barHeight}
              width={1}
              height={barHeight}
              fill={entropyColor(window.entropy)}
              opacity={0.9}
            >
              <title>
                {`0x${window.offset.toString(16)} · ${fixed(window.entropy)} bits/byte · ${window.length} bytes`}
              </title>
            </rect>
          );
        })}
      </svg>

      {/* X axis: file offsets, so a spike can be located without hovering. */}
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          marginTop: 4,
          fontFamily: "var(--font-mono)",
          fontSize: 9.5,
          color: "var(--text-faint)",
        }}
        aria-hidden="true"
      >
        {xTicks.map((tick) => (
          <span key={tick.fraction}>0x{tick.offset.toString(16)}</span>
        ))}
      </div>

      <div className="legend">
        {/* Descending thresholds read left-to-right as "worse to better". */}
        {[...BANDS].reverse().map((band) => (
          <span className="legend-item" key={band.label}>
            <span className="legend-swatch" style={{ background: band.colour }} />
            {band.min > 0 ? `≥ ${band.min.toFixed(1)} ` : "< 3.0 "}
            {band.label}
          </span>
        ))}
        <span className="legend-item" style={{ marginLeft: "auto" }}>
          peak{" "}
          <b style={{ color: entropyColor(profile.peak_entropy) }}>
            {fixed(profile.peak_entropy)}
          </b>
          {" at "}
          <span className="mono">0x{peak.offset.toString(16)}</span>
        </span>
      </div>
    </div>
  );
}

/**
 * Compact stacked bar showing how much of the file sits above the high-entropy
 * threshold. Used in the metric tile, where the full profile is too wide.
 */
export function EntropyMeter({ fraction }: { fraction: number }) {
  const percent = Math.min(100, Math.max(0, fraction * 100));
  const colour =
    percent >= 60 ? "var(--critical)" : percent >= 30 ? "var(--high)" : "var(--medium)";
  return (
    <div
      style={{
        height: 4,
        borderRadius: 2,
        background: "var(--surface-3)",
        overflow: "hidden",
        marginTop: 8,
      }}
      aria-hidden="true"
    >
      <div style={{ width: `${percent}%`, height: "100%", background: colour }} />
    </div>
  );
}

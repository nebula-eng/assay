/**
 * Inline SVG icon set.
 *
 * Hand-drawn rather than pulled from an icon package: the whole set is under
 * 2.5 KB, inherits `currentColor`, and stays crisp at the 12–16 px sizes this
 * UI actually uses. Every path is stroke-only so optical weight can be tuned
 * per call with `strokeWidth`.
 */

interface IconProps {
  className?: string;
  size?: number;
  style?: React.CSSProperties;
  strokeWidth?: number;
}

function Svg({
  children,
  className,
  size = 16,
  style,
  strokeWidth = 1.7,
  viewBox = "0 0 24 24",
}: IconProps & { children: React.ReactNode; viewBox?: string }) {
  return (
    <svg
      className={className}
      style={style}
      width={size}
      height={size}
      viewBox={viewBox}
      fill="none"
      stroke="currentColor"
      strokeWidth={strokeWidth}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      {children}
    </svg>
  );
}

export function IconSearch(props: IconProps) {
  return (
    <Svg {...props}>
      <circle cx="11" cy="11" r="7" />
      <path d="m20 20-3.5-3.5" />
    </Svg>
  );
}

export function IconX(props: IconProps) {
  return (
    <Svg {...props}>
      <path d="M6 6l12 12M18 6L6 18" />
    </Svg>
  );
}

export function IconPlus(props: IconProps) {
  return (
    <Svg {...props}>
      <path d="M12 5v14M5 12h14" />
    </Svg>
  );
}

export function IconTrash(props: IconProps) {
  return (
    <Svg {...props}>
      <path d="M4 7h16M10 4h4M6 7l1 13h10l1-13" />
      <path d="M10 11v6M14 11v6" />
    </Svg>
  );
}

export function IconLayers(props: IconProps) {
  return (
    <Svg {...props}>
      <path d="m12 3 9 5-9 5-9-5 9-5Z" />
      <path d="m3 13 9 5 9-5" />
    </Svg>
  );
}

export function IconAlert(props: IconProps) {
  return (
    <Svg {...props}>
      <path d="M12 4 3 20h18L12 4Z" />
      <path d="M12 10v4M12 17v.01" />
    </Svg>
  );
}

export function IconInfo(props: IconProps) {
  return (
    <Svg {...props}>
      <circle cx="12" cy="12" r="8.5" />
      <path d="M12 11v5M12 8v.01" />
    </Svg>
  );
}

export function IconChevron(props: IconProps) {
  return (
    <Svg {...props}>
      <path d="m9 6 6 6-6 6" />
    </Svg>
  );
}

export function IconCopy(props: IconProps) {
  return (
    <Svg {...props}>
      <rect x="9" y="9" width="11" height="11" rx="2" />
      <path d="M15 5H6a2 2 0 0 0-2 2v9" />
    </Svg>
  );
}

export function IconCheck(props: IconProps) {
  return (
    <Svg {...props}>
      <path d="m5 13 4 4L19 7" />
    </Svg>
  );
}

export function IconFolder(props: IconProps) {
  return (
    <Svg {...props}>
      <path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7Z" />
    </Svg>
  );
}

/**
 * Severity glyph.
 *
 * Shape carries the meaning and colour reinforces it, so the four levels remain
 * distinguishable for a reader who cannot separate red from orange: octagon /
 * triangle / filled circle / hollow circle.
 */
export function IconSeverity({
  level,
  ...props
}: IconProps & { level: "critical" | "high" | "medium" | "low" | "info" }) {
  switch (level) {
    case "critical":
      return (
        <Svg {...props}>
          <path d="M8 3h8l5 5v8l-5 5H8l-5-5V8l5-5Z" />
          <path d="M12 8v5M12 16v.01" />
        </Svg>
      );
    case "high":
      return (
        <Svg {...props}>
          <path d="M12 4 3 20h18L12 4Z" />
          <path d="M12 10v4M12 17v.01" />
        </Svg>
      );
    case "medium":
      return (
        <Svg {...props}>
          <circle cx="12" cy="12" r="8.5" />
          <path d="M12 8v4.5" />
          <circle cx="12" cy="15.5" r="0.9" fill="currentColor" stroke="none" />
        </Svg>
      );
    case "low":
      return (
        <Svg {...props}>
          <circle cx="12" cy="12" r="8.5" />
          <path d="M12 10.5v5" />
          <circle cx="12" cy="8" r="0.9" fill="currentColor" stroke="none" />
        </Svg>
      );
    default:
      return (
        <Svg {...props}>
          <circle cx="12" cy="12" r="8.5" />
          <path d="M12 11v5" />
          <circle cx="12" cy="8" r="0.9" fill="currentColor" stroke="none" />
        </Svg>
      );
  }
}

/** The brand mark: three offset laminae, echoing "layers of a binary". */
export function BrandMark({ className, size = 24 }: IconProps) {
  return (
    <svg
      className={className}
      width={size}
      height={size}
      viewBox="0 0 32 32"
      fill="none"
      aria-hidden="true"
      focusable="false"
    >
      <defs>
        <linearGradient
          id="assay-grad"
          x1="4"
          y1="4"
          x2="28"
          y2="28"
          gradientUnits="userSpaceOnUse"
        >
          <stop stopColor="var(--brand-from)" />
          <stop offset="1" stopColor="var(--brand-to)" />
        </linearGradient>
      </defs>
      <path
        d="M16 3 29 10.5 16 18 3 10.5 16 3Z"
        stroke="url(#assay-grad)"
        strokeWidth="1.7"
        strokeLinejoin="round"
      />
      <path
        d="M3 16.5 16 24l13-7.5"
        stroke="url(#assay-grad)"
        strokeWidth="1.7"
        strokeLinecap="round"
        strokeLinejoin="round"
        opacity="0.68"
      />
      <path
        d="M3 22 16 29.5 29 22"
        stroke="url(#assay-grad)"
        strokeWidth="1.7"
        strokeLinecap="round"
        strokeLinejoin="round"
        opacity="0.36"
      />
    </svg>
  );
}

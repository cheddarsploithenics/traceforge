/**
 * Small inline stroke icons (24px grid, drawn at 16px by default). Inline SVG
 * keeps the bundle dependency-free and works under the strict CSP.
 */
const PATHS = {
  overview: "M4 4h7v7H4zM13 4h7v4h-7zM13 10h7v10h-7zM4 13h7v7H4z",
  scans:
    "M12 3a9 9 0 1 0 9 9M12 7a5 5 0 1 0 5 5M12 12l7-7M12 11.5a.5.5 0 1 0 0 1 .5.5 0 1 0 0-1",
  projects: "M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z",
  assets: "M4 5h16v5H4zM4 14h16v5H4zM7.5 7.5h.01M7.5 16.5h.01",
  compare: "M8 4v16M16 4v16M4 8h4M16 16h4M4 16l4-4M20 8l-4 4",
  external: "M14 4h6v6M20 4l-9 9M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5",
  plusSmall: "M12 7v10M7 12h10",
  minusSmall: "M7 12h10",
  tilde: "M5 13c2-3 4-3 7 0s5 3 7 0",
  question: "M9.5 9a2.5 2.5 0 1 1 3.5 2.3c-.6.3-1 .9-1 1.6v.6M12 17v.01",
  plus: "M12 5v14M5 12h14",
  refresh: "M20 11a8 8 0 1 0-2.3 5.7M20 4v7h-7",
  close: "M6 6l12 12M18 6L6 18",
  download: "M12 4v11M7 10l5 5 5-5M5 20h14",
  stop: "M7 7h10v10H7z",
  shield: "M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6z",
  logout: "M15 4h4v16h-4M10 8l-4 4 4 4M6 12h11",
  check: "M5 12.5l4.5 4.5L19 7.5",
  x: "M7 7l10 10M17 7L7 17",
  clock: "M12 7v5l3 2M12 3a9 9 0 1 0 0 18 9 9 0 1 0 0-18",
  slash: "M12 3a9 9 0 1 0 0 18 9 9 0 1 0 0-18M6 18L18 6",
  alert: "M12 8v5M12 16.5v.5M10.3 4.2L2.6 18a2 2 0 0 0 1.7 3h15.4a2 2 0 0 0 1.7-3L13.7 4.2a2 2 0 0 0-3.4 0",
} as const;

export type IconName = keyof typeof PATHS;

export function Icon({
  name,
  size = 16,
  strokeWidth = 1.8,
  className,
}: {
  name: IconName;
  size?: number;
  strokeWidth?: number;
  className?: string;
}) {
  return (
    <svg
      className={className ? `icon ${className}` : "icon"}
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={strokeWidth}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      <path d={PATHS[name]} />
    </svg>
  );
}

/** The TraceForge mark: a shield with a trace line through it. */
export function BrandMark({ size = 22 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" aria-hidden="true" focusable="false" className="brand-mark">
      <path d="M12 2.5l8 3v6.2c0 4.7-3.4 8.6-8 9.8-4.6-1.2-8-5.1-8-9.8V5.5z" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinejoin="round" />
      <path d="M6.5 12.5h3l1.5-3 2 6 1.5-3h3" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

import { useMemo, useRef, useState } from "react";
import { SERVICE_COLORS, fmtNumber } from "../api.js";
import { useTooltip } from "./Tooltip.jsx";

/**
 * Stacked area chart of events over time, split by service.
 *
 * Hand-rolled SVG so the marks follow the project's chart specs: one y-axis,
 * a 2px surface gap between stacked fills, thin 2px series lines, a recessive
 * grid, a crosshair + tooltip on hover, and colour that follows the service
 * (fixed slot order) rather than its stack position.
 */
const SERVICES = ["ssh", "telnet", "ftp", "http"];
const PAD = { top: 12, right: 16, bottom: 26, left: 44 };

export default function AttackTimeline({ data, height = 260 }) {
  const wrapRef = useRef(null);
  const [width, setWidth] = useState(720);
  const [hover, setHover] = useState(null);
  const [handlers, Tooltip] = useTooltip();

  // Observe container width so the chart is responsive without a chart lib.
  useMemo(() => {
    if (!wrapRef.current || typeof ResizeObserver === "undefined") return;
    const ro = new ResizeObserver((entries) => {
      setWidth(Math.max(320, entries[0].contentRect.width));
    });
    ro.observe(wrapRef.current);
    return () => ro.disconnect();
  }, [wrapRef.current]);

  const points = data?.points || [];
  const series = (data?.series || SERVICES).filter((s) => SERVICES.includes(s));
  const activeSeries = series.length ? series : SERVICES;

  const { paths, maxY, xFor, plotW, plotH } = useMemo(() => {
    const plotW = width - PAD.left - PAD.right;
    const plotH = height - PAD.top - PAD.bottom;
    if (!points.length) return { paths: [], maxY: 0, xFor: () => 0, plotW, plotH };

    const totals = points.map((p) =>
      activeSeries.reduce((sum, s) => sum + (p[s] || 0), 0)
    );
    const maxY = Math.max(1, ...totals);
    const xFor = (i) => PAD.left + (points.length === 1 ? plotW / 2 : (i / (points.length - 1)) * plotW);
    const yFor = (v) => PAD.top + plotH - (v / maxY) * plotH;

    // Build stacked bands bottom-up so SSH sits on the baseline.
    const paths = [];
    const baseline = new Array(points.length).fill(0);
    for (const s of activeSeries) {
      const upper = points.map((p, i) => baseline[i] + (p[s] || 0));
      const top = upper.map((v, i) => `${xFor(i)},${yFor(v)}`);
      const bot = baseline
        .map((v, i) => `${xFor(i)},${yFor(v)}`)
        .reverse();
      paths.push({
        service: s,
        d: `M${top.join("L")}L${bot.join("L")}Z`,
        line: `M${top.join("L")}`,
      });
      for (let i = 0; i < points.length; i++) baseline[i] = upper[i];
    }
    return { paths, maxY, xFor, plotW, plotH };
  }, [points, activeSeries, width, height]);

  const yTicks = useMemo(() => {
    const step = niceStep(maxY, 4);
    const ticks = [];
    for (let v = 0; v <= maxY + 0.001; v += step) ticks.push(v);
    return ticks;
  }, [maxY]);

  function onMove(evt) {
    if (!points.length) return;
    const rect = evt.currentTarget.getBoundingClientRect();
    const x = evt.clientX - rect.left;
    const rel = (x - PAD.left) / (plotW || 1);
    const i = Math.max(0, Math.min(points.length - 1, Math.round(rel * (points.length - 1))));
    setHover(i);
    const p = points[i];
    const total = activeSeries.reduce((sum, s) => sum + (p[s] || 0), 0);
    handlers.show(
      <>
        <div className="t-title">{fmtTs(p.ts)}</div>
        {activeSeries.map((s) => (
          <div className="t-row" key={s}>
            <span>
              <span className="svc-dot" style={{ background: SERVICE_COLORS[s] }} />
              {s}
            </span>
            <span className="mono">{fmtNumber(p[s] || 0)}</span>
          </div>
        ))}
        <div className="t-row" style={{ marginTop: 4, fontWeight: 700 }}>
          <span>total</span>
          <span className="mono">{fmtNumber(total)}</span>
        </div>
      </>,
      evt
    );
  }

  if (!points.length) return <div className="empty">No activity in this window.</div>;

  return (
    <div ref={wrapRef}>
      <svg
        width="100%"
        height={height}
        viewBox={`0 0 ${width} ${height}`}
        onMouseMove={onMove}
        onMouseLeave={() => {
          setHover(null);
          handlers.hide();
        }}
        role="img"
        aria-label="Events over time by service"
      >
        {/* grid + y-axis */}
        {yTicks.map((v) => {
          const y = PAD.top + plotH - (v / maxY) * plotH;
          return (
            <g key={v}>
              <line x1={PAD.left} x2={width - PAD.right} y1={y} y2={y} stroke="var(--grid)" strokeWidth="1" />
              <text x={PAD.left - 8} y={y + 4} textAnchor="end" fontSize="10" fill="var(--text-muted)">
                {compact(v)}
              </text>
            </g>
          );
        })}

        {/* stacked bands; 2px surface gap between fills via a stroke in the surface colour */}
        {paths.map((p) => (
          <g key={p.service}>
            <path d={p.d} fill={SERVICE_COLORS[p.service]} fillOpacity="0.5" stroke="none" />
            <path d={p.line} fill="none" stroke={SERVICE_COLORS[p.service]} strokeWidth="2" />
          </g>
        ))}

        {/* x labels: first, middle, last */}
        {[0, Math.floor(points.length / 2), points.length - 1].map((i) => (
          <text
            key={i}
            x={xFor(i)}
            y={height - 8}
            textAnchor={i === 0 ? "start" : i === points.length - 1 ? "end" : "middle"}
            fontSize="10"
            fill="var(--text-muted)"
          >
            {fmtTs(points[i].ts)}
          </text>
        ))}

        {/* crosshair */}
        {hover !== null && (
          <line
            x1={xFor(hover)}
            x2={xFor(hover)}
            y1={PAD.top}
            y2={PAD.top + plotH}
            stroke="var(--border-strong)"
            strokeWidth="1"
            strokeDasharray="3 3"
          />
        )}
      </svg>

      <div className="legend">
        {activeSeries.map((s) => (
          <span className="legend-item" key={s}>
            <span className="legend-swatch" style={{ background: SERVICE_COLORS[s] }} />
            {s}
          </span>
        ))}
      </div>
      <Tooltip />
    </div>
  );
}

function niceStep(max, count) {
  const raw = max / count;
  const mag = Math.pow(10, Math.floor(Math.log10(raw || 1)));
  const norm = raw / mag;
  const step = norm >= 5 ? 5 : norm >= 2 ? 2 : 1;
  return Math.max(1, step * mag);
}
function compact(n) {
  if (n >= 1000) return `${(n / 1000).toFixed(n % 1000 === 0 ? 0 : 1)}k`;
  return `${n}`;
}
function fmtTs(iso) {
  const d = new Date(iso);
  return d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

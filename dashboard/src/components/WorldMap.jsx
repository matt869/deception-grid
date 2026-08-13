import { useMemo, useRef, useState } from "react";
import { classColor, fmtNumber, flag } from "../api.js";
import { useTooltip } from "./Tooltip.jsx";

/**
 * Geographic origin plot + ranked country list.
 *
 * There is no bundled topology (a real basemap needs a licensed dataset this
 * project does not ship), so this is an honest equirectangular scatter over a
 * graticule rather than a fake choropleth: each dot is one source at its
 * lat/long, coloured by classification and sized by threat score. The ranked
 * country list beside it carries the exact magnitudes — the plot is for spatial
 * intuition, the list is for reading values. Points without geolocation are
 * counted, never invented onto the map.
 */
const PAD = 8;

export default function WorldMap({ points = [], countries = [], withoutGeo = 0, height = 300 }) {
  const wrapRef = useRef(null);
  const [width, setWidth] = useState(560);
  const [handlers, Tooltip] = useTooltip();

  useMemo(() => {
    if (!wrapRef.current || typeof ResizeObserver === "undefined") return;
    const ro = new ResizeObserver((e) => setWidth(Math.max(320, e[0].contentRect.width)));
    ro.observe(wrapRef.current);
    return () => ro.disconnect();
  }, [wrapRef.current]);

  const plotW = width - PAD * 2;
  const plotH = height - PAD * 2;
  const project = (lat, lon) => [
    PAD + ((lon + 180) / 360) * plotW,
    PAD + ((90 - lat) / 180) * plotH,
  ];

  const maxCountry = Math.max(1, ...countries.map((c) => c.events));

  return (
    <div className="grid cols-2" style={{ gap: 16 }}>
      <div ref={wrapRef}>
        <svg width="100%" height={height} viewBox={`0 0 ${width} ${height}`} role="img" aria-label="Attacker origins">
          <rect x={PAD} y={PAD} width={plotW} height={plotH} fill="var(--surface-2)" rx="6" />
          {/* graticule */}
          {[-120, -60, 0, 60, 120].map((lon) => {
            const [x] = project(0, lon);
            return <line key={`v${lon}`} x1={x} x2={x} y1={PAD} y2={PAD + plotH} stroke="var(--grid)" strokeWidth="1" />;
          })}
          {[-60, -30, 0, 30, 60].map((lat) => {
            const [, y] = project(lat, 0);
            const equator = lat === 0;
            return (
              <line
                key={`h${lat}`}
                x1={PAD}
                x2={PAD + plotW}
                y1={y}
                y2={y}
                stroke={equator ? "var(--border-strong)" : "var(--grid)"}
                strokeWidth="1"
                strokeDasharray={equator ? "none" : "2 3"}
              />
            );
          })}
          {/* points, largest score first so small ones sit on top */}
          {[...points]
            .sort((a, b) => b.score - a.score)
            .map((p, i) => {
              const [x, y] = project(p.lat, p.lon);
              const r = 3 + Math.sqrt(Math.max(p.score, 1)) * 0.7;
              return (
                <circle
                  key={`${p.src_ip}-${i}`}
                  cx={x}
                  cy={y}
                  r={r}
                  fill={classColor(p.classification)}
                  fillOpacity="0.62"
                  stroke="var(--surface-1)"
                  strokeWidth="1.5"
                  onMouseEnter={(e) =>
                    handlers.show(
                      <>
                        <div className="t-title mono">{p.src_ip}</div>
                        <div className="t-row">
                          <span>{flag(p.country)} {p.country_name || p.country || "??"}</span>
                        </div>
                        <div className="t-row">
                          <span>score</span>
                          <span className="mono">{p.score?.toFixed(0)}</span>
                        </div>
                        <div className="t-row">
                          <span>class</span>
                          <span>{p.classification}</span>
                        </div>
                        <div className="t-row">
                          <span>events</span>
                          <span className="mono">{fmtNumber(p.events)}</span>
                        </div>
                      </>,
                      e
                    )
                  }
                  onMouseMove={handlers.move}
                  onMouseLeave={handlers.hide}
                  style={{ cursor: "pointer" }}
                />
              );
            })}
        </svg>
        <div className="muted" style={{ fontSize: 11, marginTop: 4 }}>
          {fmtNumber(points.length)} located source{points.length === 1 ? "" : "s"}
          {withoutGeo > 0 && ` · ${fmtNumber(withoutGeo)} without geolocation (not shown)`}
        </div>
      </div>

      <div className="table-scroll" style={{ maxHeight: height + 24, overflowY: "auto" }}>
        <table>
          <thead>
            <tr>
              <th>Country</th>
              <th className="right">Events</th>
              <th className="right">Sources</th>
            </tr>
          </thead>
          <tbody>
            {countries.length === 0 && (
              <tr>
                <td colSpan="3" className="empty">No geolocated activity.</td>
              </tr>
            )}
            {countries.map((c) => (
              <tr key={c.country || "unknown"}>
                <td>
                  {flag(c.country)} {c.country_name || c.country || "Unknown"}
                  <div className="bar-track" style={{ marginTop: 4, width: 120 }}>
                    <div className="bar-fill" style={{ width: `${(c.events / maxCountry) * 100}%` }} />
                  </div>
                </td>
                <td className="right">{fmtNumber(c.events)}</td>
                <td className="right">{fmtNumber(c.attackers)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <Tooltip />
    </div>
  );
}

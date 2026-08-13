import { useMemo } from "react";
import { fmtNumber } from "../api.js";
import { useTooltip } from "./Tooltip.jsx";

/**
 * Weekday × UTC-hour activity heatmap.
 *
 * A single-hue sequential ramp (magnitude), light→dark, with the intensity
 * carried by a fixed accent hue at varying opacity over the surface. Reveals
 * whether a campaign runs on a human schedule or a cron job.
 */
const HOURS = Array.from({ length: 24 }, (_, i) => i);

export default function HourHeatmap({ data }) {
  const [handlers, Tooltip] = useTooltip();
  const grid = data?.grid || [];
  const weekdays = data?.weekdays || ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
  const max = data?.max || 1;

  const cells = useMemo(() => grid, [grid]);
  if (!cells.length) return <div className="empty">No activity to chart.</div>;

  return (
    <div>
      <div style={{ overflowX: "auto" }}>
        <table style={{ borderCollapse: "separate", borderSpacing: "3px", width: "auto" }}>
          <thead>
            <tr>
              <th style={{ position: "static", background: "none", border: "none" }}></th>
              {HOURS.map((h) => (
                <th
                  key={h}
                  style={{
                    position: "static",
                    background: "none",
                    border: "none",
                    padding: 0,
                    fontSize: 9,
                    textAlign: "center",
                    width: 22,
                  }}
                >
                  {h % 6 === 0 ? `${h}h` : ""}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {cells.map((row, d) => (
              <tr key={d}>
                <td style={{ border: "none", padding: "0 6px 0 0", fontSize: 11, color: "var(--text-muted)" }}>
                  {weekdays[d]}
                </td>
                {row.map((count, h) => {
                  const intensity = max ? count / max : 0;
                  return (
                    <td key={h} style={{ border: "none", padding: 0 }}>
                      <div
                        onMouseEnter={(e) =>
                          handlers.show(
                            <>
                              <div className="t-title">
                                {weekdays[d]} {String(h).padStart(2, "0")}:00 UTC
                              </div>
                              <div className="t-row">
                                <span>events</span>
                                <span className="mono">{fmtNumber(count)}</span>
                              </div>
                            </>,
                            e
                          )
                        }
                        onMouseMove={handlers.move}
                        onMouseLeave={handlers.hide}
                        title=""
                        style={{
                          width: 22,
                          height: 18,
                          borderRadius: 3,
                          background:
                            count === 0
                              ? "var(--surface-2)"
                              : `color-mix(in srgb, var(--accent) ${18 + intensity * 82}%, var(--surface-2))`,
                          cursor: "default",
                        }}
                      />
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="legend" style={{ alignItems: "center" }}>
        <span className="muted" style={{ fontSize: 11 }}>less</span>
        {[0.15, 0.4, 0.65, 0.9, 1].map((t) => (
          <span
            key={t}
            className="legend-swatch"
            style={{ background: `color-mix(in srgb, var(--accent) ${18 + t * 82}%, var(--surface-2))` }}
          />
        ))}
        <span className="muted" style={{ fontSize: 11 }}>more · peak {fmtNumber(max)}/hr</span>
      </div>
      <Tooltip />
    </div>
  );
}

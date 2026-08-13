import { Link } from "react-router-dom";
import { SERVICE_COLORS, severityClass, fmtTime, flag } from "../api.js";

/**
 * The events table, shared by the live feed and any filtered listing.
 *
 * Renders the fields that identify one interaction — who, what service, what
 * they sent — with the source IP linking through to its attacker profile. The
 * "what" column adapts per event type so a command, an HTTP path and a
 * credential attempt each show their salient field rather than a fixed column
 * that is empty three times out of four.
 */
export default function EventTable({ events = [], showSession = false, highlightId = null }) {
  if (!events.length) return <div className="empty">No events.</div>;

  return (
    <div className="table-scroll">
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Sev</th>
            <th>Service</th>
            <th>Source</th>
            <th>Type</th>
            <th>Detail</th>
            <th>Tags</th>
          </tr>
        </thead>
        <tbody>
          {events.map((e) => (
            <tr
              key={e.event_id}
              style={
                e.event_id === highlightId
                  ? { background: "color-mix(in srgb, var(--accent) 10%, transparent)" }
                  : undefined
              }
            >
              <td className="mono" style={{ whiteSpace: "nowrap" }}>{fmtTime(e.ts)}</td>
              <td>
                <span className={severityClass(e.severity)} />
              </td>
              <td>
                <span className="svc-dot" style={{ background: SERVICE_COLORS[e.service] || "var(--text-muted)" }} />
                {e.service}
              </td>
              <td style={{ whiteSpace: "nowrap" }}>
                {flag(e.country)} <Link to={`/attackers/${e.src_ip}`} className="mono">{e.src_ip}</Link>
              </td>
              <td className="mono" style={{ whiteSpace: "nowrap" }}>{e.event_type}</td>
              <td style={{ maxWidth: 340 }}>
                <Detail event={e} />
              </td>
              <td style={{ maxWidth: 200 }}>
                {(e.tags || []).slice(0, 4).map((t) => (
                  <span className="tag" key={t}>{t}</span>
                ))}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Detail({ event: e }) {
  if (e.event_type === "command") return <code>{truncate(e.command, 80)}</code>;
  if (e.event_type === "http_request")
    return (
      <span>
        <span className="mono muted">{e.http_method}</span> <code>{truncate(e.path, 70)}</code>
      </span>
    );
  if (e.event_type === "auth_attempt" || e.event_type === "auth_success") {
    return (
      <span className="mono">
        {e.username || "—"}
        {e.password ? <span className="muted"> : {e.password}</span> : null}
      </span>
    );
  }
  if (e.user_agent) return <span className="muted mono">{truncate(e.user_agent, 60)}</span>;
  return <span className="muted">—</span>;
}

function truncate(s, n) {
  if (!s) return "—";
  return s.length > n ? s.slice(0, n) + "…" : s;
}

import { useState, Fragment } from "react";
import { api, severityClass, fmtRelative, fmtNumber, flag } from "../api.js";
import { useApi } from "../useApi.js";
import { Loading, ErrorBox } from "../components/common.jsx";
import { Link } from "react-router-dom";

/**
 * The triage queue.
 *
 * Alerts are deduplicated server-side, so each row is one condition with a hit
 * counter, not a wall of identical lines. An analyst can acknowledge or close a
 * row inline, and re-run detection on demand. Evidence expands in place — the
 * point of a honeypot is the detail, and hiding it behind another click loses
 * the plot.
 */
export default function Alerts() {
  const [status, setStatus] = useState("new");
  const [severity, setSeverity] = useState("");
  const [expanded, setExpanded] = useState(null);
  const [busy, setBusy] = useState(false);

  const alerts = useApi(({ signal }) => api.alerts({ status, severity, limit: 200 }), [status, severity]);

  async function updateStatus(alert, next) {
    setBusy(true);
    try {
      await api.setAlertStatus(alert.alert_id, next);
      await alerts.refresh();
    } finally {
      setBusy(false);
    }
  }

  async function runDetection() {
    setBusy(true);
    try {
      await api.runDetection(168);
      await alerts.refresh();
    } finally {
      setBusy(false);
    }
  }

  const items = alerts.data?.items || [];

  return (
    <div>
      <div className="topbar">
        <div>
          <h1 className="page-title">Alerts</h1>
          <div className="page-sub">{alerts.data ? `${alerts.data.total} matching` : "…"}</div>
        </div>
        <div className="controls">
          <div className="seg">
            {["new", "acknowledged", "closed", ""].map((st) => (
              <button key={st || "all"} className={status === st ? "active" : ""} onClick={() => setStatus(st)}>
                {st || "all"}
              </button>
            ))}
          </div>
          <select value={severity} onChange={(e) => setSeverity(e.target.value)}>
            <option value="">Any severity</option>
            <option value="medium">Medium+</option>
            <option value="high">High+</option>
            <option value="critical">Critical</option>
          </select>
          <button onClick={runDetection} disabled={busy}>
            {busy ? "Running…" : "Re-run detection"}
          </button>
        </div>
      </div>

      {alerts.error && <ErrorBox error={alerts.error} />}
      {alerts.loading && !alerts.data ? (
        <Loading />
      ) : items.length === 0 ? (
        <div className="card">
          <div className="empty">No alerts for this filter.</div>
        </div>
      ) : (
        <div className="card">
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Sev</th>
                  <th>Rule</th>
                  <th>Source</th>
                  <th className="right">Hits</th>
                  <th>Last seen</th>
                  <th>MITRE</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {items.map((a) => (
                  <Fragment key={a.alert_id}>
                    <tr style={{ cursor: "pointer" }}
                        onClick={() => setExpanded(expanded === a.alert_id ? null : a.alert_id)}>
                      <td><span className={severityClass(a.severity)} /></td>
                      <td>
                        <div style={{ fontWeight: 600 }}>{a.rule_name}</div>
                        <div className="muted mono" style={{ fontSize: 11 }}>{a.title}</div>
                      </td>
                      <td className="mono" style={{ whiteSpace: "nowrap" }}>
                        {a.src_ip ? <Link to={`/attackers/${a.src_ip}`}>{a.src_ip}</Link> : "—"}
                      </td>
                      <td className="right">{fmtNumber(a.hit_count)}</td>
                      <td style={{ whiteSpace: "nowrap" }}>{fmtRelative(a.last_seen)}</td>
                      <td>{(a.mitre || []).map((m) => <span className="tag" key={m}>{m}</span>)}</td>
                      <td onClick={(e) => e.stopPropagation()} style={{ whiteSpace: "nowrap" }}>
                        {a.status !== "acknowledged" && (
                          <button onClick={() => updateStatus(a, "acknowledged")} disabled={busy}
                                  style={{ padding: "3px 8px", fontSize: 12 }}>Ack</button>
                        )}{" "}
                        {a.status !== "closed" && (
                          <button onClick={() => updateStatus(a, "closed")} disabled={busy}
                                  style={{ padding: "3px 8px", fontSize: 12 }}>Close</button>
                        )}
                      </td>
                    </tr>
                    {expanded === a.alert_id && (
                      <tr>
                        <td colSpan="7" style={{ background: "var(--surface-2)" }}>
                          <div style={{ padding: "4px 4px 10px" }}>
                            <p style={{ marginTop: 0 }}>{a.description}</p>
                            <Evidence evidence={a.evidence} />
                          </div>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

function Evidence({ evidence }) {
  if (!evidence) return null;
  const entries = Object.entries(evidence).filter(([, v]) => v != null && (!Array.isArray(v) || v.length));
  return (
    <div className="grid cols-2" style={{ gap: 8 }}>
      {entries.map(([key, value]) => (
        <div key={key} className="row spread" style={{ alignItems: "start", gap: 10 }}>
          <span className="muted" style={{ fontSize: 12 }}>{key}</span>
          <span className="mono" style={{ fontSize: 12, textAlign: "right", wordBreak: "break-word" }}>
            {Array.isArray(value) ? value.slice(0, 12).join(", ") : String(value)}
          </span>
        </div>
      ))}
    </div>
  );
}

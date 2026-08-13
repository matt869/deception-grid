import { useParams, Link } from "react-router-dom";
import { api, classColor, fmtNumber, fmtTime, fmtRelative, flag, SERVICE_COLORS } from "../api.js";
import { useApi } from "../useApi.js";
import { Loading, ErrorBox } from "../components/common.jsx";
import EventTable from "../components/EventTable.jsx";
import CredentialCloud from "../components/CredentialCloud.jsx";

/**
 * One source's dossier: identity and network, the transparent score breakdown,
 * the credentials and paths it tried, and its recent events. The score panel is
 * the point — it shows *why* the number is what it is, component by component,
 * because a triage verdict that can't be questioned is worthless.
 */
export default function AttackerProfile() {
  const { ip } = useParams();
  const { data, error, loading } = useApi(({ signal }) => api.attacker(ip), [ip]);

  if (loading && !data) return <Loading label={`Loading ${ip}…`} />;
  if (error) return <ErrorBox error={error} />;
  if (!data) return null;

  const exp = data.score_explanation;

  return (
    <div>
      <div className="topbar">
        <div>
          <h1 className="page-title mono">
            {flag(data.country)} {data.src_ip}
          </h1>
          <div className="page-sub">
            {data.country_name || "Unknown location"}
            {data.as_org ? ` · AS${data.asn} ${data.as_org}` : ""} · first seen {fmtRelative(data.first_seen)}
          </div>
        </div>
        <Link to="/attackers">← All attackers</Link>
      </div>

      <div className="grid cols-4" style={{ marginBottom: 16 }}>
        <div className="card stat">
          <div className="label">Threat score</div>
          <div className="value" style={{ color: classColor(data.classification) }}>
            {data.threat_score?.toFixed(0)}
          </div>
          <div className="delta">
            <span className="chip" style={{ borderColor: classColor(data.classification), color: classColor(data.classification) }}>
              {data.classification}
            </span>
          </div>
        </div>
        <div className="card stat">
          <div className="label">Events</div>
          <div className="value">{fmtNumber(data.event_count)}</div>
          <div className="delta muted">{fmtNumber(data.session_count)} sessions</div>
        </div>
        <div className="card stat">
          <div className="label">Auth attempts</div>
          <div className="value">{fmtNumber(data.auth_attempts)}</div>
          <div className="delta muted">{data.distinct_usernames} users · {data.distinct_passwords} passwords</div>
        </div>
        <div className="card stat">
          <div className="label">Services</div>
          <div className="value" style={{ fontSize: 18, display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
            {(data.services || []).map((s) => (
              <span key={s} className="chip">
                <span className="svc-dot" style={{ background: SERVICE_COLORS[s], margin: 0 }} />
                {s}
              </span>
            ))}
          </div>
        </div>
      </div>

      {exp && (
        <div className="card" style={{ marginBottom: 16 }}>
          <h3>Score breakdown</h3>
          <div className="card-sub">
            Raw {exp.raw_score?.toFixed(1)} × recency {exp.recency_decay} = {exp.score?.toFixed(1)} ·
            last active {exp.age_days?.toFixed(1)}d ago · {exp.events_considered} events considered
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 8, marginTop: 8 }}>
            {Object.entries(exp.components).map(([name, value]) => {
              const weight = exp.weights[name] || 1;
              return (
                <div key={name} className="row spread" style={{ gap: 12 }}>
                  <span style={{ flex: "0 0 32%", fontSize: 13 }}>{name.replace(/_/g, " ")}</span>
                  <div className="bar-track" style={{ flex: 1 }}>
                    <div
                      className="bar-fill"
                      style={{
                        width: `${(value / weight) * 100}%`,
                        background: value / weight > 0.66 ? "var(--sev-high)" : "var(--accent)",
                      }}
                    />
                  </div>
                  <span className="mono right" style={{ flex: "0 0 auto", minWidth: 72 }}>
                    {value.toFixed(1)}/{weight}
                  </span>
                </div>
              );
            })}
          </div>
          <div style={{ marginTop: 10 }}>
            {(exp.tags || []).map((t) => <span className="tag" key={t}>{t}</span>)}
          </div>
        </div>
      )}

      <div className="grid cols-2" style={{ marginBottom: 16 }}>
        <div className="card">
          <h3>Usernames tried</h3>
          <CredentialCloud items={(data.top_usernames || []).map((v) => ({ value: v, count: 1 }))}
                           accent="var(--svc-ssh)" emptyLabel="No usernames." />
        </div>
        <div className="card">
          <h3>Passwords tried</h3>
          <CredentialCloud items={(data.top_passwords || []).map((v) => ({ value: v, count: 1 }))}
                           accent="var(--svc-telnet)" emptyLabel="No passwords." />
        </div>
      </div>

      {data.sessions?.length > 0 && (
        <div className="card" style={{ marginBottom: 16 }}>
          <h3>Sessions ({data.sessions.length})</h3>
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Service</th><th>Started</th><th className="right">Events</th>
                  <th className="right">Auth</th><th className="right">Commands</th><th>Closed by</th>
                </tr>
              </thead>
              <tbody>
                {data.sessions.map((s) => (
                  <tr key={s.session_id}>
                    <td><span className="svc-dot" style={{ background: SERVICE_COLORS[s.service] }} />{s.service}</td>
                    <td className="mono">{fmtTime(s.started_at)}</td>
                    <td className="right">{s.event_count}</td>
                    <td className="right">{s.auth_attempts}</td>
                    <td className="right">{s.commands_run}</td>
                    <td className="muted">{s.closed_by || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      <div className="card">
        <h3>Recent events</h3>
        <EventTable events={data.recent_events || []} />
      </div>
    </div>
  );
}

import { useState } from "react";
import { Link } from "react-router-dom";
import { api, fmtDuration, fmtNumber, fmtRelative, flag, SERVICE_COLORS } from "../api.js";
import { useApi } from "../useApi.js";
import { Loading, ErrorBox, WindowPicker } from "../components/common.jsx";

/**
 * Session browser — the entry point to replay.
 *
 * Defaults to "interactive only", because that filter is the whole game: a busy
 * sensor logs thousands of connect/disconnect pairs from scanners that never got
 * anywhere, and perhaps a dozen sessions where somebody actually typed. Those
 * dozen are what you want to watch, and finding them by scrolling is hopeless.
 */
export default function Sessions() {
  const [hours, setHours] = useState(168);
  const [service, setService] = useState("");
  const [hasCommands, setHasCommands] = useState(true);
  const [sort, setSort] = useState("started_at");

  const { data, error, loading } = useApi(
    ({ signal }) =>
      api.sessions({
        since_hours: hours,
        service,
        has_commands: hasCommands || undefined,
        sort,
        limit: 200,
      }),
    [hours, service, hasCommands, sort]
  );

  const items = data?.items || [];

  return (
    <div>
      <div className="topbar">
        <div>
          <h1 className="page-title">Sessions</h1>
          <div className="page-sub">
            {data
              ? `${fmtNumber(data.total)} ${hasCommands ? "interactive " : ""}session${
                  data.total === 1 ? "" : "s"
                } in window`
              : "…"}
          </div>
        </div>
        <div className="controls">
          <button
            className={hasCommands ? "primary" : ""}
            onClick={() => setHasCommands((v) => !v)}
            title="Only sessions where a command was actually run"
          >
            {hasCommands ? "✓ Interactive only" : "Interactive only"}
          </button>
          <select value={service} onChange={(e) => setService(e.target.value)}>
            <option value="">All services</option>
            <option value="ssh">SSH</option>
            <option value="telnet">Telnet</option>
            <option value="ftp">FTP</option>
            <option value="http">HTTP</option>
            <option value="redis">Redis</option>
            <option value="mysql">MySQL</option>
            <option value="docker">Docker</option>
          </select>
          <select value={sort} onChange={(e) => setSort(e.target.value)}>
            <option value="started_at">Sort: newest</option>
            <option value="commands_run">Sort: commands</option>
            <option value="event_count">Sort: events</option>
            <option value="auth_attempts">Sort: auth attempts</option>
            <option value="duration_ms">Sort: duration</option>
          </select>
          <WindowPicker value={hours} onChange={setHours} />
        </div>
      </div>

      {error && <ErrorBox error={error} />}
      {loading && !data ? (
        <Loading />
      ) : items.length === 0 ? (
        <div className="card">
          <div className="empty">
            No {hasCommands ? "interactive " : ""}sessions in this window.
            {hasCommands && " Turn off “Interactive only” to see connections that never got a shell."}
          </div>
        </div>
      ) : (
        <div className="card">
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Started</th>
                  <th>Service</th>
                  <th>Source</th>
                  <th className="right">Events</th>
                  <th className="right">Auth</th>
                  <th className="right">Commands</th>
                  <th className="right">Duration</th>
                  <th>Network</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {items.map((s) => (
                  <tr key={s.session_id}>
                    <td style={{ whiteSpace: "nowrap" }}>{fmtRelative(s.started_at)}</td>
                    <td style={{ whiteSpace: "nowrap" }}>
                      <span className="svc-dot" style={{ background: SERVICE_COLORS[s.service] }} />
                      {s.service}
                    </td>
                    <td style={{ whiteSpace: "nowrap" }}>
                      {flag(s.country)}{" "}
                      <Link to={`/attackers/${s.src_ip}`} className="mono">
                        {s.src_ip}
                      </Link>
                    </td>
                    <td className="right">{fmtNumber(s.event_count)}</td>
                    <td className="right">{fmtNumber(s.auth_attempts)}</td>
                    <td className="right">
                      {s.commands_run > 0 ? (
                        <strong style={{ color: "var(--sev-high)" }}>{s.commands_run}</strong>
                      ) : (
                        <span className="muted">0</span>
                      )}
                    </td>
                    <td className="right">{fmtDuration(s.duration_ms)}</td>
                    <td
                      className="muted"
                      style={{
                        maxWidth: 180,
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                      }}
                    >
                      {s.as_org || "—"}
                    </td>
                    <td>
                      <Link to={`/sessions/${s.session_id}`} className="chip" style={{ gap: 4 }}>
                        ▶ Replay
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

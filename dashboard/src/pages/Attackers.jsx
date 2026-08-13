import { useState } from "react";
import { Link } from "react-router-dom";
import { api, classColor, fmtNumber, fmtRelative, flag, SERVICE_COLORS } from "../api.js";
import { useApi } from "../useApi.js";
import { Loading, ErrorBox } from "../components/common.jsx";

/**
 * Ranked attacker list — the "who should I look at first" view. Sorted by
 * threat score by default, filterable by classification, each row linking to
 * the full profile.
 */
export default function Attackers() {
  const [sort, setSort] = useState("threat_score");
  const [classification, setClassification] = useState("");
  const { data, error, loading } = useApi(
    ({ signal }) => api.attackers({ sort, classification, limit: 100 }),
    [sort, classification]
  );

  const items = data?.items || [];

  return (
    <div>
      <div className="topbar">
        <div>
          <h1 className="page-title">Attackers</h1>
          <div className="page-sub">{data ? `${data.total} sources observed` : "…"}</div>
        </div>
        <div className="controls">
          <select value={classification} onChange={(e) => setClassification(e.target.value)}>
            <option value="">All classes</option>
            <option value="botnet-loader">Botnet loader</option>
            <option value="targeted-intrusion">Targeted intrusion</option>
            <option value="exploit-attempt">Exploit attempt</option>
            <option value="credential-bruteforce">Credential brute-force</option>
            <option value="web-scanner">Web scanner</option>
            <option value="recon-scanner">Recon scanner</option>
            <option value="opportunistic-probe">Opportunistic probe</option>
            <option value="low-signal">Low signal</option>
          </select>
          <select value={sort} onChange={(e) => setSort(e.target.value)}>
            <option value="threat_score">Sort: threat score</option>
            <option value="event_count">Sort: events</option>
            <option value="last_seen">Sort: last seen</option>
            <option value="auth_attempts">Sort: auth attempts</option>
          </select>
        </div>
      </div>

      {error && <ErrorBox error={error} />}
      {loading && !data ? (
        <Loading />
      ) : (
        <div className="card">
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th className="right">Score</th>
                  <th>Source</th>
                  <th>Class</th>
                  <th>Services</th>
                  <th className="right">Events</th>
                  <th className="right">Auth</th>
                  <th>Network</th>
                  <th>Last seen</th>
                </tr>
              </thead>
              <tbody>
                {items.map((a) => (
                  <tr key={a.src_ip}>
                    <td className="right">
                      <span style={{ fontWeight: 700, color: classColor(a.classification), fontSize: 15 }}>
                        {a.threat_score?.toFixed(0)}
                      </span>
                    </td>
                    <td>
                      {flag(a.country)}{" "}
                      <Link to={`/attackers/${a.src_ip}`} className="mono">{a.src_ip}</Link>
                    </td>
                    <td>
                      <span className="chip" style={{ borderColor: classColor(a.classification), color: classColor(a.classification) }}>
                        {a.classification}
                      </span>
                    </td>
                    <td>
                      {(a.services || []).map((s) => (
                        <span key={s} className="svc-dot" title={s} style={{ background: SERVICE_COLORS[s] }} />
                      ))}
                    </td>
                    <td className="right">{fmtNumber(a.event_count)}</td>
                    <td className="right">{fmtNumber(a.auth_attempts)}</td>
                    <td className="muted" style={{ maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {a.as_org || "—"}
                    </td>
                    <td style={{ whiteSpace: "nowrap" }}>{fmtRelative(a.last_seen)}</td>
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

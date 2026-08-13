import { useState } from "react";
import { api, SERVICE_COLORS, fmtNumber } from "../api.js";
import { useApi } from "../useApi.js";
import { StatTile, Loading, ErrorBox, WindowPicker, Bars } from "../components/common.jsx";
import AttackTimeline from "../components/AttackTimeline.jsx";
import HourHeatmap from "../components/HourHeatmap.jsx";
import WorldMap from "../components/WorldMap.jsx";
import CredentialCloud from "../components/CredentialCloud.jsx";

/**
 * The landing page: headline counters, the activity timeline, geographic
 * origins, the credential and path leaderboards, and the schedule heatmap.
 * One time-window control drives every panel so the whole page reads as a
 * single snapshot.
 */
export default function Overview() {
  const [hours, setHours] = useState(24);
  const bucket = hours <= 6 ? "5m" : hours <= 24 ? "1h" : hours <= 168 ? "6h" : "1d";

  const summary = useApi(({ signal }) => api.summary(hours), [hours]);
  const timeline = useApi(({ signal }) => api.timeseries(hours, bucket, "service"), [hours, bucket]);
  const map = useApi(({ signal }) => api.attackerMap(hours, 500), [hours]);
  const usernames = useApi(({ signal }) => api.top("usernames", hours, 20), [hours]);
  const passwords = useApi(({ signal }) => api.top("passwords", hours, 20), [hours]);
  const paths = useApi(({ signal }) => api.top("paths", hours, 12), [hours]);
  const services = useApi(({ signal }) => api.services(hours), [hours]);
  const heatmap = useApi(({ signal }) => api.heatmap(Math.max(hours, 168)), [hours]);

  const s = summary.data;

  return (
    <div>
      <div className="topbar">
        <div>
          <h1 className="page-title">Overview</h1>
          <div className="page-sub">Honeypot activity across all services</div>
        </div>
        <div className="controls">
          <WindowPicker value={hours} onChange={setHours} />
        </div>
      </div>

      {summary.error && <ErrorBox error={summary.error} />}

      <div className="grid cols-4" style={{ marginBottom: 16 }}>
        {summary.loading && !s ? (
          <Loading />
        ) : (
          <>
            <StatTile label="Events" value={s?.total_events ?? 0} />
            <StatTile label="Unique sources" value={s?.unique_attackers ?? 0} />
            <StatTile label="Countries" value={s?.unique_countries ?? 0} />
            <StatTile
              label="Open alerts"
              value={s?.open_alerts ?? 0}
              accent={s?.critical_alerts ? "var(--sev-critical)" : undefined}
              delta={s?.critical_alerts ? `${s.critical_alerts} high/critical` : "none critical"}
            />
          </>
        )}
      </div>

      <div className="card" style={{ marginBottom: 16 }}>
        <h3>Activity over time</h3>
        <div className="card-sub">Events per {bucket} bucket, stacked by service</div>
        {timeline.loading && !timeline.data ? <Loading /> : <AttackTimeline data={timeline.data} />}
      </div>

      <div className="grid cols-2" style={{ marginBottom: 16 }}>
        <div className="card">
          <h3>Origins</h3>
          <div className="card-sub">Source locations and top countries</div>
          {map.loading && !map.data ? (
            <Loading />
          ) : (
            <WorldMap
              points={map.data?.points || []}
              countries={map.data?.countries || []}
              withoutGeo={map.data?.points_without_geo || 0}
            />
          )}
        </div>
        <div className="card">
          <h3>Services targeted</h3>
          <div className="card-sub">Events and distinct sources per service</div>
          {services.loading && !services.data ? (
            <Loading />
          ) : (
            <Bars
              items={services.data || []}
              labelKey="service"
              valueKey="events"
              colorFor={(i) => SERVICE_COLORS[i.service] || "var(--accent)"}
            />
          )}
        </div>
      </div>

      <div className="grid cols-2" style={{ marginBottom: 16 }}>
        <div className="card">
          <h3>Usernames tried</h3>
          <div className="card-sub">Sized by attempt count</div>
          {usernames.data ? <CredentialCloud items={usernames.data} accent="var(--svc-ssh)" /> : <Loading />}
        </div>
        <div className="card">
          <h3>Passwords tried</h3>
          <div className="card-sub">Sized by attempt count</div>
          {passwords.data ? <CredentialCloud items={passwords.data} accent="var(--svc-telnet)" /> : <Loading />}
        </div>
      </div>

      <div className="grid cols-2">
        <div className="card">
          <h3>Top requested paths</h3>
          <div className="card-sub">HTTP targets</div>
          {paths.data ? (
            <Bars items={paths.data} colorFor={() => "var(--svc-http)"} />
          ) : (
            <Loading />
          )}
        </div>
        <div className="card">
          <h3>Attack schedule</h3>
          <div className="card-sub">Weekday × hour (UTC), last {Math.max(hours, 168) / 24 | 0}d</div>
          {heatmap.data ? <HourHeatmap data={heatmap.data} /> : <Loading />}
        </div>
      </div>
    </div>
  );
}

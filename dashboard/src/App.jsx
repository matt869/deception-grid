import { useEffect, useState } from "react";
import { Routes, Route, NavLink, Navigate } from "react-router-dom";
import { api } from "./api.js";
import Overview from "./pages/Overview.jsx";
import LiveFeed from "./pages/LiveFeed.jsx";
import Attackers from "./pages/Attackers.jsx";
import AttackerProfile from "./pages/AttackerProfile.jsx";
import Sessions from "./pages/Sessions.jsx";
import SessionReplay from "./pages/SessionReplay.jsx";
import Payloads from "./pages/Payloads.jsx";
import Alerts from "./pages/Alerts.jsx";

const NAV = [
  { to: "/overview", label: "Overview", icon: "◧" },
  { to: "/live", label: "Live feed", icon: "◉" },
  { to: "/sessions", label: "Sessions", icon: "▶" },
  { to: "/attackers", label: "Attackers", icon: "⚑" },
  { to: "/payloads", label: "Payloads", icon: "⬢" },
  { to: "/alerts", label: "Alerts", icon: "!" },
];

export default function App() {
  const [theme, setTheme] = useState(() => localStorage.getItem("theme") || "dark");
  const [health, setHealth] = useState(null);

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem("theme", theme);
  }, [theme]);

  // Poll health for the sidebar status line and the open-alert badge.
  useEffect(() => {
    let alive = true;
    const load = () => api.health().then((h) => alive && setHealth(h)).catch(() => alive && setHealth(null));
    load();
    const timer = setInterval(load, 15000);
    return () => {
      alive = false;
      clearInterval(timer);
    };
  }, []);

  return (
    <div className="app">
      <nav className="sidebar">
        <div className="brand">
          <span className="dot" /> Honeypot
        </div>
        {NAV.map((n) => (
          <NavLink key={n.to} to={n.to} className={({ isActive }) => `nav-link ${isActive ? "active" : ""}`}>
            <span style={{ width: 18, textAlign: "center" }}>{n.icon}</span>
            {n.label}
            {n.to === "/alerts" && health?.events_total > 0 && (
              <span className="badge">
                <AlertBadge />
              </span>
            )}
          </NavLink>
        ))}

        <div style={{ marginTop: "auto", paddingTop: 16 }}>
          <button
            onClick={() => setTheme((t) => (t === "dark" ? "light" : "dark"))}
            style={{ width: "100%", marginBottom: 10 }}
          >
            {theme === "dark" ? "☀ Light" : "☾ Dark"}
          </button>
          <HealthLine health={health} />
        </div>
      </nav>

      <main className="main">
        <Routes>
          <Route path="/" element={<Navigate to="/overview" replace />} />
          <Route path="/overview" element={<Overview />} />
          <Route path="/live" element={<LiveFeed />} />
          <Route path="/sessions" element={<Sessions />} />
          <Route path="/sessions/:id" element={<SessionReplay />} />
          <Route path="/attackers" element={<Attackers />} />
          <Route path="/attackers/:ip" element={<AttackerProfile />} />
          <Route path="/payloads" element={<Payloads />} />
          <Route path="/alerts" element={<Alerts />} />
          <Route path="*" element={<div className="empty">Not found.</div>} />
        </Routes>
      </main>
    </div>
  );
}

function AlertBadge() {
  const [n, setN] = useState(null);
  useEffect(() => {
    let alive = true;
    const load = () =>
      api.alerts({ status: "new", limit: 1 }).then((r) => alive && setN(r.total)).catch(() => {});
    load();
    const t = setInterval(load, 15000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, []);
  if (!n) return null;
  return (
    <span
      className="chip"
      style={{ background: "var(--sev-critical)", color: "#fff", border: "none", padding: "1px 7px" }}
    >
      {n}
    </span>
  );
}

function HealthLine({ health }) {
  if (!health) {
    return (
      <div className="muted" style={{ fontSize: 11, padding: "0 4px" }}>
        <span style={{ color: "var(--sev-high)" }}>●</span> API unreachable
      </div>
    );
  }
  return (
    <div className="muted" style={{ fontSize: 11, padding: "0 4px", lineHeight: 1.7 }}>
      <div>
        <span style={{ color: health.status === "ok" ? "var(--svc-ftp)" : "var(--sev-high)" }}>●</span>{" "}
        API {health.status} · v{health.version}
      </div>
      <div>{health.events_total?.toLocaleString()} events · {health.rules_loaded} rules</div>
      <div>geoip: {health.geoip_available ? "on" : "off"}</div>
    </div>
  );
}

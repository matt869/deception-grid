/*
 * Thin API client + shared display helpers.
 *
 * One fetch wrapper, one hook. Everything the pages need is a named function
 * here so a change to the API surface has exactly one place to update.
 */

const BASE = import.meta.env.VITE_API_BASE || "/api";

async function request(path, { signal } = {}) {
  const res = await fetch(`${BASE}${path}`, { signal });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      detail = (await res.json()).detail || detail;
    } catch {
      /* body was not JSON */
    }
    const err = new Error(detail);
    err.status = res.status;
    throw err;
  }
  return res.json();
}

async function send(path, method, body) {
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: { "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail || res.statusText);
  return res.json();
}

const qs = (params) =>
  "?" +
  Object.entries(params)
    .filter(([, v]) => v !== undefined && v !== null && v !== "")
    .map(([k, v]) => `${k}=${encodeURIComponent(v)}`)
    .join("&");

export const api = {
  health: () => request("/health"),

  summary: (hours) => request(`/stats/summary${qs({ hours })}`),
  timeseries: (hours, bucket, by) => request(`/stats/timeseries${qs({ hours, bucket, by })}`),
  heatmap: (hours) => request(`/stats/heatmap${qs({ hours })}`),
  services: (hours) => request(`/stats/services${qs({ hours })}`),
  countries: (hours, limit) => request(`/stats/countries${qs({ hours, limit })}`),
  asns: (hours, limit) => request(`/stats/asns${qs({ hours, limit })}`),
  top: (field, hours, limit) => request(`/stats/top/${field}${qs({ hours, limit })}`),
  credentials: (hours, limit) => request(`/stats/credentials${qs({ hours, limit })}`),

  events: (params) => request(`/events${qs(params)}`),
  live: (params) => request(`/events/live${qs(params)}`),
  session: (id) => request(`/sessions/${id}`),

  attackers: (params) => request(`/attackers${qs(params)}`),
  attacker: (ip) => request(`/attackers/${ip}`),
  attackerMap: (hours, limit) => request(`/attackers/map${qs({ hours, limit })}`),

  alerts: (params) => request(`/alerts${qs(params)}`),
  alertsByRule: (hours) => request(`/alerts/by-rule${qs({ hours })}`),
  rules: () => request("/alerts/rules"),
  setAlertStatus: (id, status, notes) => send(`/alerts/${id}`, "PATCH", { status, notes }),
  runDetection: (hours) => send(`/alerts/run${qs({ hours })}`, "POST"),
};

/* --------------------------------------------------------------- display */

export const SERVICE_COLORS = {
  ssh: "var(--svc-ssh)",
  telnet: "var(--svc-telnet)",
  ftp: "var(--svc-ftp)",
  http: "var(--svc-http)",
  redis: "var(--svc-redis)",
  mysql: "var(--svc-mysql)",
};

export const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];

export function severityClass(sev) {
  return `sev sev-${sev || "info"}`;
}

export function fmtNumber(n) {
  if (n === null || n === undefined) return "—";
  return n.toLocaleString();
}

export function fmtTime(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  return d.toLocaleString(undefined, {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export function fmtRelative(iso) {
  if (!iso) return "—";
  const diff = (Date.now() - new Date(iso).getTime()) / 1000;
  if (diff < 60) return `${Math.floor(diff)}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

export function classColor(classification) {
  const map = {
    "botnet-loader": "var(--sev-critical)",
    "targeted-intrusion": "var(--sev-critical)",
    "exploit-attempt": "var(--sev-high)",
    "credential-bruteforce": "var(--sev-high)",
    "web-scanner": "var(--sev-medium)",
    "recon-scanner": "var(--sev-medium)",
    "opportunistic-probe": "var(--sev-low)",
    "low-signal": "var(--sev-info)",
  };
  return map[classification] || "var(--sev-info)";
}

// A country code -> flag emoji, purely cosmetic and safe for unknowns.
export function flag(cc) {
  if (!cc || cc.length !== 2) return "";
  const A = 0x1f1e6;
  return String.fromCodePoint(A + cc.charCodeAt(0) - 65, A + cc.charCodeAt(1) - 65);
}

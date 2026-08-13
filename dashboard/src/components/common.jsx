import { fmtNumber } from "../api.js";

export function StatTile({ label, value, delta, accent }) {
  return (
    <div className="card stat">
      <div className="label">{label}</div>
      <div className="value" style={accent ? { color: accent } : undefined}>
        {typeof value === "number" ? fmtNumber(value) : value}
      </div>
      {delta != null && <div className="delta muted">{delta}</div>}
    </div>
  );
}

export function Loading({ label = "Loading…" }) {
  return (
    <div className="row" style={{ gap: 10, color: "var(--text-muted)", padding: 20 }}>
      <span className="spinner" /> {label}
    </div>
  );
}

export function ErrorBox({ error }) {
  return (
    <div className="card" style={{ borderColor: "var(--sev-critical)" }}>
      <strong style={{ color: "var(--sev-critical)" }}>Request failed</strong>
      <div className="muted" style={{ marginTop: 4 }}>
        {String(error?.message || error)}
      </div>
      <div className="muted" style={{ marginTop: 8, fontSize: 12 }}>
        Is the API running? <code>uvicorn api.main:app --reload</code>
      </div>
    </div>
  );
}

export function WindowPicker({ value, onChange }) {
  const options = [
    { h: 1, label: "1h" },
    { h: 6, label: "6h" },
    { h: 24, label: "24h" },
    { h: 168, label: "7d" },
    { h: 720, label: "30d" },
  ];
  return (
    <div className="seg" role="group" aria-label="Time window">
      {options.map((o) => (
        <button key={o.h} className={value === o.h ? "active" : ""} onClick={() => onChange(o.h)}>
          {o.label}
        </button>
      ))}
    </div>
  );
}

export function Bars({ items, colorFor, valueKey = "count", labelKey = "value", max }) {
  if (!items?.length) return <div className="empty">No data.</div>;
  const top = max || Math.max(...items.map((i) => i[valueKey]));
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
      {items.map((item, i) => (
        <div key={item[labelKey] ?? i} className="row spread" style={{ gap: 12 }}>
          <span className="mono" style={{ minWidth: 0, flex: "0 0 45%", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
            {item[labelKey] || <span className="muted">(empty)</span>}
          </span>
          <div className="bar-track" style={{ flex: 1 }}>
            <div
              className="bar-fill"
              style={{
                width: `${(item[valueKey] / top) * 100}%`,
                background: colorFor ? colorFor(item) : "var(--accent)",
              }}
            />
          </div>
          <span className="mono right" style={{ flex: "0 0 auto", minWidth: 44 }}>
            {fmtNumber(item[valueKey])}
          </span>
        </div>
      ))}
    </div>
  );
}

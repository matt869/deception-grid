import { fmtNumber } from "../api.js";

/**
 * Ranked credential display.
 *
 * A "word cloud" sizes words by frequency but makes exact values unreadable and
 * long strings collide — a poor fit for credentials, where the precise counts
 * and the exact strings both matter. This uses sized, ranked pills instead:
 * font scales with frequency for at-a-glance weight, and every value stays fully
 * legible with its count. Honest about magnitude, and copy-pasteable.
 */
export default function CredentialCloud({ items = [], accent = "var(--accent)", emptyLabel = "None seen." }) {
  if (!items.length) return <div className="empty">{emptyLabel}</div>;

  const max = Math.max(...items.map((i) => i.count));
  const min = Math.min(...items.map((i) => i.count));
  const scale = (c) => {
    if (max === min) return 15;
    return 12 + ((c - min) / (max - min)) * 12; // 12–24px
  };

  return (
    <div style={{ display: "flex", flexWrap: "wrap", gap: 8, alignItems: "baseline" }}>
      {items.map((item) => {
        const value = item.value ?? item.username ?? "";
        const size = scale(item.count);
        const weight = 400 + Math.round(((item.count - min) / (max - min || 1)) * 400);
        return (
          <span
            key={value}
            title={`${value} — ${fmtNumber(item.count)}`}
            style={{
              fontFamily: "var(--mono)",
              fontSize: size,
              fontWeight: weight,
              lineHeight: 1.3,
              color: `color-mix(in srgb, ${accent} ${40 + ((item.count - min) / (max - min || 1)) * 60}%, var(--text-primary))`,
            }}
          >
            {value || <span className="muted">(empty)</span>}
            <sub style={{ fontSize: 10, color: "var(--text-muted)", fontWeight: 400 }}>
              {" "}
              {fmtNumber(item.count)}
            </sub>
          </span>
        );
      })}
    </div>
  );
}

import { useState } from "react";
import { api, fmtBytes, fmtNumber, fmtRelative } from "../api.js";
import { useApi } from "../useApi.js";
import { Bars, ErrorBox, Loading, StatTile } from "../components/common.jsx";

/**
 * Captured artefacts, statically analysed.
 *
 * The architecture breakdown leads the page because it answers a question the
 * event tables cannot: IoT botnets ship one build per CPU family and the loader
 * picks by `uname`, so the spread of architectures is a census of what the
 * internet believes is listening on these ports. A pile of MIPS and ARM means
 * the sensor is being read as a router.
 *
 * Every indicator shown here arrives from the API already defanged
 * (`hxxp://evil[.]com`) and is rendered as plain text, never as a link. That is
 * deliberate and load-bearing: these URLs point at live malware hosts, and this
 * page is the one place a person might click one.
 */
export default function Payloads() {
  const [fileType, setFileType] = useState("");
  const [arch, setArch] = useState("");
  const [sort, setSort] = useState("last_seen");
  const [packedOnly, setPackedOnly] = useState(false);
  const [selected, setSelected] = useState(null);

  const { data, error, loading } = useApi(
    () => api.payloads({ file_type: fileType, arch, sort, packed_only: packedOnly, limit: 100 }),
    [fileType, arch, sort, packedOnly]
  );
  const { data: arches } = useApi(() => api.payloadArchitectures(), []);

  const items = data?.items || [];
  const archRows = arches || [];
  const packedCount = items.filter((p) => p.likely_packed).length;

  return (
    <div>
      <div className="topbar">
        <div>
          <h1 className="page-title">Payloads</h1>
          <div className="page-sub">
            {data ? `${data.total} artefacts analysed — nothing is ever executed` : "…"}
          </div>
        </div>
        <div className="controls">
          <select
            value={arch}
            onChange={(e) => setArch(e.target.value)}
            aria-label="Filter by architecture"
          >
            <option value="">All architectures</option>
            {archRows.map((a) => (
              <option key={a.arch} value={a.arch}>
                {a.arch} ({a.count})
              </option>
            ))}
          </select>
          <select
            value={fileType}
            onChange={(e) => setFileType(e.target.value)}
            aria-label="Filter by file type"
          >
            <option value="">All types</option>
            <option value="elf">ELF</option>
            <option value="pe">PE</option>
            <option value="script-sh">Shell script</option>
            <option value="script-python">Python script</option>
            <option value="zip">Zip</option>
            <option value="gzip">Gzip</option>
            <option value="unknown">Unknown</option>
          </select>
          <select value={sort} onChange={(e) => setSort(e.target.value)} aria-label="Sort by">
            <option value="last_seen">Sort: last seen</option>
            <option value="first_seen">Sort: first seen</option>
            <option value="size">Sort: size</option>
            <option value="entropy">Sort: entropy</option>
            <option value="event_count">Sort: sightings</option>
          </select>
          <button
            className={packedOnly ? "active" : ""}
            onClick={() => setPackedOnly((v) => !v)}
            aria-pressed={packedOnly}
          >
            Packed only
          </button>
        </div>
      </div>

      {error && <ErrorBox error={error} />}

      {loading && !data ? (
        <Loading />
      ) : (
        <>
          <div className="grid stats">
            <StatTile label="Artefacts" value={data?.total ?? 0} />
            <StatTile label="CPU families" value={archRows.length} />
            <StatTile
              label="Likely packed"
              value={packedCount}
              accent={packedCount ? "var(--sev-high)" : undefined}
            />
            <StatTile
              label="Total sightings"
              value={items.reduce((n, p) => n + (p.event_count || 0), 0)}
            />
          </div>

          {archRows.length > 0 && (
            <div className="card" style={{ marginTop: 16 }}>
              <h2 className="card-title">Target architectures</h2>
              <div className="muted" style={{ marginBottom: 12, fontSize: 12 }}>
                What the operators thought this sensor was.
              </div>
              <Bars items={archRows} labelKey="arch" valueKey="count" />
            </div>
          )}

          <div className="card" style={{ marginTop: 16 }}>
            {items.length === 0 ? (
              <div className="empty">
                No analysed artefacts yet. Run <code>python -m pipeline.analysis.store</code> after
                the sensor captures an upload.
              </div>
            ) : (
              <div className="table-scroll">
                <table>
                  <thead>
                    <tr>
                      <th>SHA256</th>
                      <th>Type</th>
                      <th>Arch</th>
                      <th>Build</th>
                      <th className="right">Size</th>
                      <th className="right">Entropy</th>
                      <th>Behaviour</th>
                      <th className="right">Seen</th>
                      <th>Last</th>
                    </tr>
                  </thead>
                  <tbody>
                    {items.map((p) => (
                      <tr
                        key={p.sha256}
                        onClick={() => setSelected(p)}
                        style={{ cursor: "pointer" }}
                      >
                        <td className="mono">{p.sha256.slice(0, 12)}…</td>
                        <td>{p.file_type || "—"}</td>
                        <td className="mono">{p.arch || "—"}</td>
                        <td className="muted">
                          {[p.linkage, p.stripped ? "stripped" : null]
                            .filter(Boolean)
                            .join(" · ") || "—"}
                        </td>
                        <td className="right mono">{fmtBytes(p.size)}</td>
                        <td className="right mono">
                          {p.likely_packed ? (
                            <span style={{ color: "var(--sev-high)" }} title="Likely packed">
                              {p.entropy?.toFixed(2)}
                            </span>
                          ) : (
                            p.entropy?.toFixed(2)
                          )}
                        </td>
                        <td>
                          {(p.behaviour_tags || []).slice(0, 3).map((t) => (
                            <span key={t} className="chip">
                              {t}
                            </span>
                          ))}
                        </td>
                        <td className="right">{fmtNumber(p.event_count)}</td>
                        <td className="muted">{fmtRelative(p.last_seen)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </>
      )}

      {selected && <PayloadDetail sha256={selected.sha256} onClose={() => setSelected(null)} />}
    </div>
  );
}

/** Full profile for one artefact, including the sources that delivered it. */
export function PayloadDetail({ sha256, onClose }) {
  const { data, error, loading } = useApi(() => api.payload(sha256), [sha256]);

  return (
    <div className="card" style={{ marginTop: 16 }} data-testid="payload-detail">
      <div className="row spread">
        <h2 className="card-title">Artefact {sha256.slice(0, 16)}…</h2>
        <button onClick={onClose}>Close</button>
      </div>

      {error && <ErrorBox error={error} />}
      {loading && !data && <Loading />}

      {data && (
        <>
          <div className="mono muted" style={{ wordBreak: "break-all", marginBottom: 12 }}>
            {data.sha256}
          </div>

          <dl className="kv">
            <dt>Type</dt>
            <dd>
              {data.file_type} <span className="muted">({data.mime})</span>
            </dd>
            <dt>Architecture</dt>
            <dd className="mono">{data.arch || "—"}</dd>
            <dt>Linkage</dt>
            <dd>
              {data.linkage || "—"}
              {data.stripped ? " · stripped" : ""}
            </dd>
            <dt>Size</dt>
            <dd>{fmtBytes(data.size)}</dd>
            <dt>Entropy</dt>
            <dd>
              {data.entropy?.toFixed(3)}
              {data.likely_packed && (
                <span className="chip" style={{ marginLeft: 8 }}>
                  likely packed
                </span>
              )}
            </dd>
            <dt>Strings</dt>
            <dd>{fmtNumber(data.strings_count)}</dd>
          </dl>

          {data.behaviour_tags?.length > 0 && (
            <Section title="Behaviour">
              {data.behaviour_tags.map((t) => (
                <span key={t} className="chip">
                  {t}
                </span>
              ))}
            </Section>
          )}

          {data.yara_matches?.length > 0 && (
            <Section title="YARA">
              {data.yara_matches.map((m) => (
                <span key={m} className="chip">
                  {m}
                </span>
              ))}
            </Section>
          )}

          <Indicators iocs={data.iocs} />

          {data.sources?.length > 0 && (
            <Section title={`Delivered by ${data.sources.length} source(s)`}>
              <table>
                <thead>
                  <tr>
                    <th>Source</th>
                    <th className="right">Events</th>
                    <th>First</th>
                    <th>Last</th>
                  </tr>
                </thead>
                <tbody>
                  {data.sources.map((s) => (
                    <tr key={s.src_ip}>
                      <td className="mono">{s.src_ip}</td>
                      <td className="right">{fmtNumber(s.events)}</td>
                      <td className="muted">{fmtRelative(s.first_seen)}</td>
                      <td className="muted">{fmtRelative(s.last_seen)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Section>
          )}
        </>
      )}
    </div>
  );
}

function Section({ title, children }) {
  return (
    <div style={{ marginTop: 16 }}>
      <h3 style={{ fontSize: 13, margin: "0 0 8px" }}>{title}</h3>
      {children}
    </div>
  );
}

/**
 * Indicators, rendered as inert text.
 *
 * These are never wrapped in an anchor and never re-fanged. The API defangs on
 * the way out; this component's only job is not to undo that.
 */
function Indicators({ iocs }) {
  const groups = [
    ["URLs", iocs?.urls],
    ["Domains", iocs?.domains],
    ["Addresses", iocs?.ipv4],
  ].filter(([, values]) => values?.length);

  if (!groups.length) return null;

  return (
    <Section title="Indicators">
      <div className="muted" style={{ fontSize: 12, marginBottom: 8 }}>
        Defanged — these point at live malware hosts. Do not re-fang and fetch.
      </div>
      {groups.map(([label, values]) => (
        <div key={label} style={{ marginBottom: 8 }}>
          <div className="muted" style={{ fontSize: 11 }}>
            {label}
          </div>
          {values.map((v) => (
            <div key={v} className="mono" style={{ wordBreak: "break-all" }}>
              {v}
            </div>
          ))}
        </div>
      ))}
    </Section>
  );
}

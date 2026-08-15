import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { api, fmtDuration, fmtNumber, fmtTime, flag, SERVICE_COLORS } from "../api.js";
import { useApi } from "../useApi.js";
import { Loading, ErrorBox } from "../components/common.jsx";
import EventTable from "../components/EventTable.jsx";

/**
 * Session replay — watch one connection back, in order, at attacker pace.
 *
 * The transcript is the honeypot's most valuable artifact: a table of events
 * tells you *what* was tried, but replaying them in sequence shows *how* the
 * operator worked — where they hesitated, what they tried after a failure, the
 * order they enumerated things in. That reads very differently from a grid.
 *
 * Timing is real but compressed. Gaps are clamped to a playable range so a
 * session with a two-minute pause doesn't stall the player, and any gap the
 * clamp swallowed is drawn explicitly as an idle marker — the viewer always
 * sees that time passed, rather than being quietly lied to about the pace.
 */

const MIN_STEP_MS = 140; // floor: bursts stay watchable rather than instant
const MAX_STEP_MS = 2200; // ceiling: nobody waits out a real 90-second idle
const IDLE_MARKER_MS = 5000; // above this, draw the gap as its own line
const SPEEDS = [1, 2, 4, 8];

export default function SessionReplay() {
  const { id } = useParams();
  const { data, error, loading } = useApi(({ signal }) => api.session(id), [id]);

  const events = useMemo(() => data?.events || [], [data]);
  const [cursor, setCursor] = useState(0); // events revealed so far
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState(1);
  const paneRef = useRef(null);

  // Autoplay once the transcript lands, and reset when navigating between
  // sessions without unmounting the page.
  useEffect(() => {
    setCursor(0);
    setPlaying(events.length > 0);
  }, [id, events.length]);

  const gapBefore = useCallback(
    (i) => {
      if (i <= 0 || i >= events.length) return 0;
      return new Date(events[i].ts) - new Date(events[i - 1].ts);
    },
    [events]
  );

  // One timer per step: the delay is derived from the *next* event's real gap,
  // so playback speeds up and slows down the way the session actually did.
  useEffect(() => {
    if (!playing || cursor >= events.length) return;
    const delay = Math.min(Math.max(gapBefore(cursor), MIN_STEP_MS), MAX_STEP_MS) / speed;
    const timer = setTimeout(() => setCursor((c) => c + 1), delay);
    return () => clearTimeout(timer);
  }, [playing, cursor, speed, events.length, gapBefore]);

  useEffect(() => {
    if (events.length && cursor >= events.length) setPlaying(false);
  }, [cursor, events.length]);

  // Keep the newest line in view while playing, but don't fight the user if
  // they've scrolled up to read something.
  useEffect(() => {
    const pane = paneRef.current;
    if (!pane || !playing) return;
    pane.scrollTop = pane.scrollHeight;
  }, [cursor, playing]);

  const toggle = useCallback(() => {
    setPlaying((p) => {
      if (!p && cursor >= events.length) setCursor(0); // replay from the top
      return !p;
    });
  }, [cursor, events.length]);

  const step = useCallback(
    (n) => {
      setPlaying(false);
      setCursor((c) => Math.min(Math.max(c + n, 0), events.length));
    },
    [events.length]
  );

  useEffect(() => {
    const onKey = (e) => {
      if (e.target.matches("input, select, textarea")) return;
      if (e.code === "Space") {
        e.preventDefault();
        toggle();
      } else if (e.code === "ArrowRight") {
        step(1);
      } else if (e.code === "ArrowLeft") {
        step(-1);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [toggle, step]);

  if (loading && !data) return <Loading label={`Loading session ${id.slice(0, 8)}…`} />;
  if (error) return <ErrorBox error={error} />;
  if (!data) return null;

  const visible = events.slice(0, cursor);
  const finished = cursor >= events.length;
  const elapsed =
    visible.length > 1 ? new Date(visible[visible.length - 1].ts) - new Date(visible[0].ts) : 0;

  return (
    <div>
      <div className="topbar">
        <div>
          <h1 className="page-title">
            <span className="svc-dot" style={{ background: SERVICE_COLORS[data.service] }} />
            {data.service} session
          </h1>
          <div className="page-sub">
            {flag(data.country)}{" "}
            <Link to={`/attackers/${data.src_ip}`} className="mono">
              {data.src_ip}
            </Link>
            {data.country_name ? ` · ${data.country_name}` : ""}
            {data.as_org ? ` · AS${data.asn} ${data.as_org}` : ""} · {fmtTime(data.started_at)} ·
            lasted {fmtDuration(data.duration_ms)}
          </div>
        </div>
        <Link to="/sessions">← All sessions</Link>
      </div>

      <div className="grid cols-4" style={{ marginBottom: 16 }}>
        <div className="card stat">
          <div className="label">Events</div>
          <div className="value">{fmtNumber(data.event_count)}</div>
          <div className="delta muted">{fmtNumber(events.length)} in transcript</div>
        </div>
        <div className="card stat">
          <div className="label">Commands</div>
          <div className="value" style={data.commands_run ? { color: "var(--sev-high)" } : undefined}>
            {fmtNumber(data.commands_run)}
          </div>
          <div className="delta muted">{data.commands_run ? "reached a shell" : "no shell"}</div>
        </div>
        <div className="card stat">
          <div className="label">Auth attempts</div>
          <div className="value">{fmtNumber(data.auth_attempts)}</div>
          <div className="delta muted">{fmtNumber(data.bytes_in)} bytes in</div>
        </div>
        <div className="card stat">
          <div className="label">Closed by</div>
          <div className="value" style={{ fontSize: 20 }}>
            {data.closed_by || "—"}
          </div>
          <div className="delta muted">{data.client_banner || "no banner"}</div>
        </div>
      </div>

      <div className="card" style={{ marginBottom: 16 }}>
        <div className="row spread" style={{ marginBottom: 10, flexWrap: "wrap", gap: 12 }}>
          <div className="row" style={{ gap: 8 }}>
            <button className="primary" onClick={toggle} style={{ minWidth: 92 }}>
              {playing ? "❚❚ Pause" : finished ? "↻ Replay" : "▶ Play"}
            </button>
            <button onClick={() => step(-1)} disabled={cursor === 0} title="Previous event (←)">
              ‹
            </button>
            <button onClick={() => step(1)} disabled={finished} title="Next event (→)">
              ›
            </button>
            <div className="seg" role="group" aria-label="Playback speed">
              {SPEEDS.map((s) => (
                <button key={s} className={speed === s ? "active" : ""} onClick={() => setSpeed(s)}>
                  {s}×
                </button>
              ))}
            </div>
          </div>
          <div className="muted mono" style={{ fontSize: 12 }}>
            {cursor} / {events.length} · {fmtDuration(elapsed)} elapsed
          </div>
        </div>

        <input
          type="range"
          min={0}
          max={events.length}
          value={cursor}
          onChange={(e) => {
            setPlaying(false);
            setCursor(Number(e.target.value));
          }}
          aria-label="Scrub transcript"
          style={{ width: "100%", padding: 0, marginBottom: 12 }}
        />

        <div className="term" ref={paneRef}>
          {visible.length === 0 && (
            <div className="term-line muted">Press play to replay this session.</div>
          )}
          {visible.map((event, i) => (
            <TranscriptLine key={event.event_id} event={event} gap={gapBefore(i)} />
          ))}
          {playing && <span className="term-caret" />}
        </div>

        <div className="muted" style={{ fontSize: 12, marginTop: 10 }}>
          Real inter-event timing, clamped to {MIN_STEP_MS}–{MAX_STEP_MS}ms per step. Idle gaps over{" "}
          {IDLE_MARKER_MS / 1000}s are shown as their true length. Space = play/pause, ← → = step.
        </div>
      </div>

      <div className="card">
        <h3>Full transcript</h3>
        <div className="card-sub">
          Every event in this session, in order — the same rows the replay walks through.
        </div>
        <EventTable events={events} highlightId={visible[visible.length - 1]?.event_id} />
      </div>
    </div>
  );
}

/**
 * One transcript line. The shape follows the event type rather than a fixed
 * layout, so a command reads like a shell line and a login reads like a prompt.
 */
function TranscriptLine({ event: e, gap }) {
  const time = new Date(e.ts).toISOString().slice(11, 19);
  return (
    <>
      {gap > IDLE_MARKER_MS && (
        <div className="term-idle">
          <span>⋯ {fmtDuration(gap)} idle</span>
        </div>
      )}
      <div className={`term-line term-${e.event_type}`}>
        <span className="term-ts">{time}</span>
        <span className="term-body">
          <Body event={e} />
        </span>
      </div>
    </>
  );
}

function Body({ event: e }) {
  switch (e.event_type) {
    case "connect":
      return (
        <span className="muted">
          ── connection opened from {e.src_ip}:{e.src_port} to port {e.dst_port} ──
        </span>
      );
    case "disconnect":
      return <span className="muted">── connection closed ({e.extra?.reason || "client"}) ──</span>;
    case "auth_attempt":
      return (
        <span>
          <span className="term-prompt">login:</span> {e.username || "(none)"}{" "}
          <span className="term-prompt">password:</span>{" "}
          <span className="term-cred">{e.password || "(none)"}</span>
        </span>
      );
    case "auth_success":
      return (
        <span className="term-ok">
          ✓ accepted {e.username || ""} — shell granted (emulated)
        </span>
      );
    case "command":
      return (
        <span>
          <span className="term-prompt">$</span> <span className="term-cmd">{e.command}</span>
        </span>
      );
    case "http_request":
      return (
        <span>
          <span className="term-prompt">{e.http_method}</span> <span className="term-cmd">{e.path}</span>
          {e.status_code ? <span className="muted"> → {e.status_code}</span> : null}
          {e.user_agent ? <div className="term-ua">{e.user_agent}</div> : null}
        </span>
      );
    case "file_upload":
      return (
        <span className="term-warn">
          ⬆ upload {fmtNumber(e.payload_size)} bytes · sha256 {(e.payload_sha256 || "").slice(0, 16)}…
        </span>
      );
    case "error":
      return <span className="term-warn">! {e.command || e.extra?.error || "protocol error"}</span>;
    default:
      return <span className="muted">{e.event_type}</span>;
  }
}

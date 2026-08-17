import { useEffect, useRef, useState, useCallback } from "react";
import { api } from "../api.js";
import EventTable from "../components/EventTable.jsx";
import { ErrorBox } from "../components/common.jsx";

/**
 * Live event feed with incremental polling.
 *
 * Uses the ``after_id`` cursor so each poll transfers only what arrived since
 * the last one, and prepends it — the feed grows at the top like a real console
 * tail. Polling pauses when the browser tab is hidden (no point fetching for a
 * feed nobody is watching) and can be paused manually to read without the list
 * shifting underfoot.
 */
const POLL_MS = 3000;
const MAX_ROWS = 400;

export default function LiveFeed() {
  const [events, setEvents] = useState([]);
  const [paused, setPaused] = useState(false);
  const [service, setService] = useState("");
  const [minSeverity, setMinSeverity] = useState("");
  const [error, setError] = useState(null);
  const [newest, setNewest] = useState(null);
  const cursorRef = useRef(null);

  // Reset the buffer whenever the filter changes — mixing filtered and
  // unfiltered rows in one list would be misleading.
  useEffect(() => {
    setEvents([]);
    cursorRef.current = null;
  }, [service, minSeverity]);

  const poll = useCallback(async () => {
    try {
      const params = { limit: 100 };
      if (service) params.service = service;
      if (minSeverity) params.min_severity = minSeverity;
      if (cursorRef.current) params.after_id = cursorRef.current;

      const fresh = await api.live(params);
      setError(null);
      if (fresh.length) {
        cursorRef.current = fresh[0].event_id;
        setNewest(fresh[0].event_id);
        setEvents((prev) => [...fresh, ...prev].slice(0, MAX_ROWS));
        // Clear the highlight after a moment so it flags only truly new rows.
        setTimeout(() => setNewest(null), 1500);
      }
    } catch (err) {
      setError(err);
    }
  }, [service, minSeverity]);

  useEffect(() => {
    if (paused) return;
    poll();
    const timer = setInterval(() => {
      if (!document.hidden) poll();
    }, POLL_MS);
    return () => clearInterval(timer);
  }, [poll, paused]);

  return (
    <div>
      <div className="topbar">
        <div>
          <h1 className="page-title">Live feed</h1>
          <div className="page-sub">
            <span className="pill-live">
              {!paused && <span className="live-dot" />}
              {paused ? "Paused" : "Streaming"} · {events.length} events buffered
            </span>
          </div>
        </div>
        <div className="controls">
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
          <select value={minSeverity} onChange={(e) => setMinSeverity(e.target.value)}>
            <option value="">Any severity</option>
            <option value="low">Low+</option>
            <option value="medium">Medium+</option>
            <option value="high">High+</option>
            <option value="critical">Critical only</option>
          </select>
          <button className={paused ? "primary" : ""} onClick={() => setPaused((p) => !p)}>
            {paused ? "Resume" : "Pause"}
          </button>
        </div>
      </div>

      {error && <ErrorBox error={error} />}

      <div className="card">
        {events.length === 0 ? (
          <div className="empty">
            Waiting for events… run the honeypot and generate some traffic with{" "}
            <code>python -m attacker.run</code>.
          </div>
        ) : (
          <EventTable events={events} highlightId={newest} showSession />
        )}
      </div>
    </div>
  );
}

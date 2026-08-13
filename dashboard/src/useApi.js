import { useCallback, useEffect, useRef, useState } from "react";

/**
 * Fetch-on-mount hook with loading/error state and manual refresh.
 *
 * ``deps`` re-runs the fetcher when they change. An AbortController cancels the
 * in-flight request on unmount or re-run, so a fast filter change never lets a
 * slow earlier response overwrite a fast later one — the classic stale-render
 * race.
 */
export function useApi(fetcher, deps = [], { pollMs } = {}) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);
  const fetcherRef = useRef(fetcher);
  fetcherRef.current = fetcher;

  const load = useCallback(
    async (signal, quiet = false) => {
      if (!quiet) setLoading(true);
      try {
        const result = await fetcherRef.current({ signal });
        if (!signal.aborted) {
          setData(result);
          setError(null);
        }
      } catch (err) {
        if (err.name !== "AbortError") setError(err);
      } finally {
        if (!signal.aborted) setLoading(false);
      }
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    deps
  );

  useEffect(() => {
    const controller = new AbortController();
    load(controller.signal);

    let timer;
    if (pollMs) {
      timer = setInterval(() => {
        const c = new AbortController();
        load(c.signal, true); // quiet refresh: no loading flash
      }, pollMs);
    }
    return () => {
      controller.abort();
      if (timer) clearInterval(timer);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [load, pollMs]);

  const refresh = useCallback(() => {
    const c = new AbortController();
    return load(c.signal, true);
  }, [load]);

  return { data, error, loading, refresh };
}

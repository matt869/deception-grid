import { useState, useCallback } from "react";

/**
 * A fixed-position tooltip driven by mouse events.
 *
 * Returns `[tip, handlers, Tooltip]`: spread `handlers` onto the hover target,
 * call `handlers.show(content, evt)` from a mark's own handler, and render
 * `<Tooltip />` once at the root of the chart. Kept dependency-free so every
 * hand-rolled SVG chart shares one hover implementation.
 */
export function useTooltip() {
  const [tip, setTip] = useState(null);

  const show = useCallback((content, evt) => {
    setTip({ content, x: evt.clientX, y: evt.clientY });
  }, []);
  const move = useCallback((evt) => {
    setTip((t) => (t ? { ...t, x: evt.clientX, y: evt.clientY } : t));
  }, []);
  const hide = useCallback(() => setTip(null), []);

  const Tooltip = useCallback(() => {
    if (!tip) return null;
    // Flip to the left of the cursor near the right edge so it never clips.
    const flip = tip.x > window.innerWidth - 300;
    return (
      <div
        className="tooltip"
        style={{
          left: flip ? undefined : tip.x + 14,
          right: flip ? window.innerWidth - tip.x + 14 : undefined,
          top: Math.min(tip.y + 14, window.innerHeight - 120),
        }}
      >
        {tip.content}
      </div>
    );
  }, [tip]);

  return [{ show, move, hide }, Tooltip];
}

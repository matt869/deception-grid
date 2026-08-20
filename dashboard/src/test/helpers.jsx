/*
 * Shared test helpers.
 *
 * `mockApi` maps URL substrings to JSON responses, so a test states only the
 * endpoints it cares about and any unexpected request fails loudly rather than
 * resolving to undefined and producing a confusing render.
 *
 * `renderRoute` wraps a component in the router, because every page in this app
 * uses Link or useParams and throws without one.
 */

import { render } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { vi } from "vitest";

export function mockApi(routes) {
  global.fetch = vi.fn(async (url) => {
    const match = Object.keys(routes).find((key) => String(url).includes(key));
    if (match === undefined) {
      throw new Error(`unexpected request: ${url}`);
    }
    const entry = routes[match];
    if (entry instanceof Error) throw entry;
    if (entry && entry.__status) {
      return {
        ok: false,
        status: entry.__status,
        statusText: entry.__statusText || "Error",
        json: async () => ({ detail: entry.detail }),
      };
    }
    return { ok: true, status: 200, json: async () => entry };
  });
  return global.fetch;
}

export const apiError = (status, detail) => ({ __status: status, detail });

export function renderRoute(element, { path = "/", route = "/" } = {}) {
  return render(
    <MemoryRouter initialEntries={[route]}>
      <Routes>
        <Route path={path} element={element} />
        <Route path="*" element={element} />
      </Routes>
    </MemoryRouter>
  );
}

/** A payload row shaped like the API's PayloadOut. */
export function payload(overrides = {}) {
  return {
    sha256: "35da7eb7a40f1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d",
    size: 188,
    file_type: "elf",
    mime: "application/x-executable",
    arch: "mips",
    linkage: "static",
    stripped: true,
    entropy: 3.153,
    likely_packed: false,
    strings_count: 12,
    behaviour_tags: ["iot:busybox", "family-string:mirai"],
    yara_matches: [],
    iocs: { urls: ["hxxp://45[.]33[.]32[.]9/bins/x[.]mips"], ipv4: [], domains: [] },
    format_details: { endianness: "big", bits: 32 },
    first_seen: "2026-08-20T10:00:00Z",
    last_seen: "2026-08-20T14:00:00Z",
    event_count: 3,
    analyzed_at: "2026-08-20T15:00:00Z",
    ...overrides,
  };
}

export const page = (items, total = items.length) => ({ items, total, limit: 50, offset: 0 });

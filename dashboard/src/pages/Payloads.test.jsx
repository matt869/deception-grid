/*
 * Tests for the Payloads page.
 *
 * The assertions that matter most are the ones about defanging. Indicators
 * arrive from the API already inert (`hxxp://evil[.]com`), and this page is the
 * single place in the system where a person might click one — so there are
 * tests that no rendered indicator is an anchor and that nothing on the page
 * carries a fetchable scheme. Those would fail the moment someone added a
 * convenience "open link" affordance, which is exactly when they should.
 *
 * The rest covers the shapes real data takes: a script with no architecture, an
 * artefact nobody has delivered yet, an empty store, and a failing API.
 */

import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import Payloads from "./Payloads.jsx";
import { apiError, mockApi, page, payload, renderRoute } from "../test/helpers.jsx";

const ARCHES = [
  { arch: "mips", count: 4 },
  { arch: "arm", count: 2 },
  { arch: "x86-64", count: 1 },
];

function setup(routes = {}) {
  mockApi({
    "/payloads/architectures": ARCHES,
    "/payloads?": page([payload()]),
    ...routes,
  });
  return renderRoute(<Payloads />, { path: "/payloads", route: "/payloads" });
}

describe("Payloads list", () => {
  it("renders the analysed artefacts", async () => {
    setup();
    expect(await screen.findByText(/35da7eb7a40f/)).toBeInTheDocument();
    expect(screen.getByText("elf")).toBeInTheDocument();
  });

  it("shows the architecture and build shape", async () => {
    setup();
    const digest = await screen.findByText(/35da7eb7a40f/);
    // Scoped to the row: "mips" also appears in the architecture chart above,
    // so an unscoped query matches twice and fails for the wrong reason.
    const row = within(digest.closest("tr"));
    expect(row.getByText("mips")).toBeInTheDocument();
    expect(row.getByText(/static · stripped/)).toBeInTheDocument();
  });

  it("renders the architecture breakdown", async () => {
    setup();
    expect(await screen.findByText("Target architectures")).toBeInTheDocument();
    expect(screen.getByText(/what the operators thought/i)).toBeInTheDocument();
  });

  it("offers every observed architecture as a filter", async () => {
    setup();
    const select = await screen.findByLabelText("Filter by architecture");
    expect(select).toHaveTextContent("mips (4)");
    expect(select).toHaveTextContent("arm (2)");
  });

  it("counts CPU families in the stat tiles", async () => {
    setup();
    await screen.findByText("CPU families");
    const tile = screen.getByText("CPU families").closest(".stat");
    expect(tile).toHaveTextContent("3");
  });

  it("formats byte sizes rather than printing raw counts", async () => {
    setup({ "/payloads?": page([payload({ size: 5242880 })]) });
    expect(await screen.findByText("5.0 MB")).toBeInTheDocument();
  });

  it("shows an em dash where a script has no architecture", async () => {
    setup({
      "/payloads?": page([
        payload({ file_type: "script-sh", arch: null, linkage: null, stripped: null }),
      ]),
    });
    await screen.findByText("script-sh");
    expect(screen.getAllByText("—").length).toBeGreaterThan(0);
  });

  it("explains how to populate an empty store", async () => {
    setup({ "/payloads?": page([]) });
    expect(await screen.findByText(/No analysed artefacts yet/)).toBeInTheDocument();
    expect(screen.getByText("python -m pipeline.analysis.store")).toBeInTheDocument();
  });

  it("surfaces an API failure instead of rendering an empty table", async () => {
    setup({ "/payloads?": apiError(500, "database is locked") });
    expect(await screen.findByText(/Request failed/)).toBeInTheDocument();
    expect(screen.getByText(/database is locked/)).toBeInTheDocument();
  });

  it("says nothing is executed, on the page itself", async () => {
    // The safety claim belongs where a viewer sees it, not only in the docs.
    setup();
    expect(await screen.findByText(/nothing is ever executed/i)).toBeInTheDocument();
  });
});

describe("Payloads filtering", () => {
  it("requests the chosen architecture", async () => {
    const fetchMock = mockApi({
      "/payloads/architectures": ARCHES,
      "/payloads?": page([payload()]),
    });
    renderRoute(<Payloads />, { path: "/payloads", route: "/payloads" });
    await screen.findByText(/35da7eb7a40f/);

    await userEvent.selectOptions(screen.getByLabelText("Filter by architecture"), "mips");

    await waitFor(() => {
      const urls = fetchMock.mock.calls.map((c) => String(c[0]));
      expect(urls.some((u) => u.includes("arch=mips"))).toBe(true);
    });
  });

  it("requests the chosen sort order", async () => {
    const fetchMock = mockApi({
      "/payloads/architectures": ARCHES,
      "/payloads?": page([payload()]),
    });
    renderRoute(<Payloads />, { path: "/payloads", route: "/payloads" });
    await screen.findByText(/35da7eb7a40f/);

    await userEvent.selectOptions(screen.getByLabelText("Sort by"), "entropy");

    await waitFor(() => {
      const urls = fetchMock.mock.calls.map((c) => String(c[0]));
      expect(urls.some((u) => u.includes("sort=entropy"))).toBe(true);
    });
  });

  it("toggles the packed-only filter", async () => {
    const fetchMock = mockApi({
      "/payloads/architectures": ARCHES,
      "/payloads?": page([payload()]),
    });
    renderRoute(<Payloads />, { path: "/payloads", route: "/payloads" });
    await screen.findByText(/35da7eb7a40f/);

    const button = screen.getByRole("button", { name: /packed only/i });
    expect(button).toHaveAttribute("aria-pressed", "false");
    await userEvent.click(button);

    await waitFor(() => {
      const urls = fetchMock.mock.calls.map((c) => String(c[0]));
      expect(urls.some((u) => u.includes("packed_only=true"))).toBe(true);
    });
  });

  it("highlights entropy for a likely-packed artefact", async () => {
    setup({ "/payloads?": page([payload({ likely_packed: true, entropy: 7.91 })]) });
    const cell = await screen.findByTitle("Likely packed");
    expect(cell).toHaveTextContent("7.91");
  });
});

describe("Payload detail", () => {
  async function openDetail(detail = {}) {
    mockApi({
      "/payloads/architectures": ARCHES,
      "/payloads?": page([payload()]),
      [`/payloads/${payload().sha256}`]: { ...payload(), sources: [], ...detail },
    });
    renderRoute(<Payloads />, { path: "/payloads", route: "/payloads" });
    await userEvent.click(await screen.findByText(/35da7eb7a40f/));
    return screen.findByTestId("payload-detail");
  }

  it("opens when a row is clicked", async () => {
    expect(await openDetail()).toBeInTheDocument();
  });

  it("shows the full digest, not the truncated one", async () => {
    const detail = await openDetail();
    expect(detail).toHaveTextContent(payload().sha256);
  });

  it("lists the sources that delivered the artefact", async () => {
    await openDetail({
      sources: [
        { src_ip: "45.33.32.10", events: 2, first_seen: null, last_seen: null },
        { src_ip: "8.8.8.8", events: 1, first_seen: null, last_seen: null },
      ],
    });
    expect(await screen.findByText("45.33.32.10")).toBeInTheDocument();
    expect(screen.getByText(/Delivered by 2 source/)).toBeInTheDocument();
  });

  it("handles an artefact nobody has delivered", async () => {
    // Dropped in by hand, or the event was pruned by retention.
    const detail = await openDetail({ sources: [], event_count: 0 });
    expect(detail).toBeInTheDocument();
    expect(screen.queryByText(/Delivered by/)).not.toBeInTheDocument();
  });

  it("closes again", async () => {
    await openDetail();
    await userEvent.click(screen.getByRole("button", { name: /close/i }));
    await waitFor(() => {
      expect(screen.queryByTestId("payload-detail")).not.toBeInTheDocument();
    });
  });
});

describe("indicators stay inert", () => {
  const LIVE_SCHEMES = ["http://", "https://", "ftp://"];

  it("renders defanged indicators as plain text", async () => {
    mockApi({
      "/payloads/architectures": ARCHES,
      "/payloads?": page([payload()]),
      [`/payloads/${payload().sha256}`]: {
        ...payload(),
        sources: [],
        iocs: {
          urls: ["hxxp://45[.]33[.]32[.]9/bins/x[.]mips"],
          domains: ["evil[.]top"],
          ipv4: ["45[.]33[.]32[.]9"],
        },
      },
    });
    renderRoute(<Payloads />, { path: "/payloads", route: "/payloads" });
    await userEvent.click(await screen.findByText(/35da7eb7a40f/));

    const detail = await screen.findByTestId("payload-detail");
    expect(detail).toHaveTextContent("hxxp://45[.]33[.]32[.]9/bins/x[.]mips");
    expect(detail).toHaveTextContent("evil[.]top");
  });

  it("wraps no indicator in a link", async () => {
    mockApi({
      "/payloads/architectures": ARCHES,
      "/payloads?": page([payload()]),
      [`/payloads/${payload().sha256}`]: {
        ...payload(),
        sources: [],
        iocs: { urls: ["hxxp://45[.]33[.]32[.]9/x"], domains: [], ipv4: [] },
      },
    });
    renderRoute(<Payloads />, { path: "/payloads", route: "/payloads" });
    await userEvent.click(await screen.findByText(/35da7eb7a40f/));
    await screen.findByTestId("payload-detail");

    for (const anchor of document.querySelectorAll("a")) {
      expect(anchor.getAttribute("href") || "").not.toMatch(/45\.33\.32\.9/);
    }
  });

  it("puts no fetchable scheme anywhere in the rendered page", async () => {
    mockApi({
      "/payloads/architectures": ARCHES,
      "/payloads?": page([payload()]),
      [`/payloads/${payload().sha256}`]: {
        ...payload(),
        sources: [],
        iocs: { urls: ["hxxp://45[.]33[.]32[.]9/x"], domains: [], ipv4: [] },
      },
    });
    renderRoute(<Payloads />, { path: "/payloads", route: "/payloads" });
    await userEvent.click(await screen.findByText(/35da7eb7a40f/));
    const detail = await screen.findByTestId("payload-detail");

    for (const scheme of LIVE_SCHEMES) {
      expect(detail.textContent).not.toContain(scheme);
    }
  });

  it("warns the reader not to re-fang", async () => {
    mockApi({
      "/payloads/architectures": ARCHES,
      "/payloads?": page([payload()]),
      [`/payloads/${payload().sha256}`]: {
        ...payload(),
        sources: [],
        iocs: { urls: ["hxxp://a[.]com/x"], domains: [], ipv4: [] },
      },
    });
    renderRoute(<Payloads />, { path: "/payloads", route: "/payloads" });
    await userEvent.click(await screen.findByText(/35da7eb7a40f/));
    expect(await screen.findByText(/Do not re-fang and fetch/)).toBeInTheDocument();
  });
});

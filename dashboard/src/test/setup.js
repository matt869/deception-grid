/*
 * Vitest setup, run once before every test file.
 *
 * Two things happen here. jest-dom adds the DOM matchers (toBeInTheDocument and
 * friends), and fetch is stubbed out at the global level so no test can reach
 * the network by accident — a suite that silently depends on a running API is
 * a suite that fails on someone else's machine for reasons they cannot see.
 * Tests that need a response install their own mock with `mockApi`.
 */

import "@testing-library/jest-dom/vitest";
import { afterEach, beforeEach, vi } from "vitest";
import { cleanup } from "@testing-library/react";

beforeEach(() => {
  global.fetch = vi.fn(() => {
    throw new Error("unmocked fetch: use mockApi() from src/test/helpers.jsx");
  });
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

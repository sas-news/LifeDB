import { describe, expect, test } from "bun:test";
import { DEFAULT_SETTINGS, parseSettings } from "../src/settings.ts";

describe("settings", () => {
  test("accepts a full valid object", () => {
    const result = parseSettings({
      serviceUrl: "http://127.0.0.1:7331",
      token: null,
      tokenFile: "/run/secrets/lifedb-api-token",
      timeoutMs: 8000,
      maxResponseBytes: 512000,
      clientLabel: "opencode",
      workspace: "/srv/project",
      sensitivity: null,
      budgetChars: 12000,
      coreChars: 4000,
      continuityChars: 2000,
      relevantChars: 6000,
      limit: 8,
    });
    expect(result.ok).toBe(true);
  });

  test("applies documented defaults for omitted fields", () => {
    const result = parseSettings({
      serviceUrl: "http://127.0.0.1:7331",
      tokenFile: "/run/secrets/lifedb-api-token",
    });
    if (result.ok !== true) {
      throw new Error(`expected ok, got ${result.reason}`);
    }
    expect(result.settings.timeoutMs).toBe(DEFAULT_SETTINGS.timeoutMs);
    expect(result.settings.maxResponseBytes).toBe(DEFAULT_SETTINGS.maxResponseBytes);
    expect(result.settings.clientLabel).toBe("opencode");
    expect(result.settings.budgetChars).toBe(12000);
    expect(result.settings.limit).toBe(8);
  });

  test("rejects unknown fields closed", () => {
    const result = parseSettings({
      serviceUrl: "http://127.0.0.1:7331",
      tokenFile: "/run/secrets/lifedb-api-token",
      extra: true,
    });
    expect(result.ok).toBe(false);
  });

  test("rejects non-loopback service URL", () => {
    const result = parseSettings({
      serviceUrl: "https://example.com:7331",
      tokenFile: "/run/secrets/lifedb-api-token",
    });
    expect(result.ok).toBe(false);
  });

  test("rejects empty token and empty token file as unset ambiguity", () => {
    const emptyToken = parseSettings({
      serviceUrl: "http://127.0.0.1:7331",
      token: "",
      tokenFile: "/run/secrets/lifedb-api-token",
    });
    expect(emptyToken.ok).toBe(false);
    const emptyFile = parseSettings({
      serviceUrl: "http://127.0.0.1:7331",
      tokenFile: "",
    });
    expect(emptyFile.ok).toBe(false);
  });

  test("rejects both token sources set", () => {
    const result = parseSettings({
      serviceUrl: "http://127.0.0.1:7331",
      token: "x".repeat(32),
      tokenFile: "/run/secrets/lifedb-api-token",
    });
    expect(result.ok).toBe(false);
  });

  test("rejects missing credential sources", () => {
    const result = parseSettings({
      serviceUrl: "http://127.0.0.1:7331",
      token: null,
      tokenFile: null,
    });
    expect(result.ok).toBe(false);
  });

  test("rejects out-of-range budgets and timeouts", () => {
    const badTimeout = parseSettings({
      serviceUrl: "http://127.0.0.1:7331",
      tokenFile: "/run/secrets/lifedb-api-token",
      timeoutMs: 0,
    });
    expect(badTimeout.ok).toBe(false);
    const badBudget = parseSettings({
      serviceUrl: "http://127.0.0.1:7331",
      tokenFile: "/run/secrets/lifedb-api-token",
      budgetChars: -1,
    });
    expect(badBudget.ok).toBe(false);
  });

  test("rejects non-object input without throwing", () => {
    for (const input of [null, 42, "url", []]) {
      expect(parseSettings(input).ok).toBe(false);
    }
  });

  test("rejects inline credentials over the 4096-byte contract", () => {
    const result = parseSettings({
      serviceUrl: "http://127.0.0.1:7331",
      token: "x".repeat(4097),
    });
    expect(result.ok).toBe(false);
  });
});

import { describe, expect, test } from "bun:test";
import { createLogger } from "../src/logging.ts";

describe("sanitized structured logging", () => {
  test("emits only operation and outcome class", () => {
    const entries: Array<unknown> = [];
    const log = createLogger((entry) => {
      entries.push(entry);
    });
    log.info("context.fetch", "ok");
    log.warn("turn.submit", "fail-open");
    log.warn("turn.postflight", "conflict");
    expect(entries.length).toBe(3);
    const first = entries[0] as Record<string, unknown>;
    expect(Object.keys(first).sort()).toEqual(["level", "op", "outcome"]);
  });

  test("sanitizes hostile operation names", () => {
    const entries: Array<Record<string, unknown>> = [];
    const log = createLogger((entry) => {
      entries.push(entry as Record<string, unknown>);
    });
    log.info(`evil ${"k".repeat(32)} /srv/secret`, "ok");
    const op = entries[0]?.["op"];
    expect(typeof op).toBe("string");
    expect(String(op)).not.toContain("k".repeat(32));
  });

  test("rejects unknown outcomes closed", () => {
    const entries: Array<unknown> = [];
    const log = createLogger((entry) => {
      entries.push(entry);
    });
    log.info("context.fetch", "hacked" as never);
    expect(entries.length).toBe(0);
  });

  test("contains a throwing sink", () => {
    const log = createLogger(() => { throw new Error("sink unavailable"); });
    expect(() => log.warn("turn.submit", "fail-open")).not.toThrow();
  });
});

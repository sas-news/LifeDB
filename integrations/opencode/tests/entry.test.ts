import { describe, expect, test } from "bun:test";
import plugin from "../src/entry.ts";

describe("bundled OpenCode entrypoint", () => {
  test("exports the exact server plugin shape", () => {
    expect(plugin.id).toBe("lifedb");
    expect(typeof plugin.server).toBe("function");
  });
});

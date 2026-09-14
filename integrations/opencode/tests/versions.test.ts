import { describe, expect, test } from "bun:test";
import { COMPAT_OPENCODE_VERSION } from "../src/settings.ts";
import manifest from "../package.json";

function getDevVersion(deps: unknown, name: string): string {
  if (typeof deps !== "object" || deps === null) {
    throw new Error("devDependencies must be an object");
  }
  if (!(name in deps)) {
    throw new Error(`missing devDependency ${name}`);
  }
  const value: unknown = (deps as Record<string, unknown>)[name];
  if (typeof value !== "string") {
    throw new Error(`devDependency ${name} must be a string`);
  }
  return value;
}

describe("version contract", () => {
  test("pins both host type packages exactly", () => {
    const data: unknown = manifest;
    if (typeof data !== "object" || data === null || !("devDependencies" in data)) {
      throw new Error("package.json must declare devDependencies");
    }
    const deps: unknown = (data as { devDependencies: unknown }).devDependencies;
    expect(getDevVersion(deps, "@opencode-ai/plugin")).toBe("1.18.29");
    expect(getDevVersion(deps, "@opencode-ai/sdk")).toBe("1.18.29");
  });

  test("compatibility target matches the pinned host", () => {
    expect(COMPAT_OPENCODE_VERSION).toBe("1.18.29");
  });

  test("declares no runtime dependencies", () => {
    const data: unknown = manifest;
    if (typeof data !== "object" || data === null) {
      throw new Error("package.json must be an object");
    }
    expect("dependencies" in data).toBe(false);
  });
});

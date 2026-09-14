import { describe, expect, test } from "bun:test";
import { composeHooks } from "../src/plugin.ts";

describe("OpenCode local hook composition", () => {
  test("preserves lifecycle hooks and disposes each side once", async () => {
    let preflightDisposals = 0;
    let postflightDisposals = 0;
    const preflight = { "chat.message": async () => undefined, dispose: async () => { preflightDisposals += 1; } };
    const postflight = { event: async () => undefined, dispose: async () => { postflightDisposals += 1; } };
    const hooks = composeHooks(preflight, postflight);
    expect(hooks["chat.message"]).toBe(preflight["chat.message"]);
    expect(hooks.event).toBe(postflight.event);
    await hooks.dispose?.();
    await hooks.dispose?.();
    expect(preflightDisposals).toBe(1);
    expect(postflightDisposals).toBe(1);
  });
});

import { describe, expect, test } from "bun:test";
import { PreflightState } from "../src/preflightState.ts";

describe("Task7 preflight state", () => {
  test("keeps bounded state, evicts oldest deterministically, and clears on disposal", async () => {
    const state = new PreflightState({ maxSessions: 2, maxUsersPerSession: 2, maxUsers: 3 });
    expect(state.register({ sessionID: "s1", messageID: "m1", query: "one" })).toBe(true);
    expect(state.register({ sessionID: "s1", messageID: "m2", query: "two" })).toBe(true);
    expect(state.register({ sessionID: "s2", messageID: "m3", query: "three" })).toBe(true);
    expect(state.register({ sessionID: "s3", messageID: "m4", query: "four" })).toBe(true);
    expect(state.read("s1", "m1")).toBeUndefined();
    expect(state.sessionCount).toBeLessThanOrEqual(2);
    expect(state.userCount).toBeLessThanOrEqual(3);
    expect(state.evict("s2", "m3")).toBe(true);
    expect(state.read("s2", "m3")).toBeUndefined();
    await state.dispose();
    expect(state.sessionCount).toBe(0);
    expect(state.userCount).toBe(0);
    expect(state.register({ sessionID: "s4", messageID: "m5", query: "five" })).toBe(false);
  });

  test("enumerates immutable pending snapshots for one session in registration order", () => {
    const state = new PreflightState();
    state.register({ sessionID: "s1", messageID: "m2", query: "two", workspace: "/workspace" });
    state.register({ sessionID: "s1", messageID: "m1", query: "one" });
    state.register({ sessionID: "s2", messageID: "other", query: "other" });

    const snapshots = state.readAll("s1");
    expect(snapshots.map((entry) => entry.messageID)).toEqual(["m2", "m1"]);
    expect(snapshots[0]).toEqual({ sessionID: "s1", messageID: "m2", query: "two", workspace: "/workspace", context: { status: "unresolved" } });
    expect(state.readAll("missing")).toEqual([]);
  });
});

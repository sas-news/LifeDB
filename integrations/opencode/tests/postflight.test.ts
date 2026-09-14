import { describe, expect, test } from "bun:test";
import type { Part } from "@opencode-ai/sdk";
import { createPostflightHooks, type SessionMessagesClient } from "../src/postflight.ts";
import { PreflightState } from "../src/preflightState.ts";
import type { BridgeDeps } from "../src/bridge.ts";
import type { Transport } from "../src/httpClient.ts";
import type { Settings } from "../src/settings.ts";
import { assistant, DIRECTORY, idle, messageList, SESSION, text, TOKEN, user, WORKSPACE } from "./postflightFixtures.ts";

function settings(): Settings { return { serviceUrl: "http://127.0.0.1:7331", token: TOKEN, tokenFile: null, timeoutMs: 1000, maxResponseBytes: 1024 * 1024, clientLabel: "opencode", workspace: WORKSPACE, sensitivity: "personal", budgetChars: 12000, coreChars: 4000, continuityChars: 2000, relevantChars: 6000, limit: 8 }; }
function deps(transport: Transport, entries: Array<unknown> = []): BridgeDeps { return { transport, clock: () => 1000, serviceUrl: "http://127.0.0.1:7331", token: TOKEN, timeoutMs: 1000, maxResponseBytes: 1024 * 1024, log: (entry) => { entries.push(entry); } }; }
function successTransport(calls: Array<Record<string, unknown>>, status = 201): Transport { return async (request) => { const parsed: unknown = JSON.parse(request.body); if (isRecord(parsed)) calls.push(parsed); return { status, headers: {}, body: new Uint8Array() }; }; }
function isRecord(value: unknown): value is Record<string, unknown> { return typeof value === "object" && value !== null && !Array.isArray(value); }
function client(messages: Array<{ info: import("@opencode-ai/sdk").Message; parts: Part[] }>): SessionMessagesClient { return { session: { messages: async (options) => ({ data: messages, options }) } }; }
async function register(state: PreflightState): Promise<void> { state.register({ sessionID: SESSION, messageID: "u1", query: "question", workspace: WORKSPACE }); }

describe("Task8 postflight hooks", () => {
  test("captures the latest final linked assistant as ordered clean text", async () => {
    const calls: Array<Record<string, unknown>> = [];
    const state = new PreflightState();
    await register(state);
    const messages = messageList(user("u1"), assistant("tool", "u1", 2000, "tool output"), assistant("final", "u1", 3000, "first"), { ...assistant("latest", "u1", 4000, "second"), parts: [text("latest", "second"), text("latest", "ignored", { ignored: true }), { id: "reason", sessionID: SESSION, messageID: "latest", type: "reasoning", text: "thought", time: { start: 1 } }] });
    const hooks = createPostflightHooks({ settings: settings(), deps: deps(successTransport(calls)), state, client: client(messages), directory: DIRECTORY });
    const event = hooks.event;
    if (event === undefined) throw new Error("event hook missing");
    await event(idle());
    expect(calls).toEqual([{ host: "opencode", session_id: SESSION, turn_id: "u1", workspace: WORKSPACE, user_text: "question", assistant_text: "second", captured_at: "1970-01-01T00:00:04.000Z" }]);
    expect(state.read(SESSION, "u1")).toBeUndefined();
  });

  test("uses exact SDK path/query and suppresses overlapping idle", async () => {
    const calls: Array<Record<string, unknown>> = [];
    let release: () => void = () => { throw new Error("messages was not called"); };
    const entered = new Promise<void>((resolve) => { release = resolve; });
    const sdk: SessionMessagesClient = { session: { messages: async (options) => { expect(options).toEqual({ path: { id: SESSION }, query: { directory: DIRECTORY } }); await entered; return { data: messageList(user("u1"), assistant("a1", "u1")) }; } } };
    const state = new PreflightState();
    await register(state);
    const hooks = createPostflightHooks({ settings: settings(), deps: deps(successTransport(calls)), state, client: sdk, directory: DIRECTORY });
    const event = hooks.event;
    if (event === undefined) throw new Error("event hook missing");
    const statusIdle = { event: { type: "session.status" as const, properties: { sessionID: SESSION, status: { type: "idle" as const } } } };
    const first = event(statusIdle);
    const second = event(idle());
    const third = event(statusIdle);
    release();
    await Promise.all([first, second, third]);
    expect(calls).toHaveLength(1);
  });

  test("treats missing, compacted, non-final, and textless pairs as terminal", async () => {
    const state = new PreflightState();
    const attempts: Array<Record<string, unknown>> = [];
    const hooks = createPostflightHooks({ settings: settings(), deps: deps(successTransport(attempts)), state, client: client([]), directory: DIRECTORY });
    const event = hooks.event;
    if (event === undefined) throw new Error("event hook missing");
    for (const messages of [[], messageList(user("u1"), assistant("a1", "u1", 0, "")), messageList(user("u1"), { ...assistant("a1", "u1"), info: { ...assistant("a1", "u1").info, finish: "tool-calls" } }), messageList(user("u1"), { ...assistant("a1", "u1"), parts: [{ id: "compact", sessionID: SESSION, messageID: "a1", type: "compaction", auto: true }] }), messageList(user("u1"), { ...assistant("a1", "u1"), info: { ...assistant("a1", "u1").info, finish: "aborted" } })]) {
      state.register({ sessionID: SESSION, messageID: "u1", query: "question", workspace: WORKSPACE });
      const current = createPostflightHooks({ settings: settings(), deps: deps(successTransport(attempts)), state, client: client(messages), directory: DIRECTORY }).event;
      if (current === undefined) throw new Error("event hook missing");
      await current(idle());
      expect(state.read(SESSION, "u1")).toBeUndefined();
    }
    expect(attempts).toHaveLength(0);
  });

  test("scopes compaction eviction to its associated pending pair", async () => {
    const calls: Array<Record<string, unknown>> = [];
    const state = new PreflightState();
    state.register({ sessionID: SESSION, messageID: "u1", query: "question-a", workspace: WORKSPACE });
    state.register({ sessionID: SESSION, messageID: "u2", query: "question-b", workspace: WORKSPACE });
    const compactedAssistant = assistant("a2", "u2", 4000, "answer-b");
    const messages = messageList(
      user("u1", "question-a"),
      assistant("a1", "u1", 3000, "answer-a"),
      user("u2", "question-b"),
      { ...compactedAssistant, parts: [...compactedAssistant.parts, { id: "compact-b", sessionID: SESSION, messageID: "a2", type: "compaction", auto: true }] },
    );
    const hooks = createPostflightHooks({ settings: settings(), deps: deps(successTransport(calls)), state, client: client(messages), directory: DIRECTORY });
    const event = hooks.event;
    if (event === undefined) throw new Error("event hook missing");
    await event(idle());
    expect(calls).toHaveLength(1);
    expect(calls[0]?.["turn_id"]).toBe("u1");
    expect(state.userCount).toBe(0);
  });

  test("postflight outcome reflects the submit result", async () => {
    for (const [status, expected] of [[201, "ok"], [400, "fail-open"], [409, "conflict"], [422, "rejected"]] as const) {
      const entries: Array<unknown> = [];
      const state = new PreflightState();
      await register(state);
      const hooks = createPostflightHooks({ settings: settings(), deps: deps(successTransport([], status), entries), state, client: client(messageList(user("u1"), assistant("a1", "u1"))), directory: DIRECTORY });
      const event = hooks.event;
      if (event === undefined) throw new Error("event hook missing");
      await event(idle());
      const postflight = entries.filter((entry): entry is Record<string, unknown> => isRecord(entry) && entry["op"] === "turn.postflight");
      expect(postflight).toEqual([{ op: "turn.postflight", outcome: expected }]);
    }
  });

  test("evicts pending state for every bridge outcome without retry", async () => {
    for (const status of [201, 400, 401, 409, 422, 500]) {
      const calls: Array<Record<string, unknown>> = [];
      const state = new PreflightState();
      await register(state);
      const hooks = createPostflightHooks({ settings: settings(), deps: deps(successTransport(calls, status)), state, client: client(messageList(user("u1"), assistant("a1", "u1"))), directory: DIRECTORY });
      const event = hooks.event;
      if (event === undefined) throw new Error("event hook missing");
      await event(idle());
      expect(calls).toHaveLength(1);
      expect(state.userCount).toBe(0);
    }
  });

  test("captures a user message with OpenCode summary metadata without persisting it", async () => {
    const calls: Array<Record<string, unknown>> = [];
    const state = new PreflightState();
    await register(state);
    const sourceUser = user("u1");
    const summarizedUser = { ...sourceUser, info: { ...sourceUser.info, summary: { diffs: [] } } };
    const hooks = createPostflightHooks({ settings: settings(), deps: deps(successTransport(calls)), state, client: client(messageList(summarizedUser, assistant("a1", "u1", 3000, "answer"))), directory: DIRECTORY });
    const event = hooks.event;
    if (event === undefined) throw new Error("event hook missing");
    await event(idle());
    expect(calls).toEqual([{ host: "opencode", session_id: SESSION, turn_id: "u1", workspace: WORKSPACE, user_text: "question", assistant_text: "answer", captured_at: "1970-01-01T00:00:03.000Z" }]);
    expect(calls[0]?.["summary"]).toBeUndefined();
    expect(state.read(SESSION, "u1")).toBeUndefined();
  });

  test("ignores non-idle events and captures once on deprecated idle", async () => {
    const state = new PreflightState();
    const calls: Array<Record<string, unknown>> = [];
    await register(state);
    const hooks = createPostflightHooks({ settings: settings(), deps: deps(successTransport(calls)), state, client: client(messageList(user("u1"), assistant("a1", "u1"))), directory: DIRECTORY });
    const event = hooks.event;
    if (event === undefined) throw new Error("event hook missing");
    await event({ event: { type: "session.status", properties: { sessionID: SESSION, status: { type: "busy" } } } });
    await event({ event: { type: "session.status", properties: { sessionID: SESSION, status: { type: "retry", attempt: 1, message: "retry", next: 1000 } } } });
    await event({ event: { type: "server.connected", properties: {} } });
    expect(state.userCount).toBe(1);
    await event({ event: { type: "session.status", properties: { sessionID: SESSION, status: { type: "idle" } } } });
    expect(state.userCount).toBe(1);
    expect(calls).toHaveLength(0);
    await event(idle());
    expect(state.userCount).toBe(0);
    expect(calls).toHaveLength(1);
  });
});

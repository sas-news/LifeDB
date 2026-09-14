import { describe, expect, test } from "bun:test";
import type { Message, Part, TextPart, UserMessage } from "@opencode-ai/sdk";
import { type BridgeDeps, type ContextPack } from "../src/bridge.ts";
import { createPreflightHooks } from "../src/preflight.ts";
import { PreflightState } from "../src/preflightState.ts";
import type { Settings } from "../src/settings.ts";
import type { Transport } from "../src/httpClient.ts";

const TOKEN = "k".repeat(32);
const SESSION = "ses-1";
const WORKSPACE = "/srv/project";
const SOURCE_ID = "019d0000-0000-7000-8000-000000000001";

function settings(): Settings {
  return {
    serviceUrl: "http://127.0.0.1:7331",
    token: TOKEN,
    tokenFile: null,
    timeoutMs: 1000,
    maxResponseBytes: 1024 * 1024,
    clientLabel: "opencode",
    workspace: WORKSPACE,
    sensitivity: "personal",
    budgetChars: 12000,
    coreChars: 4000,
    continuityChars: 2000,
    relevantChars: 6000,
    limit: 8,
  };
}

function pack(): ContextPack {
  return {
    schema: "0.2",
    id: "019d0000-0000-7000-8000-000000000002",
    generated_at: "2026-09-07T00:00:00Z",
    query: "hello",
    core: [{ source_kind: "canon", source_id: SOURCE_ID, title: "Memory", snippet: "remembered" }],
    continuity: [],
    relevant: [],
    evidence_handles: [],
    rendered_markdown: `<lifedb-data source="canon:${SOURCE_ID}" sensitivity="personal" untrusted="true">remembered</lifedb-data>`,
    authorization: { principal: "owner", sensitivity_ceiling: "personal" },
    budget: { budget_chars: 100, core_chars: 100, continuity_chars: 0, relevant_chars: 0, used_chars: 9 },
    watermark: { durable_sequence: 1, indexed_sequence: 1, dirty: false },
    truncated: false,
    degraded: [],
  };
}

function userMessage(id: string, sessionID = SESSION): UserMessage {
  return { id, sessionID, role: "user", time: { created: 1000 }, agent: "build", model: { providerID: "provider", modelID: "model" } };
}

function textPart(messageID: string, text = "hello"): TextPart {
  return { id: `part-${messageID}`, sessionID: SESSION, messageID, type: "text", text };
}

function depsWith(transport: Transport): BridgeDeps {
  return { transport, clock: () => 1000, serviceUrl: "http://127.0.0.1:7331", token: TOKEN, timeoutMs: 1000, maxResponseBytes: 1024 * 1024, log: () => undefined };
}

function output(message: UserMessage, parts: Part[]): { messages: Array<{ info: Message; parts: Part[] }> } {
  return { messages: [{ info: message, parts }] };
}

async function register(hooks: ReturnType<typeof createPreflightHooks>, message: UserMessage, parts: Part[]): Promise<void> {
  const chat = hooks["chat.message"];
  if (chat === undefined) throw new Error("chat.message hook missing");
  await chat({ sessionID: message.sessionID, messageID: message.id }, { message, parts });
}

function transformOf(hooks: ReturnType<typeof createPreflightHooks>): NonNullable<ReturnType<typeof createPreflightHooks>["experimental.chat.messages.transform"]> {
  const transform = hooks["experimental.chat.messages.transform"];
  if (transform === undefined) throw new Error("transform hook missing");
  return transform;
}

describe("Task7 lifecycle blockers", () => {
  test("does not inject after disposal completes during an in-flight fetch", async () => {
    let release: () => void = () => { throw new Error("transport was not entered"); };
    let enteredResolve: () => void = () => { throw new Error("transport entry was not observed"); };
    const entered = new Promise<void>((resolve) => { enteredResolve = resolve; });
    const transport: Transport = async () => {
      enteredResolve();
      await new Promise<void>((resolve) => { release = resolve; });
      return { status: 200, headers: {}, body: new TextEncoder().encode(JSON.stringify(pack())) };
    };
    const hooks = createPreflightHooks({ settings: settings(), deps: depsWith(transport) });
    const message = userMessage("u1");
    await register(hooks, message, [textPart(message.id)]);
    const messages = output(message, [textPart(message.id)]);
    const pending = transformOf(hooks)({}, messages);
    await entered;
    await hooks.dispose?.();
    release();
    await pending;
    expect(messages.messages).toHaveLength(1);
  });

  test("evicting one in-flight user does not cancel or inject it and leaves a newer user usable", async () => {
    let resolveFirstEntered: () => void = () => { throw new Error("first transport entry was not observed"); };
    let resolveSecondEntered: () => void = () => { throw new Error("second transport entry was not observed"); };
    const firstEntered = new Promise<void>((resolve) => { resolveFirstEntered = resolve; });
    const secondEntered = new Promise<void>((resolve) => { resolveSecondEntered = resolve; });
    let releaseFirst: () => void = () => { throw new Error("first transport was not released"); };
    let releaseSecond: () => void = () => { throw new Error("second transport was not released"); };
    const firstGate = new Promise<void>((resolve) => { releaseFirst = resolve; });
    const secondGate = new Promise<void>((resolve) => { releaseSecond = resolve; });
    const transport: Transport = async (request) => {
      const query = request.body.includes('"query":"one"') ? "one" : "two";
      if (query === "one") {
        resolveFirstEntered();
        await firstGate;
      } else {
        resolveSecondEntered();
        await secondGate;
      }
      return { status: 200, headers: {}, body: new TextEncoder().encode(JSON.stringify(pack())) };
    };
    const state = new PreflightState();
    const hooks = createPreflightHooks({ settings: settings(), deps: depsWith(transport), state });
    const first = userMessage("u1");
    const second = userMessage("u2");
    await register(hooks, first, [textPart(first.id, "one")]);
    const firstMessages = output(first, [textPart(first.id, "one")]);
    const firstPending = transformOf(hooks)({}, firstMessages);
    await firstEntered;
    expect(state.evict(SESSION, first.id)).toBe(true);
    await register(hooks, second, [textPart(second.id, "two")]);
    const secondMessages = output(second, [textPart(second.id, "two")]);
    const secondPending = transformOf(hooks)({}, secondMessages);
    await secondEntered;
    releaseFirst();
    releaseSecond();
    await Promise.all([firstPending, secondPending]);
    expect(firstMessages.messages).toHaveLength(1);
    expect(secondMessages.messages).toHaveLength(2);
  });

  test("does not inject an older selected-head user after a newer user registers", async () => {
    let calls = 0;
    const transport: Transport = async () => {
      calls += 1;
      return { status: 200, headers: {}, body: new TextEncoder().encode(JSON.stringify(pack())) };
    };
    const hooks = createPreflightHooks({ settings: settings(), deps: depsWith(transport) });
    const first = userMessage("u1");
    const second = userMessage("u2");
    await register(hooks, first, [textPart(first.id)]);
    await register(hooks, second, [textPart(second.id)]);
    const selectedHead = output(first, [textPart(first.id)]);
    await transformOf(hooks)({}, selectedHead);
    expect(selectedHead.messages).toHaveLength(1);
    expect(calls).toBe(0);
  });

  test("rejects malformed mixed parts while ignoring valid non-text parts", async () => {
    let calls = 0;
    const transport: Transport = async () => {
      calls += 1;
      return { status: 200, headers: {}, body: new TextEncoder().encode(JSON.stringify(pack())) };
    };
    const invalidHooks = createPreflightHooks({ settings: settings(), deps: depsWith(transport) });
    const message = userMessage("u1");
    const chat = invalidHooks["chat.message"];
    if (chat === undefined) throw new Error("chat.message hook missing");
    await Reflect.apply(chat, undefined, [
      { sessionID: SESSION, messageID: message.id },
      { message, parts: [textPart(message.id), { type: "file", bad: true }] },
    ]);
    const invalidOutput = output(message, [textPart(message.id)]);
    await transformOf(invalidHooks)({}, invalidOutput);
    expect(invalidOutput.messages).toHaveLength(1);
    const validHooks = createPreflightHooks({ settings: settings(), deps: depsWith(transport) });
    const validParts: Part[] = [
      textPart(message.id),
      { id: "file-1", sessionID: SESSION, messageID: message.id, type: "file", mime: "text/plain", filename: "x", url: "file:///x" },
      { id: "reasoning-1", sessionID: SESSION, messageID: message.id, type: "reasoning", text: "thought", time: { start: 1000 } },
    ];
    await register(validHooks, message, validParts);
    const messages = output(message, validParts);
    await transformOf(validHooks)({}, messages);
    expect(messages.messages).toHaveLength(2);
    expect(calls).toBe(1);
  });

  test("fails open for malformed transform entries", async () => {
    const hooks = createPreflightHooks({ settings: settings(), deps: depsWith(async () => ({ status: 200, headers: {}, body: new Uint8Array() })) });
    const transform = transformOf(hooks);
    const malformed = { messages: [null] };
    await Reflect.apply(transform, undefined, [{}, malformed]);
    expect(malformed.messages).toHaveLength(1);
  });
});

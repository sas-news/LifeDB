import { describe, expect, test } from "bun:test";
import type { Message, Part, TextPart, UserMessage } from "@opencode-ai/sdk";
import { type BridgeDeps, type ContextPack } from "../src/bridge.ts";
import { type Settings } from "../src/settings.ts";
import { PREFLIGHT_MARKER, createPreflightHooks } from "../src/preflight.ts";
import type { Transport } from "../src/httpClient.ts";

const TOKEN = "k".repeat(32);
const SESSION = "ses-1";
const WORKSPACE = "/srv/project";
const USER_ID = "msg-user-1";
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

function userMessage(id = USER_ID, sessionID = SESSION): UserMessage {
  return {
    id,
    sessionID,
    role: "user",
    time: { created: 1000 },
    agent: "build",
    model: { providerID: "provider", modelID: "model" },
  };
}

function textPart(messageID = USER_ID, text = "hello"): TextPart {
  return { id: `part-${messageID}`, sessionID: SESSION, messageID, type: "text", text };
}

function syntheticTextPart(): TextPart {
  return { ...textPart(), synthetic: true };
}

function ignoredTextPart(): TextPart {
  return { ...textPart(), ignored: true };
}

function depsWith(transport: Transport): BridgeDeps {
  return {
    transport,
    clock: () => 1000,
    serviceUrl: "http://127.0.0.1:7331",
    token: TOKEN,
    timeoutMs: 1000,
    maxResponseBytes: 1024 * 1024,
    log: () => undefined,
  };
}

function transformOutput(message: UserMessage = userMessage(), parts: Part[] = [textPart()]): {
  messages: Array<{ info: Message; parts: Part[] }>;
} {
  return { messages: [{ info: message, parts }] };
}

async function register(
  hooks: ReturnType<typeof createPreflightHooks>,
  message: UserMessage = userMessage(),
  parts: Part[] = [textPart(message.id)],
): Promise<void> {
  const chat = hooks["chat.message"];
  if (chat === undefined) throw new Error("chat.message hook missing");
  await chat({ sessionID: message.sessionID, messageID: message.id }, { message, parts });
}

describe("Task7 preflight hooks", () => {
  test("registers without mutation and injects one equivalent API-only message per fresh transform", async () => {
    let calls = 0;
    let request = "";
    const transport: Transport = async (input) => {
      calls += 1;
      request = input.body;
      return { status: 200, headers: {}, body: new TextEncoder().encode(JSON.stringify(pack())) };
    };
    const hooks = createPreflightHooks({ settings: settings(), deps: depsWith(transport) });
    const message = userMessage();
    const parts = [textPart()];
    const before = structuredClone({ message, parts });
    await register(hooks, message, parts);
    expect({ message, parts }).toEqual(before);
    const first = transformOutput(message, parts);
    const firstExisting = first.messages[0];
    if (firstExisting === undefined) throw new Error("missing first message");
    const firstInfo = firstExisting.info;
    const firstParts = firstExisting.parts;
    const firstArray = first.messages;
    const transform = hooks["experimental.chat.messages.transform"];
    if (transform === undefined) throw new Error("transform hook missing");
    await transform({}, first);
    expect(first.messages).toBe(firstArray);
    expect(first.messages[1]?.info).toBe(firstInfo);
    expect(first.messages[1]?.parts).toBe(firstParts);
    const injected = first.messages[0];
    if (injected === undefined) throw new Error("missing injection");
    expect(injected.info.role).toBe("user");
    expect(Object.keys(injected.info).sort()).toEqual(["agent", "id", "model", "role", "sessionID", "time"]);
    expect(injected.parts).toHaveLength(1);
    expect(Object.keys(injected.parts[0] ?? {}).sort()).toEqual(["id", "messageID", "sessionID", "synthetic", "text", "type"]);
    expect(injected.parts[0]).toMatchObject({ type: "text", synthetic: true });
    const injectedPart = injected.parts[0];
    if (injectedPart === undefined || injectedPart.type !== "text") throw new Error("missing text injection");
    expect(injectedPart.text).toContain(PREFLIGHT_MARKER);
    expect(request).toContain('"client":"opencode"');
    expect(request).toContain('"workspace":"/srv/project"');
    expect(request).toContain('"sensitivity_ceiling":"personal"');
    expect(request).toContain('"budget_chars":12000');
    const second = transformOutput(message, parts);
    await transform({}, second);
    expect(calls).toBe(1);
    expect(second.messages).toHaveLength(2);
    expect(second.messages[0]).toEqual(first.messages[0]);
    await hooks.dispose?.();
  });

  test("isolates sessions and rejects stale, later-real-user, and compaction sequences", async () => {
    let calls = 0;
    const transport: Transport = async () => {
      calls += 1;
      return { status: 200, headers: {}, body: new TextEncoder().encode(JSON.stringify(pack())) };
    };
    const hooks = createPreflightHooks({ settings: settings(), deps: depsWith(transport) });
    await register(hooks);
    const transform = hooks["experimental.chat.messages.transform"];
    if (transform === undefined) throw new Error("transform hook missing");
    const otherSession = transformOutput(userMessage(USER_ID, "ses-2"), [textPart(USER_ID)]);
    await transform({}, otherSession);
    expect(otherSession.messages).toHaveLength(1);
    const later = transformOutput(userMessage("msg-user-2"), [textPart("msg-user-2")]);
    later.messages.unshift({ info: userMessage(), parts: [textPart()] });
    await transform({}, later);
    expect(later.messages).toHaveLength(2);
    const compacted = transformOutput(userMessage(), [
      textPart(),
      { id: "compact-1", sessionID: SESSION, messageID: USER_ID, type: "compaction", auto: true },
    ]);
    await transform({}, compacted);
    expect(compacted.messages).toHaveLength(1);
    expect(calls).toBe(0);
  });

  test("shares one in-flight fetch across concurrent transforms", async () => {
    let calls = 0;
    let enteredTransport = false;
    let releaseTransport = (): void => {
      throw new Error("transport was not entered");
    };
    const transport: Transport = async () => {
      calls += 1;
      await new Promise<void>((resolve) => {
        enteredTransport = true;
        releaseTransport = resolve;
      });
      return { status: 200, headers: {}, body: new TextEncoder().encode(JSON.stringify(pack())) };
    };
    const hooks = createPreflightHooks({ settings: settings(), deps: depsWith(transport) });
    await register(hooks);
    const transform = hooks["experimental.chat.messages.transform"];
    if (transform === undefined) throw new Error("transform setup failed");
    const first = transformOutput();
    const second = transformOutput();
    const firstTransform = transform({}, first);
    const secondTransform = transform({}, second);
    await Promise.resolve();
    expect(calls).toBe(1);
    expect(enteredTransport).toBe(true);
    releaseTransport();
    await Promise.all([firstTransform, secondTransform]);
    expect(first.messages).toHaveLength(2);
    expect(second.messages).toHaveLength(2);
  });

  test("rejects synthetic, ignored, marker, file-only, empty, and malformed registrations", async () => {
    let calls = 0;
    const transport: Transport = async () => {
      calls += 1;
      return { status: 200, headers: {}, body: new TextEncoder().encode(JSON.stringify(pack())) };
    };
    const hooks = createPreflightHooks({ settings: settings(), deps: depsWith(transport) });
    const cases: Array<Part[]> = [
      [syntheticTextPart()],
      [ignoredTextPart()],
      [textPart(USER_ID, PREFLIGHT_MARKER)],
      [{ id: "file-1", sessionID: SESSION, messageID: USER_ID, type: "file", mime: "text/plain", filename: "x", url: "file:///x" }],
      [],
    ];
    for (const parts of cases) await register(hooks, userMessage(), parts);
    await register(hooks, { ...userMessage(), id: "" }, [textPart()]);
    const transform = hooks["experimental.chat.messages.transform"];
    if (transform === undefined) throw new Error("transform hook missing");
    const output = transformOutput();
    await transform({}, output);
    expect(output.messages).toHaveLength(1);
    expect(calls).toBe(0);
  });

});

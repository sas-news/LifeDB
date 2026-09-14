import { describe, expect, test } from "bun:test";
import type { Message, Part, TextPart, UserMessage } from "@opencode-ai/sdk";
import { type BridgeDeps, type ContextPack } from "../src/bridge.ts";
import { createPreflightHooks } from "../src/preflight.ts";
import type { Transport } from "../src/httpClient.ts";
import type { Settings } from "../src/settings.ts";

const TOKEN = "k".repeat(32);
const SESSION = "ses-1";
const USER_ID = "msg-user-1";

function settings(): Settings {
  return {
    serviceUrl: "http://127.0.0.1:7331",
    token: TOKEN,
    tokenFile: null,
    timeoutMs: 1000,
    maxResponseBytes: 1024 * 1024,
    clientLabel: "opencode",
    workspace: "/srv/project",
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
    core: [{ source_kind: "canon", source_id: "019d0000-0000-7000-8000-000000000001", title: "Memory", snippet: "remembered" }],
    continuity: [],
    relevant: [],
    evidence_handles: [],
    rendered_markdown: '<lifedb-data source="canon:019d0000-0000-7000-8000-000000000001" sensitivity="personal" untrusted="true">remembered</lifedb-data>',
    authorization: { principal: "owner", sensitivity_ceiling: "personal" },
    budget: { budget_chars: 100, core_chars: 100, continuity_chars: 0, relevant_chars: 0, used_chars: 9 },
    watermark: { durable_sequence: 1, indexed_sequence: 1, dirty: false },
    truncated: false,
    degraded: [],
  };
}

function userMessage(): UserMessage {
  return { id: USER_ID, sessionID: SESSION, role: "user", time: { created: 1000 }, agent: "build", model: { providerID: "provider", modelID: "model" } };
}

function textPart(text: string, index: number): TextPart {
  return { id: `part-${index}`, sessionID: SESSION, messageID: USER_ID, type: "text", text };
}

function depsWith(transport: Transport): BridgeDeps {
  return { transport, clock: () => 1000, serviceUrl: "http://127.0.0.1:7331", token: TOKEN, timeoutMs: 1000, maxResponseBytes: 1024 * 1024, log: () => undefined };
}

function output(parts: Part[]): { messages: Array<{ info: Message; parts: Part[] }> } {
  return { messages: [{ info: userMessage(), parts }] };
}

async function registerAndTransform(parts: Part[], transport: Transport): Promise<{ calls: number; length: number }> {
  let calls = 0;
  const countedTransport: Transport = async (request) => {
    calls += 1;
    return transport(request);
  };
  const hooks = createPreflightHooks({ settings: settings(), deps: depsWith(countedTransport) });
  const chat = hooks["chat.message"];
  const transform = hooks["experimental.chat.messages.transform"];
  if (chat === undefined || transform === undefined) throw new Error("preflight hook missing");
  await chat({ sessionID: SESSION, messageID: USER_ID }, { message: userMessage(), parts });
  const messages = output(parts);
  await transform({}, messages);
  await hooks.dispose?.();
  return { calls, length: messages.messages.length };
}

describe("Task7 preflight query boundaries", () => {
  test("rejects common-envelope parts with invalid variant fields before transport", async () => {
    let calls = 0;
    const transport: Transport = async () => {
      calls += 1;
      return { status: 200, headers: {}, body: new TextEncoder().encode(JSON.stringify(pack())) };
    };
    const malformed: readonly unknown[][] = [
      [textPart("hello", 1), { id: "file-1", sessionID: SESSION, messageID: USER_ID, type: "file" }],
      [textPart("hello", 2), { id: "reasoning-1", sessionID: SESSION, messageID: USER_ID, type: "reasoning", text: 42, time: { start: 1 } }],
      [
        textPart("hello", 3),
        {
          id: "tool-1",
          sessionID: SESSION,
          messageID: USER_ID,
          type: "tool",
          callID: "call-1",
          tool: "read",
          metadata: 42,
          state: { status: "pending", input: {}, raw: "{}" },
        },
      ],
      [
        textPart("hello", 4),
        {
          id: "tool-2",
          sessionID: SESSION,
          messageID: USER_ID,
          type: "tool",
          callID: "call-2",
          tool: "read",
          state: {
            status: "completed",
            input: {},
            output: "complete",
            title: "read",
            metadata: {},
            time: { start: 1, end: 2 },
            attachments: [{ id: "attachment-1", sessionID: SESSION, messageID: USER_ID, type: "file" }],
          },
        },
      ],
    ];
    for (const parts of malformed) {
      const hooks = createPreflightHooks({ settings: settings(), deps: depsWith(transport) });
      const chat = hooks["chat.message"];
      const transform = hooks["experimental.chat.messages.transform"];
      if (chat === undefined || transform === undefined) throw new Error("preflight hook missing");
      await Reflect.apply(chat, undefined, [{ sessionID: SESSION, messageID: USER_ID }, { message: userMessage(), parts }]);
      const messages = output([textPart("hello", 3)]);
      await transform({}, messages);
      expect(messages.messages).toHaveLength(1);
      await hooks.dispose?.();
    }
    expect(calls).toBe(0);
  });

  test("accepts exactly 4096 characters including the joined separator", async () => {
    const result = await registerAndTransform(
      [textPart("a".repeat(2047), 1), textPart("b".repeat(2048), 2)],
      async () => ({ status: 200, headers: {}, body: new TextEncoder().encode(JSON.stringify(pack())) }),
    );
    expect(result).toEqual({ calls: 1, length: 2 });
  });

  test("rejects 4097 aggregate characters before making a transport call", async () => {
    const result = await registerAndTransform(
      [textPart("a".repeat(2047), 1), textPart("b".repeat(2049), 2)],
      async () => ({ status: 200, headers: {}, body: new TextEncoder().encode(JSON.stringify(pack())) }),
    );
    expect(result).toEqual({ calls: 0, length: 1 });
  });

  test("rejects six large text parts before joining or making a transport call", async () => {
    const parts = Array.from({ length: 6 }, (_, index) => textPart("x".repeat(700), index));
    const result = await registerAndTransform(
      parts,
      async () => ({ status: 200, headers: {}, body: new TextEncoder().encode(JSON.stringify(pack())) }),
    );
    expect(result).toEqual({ calls: 0, length: 1 });
  });
});

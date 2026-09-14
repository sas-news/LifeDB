import { describe, expect, test } from "bun:test";
import type { Message, Part, TextPart, UserMessage } from "@opencode-ai/sdk";
import { type BridgeDeps } from "../src/bridge.ts";
import { createPreflightHooks } from "../src/preflight.ts";
import type { Settings } from "../src/settings.ts";
import type { Transport } from "../src/httpClient.ts";

const TOKEN = "k".repeat(32);
const SESSION = "ses-1";
const USER_ID = "msg-user-1";

function settings(): Settings {
  return { serviceUrl: "http://127.0.0.1:7331", token: TOKEN, tokenFile: null, timeoutMs: 1000, maxResponseBytes: 1024 * 1024, clientLabel: "opencode", workspace: "/srv/project", sensitivity: "personal", budgetChars: 12000, coreChars: 4000, continuityChars: 2000, relevantChars: 6000, limit: 8 };
}

function userMessage(): UserMessage {
  return { id: USER_ID, sessionID: SESSION, role: "user", time: { created: 1000 }, agent: "build", model: { providerID: "provider", modelID: "model" } };
}

function textPart(): TextPart {
  return { id: "part-1", sessionID: SESSION, messageID: USER_ID, type: "text", text: "hello" };
}

function depsWith(transport: Transport): BridgeDeps {
  return { transport, clock: () => 1000, serviceUrl: "http://127.0.0.1:7331", token: TOKEN, timeoutMs: 1000, maxResponseBytes: 1024 * 1024, log: () => undefined };
}

function transformOutput(message: UserMessage = userMessage(), parts: Part[] = [textPart()]): { messages: Array<{ info: Message; parts: Part[] }> } {
  return { messages: [{ info: message, parts }] };
}

describe("Task7 preflight failures", () => {
  test("fails open without retry for malformed, empty, unavailable, rejected, timeout, or thrown responses", async () => {
    const responses: Array<Transport> = [
      async () => ({ status: 200, headers: {}, body: new TextEncoder().encode("{}") }),
      async () => ({ status: 200, headers: {}, body: new TextEncoder().encode("") }),
      async () => ({ status: 401, headers: {}, body: new Uint8Array() }),
      async () => ({ status: 422, headers: {}, body: new Uint8Array() }),
      async () => ({ status: 500, headers: {}, body: new Uint8Array() }),
      async () => ({ kind: "timeout" }),
      async () => { throw new Error("sink unavailable"); },
    ];
    for (const transport of responses) {
      const hooks = createPreflightHooks({ settings: settings(), deps: depsWith(transport) });
      const chat = hooks["chat.message"];
      const transform = hooks["experimental.chat.messages.transform"];
      if (chat === undefined || transform === undefined) throw new Error("preflight hook missing");
      await chat({ sessionID: SESSION, messageID: USER_ID }, { message: userMessage(), parts: [textPart()] });
      const output = transformOutput();
      await transform({}, output);
      expect(output.messages).toHaveLength(1);
      await hooks.dispose?.();
    }
  });

});

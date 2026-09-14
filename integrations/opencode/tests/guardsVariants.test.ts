import { describe, expect, test } from "bun:test";
import { isKnownPartWithIdentity } from "../src/guards.ts";

const identity = { sessionID: "ses-1", messageID: "msg-1" };

function part(type: string, fields: Record<string, unknown> = {}): unknown {
  return { id: "part-1", ...identity, type, ...fields };
}

function validParts(): readonly unknown[] {
  return [
    part("text", { text: "hello" }),
    part("subtask", { prompt: "p", description: "d", agent: "a" }),
    part("reasoning", { text: "thought", time: { start: 1 } }),
    part("file", { mime: "text/plain", url: "file:///tmp/x" }),
    part("tool", {
      callID: "call-1",
      tool: "read",
      state: { status: "pending", input: {}, raw: "{}" },
    }),
    part("tool", {
      callID: "call-2",
      tool: "read",
      metadata: { nested: { count: 2 }, values: ["kept", null, true] },
      state: {
        status: "completed",
        input: { arbitrary: { enabled: true } },
        output: "complete",
        title: "read",
        metadata: { result: { count: 1 } },
        time: { start: 1, end: 2 },
        attachments: [
          {
            id: "attachment-1",
            sessionID: "ses-1",
            messageID: "msg-1",
            type: "file",
            mime: "text/plain",
            filename: "result.txt",
            url: "file:///tmp/result.txt",
            source: {
              type: "file",
              path: "/tmp/result.txt",
              text: { value: "result", start: 1, end: 2 },
            },
          },
        ],
      },
    }),
    part("step-start"),
    part("step-finish", {
      reason: "stop",
      cost: 0,
      tokens: { input: 1, output: 1, reasoning: 0, cache: { read: 0, write: 0 } },
    }),
    part("snapshot", { snapshot: "snap" }),
    part("patch", { hash: "hash", files: ["one.ts"] }),
    part("agent", { name: "build" }),
    part("retry", {
      attempt: 1,
      error: { name: "APIError", data: { message: "retry", isRetryable: true } },
      time: { created: 1 },
    }),
    part("compaction", { auto: true }),
  ];
}

describe("SDK Part variant guards", () => {
  test("accepts every complete installed SDK 1.18.29 Part variant", () => {
    for (const value of validParts()) {
      expect(isKnownPartWithIdentity(value, identity)).toBe(true);
    }
  });

  test("rejects variants with missing or invalid discriminant-required fields", () => {
    const malformed: readonly unknown[] = [
      part("text"),
      part("subtask", { description: "d", agent: "a" }),
      part("reasoning", { text: "thought", time: { start: "not-a-time" } }),
      part("file", { url: "file:///tmp/x" }),
      part("file", { mime: "text/plain", url: 42 }),
      part("tool", { callID: "call-1", tool: "read" }),
      part("tool", {
        callID: "call-1",
        tool: "read",
        metadata: 42,
        state: { status: "pending", input: {}, raw: "{}" },
      }),
      part("tool", {
        callID: "call-1",
        tool: "read",
        state: {
          status: "completed",
          input: {},
          output: "complete",
          title: "read",
          metadata: {},
          time: { start: 1, end: 2 },
          attachments: [{ id: "attachment-1", sessionID: "ses-1", messageID: "msg-1", type: "file" }],
        },
      }),
      part("step-finish", { reason: "stop", cost: 0 }),
      part("snapshot"),
      part("patch", { hash: "hash", files: [42] }),
      part("agent"),
      part("retry", { attempt: 1 }),
      part("compaction", { auto: "yes" }),
    ];

    for (const value of malformed) {
      expect(isKnownPartWithIdentity(value, identity)).toBe(false);
    }
  });
});

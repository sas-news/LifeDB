import { describe, expect, test } from "bun:test";
import {
  extractCleanText,
  isAssistantMessage,
  isCompletedAssistant,
  isOpaqueId,
  isTextPart,
  isUserMessage,
} from "../src/guards.ts";

function userMessage(overrides: Record<string, unknown> = {}): unknown {
  return {
    id: "msg-user-1",
    sessionID: "ses-1",
    role: "user",
    time: { created: 1000 },
    agent: "build",
    model: { providerID: "p", modelID: "m" },
    ...overrides,
  };
}

function assistantMessage(overrides: Record<string, unknown> = {}): unknown {
  return {
    id: "msg-asst-1",
    sessionID: "ses-1",
    role: "assistant",
    time: { created: 1000, completed: 2000 },
    parentID: "msg-user-1",
    modelID: "m",
    providerID: "p",
    mode: "build",
    path: { cwd: "/srv", root: "/srv" },
    cost: 0,
    tokens: {
      input: 1,
      output: 1,
      reasoning: 0,
      cache: { read: 0, write: 0 },
    },
    ...overrides,
  };
}

function textPart(overrides: Record<string, unknown> = {}): unknown {
  return {
    id: "part-1",
    sessionID: "ses-1",
    messageID: "msg-user-1",
    type: "text",
    text: "hello",
    ...overrides,
  };
}

describe("message and part guards", () => {
  test("accepts a well-formed user message", () => {
    expect(isUserMessage(userMessage())).toBe(true);
    expect(isAssistantMessage(userMessage())).toBe(false);
  });

  test("rejects malformed Unicode and controls in message metadata", () => {
    expect(isUserMessage(userMessage({ agent: "\ud800" }))).toBe(false);
    expect(isUserMessage(userMessage({ model: { providerID: "p", modelID: "\u0000" } }))).toBe(false);
    expect(isAssistantMessage(assistantMessage({ mode: "\u007f" }))).toBe(false);
    expect(isAssistantMessage(assistantMessage({ path: { cwd: "\ud800", root: "/srv" } }))).toBe(false);
    expect(isUserMessage(userMessage({ agent: "日本語 🧠" }))).toBe(true);
  });

  test("accepts OpenCode summary metadata without accepting malformed forms", () => {
    expect(isUserMessage(userMessage({ summary: { diffs: [] } }))).toBe(true);
    for (const summary of [true, false, "summary", 1, [], null]) {
      expect(isUserMessage(userMessage({ summary }))).toBe(false);
    }
  });

  test("accepts a well-formed assistant message", () => {
    expect(isAssistantMessage(assistantMessage())).toBe(true);
    expect(isUserMessage(assistantMessage())).toBe(false);
  });

  test("rejects malformed assistant summary and finish values at the SDK boundary", () => {
    expect(isAssistantMessage(assistantMessage({ summary: { title: "not-a-boolean" } }))).toBe(false);
    expect(isAssistantMessage(assistantMessage({ finish: 42 }))).toBe(false);
    expect(isAssistantMessage(assistantMessage({ finish: { reason: "stop" } }))).toBe(false);
  });

  test("completed assistant requires completion time, no error, no summary", () => {
    expect(isCompletedAssistant(assistantMessage())).toBe(true);
    expect(
      isCompletedAssistant(assistantMessage({ time: { created: 1000 } })),
    ).toBe(false);
    expect(
      isCompletedAssistant(
        assistantMessage({ error: { name: "UnknownError", data: { message: "x" } } }),
      ),
    ).toBe(false);
    expect(isCompletedAssistant(assistantMessage({ summary: true }))).toBe(false);
  });

  test("text part guard excludes non-text types", () => {
    expect(isTextPart(textPart())).toBe(true);
    expect(isTextPart(textPart({ type: "reasoning" }))).toBe(false);
    expect(isTextPart(null)).toBe(false);
  });

  test("clean text extraction skips synthetic and ignored parts", () => {
    const parts: unknown = [
      textPart({ text: "keep" }),
      textPart({ text: "synthetic", synthetic: true }),
      textPart({ text: "ignored", ignored: true }),
      textPart({ type: "reasoning", text: "no" }),
    ];
    expect(extractCleanText(parts)).toEqual(["keep"]);
  });

  test("rejects unpaired surrogates and bounds aggregate clean text", () => {
    expect(isTextPart(textPart({ text: "\ud800" }))).toBe(false);
    expect(extractCleanText([textPart({ text: "\ud800" })])).toEqual([]);
    const parts = Array.from({ length: 21 }, (_, index) => textPart({ id: `part-${index}`, text: "x".repeat(200_000) }));
    expect(extractCleanText(parts)).toEqual([]);
  });

  test("opaque id bounds hold", () => {
   expect(isOpaqueId("abc")).toBe(true);
   expect(isOpaqueId("\ud800")).toBe(false);
    expect(isOpaqueId("")).toBe(false);
    expect(isOpaqueId("  ")).toBe(false);
    expect(isOpaqueId("a".repeat(257))).toBe(false);
    expect(isOpaqueId("has\nnewline")).toBe(false);
    expect(isOpaqueId(42)).toBe(false);
  });
});

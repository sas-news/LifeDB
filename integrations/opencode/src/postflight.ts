import type { Hooks } from "@opencode-ai/plugin";
import type { AssistantMessage, Message, Part } from "@opencode-ai/sdk";
import { deriveTurnId, submitTurn, type BridgeDeps } from "./bridge.ts";
import { extractCleanText, isAssistantMessage, isCompletedAssistant, isKnownPartWithIdentity, isOpaqueId, isUserMessage } from "./guards.ts";
import { PreflightState, type PendingSnapshot } from "./preflightState.ts";
import type { Settings } from "./settings.ts";

export type SessionMessagesClient = {
  readonly session: {
    readonly messages: (options: { readonly path: { readonly id: string }; readonly query: { readonly directory: string } }) => Promise<unknown>;
  };
};

export type PostflightHooksOptions = {
  readonly settings: Settings;
  readonly deps: BridgeDeps;
  readonly state: PreflightState;
  readonly client: SessionMessagesClient;
  readonly directory: string;
};

type MessageWithParts = { readonly info: Message; readonly parts: readonly Part[] };

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function resultData(value: unknown): readonly MessageWithParts[] | undefined {
  if (!record(value) || value["error"] !== undefined || !Array.isArray(value["data"])) return undefined;
  const entries = value["data"];
  if (!entries.every(isMessageWithParts)) return undefined;
  return entries;
}

function isMessageWithParts(value: unknown): value is MessageWithParts {
  if (!record(value) || !("info" in value) || !Array.isArray(value["parts"])) return false;
  const info = value["info"];
  if (!isUserMessage(info) && !isAssistantMessage(info)) return false;
  const identity = { sessionID: info.sessionID, messageID: info.id };
  return value["parts"].every((part) => isKnownPartWithIdentity(part, identity));
}

function finalAssistant(item: MessageWithParts): item is MessageWithParts & { readonly info: AssistantMessage } {
  if (!isCompletedAssistant(item.info)) return false;
  // OpenCode v1.18.29 uses stop|length for successful assistant completion.
  // Its upstream prompt predicate excludes tool-calls|unknown, while the
  // v1 SDK permits older records with no finish field.
  return item.info.finish === undefined || item.info.finish === "stop" || item.info.finish === "length";
}

function findAssistant(messages: readonly MessageWithParts[], pending: PendingSnapshot): MessageWithParts | undefined {
  let selected: MessageWithParts | undefined;
  for (const item of messages) {
    if (item.info.sessionID !== pending.sessionID) continue;
    if (!finalAssistant(item) || item.info.parentID !== pending.messageID) continue;
    const selectedCompleted = selected === undefined || !isAssistantMessage(selected.info) ? 0 : selected.info.time.completed ?? 0;
    if (selected === undefined || (item.info.time.completed ?? 0) > selectedCompleted) selected = item;
  }
  return selected;
}

function containsPendingUser(messages: readonly MessageWithParts[], pending: PendingSnapshot): boolean {
  return messages.some((item) => {
    if (!isUserMessage(item.info) || item.info.sessionID !== pending.sessionID || item.info.id !== pending.messageID) return false;
    return extractCleanText(item.parts).join("\n").trim() === pending.query;
  });
}

function containsCompactionForPair(messages: readonly MessageWithParts[], pending: PendingSnapshot): boolean {
  const assistantIDs = new Set(messages.flatMap((item) => isAssistantMessage(item.info) && item.info.sessionID === pending.sessionID && item.info.parentID === pending.messageID ? [item.info.id] : []));
  return messages.some((item) => item.info.sessionID === pending.sessionID && (item.info.id === pending.messageID || assistantIDs.has(item.info.id)) && item.parts.some((part) => part.type === "compaction"));
}

function cleanAssistantText(item: MessageWithParts): string | undefined {
  const texts = extractCleanText(item.parts);
  if (texts.length === 0) return undefined;
  const result = texts.join("\n");
  return result.trim().length === 0 ? undefined : result;
}

function completionTime(item: MessageWithParts): string | undefined {
  if (!isAssistantMessage(item.info) || item.info.time.completed === undefined) return undefined;
  const value = new Date(item.info.time.completed);
  return Number.isNaN(value.getTime()) ? undefined : value.toISOString();
}

function log(deps: BridgeDeps, outcome: "ok" | "fail-open" | "dropped" | "rejected" | "conflict"): void {
  try {
    deps.log({ op: "turn.postflight", outcome });
  } catch (error) {
    if (error instanceof Error) return;
    return;
  }
}

function postflightOutcome(submitOutcome: string): "ok" | "fail-open" | "rejected" | "conflict" {
  if (submitOutcome === "captured") return "ok";
  if (submitOutcome === "conflict") return "conflict";
  if (submitOutcome === "rejected") return "rejected";
  return "fail-open";
}

async function readMessages(options: PostflightHooksOptions, sessionID: string): Promise<readonly MessageWithParts[] | undefined> {
  try {
    const result = await options.client.session.messages({ path: { id: sessionID }, query: { directory: options.directory } });
    return resultData(result);
  } catch (error) {
    if (error instanceof Error) return undefined;
    return undefined;
  }
}

export function createPostflightHooks(options: PostflightHooksOptions): Hooks {
  const tails = new Map<string, Promise<void>>();
  let disposed = false;

  const processSession = async (sessionID: string): Promise<void> => {
    const pending = options.state.readAll(sessionID);
    if (pending.length === 0) return;
    const messages = await readMessages(options, sessionID);
    if (messages === undefined) {
      for (const entry of pending) options.state.evict(entry.sessionID, entry.messageID);
      log(options.deps, "fail-open");
      return;
    }
    for (const entry of pending) {
      const assistant = containsCompactionForPair(messages, entry) || !containsPendingUser(messages, entry) ? undefined : findAssistant(messages, entry);
      const text = assistant === undefined ? undefined : cleanAssistantText(assistant);
      const capturedAt = assistant === undefined ? undefined : completionTime(assistant);
      if (assistant === undefined || text === undefined || capturedAt === undefined) {
        options.state.evict(entry.sessionID, entry.messageID);
        log(options.deps, "dropped");
        continue;
      }
      try {
        const result = await submitTurn(options.deps, { payload: { session_id: entry.sessionID, turn_id: deriveTurnId(entry.sessionID, entry.messageID), ...(options.settings.workspace === null ? {} : { workspace: options.settings.workspace }), user_text: entry.query, assistant_text: text, captured_at: capturedAt } });
        log(options.deps, postflightOutcome(result.outcome));
      } catch (error) {
        if (error instanceof Error) log(options.deps, "fail-open");
        else log(options.deps, "fail-open");
      } finally {
        options.state.evict(entry.sessionID, entry.messageID);
      }
    }
  };

  const event: NonNullable<Hooks["event"]> = async (input) => {
    if (disposed) return;
    const sessionID = input.event.type === "session.idle" ? input.event.properties.sessionID : undefined;
    if (sessionID === undefined || !isOpaqueId(sessionID)) return;
    const previous = tails.get(sessionID) ?? Promise.resolve();
    const current = previous.then(() => processSession(sessionID), () => processSession(sessionID));
    tails.set(sessionID, current);
    try {
      await current;
    } catch (error) {
      if (error instanceof Error) log(options.deps, "fail-open");
      else log(options.deps, "fail-open");
    } finally {
      if (tails.get(sessionID) === current) tails.delete(sessionID);
    }
  };

  return {
    event,
    dispose: async () => {
      if (disposed) return;
      disposed = true;
      await Promise.allSettled([...tails.values()]);
      tails.clear();
    },
  };
}

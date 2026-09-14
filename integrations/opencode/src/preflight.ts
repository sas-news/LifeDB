import type { Hooks } from "@opencode-ai/plugin";
import type { Message, Part, TextPart, UserMessage } from "@opencode-ai/sdk";
import { deriveSessionId, fetchContextPack, type BridgeDeps, type ContextPack } from "./bridge.ts";
import { isAssistantMessage, isKnownPartWithIdentity, isOpaqueId, isTextPart, isUserMessage, MAX_CONTEXT_QUERY_CHARS } from "./guards.ts";
import { PreflightState, type PreflightStateLimits } from "./preflightState.ts";
import type { Settings } from "./settings.ts";

export const PREFLIGHT_MARKER = "<!-- LIFEDB_PREFLIGHT_CONTEXT_V1 -->";
const OMO_INITIATOR_MARKER = "<!-- OMO_INTERNAL_INITIATOR -->";
const OMO_NOREPLY_MARKER = "<!-- OMO_INTERNAL_NOREPLY -->";

export type PreflightHooksOptions = {
  readonly settings: Settings;
  readonly deps: BridgeDeps;
  readonly state?: PreflightState;
  readonly limits?: PreflightStateLimits;
};

type MessageWithParts = { readonly info: Message; readonly parts: Part[] };
type RealUser = { readonly index: number; readonly info: UserMessage; readonly query: string };
type MessageIdentity = { readonly sessionID: string; readonly messageID: string };

function hasInternalMarker(text: string): boolean {
  return text.includes(PREFLIGHT_MARKER) || text.includes(OMO_INITIATOR_MARKER) || text.includes(OMO_NOREPLY_MARKER);
}

function cleanUserText(value: unknown, identity?: MessageIdentity): string | undefined {
  if (!Array.isArray(value) || value.length === 0) return undefined;
  const texts: string[] = [];
  let total = 0;
  for (const part of value) {
    if (!isKnownPartWithIdentity(part, identity)) return undefined;
    if (part["type"] !== "text") continue;
    if (!isTextPart(part) || part.synthetic === true || part.ignored === true || hasInternalMarker(part.text)) return undefined;
    total += part.text.length + (texts.length === 0 ? 0 : 1);
    if (total > MAX_CONTEXT_QUERY_CHARS) return undefined;
    texts.push(part.text);
  }
  if (texts.length === 0) return undefined;
  const result = texts.join("\n");
  return result.trim().length === 0 ? undefined : result;
}

function isCompaction(parts: readonly Part[]): boolean {
  return parts.some((part) => part.type === "compaction");
}

function findCurrentUser(messages: readonly MessageWithParts[], state: PreflightState): RealUser | undefined {
  let current: RealUser | undefined;
  for (const [index, item] of messages.entries()) {
    if (isCompaction(item.parts)) return undefined;
    if (!isUserMessage(item.info)) continue;
    const query = cleanUserText(item.parts, { sessionID: item.info.sessionID, messageID: item.info.id });
    if (query === undefined) continue;
    current = { index, info: item.info, query };
  }
  if (current === undefined) return undefined;
  const pending = state.readLatest(current.info.sessionID);
  if (pending === undefined || pending.messageID !== current.info.id || pending.query !== current.query) return undefined;
  return current;
}

function isMessageWithParts(value: unknown): value is MessageWithParts {
  if (typeof value !== "object" || value === null || Array.isArray(value) || !("info" in value) || !("parts" in value)) return false;
  const info = value.info;
  if (!isUserMessage(info) && !isAssistantMessage(info)) return false;
  if (!Array.isArray(value.parts)) return false;
  return value.parts.every((part) => isKnownPartWithIdentity(part, { sessionID: info.sessionID, messageID: info.id }) && (part["type"] !== "text" || isTextPart(part)));
}

function hasInjectedMessage(messages: readonly MessageWithParts[], userID: string): boolean {
  return messages.some((item) => {
    if (!isUserMessage(item.info) || item.info.id !== syntheticMessageID(userID)) return false;
    return Array.isArray(item.parts) && item.parts.length === 1 && item.parts[0]?.type === "text" && item.parts[0].synthetic === true && item.parts[0].text.includes(PREFLIGHT_MARKER);
  });
}

function syntheticMessageID(userID: string): string {
  const suffix = userID.length > 232 ? userID.slice(userID.length - 232) : userID;
  return `lifedb-preflight-${suffix}`;
}

function buildSyntheticMessage(sessionID: string, userID: string, pack: ContextPack, created: number): MessageWithParts {
  const messageID = syntheticMessageID(userID);
  const info: UserMessage = {
    id: messageID,
    sessionID,
    role: "user",
    time: { created },
    agent: "lifedb",
    model: { providerID: "lifedb", modelID: "context-pack" },
  };
  const part: TextPart = {
    id: `${messageID}-part`,
    sessionID,
    messageID,
    type: "text",
    text: `${PREFLIGHT_MARKER}\n${pack.rendered_markdown}`,
    synthetic: true,
  };
  return { info, parts: [part] };
}

function requestFor(settings: Settings, sessionID: string, query: string): Parameters<typeof fetchContextPack>[1] {
  return {
    query,
    client: settings.clientLabel,
    session: deriveSessionId(sessionID),
    ...(settings.workspace === null ? {} : { workspace: settings.workspace }),
    limit: settings.limit,
    ...(settings.sensitivity === null ? {} : { sensitivity_ceiling: settings.sensitivity }),
    budget_chars: settings.budgetChars,
    core_chars: settings.coreChars,
    continuity_chars: settings.continuityChars,
    relevant_chars: settings.relevantChars,
  };
}

function usefulPack(pack: ContextPack): boolean {
  return pack.core.length + pack.continuity.length + pack.relevant.length + pack.evidence_handles.length > 0;
}

export function createPreflightHooks(options: PreflightHooksOptions): Hooks {
  const state = options.state ?? new PreflightState(options.limits);
  const chatMessage: NonNullable<Hooks["chat.message"]> = async (input, output) => {
    if (!isOpaqueId(input.sessionID) || !isUserMessage(output.message) || output.message.sessionID !== input.sessionID) return;
    if (input.messageID !== undefined && (input.messageID !== output.message.id || !isOpaqueId(input.messageID))) return;
    const query = cleanUserText(output.parts, { sessionID: output.message.sessionID, messageID: output.message.id });
    if (query === undefined) return;
    state.register({ sessionID: output.message.sessionID, messageID: output.message.id, query, ...(options.settings.workspace === null ? {} : { workspace: options.settings.workspace }) });
  };
  const transform: NonNullable<Hooks["experimental.chat.messages.transform"]> = async (_input, output) => {
    if (!Array.isArray(output.messages) || !output.messages.every(isMessageWithParts)) return;
    const current = findCurrentUser(output.messages, state);
    if (current === undefined || hasInjectedMessage(output.messages, current.info.id)) return;
    const pending = state.read(current.info.sessionID, current.info.id);
    if (pending === undefined) return;
    const resolved = await state.resolve(current.info.sessionID, current.info.id, async () => {
      const result = await fetchContextPack(options.deps, requestFor(options.settings, current.info.sessionID, current.query));
      return result.ok && usefulPack(result.pack) ? result.pack : null;
    });
    if (resolved === null || hasInjectedMessage(output.messages, current.info.id)) return;
    output.messages.splice(current.index, 0, buildSyntheticMessage(current.info.sessionID, current.info.id, resolved, options.deps.clock()));
  };
  const hooks: Hooks = {
    "chat.message": chatMessage,
    "experimental.chat.messages.transform": transform,
    dispose: async () => {
      await state.dispose();
    },
  };
  return hooks;
}

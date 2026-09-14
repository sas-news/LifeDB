import type { AssistantMessage, TextPart, UserMessage } from "@opencode-ai/sdk";
import { hasAnyC0OrDeleteControl, hasForbiddenControl, hasUnpairedSurrogate } from "./utf8.ts";

export type OpaqueId = string;
export type PartIdentity = { readonly sessionID: string; readonly messageID: string };
const PART_TYPES = ["text", "subtask", "reasoning", "file", "tool", "step-start", "step-finish", "snapshot", "patch", "agent", "retry", "compaction"] as const;
type KnownPartType = (typeof PART_TYPES)[number];

export function isOpaqueId(value: unknown): value is OpaqueId { return typeof value === "string" && value.length > 0 && value.length <= 256 && value.trim() === value && !hasUnpairedSurrogate(value) && !hasAnyC0OrDeleteControl(value); }
function record(value: unknown): value is Record<string, unknown> { return typeof value === "object" && value !== null && !Array.isArray(value); }
function finiteTime(value: unknown): value is number { return typeof value === "number" && Number.isFinite(value) && value >= 0; }
function safeString(value: unknown): value is string { return typeof value === "string" && !hasUnpairedSurrogate(value) && !hasForbiddenControl(value); }
function optionalSafeString(value: Record<string, unknown>, key: string): boolean { return value[key] === undefined || safeString(value[key]); }
function optionalBoolean(value: Record<string, unknown>, key: string): boolean { return value[key] === undefined || typeof value[key] === "boolean"; }
function optionalRecord(value: Record<string, unknown>, key: string): boolean { return value[key] === undefined || record(value[key]); }
function optionalFiniteTime(value: Record<string, unknown>, key: string): boolean { return value[key] === undefined || finiteTime(value[key]); }
export const MAX_CLEAN_TEXT_CHARS = 1_000_000;
export const MAX_CONTEXT_QUERY_CHARS = 4096;
function cleanText(value: unknown): value is string { return typeof value === "string" && value.length <= 200_000 && value.length > 0 && !hasUnpairedSurrogate(value) && !hasForbiddenControl(value); }
function safeResponseString(value: unknown): value is string { return typeof value === "string" && !hasUnpairedSurrogate(value) && !hasForbiddenControl(value); }
export function isUserMessage(value: unknown): value is UserMessage { return record(value) && value["role"] === "user" && isOpaqueId(value["id"]) && isOpaqueId(value["sessionID"]) && record(value["time"]) && finiteTime(value["time"]["created"]) && safeResponseString(value["agent"]) && record(value["model"]) && safeResponseString(value["model"]["providerID"]) && safeResponseString(value["model"]["modelID"]) && (value["summary"] === undefined || record(value["summary"])); }
export function isAssistantMessage(value: unknown): value is AssistantMessage { return record(value) && value["role"] === "assistant" && isOpaqueId(value["id"]) && isOpaqueId(value["sessionID"]) && isOpaqueId(value["parentID"]) && record(value["time"]) && finiteTime(value["time"]["created"]) && (value["time"]["completed"] === undefined || finiteTime(value["time"]["completed"])) && safeResponseString(value["modelID"]) && safeResponseString(value["providerID"]) && safeResponseString(value["mode"]) && record(value["path"]) && safeResponseString(value["path"]["cwd"]) && safeResponseString(value["path"]["root"]) && typeof value["cost"] === "number" && Number.isFinite(value["cost"]) && record(value["tokens"]) && optionalBoolean(value, "summary") && optionalSafeString(value, "finish"); }
function isKnownPartType(value: unknown): value is KnownPartType { return typeof value === "string" && PART_TYPES.some((partType) => partType === value); }
function assertNever(value: never): never { throw new Error(`unexpected SDK Part type: ${String(value)}`); }
function isTextTiming(value: unknown, required: boolean): boolean {
  if (value === undefined) return !required;
  return record(value) && finiteTime(value["start"]) && optionalFiniteTime(value, "end");
}
function isTextVariant(value: Record<string, unknown>, timingRequired: boolean): boolean {
  return safeString(value["text"]) && optionalBoolean(value, "synthetic") && optionalBoolean(value, "ignored") && isTextTiming(value["time"], timingRequired) && optionalRecord(value, "metadata");
}
function isFileSourceText(value: unknown): boolean {
  return record(value) && safeString(value["value"]) && finiteTime(value["start"]) && finiteTime(value["end"]);
}
function isRange(value: unknown): boolean {
  if (!record(value) || !record(value["start"]) || !record(value["end"])) return false;
  return finiteTime(value["start"]["line"]) && finiteTime(value["start"]["character"]) && finiteTime(value["end"]["line"]) && finiteTime(value["end"]["character"]);
}
function isFileSource(value: unknown): boolean {
  if (value === undefined) return true;
  if (!record(value) || !isFileSourceText(value["text"]) || !safeString(value["path"])) return false;
  switch (value["type"]) {
    case "file": return true;
    case "symbol": return isRange(value["range"]) && safeString(value["name"]) && finiteTime(value["kind"]);
    default: return false;
  }
}
function isCompleteFilePart(value: unknown): boolean {
  return record(value) && isOpaqueId(value["id"]) && isOpaqueId(value["sessionID"]) && isOpaqueId(value["messageID"]) && value["type"] === "file" && safeString(value["mime"]) && optionalSafeString(value, "filename") && safeString(value["url"]) && isFileSource(value["source"]);
}
function optionalFileParts(value: Record<string, unknown>, key: string): boolean {
  const attachments = value[key];
  return attachments === undefined || (Array.isArray(attachments) && Array.from(attachments).every((attachment: unknown) => isCompleteFilePart(attachment)));
}
function isStringRecord(value: unknown): boolean { return record(value) && Object.values(value).every((item) => safeString(item)); }
function isToolState(value: unknown): boolean {
  if (!record(value) || !record(value["input"])) return false;
  switch (value["status"]) {
    case "pending": return safeString(value["raw"]);
    case "running": return optionalSafeString(value, "title") && optionalRecord(value, "metadata") && record(value["time"]) && finiteTime(value["time"]["start"]);
    case "completed": return safeString(value["output"]) && safeString(value["title"]) && record(value["metadata"]) && record(value["time"]) && finiteTime(value["time"]["start"]) && finiteTime(value["time"]["end"]) && optionalFiniteTime(value["time"], "compacted") && optionalFileParts(value, "attachments");
    case "error": return safeString(value["error"]) && optionalRecord(value, "metadata") && record(value["time"]) && finiteTime(value["time"]["start"]) && finiteTime(value["time"]["end"]);
    default: return false;
  }
}
function isTokens(value: unknown): boolean {
  return record(value) && finiteTime(value["input"]) && finiteTime(value["output"]) && finiteTime(value["reasoning"]) && record(value["cache"]) && finiteTime(value["cache"]["read"]) && finiteTime(value["cache"]["write"]);
}
function isApiError(value: unknown): boolean {
  if (!record(value) || value["name"] !== "APIError" || !record(value["data"])) return false;
  const data = value["data"];
  return safeString(data["message"]) && typeof data["isRetryable"] === "boolean" && (data["statusCode"] === undefined || finiteTime(data["statusCode"])) && (data["responseHeaders"] === undefined || isStringRecord(data["responseHeaders"])) && (data["responseBody"] === undefined || safeString(data["responseBody"]));
}
function isAgentSource(value: unknown): boolean {
  return value === undefined || (record(value) && safeString(value["value"]) && finiteTime(value["start"]) && finiteTime(value["end"]));
}
function isVariantFields(value: Record<string, unknown>, type: KnownPartType): boolean {
  switch (type) {
    case "text": return isTextVariant(value, false);
    case "subtask": return safeString(value["prompt"]) && safeString(value["description"]) && safeString(value["agent"]);
    case "reasoning": return isTextVariant(value, true);
    case "file": return safeString(value["mime"]) && safeString(value["url"]) && optionalSafeString(value, "filename") && isFileSource(value["source"]);
    case "tool": return safeString(value["callID"]) && safeString(value["tool"]) && optionalRecord(value, "metadata") && isToolState(value["state"]);
    case "step-start": return optionalSafeString(value, "snapshot");
    case "step-finish": return safeString(value["reason"]) && optionalSafeString(value, "snapshot") && finiteTime(value["cost"]) && isTokens(value["tokens"]);
    case "snapshot": return safeString(value["snapshot"]);
    case "patch": return safeString(value["hash"]) && Array.isArray(value["files"]) && value["files"].every(safeString);
    case "agent": return safeString(value["name"]) && isAgentSource(value["source"]);
    case "retry": return finiteTime(value["attempt"]) && isApiError(value["error"]) && record(value["time"]) && finiteTime(value["time"]["created"]);
    case "compaction": return typeof value["auto"] === "boolean";
    default: return assertNever(type);
  }
}
export function isKnownPartWithIdentity(value: unknown, identity?: PartIdentity): value is Record<string, unknown> {
  if (!record(value) || !isKnownPartType(value["type"]) || !isOpaqueId(value["id"]) || !isOpaqueId(value["sessionID"]) || !isOpaqueId(value["messageID"])) return false;
  if (identity !== undefined && (value["sessionID"] !== identity.sessionID || value["messageID"] !== identity.messageID)) return false;
  return isVariantFields(value, value["type"]);
}
export function isCompletedAssistant(value: unknown): value is AssistantMessage { return isAssistantMessage(value) && finiteTime(value.time.completed) && value.error === undefined && value.summary !== true; }
export function isTextPart(value: unknown): value is TextPart { return record(value) && value["type"] === "text" && isOpaqueId(value["id"]) && isOpaqueId(value["sessionID"]) && isOpaqueId(value["messageID"]) && cleanText(value["text"]) && (value["synthetic"] === undefined || typeof value["synthetic"] === "boolean") && (value["ignored"] === undefined || typeof value["ignored"] === "boolean") && (value["time"] === undefined || (record(value["time"]) && finiteTime(value["time"]["start"]) && (value["time"]["end"] === undefined || finiteTime(value["time"]["end"])))); }
export function extractCleanText(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  const clean: string[] = [];
  let total = 0;
  for (const item of value) {
    if (!isTextPart(item) || item.synthetic === true || item.ignored === true) continue;
    total += item.text.length;
    if (total > MAX_CLEAN_TEXT_CHARS) return [];
    clean.push(item.text);
  }
  return clean;
}

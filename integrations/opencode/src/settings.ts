import { utf8ByteLength } from "./utf8.ts";

export const COMPAT_OPENCODE_VERSION = "1.18.29" as const;

export const DEFAULT_SETTINGS = {
  timeoutMs: 8000,
  maxResponseBytes: 512000,
  clientLabel: "opencode",
  budgetChars: 12000,
  coreChars: 4000,
  continuityChars: 2000,
  relevantChars: 6000,
  limit: 8,
} as const;

export type Settings = {
  readonly serviceUrl: string;
  readonly token: string | null;
  readonly tokenFile: string | null;
  readonly timeoutMs: number;
  readonly maxResponseBytes: number;
  readonly clientLabel: string;
  readonly workspace: string | null;
  readonly sensitivity: string | null;
  readonly budgetChars: number;
  readonly coreChars: number;
  readonly continuityChars: number;
  readonly relevantChars: number;
  readonly limit: number;
};

type SettingsResult =
  | { readonly ok: true; readonly settings: Settings }
  | { readonly ok: false; readonly reason: string };

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function optionalString(value: unknown, name: string): string | null | undefined {
  if (value === undefined || value === null) return null;
  if (typeof value !== "string" || value.length === 0) throw new Error(`${name} invalid`);
  return value;
}

function boundedNumber(value: unknown, fallback: number, name: string, max: number): number {
  if (value === undefined) return fallback;
  if (typeof value !== "number" || !Number.isInteger(value) || value < 1 || value > max) {
    throw new Error(`${name} invalid`);
  }
  return value;
}

function loopbackUrl(value: unknown): string {
  if (typeof value !== "string" || value.length === 0) throw new Error("serviceUrl invalid");
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error("serviceUrl invalid");
  }
  if (parsed.username || parsed.password || parsed.pathname !== "/" || parsed.search || parsed.hash) {
    throw new Error("serviceUrl invalid");
  }
  if (parsed.protocol !== "http:" || !["127.0.0.1", "localhost", "[::1]"].includes(parsed.hostname)) {
    throw new Error("serviceUrl invalid");
  }
  return parsed.origin;
}

export function parseSettings(input: unknown): SettingsResult {
  try {
    if (!isRecord(input)) throw new Error("settings must be an object");
    const keys = new Set([
      "serviceUrl", "token", "tokenFile", "timeoutMs", "maxResponseBytes", "clientLabel",
      "workspace", "sensitivity", "budgetChars", "coreChars", "continuityChars", "relevantChars", "limit",
    ]);
    for (const key of Object.keys(input)) if (!keys.has(key)) throw new Error("unknown setting");
    const token = optionalString(input["token"], "token");
    const tokenFile = optionalString(input["tokenFile"], "tokenFile");
    const hasToken = token !== null && token !== undefined;
    const hasTokenFile = tokenFile !== null && tokenFile !== undefined;
    if (hasToken === hasTokenFile) throw new Error("exactly one token source required");
    if (token !== null && token !== undefined && (utf8ByteLength(token) < 32 || utf8ByteLength(token) > 4096 || /\s/u.test(token))) throw new Error("token invalid");
    const clientLabel = input["clientLabel"] === undefined ? DEFAULT_SETTINGS.clientLabel : optionalString(input["clientLabel"], "clientLabel");
    if (clientLabel === null || clientLabel === undefined) throw new Error("clientLabel invalid");
    return {
      ok: true,
      settings: {
        serviceUrl: loopbackUrl(input["serviceUrl"]),
        token: token ?? null,
        tokenFile: tokenFile ?? null,
        timeoutMs: boundedNumber(input["timeoutMs"], DEFAULT_SETTINGS.timeoutMs, "timeoutMs", 120000),
        maxResponseBytes: boundedNumber(input["maxResponseBytes"], DEFAULT_SETTINGS.maxResponseBytes, "maxResponseBytes", 4 * 1024 * 1024),
        clientLabel,
        workspace: optionalString(input["workspace"], "workspace") ?? null,
        sensitivity: optionalString(input["sensitivity"], "sensitivity") ?? null,
        budgetChars: boundedNumber(input["budgetChars"], DEFAULT_SETTINGS.budgetChars, "budgetChars", 1000000),
        coreChars: boundedNumber(input["coreChars"], DEFAULT_SETTINGS.coreChars, "coreChars", 1000000),
        continuityChars: boundedNumber(input["continuityChars"], DEFAULT_SETTINGS.continuityChars, "continuityChars", 1000000),
        relevantChars: boundedNumber(input["relevantChars"], DEFAULT_SETTINGS.relevantChars, "relevantChars", 1000000),
        limit: boundedNumber(input["limit"], DEFAULT_SETTINGS.limit, "limit", 100),
      },
    };
  } catch (error) {
    if (error instanceof Error) return { ok: false, reason: error.message };
    return { ok: false, reason: "settings invalid" };
  }
}

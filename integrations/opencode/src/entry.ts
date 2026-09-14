import type { Hooks, PluginInput, PluginModule } from "@opencode-ai/plugin";
import { createFetchTransport } from "./httpClient.ts";
import { createPostflightHooks } from "./postflight.ts";
import { createPreflightHooks } from "./preflight.ts";
import { PreflightState } from "./preflightState.ts";
import { composeHooks } from "./plugin.ts";
import { parseSettings } from "./settings.ts";
import { loadTokenFile } from "./tokenFile.ts";

const DEFAULT_SERVICE_URL = "http://127.0.0.1:7331";

function environment(): Record<string, unknown> {
  const env = process.env;
  return {
    serviceUrl: env["LIFEDB_SERVICE_URL"] ?? DEFAULT_SERVICE_URL,
    token: env["LIFEDB_API_TOKEN"] || null,
    tokenFile: env["LIFEDB_API_TOKEN_FILE"] || null,
    timeoutMs: env["LIFEDB_OPENCODE_TIMEOUT_MS"] === undefined ? undefined : Number(env["LIFEDB_OPENCODE_TIMEOUT_MS"]),
    maxResponseBytes: env["LIFEDB_OPENCODE_MAX_RESPONSE_BYTES"] === undefined ? undefined : Number(env["LIFEDB_OPENCODE_MAX_RESPONSE_BYTES"]),
    workspace: env["LIFEDB_OPENCODE_WORKSPACE"] || null,
    sensitivity: env["LIFEDB_OPENCODE_SENSITIVITY"] || null,
    budgetChars: env["LIFEDB_OPENCODE_BUDGET_CHARS"] === undefined ? undefined : Number(env["LIFEDB_OPENCODE_BUDGET_CHARS"]),
    coreChars: env["LIFEDB_OPENCODE_CORE_CHARS"] === undefined ? undefined : Number(env["LIFEDB_OPENCODE_CORE_CHARS"]),
    continuityChars: env["LIFEDB_OPENCODE_CONTINUITY_CHARS"] === undefined ? undefined : Number(env["LIFEDB_OPENCODE_CONTINUITY_CHARS"]),
    relevantChars: env["LIFEDB_OPENCODE_RELEVANT_CHARS"] === undefined ? undefined : Number(env["LIFEDB_OPENCODE_RELEVANT_CHARS"]),
    limit: env["LIFEDB_OPENCODE_LIMIT"] === undefined ? undefined : Number(env["LIFEDB_OPENCODE_LIMIT"]),
  };
}

function emptyHooks(): Hooks {
  return { dispose: async () => undefined };
}

const server: PluginModule["server"] = async ({ client, directory }: PluginInput): Promise<Hooks> => {
  const parsed = parseSettings(environment());
  if (!parsed.ok) return emptyHooks();
  let token = parsed.settings.token;
  if (token === null && parsed.settings.tokenFile !== null) {
    const loaded = loadTokenFile(parsed.settings.tokenFile);
    if (!loaded.ok) return emptyHooks();
    token = loaded.token;
  }
  if (token === null) return emptyHooks();
  const deps = {
    transport: createFetchTransport(),
    clock: () => Date.now(),
    serviceUrl: parsed.settings.serviceUrl,
    token,
    timeoutMs: parsed.settings.timeoutMs,
    maxResponseBytes: parsed.settings.maxResponseBytes,
    log: (_entry: unknown) => undefined,
  };
  const state = new PreflightState();
  const preflight = createPreflightHooks({ settings: parsed.settings, deps, state });
  const postflight = createPostflightHooks({ settings: parsed.settings, deps, state, client: { session: client.session }, directory });
  return composeHooks(preflight, postflight);
};

const plugin = { id: "lifedb", server } satisfies PluginModule;
export default plugin;

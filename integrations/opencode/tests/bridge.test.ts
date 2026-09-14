import { describe, expect, test } from "bun:test";
import {
  buildTurnPayload,
  deriveTurnId,
  fetchContextPack,
  submitTurn,
  type BridgeDeps,
} from "../src/bridge.ts";
import type { Transport } from "../src/httpClient.ts";

const TOKEN = "k".repeat(32);

function validPackJson(): string {
  return JSON.stringify({
    schema: "0.2", id: "019d0000-0000-7000-8000-000000000001", generated_at: "2026-09-07T00:00:00Z",
    query: "", core: [], continuity: [], relevant: [], evidence_handles: ["019d0000-0000-7000-8000-000000000001"],
    rendered_markdown: '<lifedb-data source="evidence:019d0000-0000-7000-8000-000000000001" sensitivity="personal" untrusted="true">\n</lifedb-data>',
    authorization: { principal: "owner", sensitivity_ceiling: "personal" },
    budget: { budget_chars: 100, core_chars: 0, continuity_chars: 0, relevant_chars: 0, used_chars: 0 },
    watermark: { durable_sequence: 1, indexed_sequence: 1, dirty: false }, truncated: false, degraded: [],
  });
}

function depsWith(transport: Transport): BridgeDeps {
  return {
    transport,
    clock: () => 1000,
    serviceUrl: "http://127.0.0.1:7331",
    token: TOKEN,
    timeoutMs: 5000,
    maxResponseBytes: 1024 * 1024,
    log: () => undefined,
  };
}

describe("turn payload builder", () => {
  test("builds a server-shaped payload", () => {
    const result = buildTurnPayload({
      session_id: "ses-1",
      turn_id: "msg-user-1",
      workspace: "/srv/project",
      user_text: "hello",
      assistant_text: "world",
      captured_at: "2026-09-07T00:00:00Z",
    });
    if (result.ok !== true) {
      throw new Error(`expected ok, got ${result.reason}`);
    }
    expect(result.payload.host).toBe("opencode");
    expect(result.payload.session_id).toBe("ses-1");
  });

  test("derives a bounded opaque turn id without hashing text", () => {
    const id = deriveTurnId("s".repeat(256), "m".repeat(256));
    expect(id).toBe("m".repeat(256));
    expect(id.length).toBeLessThanOrEqual(256);
  });

  test("rejects empty texts and bad timestamps", () => {
    expect(
      buildTurnPayload({
        session_id: "s",
        turn_id: "t",
        user_text: "  ",
        assistant_text: "world",
        captured_at: "2026-09-07T00:00:00Z",
      }).ok,
    ).toBe(false);
    expect(
      buildTurnPayload({
        session_id: "s",
        turn_id: "t",
        user_text: "hello",
        assistant_text: "world",
        captured_at: "not-a-time",
      }).ok,
    ).toBe(false);
  });
});

describe("fake-transport driver", () => {
  test("fetches context with exact auth, URL, payload and deadline", async () => {
    let seenUrl = "";
    let seenAuth: string | undefined;
    let seenTimeout = 0;
    const transport: Transport = async (req) => {
      seenUrl = req.url;
      seenAuth = req.headers["Authorization"];
      seenTimeout = req.timeoutMs;
      expect(req.body).toContain('"session":"agent:opencode:session:ses-1"');
      return {
        status: 200,
        headers: {},
       body: new TextEncoder().encode(validPackJson()),
      };
    };
    const result = await fetchContextPack(depsWith(transport), {
      query: "q",
      session: "agent:opencode:session:ses-1",
      workspace: "/srv/project",
    });
    if (result.ok !== true) {
      throw new Error(`expected ok, got ${result.outcome}`);
    }
    expect(seenUrl).toBe("http://127.0.0.1:7331/v1/context");
    expect(seenAuth).toBe(`Bearer ${TOKEN}`);
    expect(seenTimeout).toBe(5000);
  });

  test("submit maps 201/409/422/500/timeout to fail-open outcomes", async () => {
    const payload = {
      session_id: "s",
      turn_id: "t",
      user_text: "hello",
      assistant_text: "world",
      captured_at: "2026-09-07T00:00:00Z",
    };
    const cases: Array<[number, string]> = [
      [201, "captured"],
      [409, "conflict"],
      [422, "rejected"],
      [500, "fail-open"],
    ];
    for (const [status, outcome] of cases) {
      const result = await submitTurn(depsWith(async () => ({
        status,
        headers: {},
        body: new TextEncoder().encode("{}"),
      })), { payload });
      expect(result.outcome).toBe(outcome);
    }
    const timeoutDeps = depsWith(async () => ({ kind: "timeout" }));
    const timeoutResult = await submitTurn(timeoutDeps, { payload });
    expect(timeoutResult.outcome).toBe("fail-open");
  });

  test("401 context fetch fails open without body logs", async () => {
    const logged: Array<unknown> = [];
    const deps = depsWith(async () => ({
      status: 401,
      headers: {},
      body: new TextEncoder().encode("denied"),
    }));
    deps.log = (entry: unknown) => {
      logged.push(entry);
    };
    const result = await fetchContextPack(deps, { query: "q" });
    expect(result.ok).toBe(false);
    expect(JSON.stringify(logged)).not.toContain("denied");
  });

  test("logger failures do not reject context or submit", async () => {
    let calls = 0;
    const deps = depsWith(async () => ({
      status: calls++ === 0 ? 200 : 201,
      headers: {},
       body: new TextEncoder().encode(validPackJson()),
    }));
    deps.log = () => { throw new Error("sink unavailable"); };
    const context = await fetchContextPack(deps, { query: "q" });
    expect(context.ok).toBe(true);
    const submit = await submitTurn(deps, { payload: {
      session_id: "s", turn_id: "t", user_text: "hello", assistant_text: "world",
      captured_at: "2026-09-07T00:00:00Z",
    } });
    expect(submit.outcome).toBe("captured");
  });
});

import { describe, expect, test } from "bun:test";
import {
  postJson,
  createFetchTransport,
  type Transport,
  type TransportResponse,
} from "../src/httpClient.ts";

const BASE_SETTINGS = {
  timeoutMs: 5000,
  maxResponseBytes: 1024 * 1024,
};

function okTransport(assert: (req: {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: string;
  timeoutMs: number;
}) => TransportResponse): Transport {
  return async (req) => assert(req);
}

function jsonBody(text: string): TransportResponse {
  return {
    status: 200,
    headers: { "content-type": "application/json" },
    body: new TextEncoder().encode(text),
  };
}

describe("bounded http client", () => {
  test("sends exact URL, auth, content type, payload and deadline", async () => {
    let seenTimeout = 0;
    const transport = okTransport((req) => {
      expect(req.url).toBe("http://127.0.0.1:7331/v1/context");
      expect(req.method).toBe("POST");
      expect(req.headers["Authorization"]).toBe("Bearer " + "k".repeat(32));
      expect(req.headers["Content-Type"]).toBe("application/json");
      seenTimeout = req.timeoutMs;
      expect(req.body).toBe('{"query":"recall"}');
      return jsonBody("{}");
    });
    const result = await postJson(
      transport,
      { ...BASE_SETTINGS, clock: () => 0 },
      {
        url: "http://127.0.0.1:7331/v1/context",
        token: "k".repeat(32),
        payload: { query: "recall" },
      },
    );
    if (result.kind !== "ok") {
      throw new Error(`expected ok, got ${result.kind}`);
    }
    expect(result.status).toBe(200);
    expect(seenTimeout).toBe(5000);
  });

  test("surfaces 401/422/500 statuses without throwing", async () => {
    for (const status of [401, 422, 500]) {
      const transport: Transport = async () => ({
        status,
        headers: {},
        body: new TextEncoder().encode("{}"),
      });
      const result = await postJson(
        transport,
        { ...BASE_SETTINGS, clock: () => 0 },
        { url: "http://127.0.0.1:7331/v1/turns", token: "k".repeat(32), payload: {} },
      );
      if (result.kind !== "ok") {
        throw new Error(`expected ok result for status ${status}`);
      }
      expect(result.status).toBe(status);
    }
  });

  test("maps timeout to a fail-open kind", async () => {
    const transport: Transport = async () => ({ kind: "timeout" });
    const result = await postJson(
      transport,
      { ...BASE_SETTINGS, clock: () => 0 },
      { url: "http://127.0.0.1:7331/v1/context", token: "k".repeat(32), payload: {} },
    );
    expect(result.kind).toBe("timeout");
  });

  test("settles a never-resolving injected transport by the deadline", async () => {
    const transport: Transport = async () => await new Promise<TransportResponse>(() => undefined);
    const started = performance.now();
    const result = await postJson(
      transport,
      { timeoutMs: 20, maxResponseBytes: 1024, clock: () => performance.now() },
      { url: "http://127.0.0.1:7331/v1/context", token: "k".repeat(32), payload: {} },
    );
    expect(result.kind).toBe("timeout");
    expect(performance.now() - started).toBeLessThan(250);
  });

  test("production fetch transport never follows redirects and caps streamed bytes", async () => {
    let targetHits = 0;
    const fetcher = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
      expect(init?.redirect).toBe("manual");
      expect(init?.signal).toBeInstanceOf(AbortSignal);
      if (String(input).endsWith("/redirect")) {
        return new Response(null, { status: 307, headers: { location: "/target" } });
      }
      targetHits += 1;
      return new Response(new ReadableStream({
        start(controller) {
          controller.enqueue(new Uint8Array(9));
          controller.close();
        },
      }), { status: 200 });
    };
    const transport = createFetchTransport(fetcher);
    const redirect = await postJson(transport, { ...BASE_SETTINGS, maxResponseBytes: 8, clock: () => 0 }, {
      url: "http://example.test/redirect", token: "k".repeat(32), payload: {},
    });
    expect(redirect.kind).toBe("redirect-rejected");
    expect(targetHits).toBe(0);
    const oversized = await postJson(transport, { ...BASE_SETTINGS, maxResponseBytes: 8, clock: () => 0 }, {
      url: "http://example.test/data", token: "k".repeat(32), payload: {},
    });
    expect(oversized.kind).toBe("response-too-large");
  });

  test("maps thrown transport errors without leaking", async () => {
    const transport: Transport = async () => {
      throw new Error(`boom with secret ${"k".repeat(32)}`);
    };
    const result = await postJson(
      transport,
      { ...BASE_SETTINGS, clock: () => 0 },
      { url: "http://127.0.0.1:7331/v1/context", token: "k".repeat(32), payload: {} },
    );
    if (result.kind !== "transport-error") {
      throw new Error(`expected transport-error, got ${result.kind}`);
    }
    expect(result.message).not.toContain("k".repeat(32));
  });

  test("rejects cross-origin redirects that would leak authorization", async () => {
    const transport: Transport = async () => ({
      status: 307,
      headers: { location: "https://evil.example/x" },
      body: new Uint8Array(),
    });
    const result = await postJson(
      transport,
      { ...BASE_SETTINGS, clock: () => 0 },
      { url: "http://127.0.0.1:7331/v1/context", token: "k".repeat(32), payload: {} },
    );
    expect(result.kind).toBe("redirect-rejected");
  });

  test("rejects oversized responses", async () => {
    const transport: Transport = async () => ({
      status: 200,
      headers: {},
      body: new Uint8Array(1024 * 1024 + 1),
    });
    const result = await postJson(
      transport,
      { ...BASE_SETTINGS, clock: () => 0 },
      { url: "http://127.0.0.1:7331/v1/context", token: "k".repeat(32), payload: {} },
    );
    expect(result.kind).toBe("response-too-large");
  });

  test("refuses oversized request payloads client-side", async () => {
    let called = false;
    const transport: Transport = async () => {
      called = true;
      return jsonBody("{}");
    };
    const result = await postJson(
      transport,
      { ...BASE_SETTINGS, clock: () => 0 },
      {
        url: "http://127.0.0.1:7331/v1/turns",
        token: "k".repeat(32),
        payload: { blob: "x".repeat(2 * 1024 * 1024 + 1) },
      },
    );
    expect(result.kind).toBe("request-too-large");
    expect(called).toBe(false);
  });
});

import { decodeUtf8Strict, encodeUtf8 } from "./utf8.ts";

export type TransportRequest = {
  readonly url: string;
  readonly method: "POST";
  readonly headers: Record<string, string>;
  readonly body: string;
  readonly timeoutMs: number;
  readonly maxResponseBytes: number;
  readonly signal: AbortSignal;
};
export type TransportResponse =
  | { readonly status: number; readonly headers: Record<string, string>; readonly body: Uint8Array }
  | { readonly kind: "timeout" | "response-too-large" };
export type Transport = (request: TransportRequest) => Promise<TransportResponse>;
export type HttpResult =
  | { readonly kind: "ok"; readonly status: number; readonly body: string }
  | { readonly kind: "timeout" | "transport-error" | "redirect-rejected" | "response-too-large" | "request-too-large"; readonly message?: string };
export type HttpSettings = { readonly timeoutMs: number; readonly maxResponseBytes: number; readonly clock: () => number };
type Fetcher = (input: string | URL | Request, init?: RequestInit) => Promise<Response>;

async function readBoundedBody(response: Response, maxBytes: number): Promise<Uint8Array | null> {
  if (response.body === null) return new Uint8Array();
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const next = await reader.read();
    if (next.done) break;
    total += next.value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      return null;
    }
    chunks.push(next.value);
  }
  const body = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return body;
}

export function createFetchTransport(fetcher: Fetcher = fetch): Transport {
  return async (request) => {
    try {
      const response = await fetcher(request.url, {
        method: request.method,
        headers: request.headers,
        body: request.body,
        redirect: "manual",
        signal: request.signal,
      });
      if (response.status >= 300 && response.status < 400) {
        return { status: response.status, headers: Object.fromEntries(response.headers.entries()), body: new Uint8Array() };
      }
      const body = await readBoundedBody(response, request.maxResponseBytes);
      if (body === null) return { kind: "response-too-large" };
      return { status: response.status, headers: Object.fromEntries(response.headers.entries()), body };
    } catch (error) {
      if (error instanceof DOMException && error.name === "AbortError") return { kind: "timeout" };
      throw error;
    }
  };
}

export async function postJson(
  transport: Transport,
  settings: HttpSettings,
  request: { readonly url: string; readonly token: string; readonly payload: unknown },
): Promise<HttpResult> {
  const body = JSON.stringify(request.payload);
  if (encodeUtf8(body).length > 2 * 1024 * 1024) return { kind: "request-too-large" };
  const controller = new AbortController();
  const started = settings.clock();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<TransportResponse>((resolve) => {
    timer = setTimeout(() => {
      controller.abort();
      resolve({ kind: "timeout" });
    }, settings.timeoutMs);
  });
  try {
    const response = await Promise.race([
      transport({ url: request.url, method: "POST", headers: { Authorization: `Bearer ${request.token}`, "Content-Type": "application/json" }, body, timeoutMs: settings.timeoutMs, maxResponseBytes: settings.maxResponseBytes, signal: controller.signal }),
      deadline,
    ]);
    if ("kind" in response) return response;
    if (response.status >= 300 && response.status < 400) return { kind: "redirect-rejected" };
    if (response.body.length > settings.maxResponseBytes) return { kind: "response-too-large" };
    if (settings.clock() - started > settings.timeoutMs) return { kind: "timeout" };
    const responseBody = decodeUtf8Strict(response.body);
    if (responseBody === null) return { kind: "transport-error", message: "invalid response encoding" };
    return { kind: "ok", status: response.status, body: responseBody };
  } catch {
    return { kind: "transport-error", message: "transport failed" };
  } finally {
    if (timer !== undefined) clearTimeout(timer);
    controller.abort();
  }
}

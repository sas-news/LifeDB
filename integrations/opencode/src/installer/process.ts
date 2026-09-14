import { spawn } from "node:child_process";
import { StringDecoder } from "node:string_decoder";

const DEFAULT_TIMEOUT_MS = 120_000;
const DEFAULT_MAX_OUTPUT_BYTES = 4 * 1024 * 1024;
const MAX_TIMEOUT_MS = 2_147_483_647;
const MAX_OUTPUT_BYTES = 64 * 1024 * 1024;
const TERMINATION_GRACE_MS = 100;

export type ProcessLimits = {
  readonly timeoutMs?: number;
  readonly maxOutputBytes?: number;
  readonly signal?: AbortSignal;
};

export type ProcessErrorKind = "timeout" | "aborted" | "stdout-overflow" | "stderr-overflow" | "spawn-failure" | "invalid-limits";

export class ProcessError extends Error {
  public override readonly name = "ProcessError";
  public readonly kind: ProcessErrorKind;
  constructor(kindOrMessage: ProcessErrorKind | string = "spawn-failure", message?: string) {
    const isKind = kindOrMessage === "timeout" || kindOrMessage === "aborted" || kindOrMessage === "stdout-overflow" || kindOrMessage === "stderr-overflow" || kindOrMessage === "spawn-failure" || kindOrMessage === "invalid-limits";
    const kind: ProcessErrorKind = kindOrMessage === "timeout" || kindOrMessage === "aborted" || kindOrMessage === "stdout-overflow" || kindOrMessage === "stderr-overflow" || kindOrMessage === "spawn-failure" || kindOrMessage === "invalid-limits" ? kindOrMessage : "spawn-failure";
    super(message ?? (isKind ? `process failed: ${kind}` : kindOrMessage));
    this.kind = kind;
  }
}

export type ProcessRunner = (command: readonly string[], cwd: string, limits?: ProcessLimits) => Promise<{ readonly stdout: string; readonly stderr: string; readonly status: number }>;

export const runProcess: ProcessRunner = (command, cwd, limits = {}) => new Promise((resolve, reject) => {
  const timeoutMs = limits.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxOutputBytes = limits.maxOutputBytes ?? DEFAULT_MAX_OUTPUT_BYTES;
  if (!Number.isInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > MAX_TIMEOUT_MS || !Number.isInteger(maxOutputBytes) || maxOutputBytes <= 0 || maxOutputBytes > MAX_OUTPUT_BYTES) {
    return reject(new ProcessError("invalid-limits"));
  }
  if (limits.signal?.aborted === true) {
    reject(new ProcessError("aborted"));
    return;
  }

  let child: ReturnType<typeof spawn>;
  try {
    child = spawn(command[0] ?? "", command.slice(1), { cwd, shell: false, stdio: ["ignore", "pipe", "pipe"] });
  } catch {
    reject(new ProcessError("spawn-failure"));
    return;
  }
  const stdoutChunks: Buffer[] = [];
  const stderrChunks: Buffer[] = [];
  let stdoutBytes = 0;
  let stderrBytes = 0;
  let terminalError: ProcessError | undefined;
  let timeoutTimer: ReturnType<typeof setTimeout> | undefined;
  let killTimer: ReturnType<typeof setTimeout> | undefined;
  let settled = false;
  const stdoutDecoder = new StringDecoder("utf8");
  const stderrDecoder = new StringDecoder("utf8");
  const stdout = child.stdout;
  const stderr = child.stderr;
  if (stdout === null || stderr === null) {
    child.kill("SIGKILL");
    reject(new ProcessError("spawn-failure"));
    return;
  }

  const requestTermination = (error: ProcessError): void => {
    if (terminalError !== undefined) return;
    terminalError = error;
    child.kill("SIGTERM");
    killTimer = setTimeout(() => {
      if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
    }, TERMINATION_GRACE_MS);
  };
  const retain = (chunks: Buffer[], bytes: number, chunk: Buffer): number => {
    if (bytes + chunk.byteLength <= maxOutputBytes) chunks.push(chunk);
    return bytes + chunk.byteLength;
  };
  const onAbort = (): void => requestTermination(new ProcessError("aborted"));
  const onTimeout = (): void => requestTermination(new ProcessError("timeout"));
  const onError = (): void => requestTermination(new ProcessError("spawn-failure"));
  const finish = (status: number | null): void => {
    if (settled) return;
    settled = true;
    if (timeoutTimer !== undefined) clearTimeout(timeoutTimer);
    if (killTimer !== undefined) clearTimeout(killTimer);
    limits.signal?.removeEventListener("abort", onAbort);
    stdout.removeListener("data", onStdout);
    stderr.removeListener("data", onStderr);
    child.removeListener("error", onError);
    child.removeListener("close", finish);
    if (terminalError !== undefined) {
      reject(terminalError);
      return;
    }
    if (stdoutBytes > maxOutputBytes) {
      reject(new ProcessError("stdout-overflow"));
      return;
    }
    if (stderrBytes > maxOutputBytes) {
      reject(new ProcessError("stderr-overflow"));
      return;
    }
    resolve({ stdout: stdoutDecoder.write(Buffer.concat(stdoutChunks)) + stdoutDecoder.end(), stderr: stderrDecoder.write(Buffer.concat(stderrChunks)) + stderrDecoder.end(), status: status ?? 1 });
  };

  const onStdout = (chunk: Buffer): void => {
    stdoutBytes = retain(stdoutChunks, stdoutBytes, chunk);
    if (stdoutBytes > maxOutputBytes) requestTermination(new ProcessError("stdout-overflow"));
  };
  const onStderr = (chunk: Buffer): void => {
    stderrBytes = retain(stderrChunks, stderrBytes, chunk);
    if (stderrBytes > maxOutputBytes) requestTermination(new ProcessError("stderr-overflow"));
  };
  stdout.on("data", onStdout);
  stderr.on("data", onStderr);
  child.once("error", onError);
  child.once("close", finish);
  limits.signal?.addEventListener("abort", onAbort, { once: true });
  timeoutTimer = setTimeout(onTimeout, timeoutMs);
});

export async function requireCompatibleOpenCode(runner: ProcessRunner, cwd: string): Promise<void> {
  const result = await runner(["opencode", "--version"], cwd);
  if (result.status !== 0 || result.stderr !== "" || (result.stdout !== "1.18.29" && result.stdout !== "1.18.29\n")) throw new ProcessError("OpenCode compatibility check failed");
}

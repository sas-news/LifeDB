export const LOG_LEVELS = ["info", "warn"] as const;
export type LogLevel = (typeof LOG_LEVELS)[number];
export type LogOutcome = "ok" | "fail-open" | "rejected" | "conflict" | "dropped";
export type LogEntry = { readonly level: LogLevel; readonly op: string; readonly outcome: LogOutcome };
export type Logger = { readonly info: (op: string, outcome: LogOutcome) => void; readonly warn: (op: string, outcome: LogOutcome) => void };
const outcomes = new Set<LogOutcome>(["ok", "fail-open", "rejected", "conflict", "dropped"]);
function emit(sink: (entry: LogEntry) => void, level: LogLevel, op: string, outcome: LogOutcome): void {
  if (!outcomes.has(outcome)) return;
  const safeOp = /^[a-z][a-z0-9]*(?:\.[a-z][a-z0-9]*)*$/u.test(op) ? op.slice(0, 64) : "unknown";
  try {
    sink({ level, op: safeOp, outcome });
  } catch (error) {
    if (error instanceof Error) return;
    return;
  }
}
export function createLogger(sink: (entry: LogEntry) => void): Logger { return { info: (op, outcome) => emit(sink, "info", op, outcome), warn: (op, outcome) => emit(sink, "warn", op, outcome) }; }

import type { ContextPack } from "./bridge.ts";

export type PendingRegistration = {
  readonly sessionID: string;
  readonly messageID: string;
  readonly query: string;
  readonly workspace?: string;
};

export type ContextCache =
  | { readonly status: "unresolved" }
  | { readonly status: "in-flight" }
  | { readonly status: "resolved"; readonly pack: ContextPack | null };

export type PendingSnapshot = PendingRegistration & { readonly context: ContextCache };

export type PreflightStateLimits = {
  readonly maxSessions?: number;
  readonly maxUsersPerSession?: number;
  readonly maxUsers?: number;
};

const DEFAULT_LIMITS = {
  maxSessions: 32,
  maxUsersPerSession: 16,
  maxUsers: 128,
} as const;

type Entry = PendingRegistration & {
  readonly sequence: number;
  context: ContextCache;
  inFlight?: Promise<ContextPack | null>;
};

type Session = {
  readonly sequence: number;
  readonly users: Map<string, Entry>;
};

function limit(value: number | undefined, fallback: number): number {
  if (value === undefined) return fallback;
  if (!Number.isSafeInteger(value) || value < 1) throw new Error("preflight state limit invalid");
  return value;
}

export class PreflightState {
  private readonly sessions = new Map<string, Session>();
  private readonly maxSessions: number;
  private readonly maxUsersPerSession: number;
  private readonly maxUsers: number;
  private sequence = 0;
  private totalUsers = 0;
  private disposed = false;

  public constructor(limits: PreflightStateLimits = {}) {
    this.maxSessions = limit(limits.maxSessions, DEFAULT_LIMITS.maxSessions);
    this.maxUsersPerSession = limit(limits.maxUsersPerSession, DEFAULT_LIMITS.maxUsersPerSession);
    this.maxUsers = limit(limits.maxUsers, DEFAULT_LIMITS.maxUsers);
  }

  public get sessionCount(): number {
    return this.sessions.size;
  }

  public get userCount(): number {
    return this.totalUsers;
  }

  public register(entry: PendingRegistration): boolean {
    if (this.disposed) return false;
    const existingSession = this.sessions.get(entry.sessionID);
    if (existingSession !== undefined && existingSession.users.has(entry.messageID)) return false;
    const session = existingSession ?? this.createSession(entry.sessionID);
    while (session.users.size >= this.maxUsersPerSession) this.evictOldestUser(session);
    const stored: Entry = { ...entry, sequence: ++this.sequence, context: { status: "unresolved" } };
    session.users.set(entry.messageID, stored);
    this.totalUsers += 1;
    this.enforceGlobalUserLimit();
    return true;
  }

  public read(sessionID: string, messageID: string): PendingSnapshot | undefined {
    const entry = this.sessions.get(sessionID)?.users.get(messageID);
    if (entry === undefined) return undefined;
    return this.snapshot(entry);
  }

  public readLatest(sessionID: string): PendingSnapshot | undefined {
    const users = this.sessions.get(sessionID)?.users;
    if (users === undefined) return undefined;
    let latest: Entry | undefined;
    for (const entry of users.values()) {
      if (latest === undefined || entry.sequence > latest.sequence) latest = entry;
    }
    return latest === undefined ? undefined : this.snapshot(latest);
  }

  public readAll(sessionID: string): readonly PendingSnapshot[] {
    const users = this.sessions.get(sessionID)?.users;
    if (users === undefined) return [];
    return [...users.values()].sort((left, right) => left.sequence - right.sequence).map((entry) => this.snapshot(entry));
  }

  public resolve(
    sessionID: string,
    messageID: string,
    loader: () => Promise<ContextPack | null>,
  ): Promise<ContextPack | null> {
    const session = this.sessions.get(sessionID);
    const entry = session?.users.get(messageID);
    if (entry === undefined) return Promise.resolve(null);
    if (entry.context.status === "resolved") return Promise.resolve(entry.context.pack);
    if (entry.inFlight !== undefined) return entry.inFlight;
    const pending = Promise.resolve()
      .then(loader)
      .then(
        (pack) => this.finishResolve(sessionID, messageID, entry, pack),
        () => this.finishResolve(sessionID, messageID, entry, null),
      );
    entry.inFlight = pending;
    entry.context = { status: "in-flight" };
    return pending;
  }

  public evict(sessionID: string, messageID: string): boolean {
    const session = this.sessions.get(sessionID);
    if (session === undefined || !session.users.delete(messageID)) return false;
    this.totalUsers -= 1;
    if (session.users.size === 0) this.sessions.delete(sessionID);
    return true;
  }

  public async dispose(): Promise<void> {
    this.disposed = true;
    this.sessions.clear();
    this.totalUsers = 0;
  }

  private createSession(sessionID: string): Session {
    while (this.sessions.size >= this.maxSessions) this.evictOldestSession();
    const session: Session = { sequence: ++this.sequence, users: new Map() };
    this.sessions.set(sessionID, session);
    return session;
  }

  private finishResolve(
    sessionID: string,
    messageID: string,
    entry: Entry,
    pack: ContextPack | null,
  ): ContextPack | null {
    const current = this.sessions.get(sessionID)?.users.get(messageID);
    if (current !== entry) return null;
    entry.context = { status: "resolved", pack };
    return pack;
  }

  private snapshot(entry: Entry): PendingSnapshot {
    return {
      sessionID: entry.sessionID,
      messageID: entry.messageID,
      query: entry.query,
      ...(entry.workspace === undefined ? {} : { workspace: entry.workspace }),
      context: entry.context,
    };
  }

  private evictOldestUser(session: Session): void {
    let oldest: Entry | undefined;
    for (const candidate of session.users.values()) {
      if (oldest === undefined || candidate.sequence < oldest.sequence) oldest = candidate;
    }
    if (oldest !== undefined) this.evict(oldest.sessionID, oldest.messageID);
  }

  private evictOldestSession(): void {
    let oldestID: string | undefined;
    let oldestSequence = Number.POSITIVE_INFINITY;
    for (const [sessionID, session] of this.sessions) {
      if (session.sequence < oldestSequence) {
        oldestID = sessionID;
        oldestSequence = session.sequence;
      }
    }
    if (oldestID !== undefined) {
      const session = this.sessions.get(oldestID);
      if (session !== undefined) {
        this.totalUsers -= session.users.size;
        this.sessions.delete(oldestID);
      }
    }
  }

  private enforceGlobalUserLimit(): void {
    while (this.totalUsers > this.maxUsers) {
      let oldestSession: Session | undefined;
      for (const session of this.sessions.values()) {
        if (session.users.size > 0 && (oldestSession === undefined || session.sequence < oldestSession.sequence)) {
          oldestSession = session;
        }
      }
      if (oldestSession === undefined) return;
      this.evictOldestUser(oldestSession);
    }
  }
}

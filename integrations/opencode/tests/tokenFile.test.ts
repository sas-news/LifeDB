import { describe, expect, test } from "bun:test";
import { loadTokenFile, type TokenFileSystem } from "../src/tokenFile.ts";
import { O_NOFOLLOW, O_NONBLOCK } from "node:constants";

const GOOD_TOKEN = "t".repeat(40);

function baseStat() {
  return {
    isFile: () => true,
    isSymbolicLink: () => false,
    isDirectory: () => false,
    isFifo: () => false,
    mode: 0o100600,
    uid: 1000,
    dev: 7,
    ino: 42,
    size: GOOD_TOKEN.length,
    mtimeNs: 111n,
    ctimeNs: 222n,
  };
}

function makeFs(overrides: Partial<TokenFileSystem> = {}): TokenFileSystem {
  const stat = baseStat();
  const payload = new TextEncoder().encode(GOOD_TOKEN);
  return {
    lstat: (_path: string) => ({ ...stat }),
    open: (_path: string) => 3,
    fstat: (_fd: number) => ({ ...stat }),
    read: (_fd: number, _length: number) => payload,
    close: (_fd: number) => undefined,
    currentUid: () => 1000,
    ...overrides,
  };
}

describe("token file loader", () => {
  test("loads exact bytes from a safe file", () => {
    const result = loadTokenFile("/run/secrets/lifedb-api-token", { fs: makeFs() });
    if (result.ok !== true) {
      throw new Error(`expected ok, got ${result.code}`);
    }
    expect(result.token).toBe(GOOD_TOKEN);
  });

  test("opens without following or blocking special files and preserves stat precision", () => {
    let flags = 0;
    const fs = makeFs({
      open: (_path: string, receivedFlags?: number) => {
        flags = receivedFlags ?? 0;
        return 3;
      },
      lstat: (_path: string) => ({ ...baseStat(), mtimeNs: 9007199254740993n, ctimeNs: 9007199254740995n }),
      fstat: (_fd: number) => ({ ...baseStat(), mtimeNs: 9007199254740993n, ctimeNs: 9007199254740995n }),
    });
    const result = loadTokenFile("/run/secrets/lifedb-api-token", { fs });
    expect(result.ok).toBe(true);
    expect(flags & O_NONBLOCK).toBeTruthy();
    expect(flags & O_NOFOLLOW).toBeTruthy();
  });

  test("rejects relative paths", () => {
    const result = loadTokenFile("relative/token", { fs: makeFs() });
    expect(result.ok).toBe(false);
  });

  test("rejects symlinks without leaking the path", () => {
    const fs = makeFs({ lstat: (_p: string) => ({ ...baseStat(), isSymbolicLink: () => true }) });
    const result = loadTokenFile("/run/secrets/lifedb-api-token", { fs });
    if (result.ok !== false) {
      throw new Error("expected failure");
    }
    expect(result.message).not.toContain("/run/secrets");
    expect(result.code).toBe("symlink");
  });

  test("rejects group/other permission bits", () => {
    const fs = makeFs({ fstat: (_fd: number) => ({ ...baseStat(), mode: 0o100644 }) });
    const result = loadTokenFile("/run/secrets/lifedb-api-token", { fs });
    if (result.ok !== false) {
      throw new Error("expected failure");
    }
    expect(result.code).toBe("permissions");
  });

  test("rejects wrong owner", () => {
    const fs = makeFs({ currentUid: () => 2000 });
    const result = loadTokenFile("/run/secrets/lifedb-api-token", { fs });
    if (result.ok !== false) {
      throw new Error("expected failure");
    }
    expect(result.code).toBe("owner");
  });

  test("rejects dev/ino swap races between lstat and open", () => {
    const fs = makeFs({ fstat: (_fd: number) => ({ ...baseStat(), ino: 99 }) });
    const result = loadTokenFile("/run/secrets/lifedb-api-token", { fs });
    if (result.ok !== false) {
      throw new Error("expected failure");
    }
    expect(result.code).toBe("changed");
  });

  test("rejects oversized files before reading", () => {
    let opened = false;
    const fs = makeFs({
      lstat: (_p: string) => ({ ...baseStat(), size: 4097 }),
      open: (_p: string) => {
        opened = true;
        return 3;
      },
    });
    const result = loadTokenFile("/run/secrets/lifedb-api-token", { fs });
    expect(result.ok).toBe(false);
    expect(opened).toBe(false);
  });

  test("never trims trailing newlines", () => {
    const payload = new TextEncoder().encode(`${GOOD_TOKEN}\n`);
    const fs = makeFs({
      lstat: (_p: string) => ({ ...baseStat(), size: payload.length }),
      fstat: (_fd: number) => ({ ...baseStat(), size: payload.length }),
      read: (_fd: number, _length: number) => payload,
    });
    const result = loadTokenFile("/run/secrets/lifedb-api-token", { fs });
    expect(result.ok).toBe(false);
  });

  test("closes the descriptor on read failure", () => {
    let closed = 0;
    const fs = makeFs({
      read: (_fd: number, _length: number): Uint8Array => {
        throw new Error("disk gone");
      },
      close: (_fd: number) => {
        closed += 1;
      },
    });
    const result = loadTokenFile("/run/secrets/lifedb-api-token", { fs });
    expect(result.ok).toBe(false);
    expect(closed).toBe(1);
  });
});

import { closeSync, fstatSync, lstatSync, openSync, readSync } from "node:fs";
import { O_NOFOLLOW, O_NONBLOCK, O_RDONLY } from "node:constants";
import type { BigIntStats } from "node:fs";
import { decodeUtf8Strict, utf8ByteLength } from "./utf8.ts";

export const MAX_TOKEN_FILE_BYTES = 4096;
type Stat = { readonly isFile: () => boolean; readonly isSymbolicLink: () => boolean; readonly isDirectory: () => boolean; readonly isFifo: () => boolean; readonly mode: number; readonly uid: number; readonly dev: number; readonly ino: number; readonly size: number; readonly mtimeNs: number | bigint; readonly ctimeNs: number | bigint };
export type TokenFileSystem = {
  readonly lstat: (path: string) => Stat;
  readonly open: (path: string, flags?: number) => number;
  readonly fstat: (fd: number) => Stat;
  readonly read: (fd: number, length: number) => Uint8Array;
  readonly close: (fd: number) => void;
  readonly currentUid: () => number;
};
type TokenResult = { readonly ok: true; readonly token: string } | { readonly ok: false; readonly code: string; readonly message: string };
const OPEN_FLAGS = O_RDONLY | O_NOFOLLOW | O_NONBLOCK | 0x80000;

const nativeFs: TokenFileSystem = {
  lstat: (path) => toStat(lstatSync(path, { bigint: true })),
  open: (path) => openSync(path, OPEN_FLAGS),
  fstat: (fd) => toStat(fstatSync(fd, { bigint: true })),
  read: (fd, length) => {
    const buffer = new Uint8Array(length);
    const bytesRead = readSync(fd, buffer, 0, length, null);
    return buffer.subarray(0, bytesRead);
  },
  close: (fd) => closeSync(fd),
  currentUid: () => process.getuid?.() ?? -1,
};

function toStat(stat: BigIntStats): Stat {
  return { isFile: () => stat.isFile(), isSymbolicLink: () => stat.isSymbolicLink(), isDirectory: () => stat.isDirectory(), isFifo: () => stat.isFIFO(), mode: Number(stat.mode), uid: Number(stat.uid), dev: Number(stat.dev), ino: Number(stat.ino), size: Number(stat.size), mtimeNs: stat.mtimeNs, ctimeNs: stat.ctimeNs };
}

function safeClose(fs: TokenFileSystem, fd: number): void {
  try { fs.close(fd); } catch (error) { if (error instanceof Error) return; throw error; }
}

function sameFile(left: Stat, right: Stat): boolean {
  return left.dev === right.dev && left.ino === right.ino && left.size === right.size && left.mode === right.mode && left.uid === right.uid && left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs;
}

function failure(code: string): TokenResult { return { ok: false, code, message: "token file rejected" }; }

export function loadTokenFile(path: string, options: { readonly fs?: TokenFileSystem } = {}): TokenResult {
  if (!path.startsWith("/")) return failure("absolute");
  const fs = options.fs ?? nativeFs;
  let opened = false;
  let fd = -1;
  try {
    const before = fs.lstat(path);
    if (before.isSymbolicLink()) return failure("symlink");
    if (!before.isFile() || before.isDirectory() || before.isFifo()) return failure("type");
    if ((before.mode & 0o077) !== 0) return failure("permissions");
    if (before.uid !== fs.currentUid()) return failure("owner");
    if (before.size < 0 || before.size > MAX_TOKEN_FILE_BYTES) return failure("size");
    fd = fs.open(path, OPEN_FLAGS);
    opened = true;
    const openedStat = fs.fstat(fd);
    if (!openedStat.isFile() || openedStat.isSymbolicLink() || openedStat.isDirectory() || (openedStat.mode & 0o077) !== 0) return failure(openedStat.mode === before.mode ? "type" : "permissions");
    if (openedStat.uid !== fs.currentUid()) return failure("owner");
    if (!sameFile(before, openedStat)) return failure("changed");
    const bytes = fs.read(fd, MAX_TOKEN_FILE_BYTES + 1);
    const finished = fs.fstat(fd);
    if (!sameFile(openedStat, finished) || bytes.length !== finished.size || bytes.length > MAX_TOKEN_FILE_BYTES) return failure("changed");
    const after = fs.lstat(path);
    if (!sameFile(finished, after)) return failure("changed");
    const decoded = decodeUtf8Strict(bytes);
    if (decoded === null || utf8ByteLength(decoded) < 32 || decoded.length === 0 || /\s/u.test(decoded)) return failure("content");
    return { ok: true, token: decoded };
  } catch {
    return failure("io");
  } finally {
    if (opened) {
      safeClose(fs, fd);
    }
  }
}

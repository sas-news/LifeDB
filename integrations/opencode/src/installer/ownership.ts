import { createHash } from "node:crypto";
import { lstat, mkdir, open, readFile, rename, rm } from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

export const OWNER_MARKER = "// lifedb-opencode-owner:v1";
export const ACTIVE_NAME = "lifedb.ts";
export const DISABLED_NAME = "lifedb.ts.disabled";

export class InstallerError extends Error {
  public override readonly name: string = "InstallerError";
}

export class PublicationUncertainError extends InstallerError {
  public override readonly name: string = "PublicationUncertainError";
}

export type TargetState = "absent" | "active" | "disabled";

export function pluginDirectory(configHome: string): string {
  return join(configHome, "opencode", "plugins");
}

export function targetPath(configHome: string, state: TargetState): string {
  const name = state === "active" ? ACTIVE_NAME : DISABLED_NAME;
  return join(pluginDirectory(configHome), name);
}

function digest(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

export function ownedBytes(source: Uint8Array): Uint8Array {
  const header = `${OWNER_MARKER} payload-sha256:${digest(source)}\n`;
  const headerBytes = new TextEncoder().encode(header);
  const result = new Uint8Array(headerBytes.length + source.length);
  result.set(headerBytes);
  result.set(source, headerBytes.length);
  return result;
}

export function isOwned(bytes: Uint8Array): boolean {
  const newline = bytes.indexOf(10);
  if (newline < 0) return false;
  const header = new TextDecoder().decode(bytes.subarray(0, newline));
  const match = new RegExp(`^${OWNER_MARKER} payload-sha256:([0-9a-f]{64})$`, "u").exec(header);
  return match?.[1] === digest(bytes.subarray(newline + 1));
}

async function validatePlugin(path: string): Promise<void> {
  const loaded: unknown = await import(`${pathToFileURL(path).href}?lifedb=${Date.now()}`);
  if (typeof loaded !== "object" || loaded === null || !("default" in loaded)) throw new InstallerError("plugin candidate is invalid");
  const candidate = loaded.default;
  if (typeof candidate !== "object" || candidate === null || !("id" in candidate) || !("server" in candidate) || candidate.id !== "lifedb" || typeof candidate.server !== "function") throw new InstallerError("plugin candidate is invalid");
}

async function exists(path: string): Promise<boolean> {
  try {
    await lstat(path);
    return true;
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") return false;
    throw error;
  }
}

export async function readOwned(path: string): Promise<Uint8Array | undefined> {
  let info;
  try {
    info = await lstat(path);
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") return undefined;
    throw new InstallerError("plugin target cannot be inspected");
  }
  if (!info.isFile() || info.isSymbolicLink()) throw new InstallerError("plugin target is not a regular file");
  if ((info.mode & 0o777) !== 0o600) throw new InstallerError("plugin target permissions are unsafe");
  const bytes = await readFile(path);
  if (!isOwned(bytes)) throw new InstallerError("plugin target is not owned");
  return bytes;
}

async function lock(directory: string): Promise<string> {
  const path = join(directory, ".lifedb.lock");
  try {
    await mkdir(path);
  } catch {
    throw new InstallerError("another installer operation is active");
  }
  return path;
}

async function unlock(path: string): Promise<void> {
  await rm(path, { recursive: true, force: true });
}

export async function publishOwned(configHome: string, source: Uint8Array): Promise<void> {
  const directory = pluginDirectory(configHome);
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const lockPath = await lock(directory);
  try {
    const destination = targetPath(configHome, "active");
    const bytes = ownedBytes(source);
    const disabled = await readOwned(targetPath(configHome, "disabled"));
    if (disabled !== undefined) throw new InstallerError("both plugin lifecycle targets exist");
    const current = await readOwned(destination);
    if (current !== undefined && Buffer.from(current).equals(Buffer.from(bytes))) return;
    const temporary = join(directory, `.lifedb.${process.pid}.${Date.now()}.tmp.ts`);
    let renamed = false;
    let ownsTemporary = false;
    try {
      const handle = await open(temporary, "wx", 0o600);
      ownsTemporary = true;
      try {
        await handle.write(bytes);
        await handle.chmod(0o600);
        await handle.sync();
      } finally {
        await handle.close();
      }
      await validatePlugin(temporary);
      await rename(temporary, destination);
      renamed = true;
      try {
        const directoryHandle = await open(directory, "r");
        try { await directoryHandle.sync(); } finally { await directoryHandle.close(); }
      } catch (error) {
        throw new PublicationUncertainError("plugin publication durability is uncertain");
      }
    } finally {
      if (ownsTemporary && !renamed) await rm(temporary, { force: true });
    }
  } finally {
    await unlock(lockPath);
  }
}

export async function renameOwned(configHome: string, from: TargetState, to: TargetState): Promise<void> {
  const directory = pluginDirectory(configHome);
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const lockPath = await lock(directory);
  try {
    const source = targetPath(configHome, from);
    const destination = targetPath(configHome, to);
    const bytes = await readOwned(source);
    if (bytes === undefined) throw new InstallerError("owned plugin target is absent");
    if (await exists(destination)) throw new InstallerError("both plugin lifecycle targets exist");
    await rename(source, destination);
    const directoryHandle = await open(directory, "r");
    try { await directoryHandle.sync(); } finally { await directoryHandle.close(); }
  } finally {
    await unlock(lockPath);
  }
}

export async function removeOwned(configHome: string): Promise<void> {
  const directory = pluginDirectory(configHome);
  try {
    await lstat(directory);
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") return;
    throw new InstallerError("plugin directory cannot be inspected");
  }
  const lockPath = await lock(directory);
  try {
    const active = await readOwned(targetPath(configHome, "active"));
    const disabled = await readOwned(targetPath(configHome, "disabled"));
    if (active !== undefined && disabled !== undefined) throw new InstallerError("both plugin lifecycle targets exist");
    const target = active === undefined ? targetPath(configHome, "disabled") : targetPath(configHome, "active");
    if (active !== undefined || disabled !== undefined) await rm(target);
    const directoryHandle = await open(directory, "r");
    try { await directoryHandle.sync(); } finally { await directoryHandle.close(); }
  } finally {
    await unlock(lockPath);
  }
}

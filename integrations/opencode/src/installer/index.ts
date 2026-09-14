import { mkdtemp, mkdir, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { renameOwned, pluginDirectory, publishOwned, removeOwned, targetPath } from "./ownership.ts";
import { requireCompatibleOpenCode, runProcess, type ProcessRunner } from "./process.ts";

export { pluginDirectory, targetPath } from "./ownership.ts";
export const lifecyclePath = targetPath;
export type { ProcessLimits, ProcessRunner } from "./process.ts";

export async function createTempConfigHome(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "lifedb-opencode-"));
  await mkdir(pluginDirectory(root), { recursive: true, mode: 0o700 });
  return root;
}

export async function installPlugin(options: { readonly configHome: string; readonly source: Uint8Array; readonly hostVersion: string; readonly runner?: ProcessRunner; readonly cwd?: string }): Promise<void> {
  if (options.hostVersion !== "1.18.29") throw new Error("OpenCode compatibility check failed");
  const runner = options.runner;
  if (runner !== undefined) await requireCompatibleOpenCode(runner, options.cwd ?? process.cwd());
  await publishOwned(options.configHome, options.source);
}

export async function disablePlugin(configHome: string): Promise<void> {
  await renameOwned(configHome, "active", "disabled");
}

export async function enablePlugin(configHome: string): Promise<void> {
  await renameOwned(configHome, "disabled", "active");
}

export async function uninstallPlugin(configHome: string): Promise<void> {
  await removeOwned(configHome);
}

export async function runInstallerCommand(command: string, options: { readonly configHome: string; readonly sourcePath: string; readonly cwd: string; readonly runner?: ProcessRunner }): Promise<void> {
  const runner = options.runner ?? runProcess;
  if (!new Set(["check", "install", "disable", "enable", "uninstall"]).has(command)) throw new Error("unsupported installer command");
  await requireCompatibleOpenCode(runner, options.cwd);
  if (command === "check") return;
  if (command === "install") {
    const stagingDirectory = await mkdtemp(join(options.cwd, ".lifedb-entry-"));
    const stagingPath = join(stagingDirectory, "entry.ts");
    try {
      const tests = await runner(["bun", "test"], options.cwd);
      if (tests.status !== 0) throw new Error("installer validation failed");
      const typecheck = await runner(["bun", "run", "typecheck"], options.cwd);
      if (typecheck.status !== 0) throw new Error("installer validation failed");
      const build = await runner(["bun", "build", options.sourcePath, "--target=bun", "--format=esm", "--outfile", stagingPath], options.cwd);
      if (build.status !== 0) throw new Error("installer validation failed");
      await installPlugin({ configHome: options.configHome, source: await readFile(stagingPath), hostVersion: "1.18.29" });
     } finally {
      await rm(stagingDirectory, { recursive: true, force: true });
    }
    return;
  }
  if (command === "disable") return disablePlugin(options.configHome);
  if (command === "enable") return enablePlugin(options.configHome);
  return uninstallPlugin(options.configHome);
}

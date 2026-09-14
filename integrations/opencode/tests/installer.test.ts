import { afterEach, describe, expect, test } from "bun:test";
import { chmod, mkdir, readFile, readdir, rm, stat, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { createTempConfigHome, installPlugin, lifecyclePath, uninstallPlugin, disablePlugin, enablePlugin, runInstallerCommand } from "../src/installer/index.ts";
import { resolveConfigHome } from "../src/installer/environment.ts";
import { ProcessError, requireCompatibleOpenCode, runProcess, type ProcessRunner } from "../src/installer/process.ts";
import { publishOwned } from "../src/installer/ownership.ts";

const roots: string[] = [];
const source = new TextEncoder().encode("// bundled lifedb plugin\nexport default { id: 'lifedb', server: async () => ({}) };\n");
const node = process.execPath;

function childScript(script: string): readonly string[] {
  return [node, "-e", script];
}

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

async function configHome(): Promise<string> {
  const root = await createTempConfigHome();
  roots.push(root);
  return root;
}

describe("OpenCode installer lifecycle", () => {
  test("publishes an owned mode-0600 file and is byte/mtime idempotent", async () => {
    const root = await configHome();
    const target = lifecyclePath(root, "active");
    await installPlugin({ configHome: root, source, hostVersion: "1.18.29" });
    const first = await readFile(target);
    const firstStat = await stat(target);
    await installPlugin({ configHome: root, source, hostVersion: "1.18.29" });
    const secondStat = await stat(target);
    expect(await readFile(target)).toEqual(first);
    expect(secondStat.mtimeMs).toBe(firstStat.mtimeMs);
    expect(secondStat.mode & 0o777).toBe(0o600);
  });

  test("supports disable, enable, and uninstall only for owned files", async () => {
    const root = await configHome();
    await installPlugin({ configHome: root, source, hostVersion: "1.18.29" });
    await disablePlugin(root);
    expect(await stat(lifecyclePath(root, "disabled"))).toBeTruthy();
    await enablePlugin(root);
    expect(await stat(lifecyclePath(root, "active"))).toBeTruthy();
    await uninstallPlugin(root);
    await expect(stat(lifecyclePath(root, "active"))).rejects.toThrow();
  });

  test("refuses a symlink and preserves a non-owned target", async () => {
    const root = await configHome();
    const target = lifecyclePath(root, "active");
    const unrelated = join(root, "unrelated.ts");
    await mkdir(join(root, "opencode", "plugins"), { recursive: true });
    await writeFile(unrelated, "keep\n");
    await symlink(unrelated, target);
    await expect(installPlugin({ configHome: root, source, hostVersion: "1.18.29" })).rejects.toThrow();
    expect(await readFile(unrelated, "utf8")).toBe("keep\n");
  });

  test("mismatched host version fails before creating the target", async () => {
    const root = await configHome();
    await expect(installPlugin({ configHome: root, source, hostVersion: "1.18.28" })).rejects.toThrow();
    await expect(stat(lifecyclePath(root, "active"))).rejects.toThrow();
  });

  test("enable refuses conflicting active and disabled targets", async () => {
    const root = await configHome();
    await installPlugin({ configHome: root, source, hostVersion: "1.18.29" });
    const active = lifecyclePath(root, "active");
    await writeFile(`${active}.disabled`, await readFile(active));
    await chmod(`${active}.disabled`, 0o600);
    await expect(disablePlugin(root)).rejects.toThrow();
  });

  test("runs the required checks before publishing and preserves bytes on failure", async () => {
    const root = await configHome();
    const cwd = await createTempConfigHome();
    roots.push(cwd);
    await installPlugin({ configHome: root, source, hostVersion: "1.18.29" });
    const before = await readFile(lifecyclePath(root, "active"));
    const commands: string[] = [];
    const runner = async (command: readonly string[]) => {
      commands.push(command.join(" "));
      return { stdout: command[0] === "opencode" ? "1.18.29\n" : "", stderr: "", status: command.includes("typecheck") ? 1 : 0 };
    };
    await expect(runInstallerCommand("install", { configHome: root, sourcePath: "src/entry.ts", cwd, runner })).rejects.toThrow();
    expect(await readFile(lifecyclePath(root, "active"))).toEqual(before);
    expect(commands).toEqual(["opencode --version", "bun test", "bun run typecheck"]);
  });

  test("resolves XDG config home without adding a second config segment", () => {
    expect(resolveConfigHome({ XDG_CONFIG_HOME: "/tmp/xdg", HOME: "/tmp/home" })).toBe("/tmp/xdg");
    expect(resolveConfigHome({ HOME: "/tmp/home" })).toBe("/tmp/home/.config");
  });

  test("rejects unsafe environment roots before creating a target", () => {
    expect(() => resolveConfigHome({ XDG_CONFIG_HOME: "relative" })).toThrow();
    expect(() => resolveConfigHome({ XDG_CONFIG_HOME: "" })).toThrow();
    expect(() => resolveConfigHome({ HOME: "/tmp/bad\nroot" })).toThrow();
    expect(() => resolveConfigHome({})).toThrow();
  });

  test("keeps a pre-existing staging candidate byte-for-byte intact on build failure", async () => {
    const root = await configHome();
    const cwd = await configHome();
    const hostilePath = join(cwd, ".lifedb-entry-hostile.ts");
    const hostile = new TextEncoder().encode("hostile\n");
    await writeFile(hostilePath, hostile);
    const runner: ProcessRunner = async (command) => ({
      stdout: command[0] === "opencode" ? "1.18.29\n" : "",
      stderr: "",
      status: command.includes("build") ? 1 : 0,
    });
    await expect(runInstallerCommand("install", { configHome: root, sourcePath: "src/entry.ts", cwd, runner })).rejects.toThrow();
    expect(Buffer.from(await readFile(hostilePath))).toEqual(Buffer.from(hostile));
  });

  test("builds to an exclusive absolute staging path and cleans it after import failure", async () => {
    const root = await configHome();
    const cwd = await configHome();
    let outputPath = "";
    const runner: ProcessRunner = async (command) => {
      if (command.includes("build")) {
        outputPath = command[command.length - 1] ?? "";
        await writeFile(outputPath, "not a plugin\n");
      }
      return { stdout: command[0] === "opencode" ? "1.18.29\n" : "", stderr: "", status: 0 };
    };
    await expect(runInstallerCommand("install", { configHome: root, sourcePath: "src/entry.ts", cwd, runner })).rejects.toThrow();
    expect(outputPath.startsWith(`${cwd}/`)).toBe(true);
    expect(await readdir(cwd)).not.toContain(outputPath.slice(cwd.length + 1).split("/")[0]);
  });

  test("preserves a publication temp collision owned by another invocation", async () => {
    const root = await configHome();
    const directory = join(root, "opencode", "plugins");
    const timestamp = 1_725_849_600_000;
    const hostilePath = join(directory, `.lifedb.${process.pid}.${timestamp}.tmp.ts`);
    const hostile = new TextEncoder().encode("hostile publication temp\n");
    await writeFile(hostilePath, hostile, { mode: 0o640 });
    const originalNow = Date.now;
    Date.now = () => timestamp;
    try {
      await expect(publishOwned(root, source)).rejects.toThrow();
    } finally {
      Date.now = originalNow;
    }
    expect(Buffer.from(await readFile(hostilePath))).toEqual(Buffer.from(hostile));
    expect((await stat(hostilePath)).mode & 0o777).toBe(0o640);
    await expect(stat(lifecyclePath(root, "active"))).rejects.toThrow();
    await expect(stat(join(directory, ".lifedb.lock"))).rejects.toThrow();
  });

  test("accepts only the exact OpenCode version contract", async () => {
    const outputs = ["1.18.29", "1.18.29\n"];
    for (const stdout of outputs) await expect(requireCompatibleOpenCode(async () => ({ stdout, stderr: "", status: 0 }), "/tmp")).resolves.toBeUndefined();
    for (const stdout of [" 1.18.29", "1.18.29 ", "1.18.29\r\n", "1.18.29\n\n", "1.18.29\nnoise"]) {
      await expect(requireCompatibleOpenCode(async () => ({ stdout, stderr: "", status: 0 }), "/tmp")).rejects.toThrow();
    }
    await expect(requireCompatibleOpenCode(async () => ({ stdout: "1.18.29\n", stderr: "diagnostic", status: 0 }), "/tmp")).rejects.toThrow();
  });

  test("returns exact output and status for a short direct child", async () => {
    const result = await runProcess(childScript("process.stdout.write('héllo'); process.stderr.write('warn'); process.exitCode = 3"), "/tmp");
    expect(result).toEqual({ stdout: "héllo", stderr: "warn", status: 3 });
  });

  test("rejects a child that exceeds its timeout after it is reaped", async () => {
    const started = Date.now();
    const promise = runProcess(childScript("setTimeout(() => {}, 10000)"), "/tmp", { timeoutMs: 30, maxOutputBytes: 1024 });
    await expect(promise).rejects.toMatchObject({ kind: "timeout", name: "ProcessError" });
    expect(Date.now() - started).toBeLessThan(1000);
  });

  test("rejects invalid timeout limits before spawning", async () => {
    const invalidTimeouts = [0, -1, Number.NaN, Number.POSITIVE_INFINITY, 1.5, Number.MAX_VALUE];
    for (const timeoutMs of invalidTimeouts) {
      const promise = runProcess(["/definitely/missing/lifedb-command"], "/tmp", { timeoutMs, maxOutputBytes: 1024 });
      await expect(promise).rejects.toMatchObject({ kind: "invalid-limits", name: "ProcessError" });
    }
  });

  test("rejects invalid output limits before spawning", async () => {
    const invalidOutputLimits = [0, -1, Number.NaN, Number.POSITIVE_INFINITY, 1.5];
    for (const maxOutputBytes of invalidOutputLimits) {
      const promise = runProcess(["/definitely/missing/lifedb-command"], "/tmp", { timeoutMs: 1000, maxOutputBytes });
      await expect(promise).rejects.toMatchObject({ kind: "invalid-limits", name: "ProcessError" });
    }
  });

  test("removes the abort listener after a successful close", async () => {
    const controller = new AbortController();
    let added = 0;
    let removed = 0;
    const add = controller.signal.addEventListener.bind(controller.signal);
    const remove = controller.signal.removeEventListener.bind(controller.signal);
    controller.signal.addEventListener = (...args: Parameters<AbortSignal["addEventListener"]>) => {
      added += 1;
      return add(...args);
    };
    controller.signal.removeEventListener = (...args: Parameters<AbortSignal["removeEventListener"]>) => {
      removed += 1;
      return remove(...args);
    };
    await runProcess(childScript("process.stdout.write('closed')"), "/tmp", { timeoutMs: 1000, maxOutputBytes: 1024, signal: controller.signal });
    expect(added).toBe(1);
    expect(removed).toBe(1);
  });

  test("rejects stdout overflow while continuing to drain the child", async () => {
    const promise = runProcess(childScript("process.stdout.write('x'.repeat(100000)); setTimeout(() => {}, 100)"), "/tmp", { timeoutMs: 1000, maxOutputBytes: 1024 });
    await expect(promise).rejects.toMatchObject({ kind: "stdout-overflow", name: "ProcessError" });
  });

  test("rejects stderr overflow without exposing output", async () => {
    const secret = "secret-output";
    const promise = runProcess(childScript(`process.stderr.write(${JSON.stringify(secret)}.repeat(10000)); setTimeout(() => {}, 100)`), "/tmp", { timeoutMs: 1000, maxOutputBytes: 32 });
    await expect(promise).rejects.toMatchObject({ kind: "stderr-overflow", name: "ProcessError" });
    await promise.catch((error: unknown) => {
      if (!(error instanceof ProcessError)) throw error;
      expect(error.message).not.toContain(secret);
    });
  });

  test("rejects external abort and reaps a child ignoring SIGTERM", async () => {
    const controller = new AbortController();
    const promise = runProcess(childScript("process.on('SIGTERM', () => {}); setTimeout(() => {}, 10000)"), "/tmp", { timeoutMs: 1000, maxOutputBytes: 1024, signal: controller.signal });
    controller.abort();
    await expect(promise).rejects.toMatchObject({ kind: "aborted", name: "ProcessError" });
  });

  test("rejects spawn failure with a sanitized typed error", async () => {
    const promise = runProcess(["/definitely/missing/lifedb-command"], "/tmp", { timeoutMs: 1000, maxOutputBytes: 1024 });
    await expect(promise).rejects.toMatchObject({ kind: "spawn-failure", name: "ProcessError" });
  });
});

import { runInstallerCommand } from "./index.ts";
import { resolveConfigHome } from "./environment.ts";

export { resolveConfigHome } from "./environment.ts";

async function main(): Promise<void> { // no-excuse-ok: catch
  try {
    const command = process.argv[2] ?? "";
    const configHome = resolveConfigHome(process.env);
    await runInstallerCommand(command, { configHome, sourcePath: "src/entry.ts", cwd: new URL("../..", import.meta.url).pathname });
  } catch (error) {
    process.stderr.write("OpenCode installer failed\n");
    process.exitCode = 1;
  }
}

await main();

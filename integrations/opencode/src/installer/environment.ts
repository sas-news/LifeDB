import { isAbsolute } from "node:path";
import { resolve } from "node:path";

export function resolveConfigHome(environment: Readonly<Record<string, string | undefined>>): string {
  const configured = environment["XDG_CONFIG_HOME"];
  const home = configured === undefined ? environment["HOME"] : configured;
  if (home === undefined || home.length === 0 || !isAbsolute(home) || /[\u0000-\u001f\u007f]/u.test(home)) throw new Error("configuration home is invalid");
  return configured === undefined ? resolve(home, ".config") : home;
}

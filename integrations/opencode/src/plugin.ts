import type { Hooks } from "@opencode-ai/plugin";

export function composeHooks(preflight: Hooks, postflight: Hooks): Hooks {
  let disposed = false;
  return {
    ...preflight,
    ...postflight,
    dispose: async () => {
      if (disposed) return;
      disposed = true;
      await Promise.allSettled([
        preflight.dispose?.() ?? Promise.resolve(),
        postflight.dispose?.() ?? Promise.resolve(),
      ]);
    },
  };
}

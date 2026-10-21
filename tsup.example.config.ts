import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["examples/server/server.ts"],
  format: ["esm"],
  target: "node20",
  outDir: "examples/server/dist",
  outExtension: () => ({ js: ".mjs" }),
  external: ["authcore-ts", "pg"],
  clean: true,
});

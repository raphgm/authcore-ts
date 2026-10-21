import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    coverage: {
      provider: "v8",
      include: ["src/**/*.ts"],
      reporter: ["text", "lcov"],
      thresholds: { lines: 90, functions: 90, statements: 90, branches: 85 },
    },
  },
  resolve: { alias: { "authcore-ts": new URL("./src/index.ts", import.meta.url).pathname } },
});

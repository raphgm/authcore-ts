import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["dist", "coverage", "examples/server/dist", "node_modules"] },
  ...tseslint.configs.strictTypeChecked,
  {
    languageOptions: { parserOptions: { projectService: true, tsconfigRootDir: import.meta.dirname } },
    rules: {
      "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_" }],
      "@typescript-eslint/restrict-template-expressions": ["error", { allowNumber: true }],
    },
  },
  { files: ["**/*.config.ts", "eslint.config.js"], ...tseslint.configs.disableTypeChecked },
);

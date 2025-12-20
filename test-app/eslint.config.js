import js from "@eslint/js";
import svelte from "eslint-plugin-svelte";
import svelteParser from "svelte-eslint-parser";
import globals from "globals";
import tsParser from "@typescript-eslint/parser";

export default [
  // Ignore patterns must be first
  {
    ignores: [
      "node_modules/**",
      "dist/**",
      "build/**",
      "target/**",
      "src-tauri/**",
      "*.config.js",
      "vite.config.js",
      ".eslintrc.cjs",
      "**/*.json",
      "**/**/*.json",
      "*.json",
    ],
  },
  js.configs.recommended,
  ...svelte.configs["flat/recommended"],
  {
    languageOptions: {
      parser: svelteParser,
      ecmaVersion: "latest",
      sourceType: "module",
      globals: {
        ...globals.browser,
        ...globals.es2021,
      },
      parserOptions: {
        parser: {
          js: "espree",
          ts: tsParser,
        },
      },
    },
    files: ["**/*.svelte"],
    plugins: {
      svelte,
    },
    rules: {},
  },
  {
    files: ["**/*.js", "**/*.mjs", "**/*.cjs"],
    languageOptions: {
      ecmaVersion: "latest",
      sourceType: "module",
      globals: {
        ...globals.browser,
        ...globals.es2021,
      },
    },
    rules: {},
  },
];

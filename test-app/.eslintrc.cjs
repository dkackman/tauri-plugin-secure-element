module.exports = {
  root: true,
  env: {
    browser: true,
    es2021: true,
  },
  extends: ["eslint:recommended", "plugin:svelte/recommended"],
  parserOptions: {
    ecmaVersion: "latest",
    sourceType: "module",
  },
  plugins: ["svelte"],
  overrides: [
    {
      files: ["*.svelte"],
      parser: "svelte-eslint-parser",
      parserOptions: {
        parser: {
          js: "espree",
          ts: "@typescript-eslint/parser",
        },
      },
    },
  ],
  rules: {},
};

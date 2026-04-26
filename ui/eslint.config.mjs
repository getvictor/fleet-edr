import js from "@eslint/js";
import { defineConfig } from "eslint/config";
import tseslint from "typescript-eslint";
import reactHooks from "eslint-plugin-react-hooks";
import reactRefresh from "eslint-plugin-react-refresh";
import security from "eslint-plugin-security";
import noUnsanitized from "eslint-plugin-no-unsanitized";

// `tseslint.config()` is deprecated in typescript-eslint v8 (Sonar
// javascript:S1874); the upstream recommendation is to use ESLint
// core's `defineConfig` from `eslint/config` instead. We still pull
// `tseslint.configs.strictTypeChecked` for the rule set, just route
// the array assembly through the non-deprecated helper.
export default defineConfig([
  { ignores: ["dist"] },
  {
    files: ["**/*.{ts,tsx}"],
    extends: [
      js.configs.recommended,
      ...tseslint.configs.strictTypeChecked,
      security.configs.recommended,
      noUnsanitized.configs.recommended,
    ],
    plugins: {
      "react-hooks": reactHooks,
      "react-refresh": reactRefresh,
    },
    languageOptions: {
      parserOptions: {
        projectService: {
          allowDefaultProject: ["vite.config.ts", "eslint.config.mjs"],
        },
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      ...reactHooks.configs.recommended.rules,
      "react-refresh/only-export-components": ["warn", { allowConstantExport: true }],

      // Security
      "no-eval": "error",
      "no-implied-eval": "error",

      // Strictness
      "eqeqeq": "error",
      "no-console": "warn",
      "@typescript-eslint/no-explicit-any": "error",
      "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_" }],
      "react-hooks/exhaustive-deps": "error",
    },
  },
]);

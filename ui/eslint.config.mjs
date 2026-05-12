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

      // Magic numbers. The TS-aware variant understands enums, numeric
      // literal types, and readonly class properties so the literal `200`
      // in `enum HttpStatus { Ok = 200 }` doesn't fire. Array indexes,
      // type indexes, and default parameter values are also exempted
      // because they're load-bearing in idiomatic React code (`arr[0]`,
      // `Tuple[1]`, `function f(x = 5)`).
      "no-magic-numbers": "off",
      "@typescript-eslint/no-magic-numbers": ["warn", {
        ignore: [-1, 0, 1, 2, 100, 1000],
        ignoreEnums: true,
        ignoreNumericLiteralTypes: true,
        ignoreReadonlyClassProperties: true,
        ignoreTypeIndexes: true,
        ignoreArrayIndexes: true,
        ignoreDefaultValues: true,
        ignoreClassFieldInitialValues: true,
      }],
    },
  },
  {
    // Test files routinely use literal sizes, fake timestamps, and
    // fixture IDs. Forcing every `expect(x).toBe(42)` to introduce a
    // named constant adds noise without catching real bugs.
    files: ["**/*.{test,spec}.{ts,tsx}", "src/test/**/*.{ts,tsx}"],
    rules: {
      "@typescript-eslint/no-magic-numbers": "off",
    },
  },
  {
    // Force every fetch primitive that adds CSRF protection to go
    // through attachCsrfHeader() in api.ts. Hardcoding "X-CSRF-Token"
    // (or any case variant) anywhere else risks (a) drifting the
    // header casing — JS object keys are case-sensitive, so a stray
    // "X-Csrf-Token" would silently send TWO headers after a merge —
    // and (b) duplicating the unsafe-method + getCsrfToken() guard
    // logic, which is exactly the path that put a CSRF regression
    // into auth.ts's break-glass surface. api.ts itself is the
    // single canonical site, so it's the only file allowed to
    // mention the literal.
    files: ["src/**/*.{ts,tsx}"],
    ignores: ["src/api.ts"],
    rules: {
      "no-restricted-syntax": [
        "error",
        {
          selector: "Literal[value=/^X-CSRF-Token$/i]",
          message:
            "Don't hardcode the CSRF header. Import attachCsrfHeader from './api' and call attachCsrfHeader(headers, method).",
        },
      ],
    },
  },
]);

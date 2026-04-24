/// <reference types="vitest/config" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig(({ mode }) => ({
  plugins: [react()],
  base: "/ui/",
  build: {
    outDir: "../server/ui/dist",
    emptyOutDir: true,
    minify: mode === "production",
    sourcemap: mode !== "production",
  },
  server: {
    proxy: {
      "/api": "http://localhost:8088",
    },
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
    passWithNoTests: true,
    coverage: {
      // SonarCloud reads UI coverage via sonar.javascript.lcov.reportPaths;
      // emit the lcov reporter alongside the terminal summary so the CI
      // scan always has a file at ui/coverage/lcov.info once UI tests land.
      // With zero UI tests today the lcov file isn't produced and Sonar
      // simply reports "no data" for this scope.
      provider: "v8",
      reporter: ["text", "lcov"],
      reportsDirectory: "./coverage",
      // Scope to application sources so ambient files (vite.config.ts,
      // test setup, generated code) don't distort the Sonar baseline once
      // real tests land. No-op today with zero tests.
      include: ["src/**/*.{ts,tsx}"],
      exclude: ["src/**/*.test.{ts,tsx}", "src/test/**"],
    },
  },
}));

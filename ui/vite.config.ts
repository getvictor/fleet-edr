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
    // Source maps in dev/test mode by default; in production, opt in
    // via UI_BUILD_SOURCEMAP=1 so the E2E coverage job can ship the
    // production-shape bundle (minified) WITH the .map files
    // monocart-coverage-reports needs to remap V8 coverage back to
    // ui/src/**. Regular `task build:ui` keeps emitting no maps so
    // production bundles stay lean.
    sourcemap: mode !== "production" || process.env.UI_BUILD_SOURCEMAP === "1",
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

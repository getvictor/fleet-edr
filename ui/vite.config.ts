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
  },
}));

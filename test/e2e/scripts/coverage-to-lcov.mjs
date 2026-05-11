// Merge the per-test V8 coverage payloads written by fixtures/test.ts
// into a single LCOV file the Sonar JavaScript analyser reads. Uses
// monocart-coverage-reports because it handles the chromium V8
// format AND walks the embedded source maps the Vite bundle ships
// with, so the LCOV's file paths point back at ui/src/** instead of
// at the minified asset filenames in server/ui/dist/.
//
// Run after a Playwright run that had E2E_COVERAGE=1 set:
//
//   node scripts/coverage-to-lcov.mjs
//
// Output: test/e2e/coverage/lcov-e2e.info. Sonar reads it via the
// extra path in sonar.javascript.lcov.reportPaths.

import { readdir, readFile, mkdir, stat } from "node:fs/promises";
import { existsSync, readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { CoverageReport } from "monocart-coverage-reports";

const __dirname = dirname(fileURLToPath(import.meta.url));
const RAW_DIR = join(__dirname, "..", "coverage-raw");
const OUT_DIR = join(__dirname, "..", "coverage");
const REPO_ROOT = join(__dirname, "..", "..", "..");
const UI_DIST = join(REPO_ROOT, "server", "ui", "dist");

// Map a Playwright-captured bundle URL onto the file on disk in
// server/ui/dist/. Playwright reports URLs like
//   http://localhost:8088/ui/assets/index-XYZ.js
// and Vite emits sibling .map files at
//   server/ui/dist/assets/index-XYZ.js.map
// monocart's default resolver would HTTP-fetch the .map URL, which
// only works while the dev server is alive — and the converter runs
// AFTER the server has been drained for Go coverage. Loading the
// .map from disk side-steps that ordering constraint.
function diskPathFor(url) {
  const m = url.match(/\/ui\/assets\/([^?#]+)$/);
  if (!m) return null;
  return join(UI_DIST, "assets", m[1]);
}

async function main() {
  if (!existsSync(RAW_DIR)) {
    console.log(`no ${RAW_DIR} (E2E_COVERAGE not set during the run?); skipping`);
    return;
  }
  const files = (await readdir(RAW_DIR)).filter((f) => f.endsWith(".json"));
  if (files.length === 0) {
    console.log("coverage-raw is empty; skipping");
    return;
  }
  console.log(`merging ${files.length} per-test coverage payload(s)`);

  await mkdir(OUT_DIR, { recursive: true });
  const report = new CoverageReport({
    reports: [["lcovonly", { file: "lcov-e2e.info" }]],
    outputDir: OUT_DIR,
    // Match the dev server's actual bundle origin so monocart picks
    // up the embedded source-mapping URL. The bundle lives at
    // /ui/assets/*.js on http://localhost:8088.
    entryFilter: (entry) => entry.url.includes("/ui/assets/"),
    // Read source maps from disk instead of HTTP-fetching them. By
    // the time this script runs, the dev server has been SIGTERM'd
    // (so its Go coverage flushes), so any HTTP request for the .map
    // would 502. Resolve the .map URL → local file in
    // server/ui/dist/assets/.
    sourceMapResolver: async (url, fallback) => {
      const p = diskPathFor(url);
      if (p && existsSync(p)) {
        return JSON.parse(readFileSync(p, "utf8"));
      }
      return fallback(url);
    },
    // Remap source-map-resolved paths back to repo-relative ui/src.
    // Vite emits source paths like "../ui/src/components/Login.tsx"
    // (relative from server/ui/dist back to ui/src). Strip the
    // leading ../ so Sonar matches against ui/src/** directly.
    sourcePath: (filePath) => {
      if (filePath.startsWith("../")) return filePath.slice(3);
      if (filePath.startsWith("ui/")) return filePath;
      return `ui/${filePath}`;
    },
    // Drop noise from the LCOV: node_modules sources unwrapped from
    // the source map. monocart calls sourceFilter against the
    // post-`sourcePath`-callback path (after our "../" → "" rewrite
    // and "ui/" prefix), so checking for "ui/src/" works. Sonar's
    // own sonar.coverage.exclusions covers test/** etc.; this filter
    // just keeps the LCOV focused on first-party UI code.
    sourceFilter: (sourcePath) =>
      sourcePath.startsWith("ui/src/") &&
      !sourcePath.includes("/node_modules/"),
  });

  for (const f of files) {
    const raw = await readFile(join(RAW_DIR, f), "utf8");
    const entries = JSON.parse(raw);
    if (!Array.isArray(entries) || entries.length === 0) continue;
    await report.add(entries);
  }

  await report.generate();
  const outPath = join(OUT_DIR, "lcov-e2e.info");
  const s = await stat(outPath);
  console.log(`wrote ${outPath} (${s.size} bytes)`);
}

main().catch((err) => {
  console.error("coverage-to-lcov failed:", err);
  process.exit(1);
});

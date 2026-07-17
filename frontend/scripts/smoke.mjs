#!/usr/bin/env node
/**
 * Post-build smoke check.
 *
 * Runs only against the production bundle (`dist/`) and never makes network
 * calls. It verifies that:
 *
 *   1. dist/index.html exists and references the built JS entrypoint
 *   2. at least one hashed JS bundle exists under dist/assets
 *   3. at least one hashed CSS bundle exists under dist/assets
 *
 * Failures are reported with non-zero exit status so CI can fail loudly.
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, resolve } from "node:path";

const distDir = resolve(process.cwd(), "dist");
function fail(msg) {
  console.error(`smoke: ${msg}`);
  process.exit(1);
}

let s;
try {
  s = statSync(distDir);
} catch {
  fail(`dist/ not found at ${distDir}; run "npm run build" first`);
}
if (!s.isDirectory()) fail("dist/ is not a directory");

const htmlPath = join(distDir, "index.html");
let html;
try {
  html = readFileSync(htmlPath, "utf8");
} catch {
  fail("dist/index.html missing");
}

if (!/<div id="root"><\/div>/.test(html)) {
  fail("dist/index.html does not contain the #root mount point");
}
if (!/src="\/assets\//.test(html)) {
  fail("dist/index.html does not reference a built JS asset under /assets/");
}

const assetsDir = join(distDir, "assets");
const files = readdirSync(assetsDir);
const js = files.filter((f) => f.endsWith(".js"));
const css = files.filter((f) => f.endsWith(".css"));
if (js.length === 0) fail("no JS bundles in dist/assets");
if (css.length === 0) fail("no CSS bundles in dist/assets");

console.log(
  `smoke: ok (${js.length} JS, ${css.length} CSS bundle(s), ${files.length} total asset file(s))`,
);
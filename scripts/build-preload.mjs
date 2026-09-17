/**
 * Post-build helper to ensure Electron preload script uses CommonJS require()
 * for Electron sandbox compatibility (Electron sandbox does not support ESM import).
 */
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, "..");
const preloadDistJs = path.join(projectRoot, "dist/main/preload.js");
const preloadDistCjs = path.join(projectRoot, "dist/main/preload.cjs");

if (fs.existsSync(preloadDistJs)) {
  let content = fs.readFileSync(preloadDistJs, "utf8");
  // Replace ESM import with CommonJS require
  content = content.replace(
    /import\s*\{\s*contextBridge,\s*ipcRenderer\s*\}\s*from\s*["']electron["'];?/,
    'const { contextBridge, ipcRenderer } = require("electron");'
  );
  // Write both .js and .cjs for complete compatibility
  fs.writeFileSync(preloadDistJs, content, "utf8");
  fs.writeFileSync(preloadDistCjs, content, "utf8");
  console.log("[Build] Electron sandbox preload script prepared successfully.");
} else {
  console.warn("[Build] Warning: dist/main/preload.js not found.");
}

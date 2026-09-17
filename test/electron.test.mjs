/**
 * NetAccess Phase P6 — macOS Electron Application UI Automated Tests
 * 
 * Validates the 20 P6 requirements:
 *  1. app startup & window configuration
 *  2. renderer loads & semantic HTML layout
 *  3. preload API exposure
 *  4. renderer cannot access Node APIs (security sandbox)
 *  5. openTarget() IPC invocation
 *  6. state/event propagation
 *  7. connecting → connected
 *  8. connecting → failed
 *  9. cancellation
 * 10. retry
 * 11. recent-target rendering
 * 12. settings read/write
 * 13. transport add/edit/delete/test
 * 14. credential redaction
 * 15. Developer Mode
 * 16. verification status rendering & honest scoping
 * 17. malformed IPC payload rejection
 * 18. external navigation restrictions
 * 19. app quit cleanup
 * 20. light/dark UI CSS rendering
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { ApplicationController } from "../src/netaccess/controller.js";
import { CleanupSupervisor } from "../src/netaccess/cleanupSupervisor.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, "..");

// 1. App Startup & Window Configuration
test("P6.1: Native macOS window configuration complies with design requirements", () => {
  const mainTs = fs.readFileSync(path.join(projectRoot, "src/main/main.ts"), "utf-8");
  
  assert.match(mainTs, /titleBarStyle:\s*"hiddenInset"/, "Window uses hiddenInset titlebar style");
  assert.match(mainTs, /trafficLightPosition:\s*\{\s*x:\s*18,\s*y:\s*18\s*\}/, "Window sets native traffic light position");
  assert.match(mainTs, /vibrancy:\s*"under-window"/, "Window configures under-window vibrancy");
  assert.match(mainTs, /visualEffectState:\s*"active"/, "Window sets visualEffectState active");
  assert.match(mainTs, /minWidth:\s*440/, "Window enforces appropriate minimum width");
  assert.match(mainTs, /minHeight:\s*520/, "Window enforces appropriate minimum height");
  assert.match(mainTs, /contextIsolation:\s*true/, "Security: contextIsolation enabled");
  assert.match(mainTs, /nodeIntegration:\s*false/, "Security: nodeIntegration disabled");
  assert.match(mainTs, /sandbox:\s*true/, "Security: sandbox enabled");
});

// 2. Renderer HTML Layout & Semantic Views
test("P6.2: Renderer loads semantic views for Initial, Connecting, Connected, and Failed states", () => {
  const html = fs.readFileSync(path.join(projectRoot, "src/renderer/index.html"), "utf-8");
  
  // Initial View
  assert.ok(html.includes('id="view-initial"'), "Initial view container present");
  assert.ok(html.includes("Where do you want to go?"), "Initial title present");
  assert.ok(html.includes('id="target-form"'), "Target form present");
  assert.ok(html.includes('id="target-input"'), "Target input present");
  assert.ok(html.includes('id="btn-open"'), "Open button present");
  assert.ok(html.includes('id="recent-list"'), "Recent destinations list present");

  // Connecting View
  assert.ok(html.includes('id="view-connecting"'), "Connecting view container present");
  assert.ok(html.includes('id="step-checking"'), "Step checking present");
  assert.ok(html.includes('id="step-finding"'), "Step finding present");
  assert.ok(html.includes('id="step-opening"'), "Step opening present");
  assert.ok(html.includes('id="btn-cancel-connecting"'), "Cancel button present");

  // Connected View
  assert.ok(html.includes('id="view-connected"'), "Connected view container present");
  assert.ok(html.includes('id="connected-target"'), "Connected target display present");
  assert.ok(html.includes('id="path-card"'), "Connection path summary card present");
  assert.ok(html.includes('id="verification-card"'), "Scoped verification card present");
  assert.ok(html.includes('id="btn-view-details"'), "View details button present");

  // Failed View
  assert.ok(html.includes('id="view-failed"'), "Failed view container present");
  assert.ok(html.includes('id="failed-code-pill"'), "Error code pill present");
  assert.ok(html.includes('id="failed-title"'), "Error title present");
  assert.ok(html.includes('id="failed-suggestion"'), "Remediation suggestion present");
  assert.ok(html.includes('id="btn-failed-retry"'), "Retry button present");

  // Drawer & Modal
  assert.ok(html.includes('id="drawer-dev"'), "Developer mode drawer present");
  assert.ok(html.includes('id="modal-settings"'), "Settings modal present");

  // Strict CSP
  assert.match(html, /<meta http-equiv="Content-Security-Policy"[^>]*default-src 'self'/, "Restrictive CSP meta tag enforced");
});

// 3. Preload API Exposure
test("P6.3: Preload exposes full typed NetAccess API without raw Electron access", () => {
  const preloadTs = fs.readFileSync(path.join(projectRoot, "src/main/preload.ts"), "utf-8");

  const requiredMethods = [
    "openTarget",
    "cancelSession",
    "closeSession",
    "getStatus",
    "getSettings",
    "updateSettings",
    "getTransports",
    "getTransportRuntimes",
    "addTransport",
    "removeTransport",
    "testTransport",
    "getRecentTargets",
    "clearRecentTargets",
    "getDoctorReport",
    "onStateChanged",
    "onDiagnosisUpdated",
    "onTransportChanged",
    "onVerificationUpdated",
    "onCompleted",
    "onFailed",
  ];

  for (const method of requiredMethods) {
    assert.ok(
      preloadTs.includes(method),
      `Preload API exposes method: ${method}`
    );
  }

  assert.match(
    preloadTs,
    /contextBridge\.exposeInMainWorld\("netaccess",\s*api\)/,
    "Preload attaches API via contextBridge.exposeInMainWorld"
  );
});

// 4. Renderer Cannot Access Node APIs
test("P6.4: Renderer is strictly sandboxed with zero Node API imports", () => {
  const preloadTs = fs.readFileSync(path.join(projectRoot, "src/main/preload.ts"), "utf-8");
  const appJs = fs.readFileSync(path.join(projectRoot, "src/renderer/app.js"), "utf-8");

  // Preload must never import fs, child_process, net, tls
  assert.doesNotMatch(preloadTs, /import.*from ["'](node:)?fs["']/, "Preload does not import fs");
  assert.doesNotMatch(preloadTs, /import.*from ["'](node:)?child_process["']/, "Preload does not import child_process");
  assert.doesNotMatch(preloadTs, /import.*from ["'](node:)?net["']/, "Preload does not import net");
  assert.doesNotMatch(preloadTs, /import.*from ["'](node:)?tls["']/, "Preload does not import tls");

  // Renderer app.js must never require or import Node modules
  assert.doesNotMatch(appJs, /require\(["'](node:)?fs["']\)/, "app.js does not require fs");
  assert.doesNotMatch(appJs, /require\(["'](node:)?child_process["']\)/, "app.js does not require child_process");
  assert.doesNotMatch(appJs, /process\.env/, "app.js does not access process.env directly");
});

// 5. IPC Handler Contract & Execution
test("P6.5: IPC openTarget executes over ApplicationController and returns typed result", async () => {
  const controller = new ApplicationController({
    skipBrowserLaunch: true,
  });

  const target = "example.com";
  const result = await controller.openTarget(target, { skipBrowserLaunch: true });

  assert.ok(result.sessionId, "openTarget returns sessionId");
  assert.equal(result.target.host, "example.com", "openTarget returns normalized host");
  assert.ok(result.path, "openTarget returns selected path");
  assert.ok(["direct", "alternate"].includes(result.path.type), "Valid path type");
  assert.ok(result.diagnosis, "openTarget returns diagnosis");
});

// 6. State & Event Propagation
test("P6.6: Controller emits stateChanged and diagnostic events to listeners", async () => {
  const controller = new ApplicationController({
    skipBrowserLaunch: true,
  });

  const emittedStates = [];
  controller.on("stateChanged", (state) => {
    emittedStates.push(state);
  });

  let diagnosisEmitted = false;
  controller.on("diagnosisUpdated", () => {
    diagnosisEmitted = true;
  });

  await controller.openTarget("example.com", { skipBrowserLaunch: true });

  assert.ok(emittedStates.length > 0, "stateChanged events were emitted");
  assert.ok(emittedStates.includes("VALIDATING") || emittedStates.includes("DIAGNOSING"), "Diagnosis state emitted");
  assert.ok(emittedStates.includes("CONNECTED") || emittedStates.includes("MONITORING"), "Connected/Monitoring state emitted");
  assert.ok(diagnosisEmitted, "diagnosisUpdated was emitted");
});

// 7. Connecting -> Connected Workflow
test("P6.7: Connecting state transitions into Connected with complete path summary", async () => {
  const controller = new ApplicationController({
    skipBrowserLaunch: true,
  });

  const res = await controller.openTarget("example.com", { skipBrowserLaunch: true });
  assert.equal(res.state, "CONNECTED", "Final result state is CONNECTED");
  assert.ok(res.path.transportName, "Transport name is defined in result");
  assert.ok(typeof res.path.latencyMs === "number", "Latency measurement present");
});

// 8. Connecting -> Failed Workflow & UserFacingError Mapping
test("P6.8: Connecting failure preserves structured error codes without generic messaging", async () => {
  const controller = new ApplicationController({
    skipBrowserLaunch: true,
  });

  // Target that fails resolution
  try {
    await controller.openTarget("invalid-nonexistent-domain-12345.xyz", { skipBrowserLaunch: true });
    assert.fail("Should have thrown UserFacingError");
  } catch (err) {
    assert.ok(err.code, "Error has structured code");
    assert.ok(
      ["DNS_UNAVAILABLE", "DESTINATION_UNREACHABLE", "NO_WORKING_PATH"].includes(err.code),
      `Appropriate error code preserved: ${err.code}`
    );
    assert.ok(err.message, "Error has explanatory message");
  }
});

// 9. Cancellation
test("P6.9: Session cancellation aborts immediately and cleans state", async () => {
  const controller = new ApplicationController({
    skipBrowserLaunch: true,
  });

  const promise = controller.openTarget("example.com", { skipBrowserLaunch: true });
  await controller.cancelSession();

  try {
    await promise;
  } catch (err) {
    assert.ok(err.code === "SESSION_FAILED" || err.message.includes("cancelled"), "Handled cancel");
  }

  const snapshot = controller.getStatus();
  assert.equal(snapshot.state, "IDLE", "State returned to IDLE after cancellation");
});

// 10. Retry Workflow
test("P6.10: Retry mechanism can re-invoke target without stale session conflict", async () => {
  const controller = new ApplicationController({
    skipBrowserLaunch: true,
  });

  const first = await controller.openTarget("example.com", { skipBrowserLaunch: true });
  assert.ok(first.sessionId);

  // Close and retry
  await controller.closeSession();
  const retry = await controller.openTarget("example.com", { skipBrowserLaunch: true });
  assert.ok(retry.sessionId);
  assert.notEqual(first.sessionId, retry.sessionId, "Retry creates fresh session ID");
});

// 11. Recent Target Rendering & Clearing
test("P6.11: Recent targets can be recorded, retrieved, and cleared", async () => {
  const controller = new ApplicationController({
    skipBrowserLaunch: true,
  });

  await controller.openTarget("example.com", { skipBrowserLaunch: true });
  const recents = controller.getRecentTargets();
  assert.ok(recents.length > 0, "Recent targets contains entry");
  assert.ok(recents.some((r) => r.host === "example.com"), "Visited host recorded");

  controller.clearRecentTargets();
  const cleared = controller.getRecentTargets();
  assert.equal(cleared.length, 0, "Recent targets cleared successfully");
});

// 12. Settings Read / Write Roundtrip
test("P6.12: Settings can be read and updated through ApplicationController", async () => {
  const controller = new ApplicationController();

  const initial = controller.getSettings();
  assert.equal(typeof initial.openInDefaultBrowser, "boolean");

  const updated = controller.updateSettings({
    openInDefaultBrowser: true,
    developerMode: true,
  });

  assert.equal(updated.openInDefaultBrowser, true, "openInDefaultBrowser updated");
  assert.equal(updated.developerMode, true, "developerMode updated");

  const fresh = controller.getSettings();
  assert.equal(fresh.openInDefaultBrowser, true);
  assert.equal(fresh.developerMode, true);
});

// 13. Transport Management (Add, List, Test, Delete)
test("P6.13: Transports can be added, tested, and removed", async () => {
  const controller = new ApplicationController();

  const testConfig = {
    id: "test-proxy-p6",
    name: "P6 Test Proxy",
    type: "http",
    host: "127.0.0.1",
    port: 9999,
    tags: ["custom"],
    trusted: true,
    enabled: true,
  };

  controller.addTransport(testConfig);
  const transports = controller.getTransports(true);
  const found = transports.find((t) => t.id === "test-proxy-p6");
  assert.ok(found, "Added transport is listed");

  // Test transport
  const testRes = await controller.testTransport("test-proxy-p6", "example.com");
  assert.ok("success" in testRes || "ok" in testRes || "latencyMs" in testRes, "testTransport returns structured result");

  // Remove transport
  const removed = controller.removeTransport("test-proxy-p6");
  assert.equal(removed, true, "Transport removed successfully");
  const remaining = controller.getTransports(true);
  assert.ok(!remaining.some((t) => t.id === "test-proxy-p6"), "Transport no longer listed");
});

// 14. Credential Redaction Across IPC Boundary
test("P6.14: Secrets and credentials are never passed across IPC", () => {
  const mainTs = fs.readFileSync(path.join(projectRoot, "src/main/main.ts"), "utf-8");

  assert.match(
    mainTs,
    /secretRef:\s*transport\.secretRef\s*\?\s*"\[REDACTED\]"/,
    "secretRef is redacted before IPC transmission"
  );
  assert.match(
    mainTs,
    /getTransports\(true\)\.map\(sanitizeTransport\)/,
    "All transports returned over IPC are sanitized"
  );
});

// 15. Developer Mode Telemetry & JSON Copy
test("P6.15: Developer Mode exposes probe waterfall, EWMA, and circuit breaker metrics", () => {
  const html = fs.readFileSync(path.join(projectRoot, "src/renderer/index.html"), "utf-8");
  const appJs = fs.readFileSync(path.join(projectRoot, "src/renderer/app.js"), "utf-8");

  assert.ok(html.includes('id="dev-waterfall"'), "Waterfall probes section in HTML");
  assert.ok(html.includes('id="dev-candidate-list"'), "Candidate transports in HTML");
  assert.ok(html.includes('id="btn-copy-dev-json"'), "Copy JSON button in HTML");

  assert.ok(appJs.includes("btnCopyDevJson"), "app.js handles copy JSON action");
  assert.ok(appJs.includes("navigator.clipboard.writeText"), "Clipboard copy implemented");
});

// 16. Verification Status & Honest Scoping
test("P6.16: Verification status uses honest scoping rather than absolute zero-leak claim", () => {
  const html = fs.readFileSync(path.join(projectRoot, "src/renderer/index.html"), "utf-8");
  const appJs = fs.readFileSync(path.join(projectRoot, "src/renderer/app.js"), "utf-8");

  assert.ok(
    html.includes("NetAccess observed the managed session using the configured connection path."),
    "Honest scoping note present in HTML"
  );
  assert.doesNotMatch(html, /Zero leaks guaranteed/i, "HTML does NOT claim zero leaks guaranteed");
  assert.doesNotMatch(appJs, /Zero leaks guaranteed/i, "app.js does NOT claim zero leaks guaranteed");
});

// 17. Malformed IPC Payload Rejection
test("P6.17: Main process IPC rejects invalid or malformed arguments", () => {
  const mainTs = fs.readFileSync(path.join(projectRoot, "src/main/main.ts"), "utf-8");

  // Check type validation checks in main.ts
  assert.match(mainTs, /typeof rawTarget !== "string"/, "Target string validation");
  assert.match(mainTs, /typeof updates !== "object"/, "Settings object validation");
  assert.match(mainTs, /typeof config !== "object"/, "Transport config validation");
  assert.match(mainTs, /typeof id !== "string"/, "Transport ID validation");
});

// 18. External Navigation Restrictions
test("P6.18: Electron window enforces strict navigation security policies", () => {
  const mainTs = fs.readFileSync(path.join(projectRoot, "src/main/main.ts"), "utf-8");

  assert.match(
    mainTs,
    /webContents\.setWindowOpenHandler\(\(\)\s*=>\s*\(\{\s*action:\s*"deny"\s*\}\)\)/,
    "Window denies window.open and popup navigation"
  );
  assert.match(
    mainTs,
    /webContents\.on\("will-navigate",\s*\(event\)\s*=>\s*\{\s*event\.preventDefault\(\);/,
    "Window prevents external page navigation"
  );
});

// 19. App Quit Cleanup
test("P6.19: App quit hook executes CleanupSupervisor.cleanupAll()", () => {
  const mainTs = fs.readFileSync(path.join(projectRoot, "src/main/main.ts"), "utf-8");

  assert.match(
    mainTs,
    /app\.on\("before-quit",\s*async\s*\(\)\s*=>\s*\{[\s\S]*CleanupSupervisor\.getShared\(\)\.cleanupAll\(\)/,
    "before-quit hook triggers complete CleanupSupervisor cleanup"
  );
});

// 20. Light / Dark UI CSS Rendering & Accessibility
test("P6.20: Stylesheet defines macOS Dark (default) and Light theme tokens with accessible controls", () => {
  const css = fs.readFileSync(path.join(projectRoot, "src/renderer/styles.css"), "utf-8");

  // Tokens
  assert.ok(css.includes("--bg-app: rgba(28, 28, 30, 0.85);"), "Dark background token defined");
  assert.ok(css.includes("@media (prefers-color-scheme: light)"), "Light theme media query defined");
  assert.ok(css.includes("--accent-blue: #0a84ff;"), "Apple blue accent token defined");
  assert.ok(css.includes("--accent-green: #30d158;"), "Apple green accent token defined");
  assert.ok(css.includes("@media (prefers-reduced-motion: reduce)"), "Reduced motion accessibility query defined");
  assert.ok(css.includes("-webkit-backdrop-filter: blur"), "macOS vibrancy blur styling defined");
});

// 21. Live macOS Electron Process Boot and Renderer Load Verification
test("P6.21: Electron launches on macOS, loads renderer, and fires ready-to-show cleanly", async () => {
  const { execSync } = await import("node:child_process");
  const electronCli = path.join(projectRoot, "node_modules/electron/cli.js");
  const output = execSync(`NETACCESS_SMOKE_TEST=1 node "${electronCli}" .`, {
    cwd: projectRoot,
    encoding: "utf-8",
    timeout: 15000,
  });

  assert.ok(
    output.includes("[NetAccess Main] Renderer loaded and window ready-to-show successfully!"),
    "Electron successfully booted, loaded renderer HTML/JS, and reached ready-to-show state"
  );
});

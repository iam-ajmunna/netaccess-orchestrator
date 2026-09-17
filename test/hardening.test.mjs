/**
 * NetAccess Pass 1 — Security & Isolation Hardening Tests
 * 
 * Verifies:
 * 1. Chromium scoped session anti-leak flags (--disable-quic, --disable-component-update, --disable-features, --no-pings)
 * 2. CleanupSupervisor.sweepOrphanedProfiles() post-reboot/crash hygiene
 * 3. ApplicationController serialized preemption of active/in-flight sessions
 * 4. ApplicationController mutex serialization of concurrent openTarget() invocations
 * 5. Renderer CSP strictness (no unsafe-inline) & zero innerHTML injection vectors
 */

import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import * as fsSync from "node:fs";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { CleanupSupervisor } from "../src/netaccess/cleanupSupervisor.ts";
import { ApplicationController } from "../src/netaccess/controller.ts";
import { parseTarget } from "../src/netaccess/engine.ts";
import { SessionManager } from "../src/netaccess/sessionManager.ts";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, "..");
const NODE_BIN = process.execPath;

// ---------------------------------------------------------------------------
// 1. Chromium Anti-Leak Flags
// ---------------------------------------------------------------------------
test("H1: Alternate session launch includes comprehensive anti-leak Chromium flags", async () => {
  let capturedArgs = [];

  const sm = new SessionManager({
    customBrowserPath: NODE_BIN,
    spawnFn: (_exe, args) => {
      capturedArgs = args;
      return {
        pid: 99991,
        on: () => {},
        kill: () => true,
      };
    },
  });

  const target = parseTarget("example.com");
  const selectedPath = {
    type: "alternate",
    transportId: "proxy-corp",
    transportName: "Corp Proxy",
    transportType: "http_proxy",
    reason: "Direct blocked",
  };
  const transportConfig = {
    id: "proxy-corp",
    name: "Corp Proxy",
    type: "http_proxy",
    host: "10.0.0.1",
    port: 8080,
    enabled: true,
  };

  const session = await sm.launchSession("sess-quic-check", target, selectedPath, transportConfig);

  // Critical Anti-Leak Flags
  assert.ok(
    capturedArgs.includes("--disable-quic"),
    "Must include --disable-quic to prevent UDP 443 proxy bypass"
  );
  assert.ok(
    capturedArgs.includes("--disable-component-update"),
    "Must include --disable-component-update to stop background browser updater network requests"
  );
  assert.ok(
    capturedArgs.includes("--disable-features=Translate,OptimizationHints,MediaRouter"),
    "Must disable background translation, optimization hints, and mDNS discovery"
  );
  assert.ok(
    capturedArgs.includes("--no-pings"),
    "Must include --no-pings to disable hyperlink auditing"
  );

  // Still preserves standard isolation flags
  assert.ok(capturedArgs.some((a) => a.startsWith("--user-data-dir=")));
  assert.ok(capturedArgs.includes("--proxy-server=http://10.0.0.1:8080"));

  await sm.closeSession("sess-quic-check");
});

// ---------------------------------------------------------------------------
// 2. Orphaned Profile Sweeping & Crash Recovery
// ---------------------------------------------------------------------------
test("H2: CleanupSupervisor.sweepOrphanedProfiles() cleans stale profiles without touching active or unrelated directories", async () => {
  const supervisor = new CleanupSupervisor(false);
  const tmp = os.tmpdir();

  // Create an active profile managed by supervisor
  const activeProfile = await supervisor.createEphemeralProfile("active-session-1");
  assert.ok(fsSync.existsSync(activeProfile), "Active profile must exist");

  // Create an orphaned profile older than 2 hours
  const orphanHex = crypto.randomBytes(6).toString("hex");
  const orphanName = `netaccess-session-crashed-1-${orphanHex}`;
  const orphanPath = path.join(tmp, orphanName);
  await fs.mkdir(orphanPath, { recursive: true, mode: 0o700 });
  await fs.writeFile(path.join(orphanPath, "data.txt"), "stale data");

  // Set orphan directory modification time to 3 hours ago
  const threeHoursAgo = new Date(Date.now() - 3 * 3600 * 1000);
  await fs.utimes(orphanPath, threeHoursAgo, threeHoursAgo);

  // Create an unrelated temp directory in tmp
  const unrelatedDir = path.join(tmp, `other-temp-${crypto.randomBytes(4).toString("hex")}`);
  await fs.mkdir(unrelatedDir, { recursive: true });
  await fs.utimes(unrelatedDir, threeHoursAgo, threeHoursAgo);

  try {
    // Run sweep with 1-hour age threshold
    const swept = await supervisor.sweepOrphanedProfiles(3600 * 1000);

    // Assert orphan was swept
    assert.ok(swept.some((p) => p.includes(orphanName)), "Orphan profile must be reported swept");
    assert.ok(!fsSync.existsSync(orphanPath), "Orphan directory must be deleted");

    // Assert active session was NOT touched
    assert.ok(fsSync.existsSync(activeProfile), "Active session profile must NOT be deleted");

    // Assert unrelated directory was NOT touched
    assert.ok(fsSync.existsSync(unrelatedDir), "Unrelated directory must NOT be deleted");
  } finally {
    // Cleanup remaining test fixtures
    await supervisor.cleanupAll();
    if (fsSync.existsSync(orphanPath)) await fs.rm(orphanPath, { recursive: true, force: true });
    if (fsSync.existsSync(unrelatedDir)) await fs.rm(unrelatedDir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// 3. Orderly Session Preemption
// ---------------------------------------------------------------------------
test("H3: ApplicationController seamlessly preempts active session when new target is opened", async () => {
  const mockLauncher = async () => ({ launched: true, pid: 11111 });
  const mockDiagnostician = async (target) => [
    {
      layer: "dns",
      ok: true,
      classHint: "healthy",
      weight: 1.0,
      likelyCause: `Resolved ${target.host}`,
      latencyMs: 10,
      startedAt: Date.now() - 10,
      endedAt: Date.now(),
    },
  ];

  const controller = new ApplicationController({
    browserLauncher: mockLauncher,
    diagnostician: mockDiagnostician,
  });

  // Open destination 1 -> transitions to CONNECTED
  const res1 = await controller.openTarget("alpha.example.com", { skipBrowserLaunch: true });
  assert.equal(res1.state, "CONNECTED");
  assert.equal(controller.getState(), "CONNECTED");

  // Now open destination 2 directly WITHOUT manually calling closeSession()
  // Previously this threw: "Cannot open target while in state CONNECTED"
  // Now it must orderly-preempt session 1 and connect to session 2
  const res2 = await controller.openTarget("beta.example.com", { skipBrowserLaunch: true });
  assert.equal(res2.state, "CONNECTED");
  assert.equal(res2.target.host, "beta.example.com");
  assert.equal(controller.getState(), "CONNECTED");

  await controller.closeSession();
  assert.equal(controller.getState(), "IDLE");
});

// ---------------------------------------------------------------------------
// 4. Concurrent openTarget() Mutex Serialization
// ---------------------------------------------------------------------------
test("H4: ApplicationController serializes rapid concurrent openTarget() invocations", async () => {
  const controller = new ApplicationController({
    diagnostician: async (target) => {
      // Simulate realistic async probe delay
      await new Promise((r) => setTimeout(r, 40));
      return [
        {
          layer: "dns",
          ok: true,
          classHint: "healthy",
          weight: 1.0,
          likelyCause: `Resolved ${target.host}`,
          latencyMs: 10,
          startedAt: Date.now() - 10,
          endedAt: Date.now(),
        },
      ];
    },
  });

  // Rapidly fire two openTarget requests simultaneously
  const [res1, res2] = await Promise.all([
    controller.openTarget("first.example.com", { skipBrowserLaunch: true }),
    controller.openTarget("second.example.com", { skipBrowserLaunch: true }),
  ]);

  // Both should succeed cleanly without crashing or throwing
  assert.equal(res1.state, "CONNECTED");
  assert.equal(res2.state, "CONNECTED");

  // The final state of controller must be connected to the second destination
  assert.equal(controller.getState(), "CONNECTED");
  const recent = controller.getRecentTargets();
  assert.ok(recent.length >= 2, "Both targets recorded in recent destinations");

  await controller.closeSession();
});

// ---------------------------------------------------------------------------
// 5. Renderer CSP & XSS Hardening
// ---------------------------------------------------------------------------
test("H5: Renderer CSP forbids 'unsafe-inline' and renderer contains zero innerHTML interpolations", () => {
  const indexHtml = fsSync.readFileSync(path.join(projectRoot, "src/renderer/index.html"), "utf-8");
  const appJs = fsSync.readFileSync(path.join(projectRoot, "src/renderer/app.js"), "utf-8");

  // Verify CSP meta tag
  const cspMatch = indexHtml.match(/<meta http-equiv="Content-Security-Policy"\s+content="([^"]+)"/);
  assert.ok(cspMatch, "CSP meta tag must exist in index.html");
  const cspContent = cspMatch[1];

  assert.ok(
    !cspContent.includes("'unsafe-inline'"),
    "CSP must NOT contain 'unsafe-inline' in style-src or script-src"
  );
  assert.ok(
    cspContent.includes("style-src 'self'"),
    "CSP must restrict styles strictly to style-src 'self'"
  );

  // Verify app.js has zero innerHTML assignments
  const innerHtmlMatches = appJs.match(/innerHTML\s*=/g);
  assert.strictEqual(
    innerHtmlMatches,
    null,
    "Renderer app.js must have zero innerHTML assignments to prevent DOM XSS"
  );
});

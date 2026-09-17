/**
 * NetAccess Fault Tolerance & Operational Recovery Suite (Pass 3 Track 3.2)
 * 
 * Verifies:
 * 1. Deterministic port collision retry via injectable portBindFn (attempts 1 & 2 fail -> attempt 3 succeeds)
 * 2. Deterministic port exhaustion (all 3 attempts fail -> throws LoopbackPortAllocationError)
 * 3. Missing Keychain credential pre-flight failure (surfaces CREDENTIALS_UNAVAILABLE with zero upstream I/O and zero leak)
 * 4. Controller pre-flight validation prevents any network probes or upstream connections when credentials missing
 * 5. Selective orphan profile sweep (preserves active sessions, removes stale sessions older than threshold)
 */

import test from "node:test";
import assert from "node:assert/strict";
import * as net from "node:net";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import * as os from "node:os";
import {
  startLoopbackBridge,
  LoopbackPortAllocationError,
  CredentialsUnavailableError,
} from "../src/netaccess/loopbackTunnel.js";
import { SessionManager } from "../src/netaccess/sessionManager.js";
import { CleanupSupervisor } from "../src/netaccess/cleanupSupervisor.js";
import { MemoryCredentialStore } from "../src/netaccess/keychain.js";
import { ApplicationController } from "../src/netaccess/controller.js";
import { TransportManager } from "../src/netaccess/transportManager.js";
import { parseTarget, makeFinding } from "../src/netaccess/engine.js";

// ---------------------------------------------------------------------------
// 1. Deterministic Ephemeral Port Retry & Exhaustion
// ---------------------------------------------------------------------------

test("Recovery 1: Deterministic loopback port collision retry (attempts 1 & 2 fail, attempt 3 succeeds)", async () => {
  let attemptCount = 0;
  const simulatedPort = 58912;

  const portBindFn = async (_server) => {
    attemptCount++;
    if (attemptCount === 1) {
      const err = new Error("listen EADDRINUSE 127.0.0.1:58910");
      err.code = "EADDRINUSE";
      throw err;
    }
    if (attemptCount === 2) {
      const err = new Error("listen EADDRINUSE 127.0.0.1:58911");
      err.code = "EADDRINUSE";
      throw err;
    }
    // Attempt 3 succeeds: listen on an ephemeral port
    await new Promise((resolve) => _server.listen(0, "127.0.0.1", resolve));
    return _server.address().port;
  };

  const bridge = await startLoopbackBridge(
    {
      id: "retry-port-bridge",
      name: "Retry Port Bridge",
      type: "http_proxy",
      host: "127.0.0.1",
      port: 8080,
      tags: ["test"],
      trusted: true,
      enabled: true,
    },
    { portBindFn },
  );

  try {
    assert.equal(attemptCount, 3, "Must retry exactly twice and succeed on the third attempt");
    assert.ok(bridge.port > 0, "Allocated port must be valid positive integer");
    assert.equal(bridge.proxyUrl, `http://127.0.0.1:${bridge.port}`);
  } finally {
    await bridge.close();
  }
});

test("Recovery 2: Deterministic port exhaustion raises LoopbackPortAllocationError after 3 failures", async () => {
  let attemptCount = 0;

  const portBindFn = async (_server) => {
    attemptCount++;
    const err = new Error(`listen EADDRINUSE 127.0.0.1:5899${attemptCount}`);
    err.code = "EADDRINUSE";
    throw err;
  };

  await assert.rejects(
    () =>
      startLoopbackBridge(
        {
          id: "exhaustion-bridge",
          name: "Exhaustion Bridge",
          type: "http_proxy",
          host: "127.0.0.1",
          port: 8080,
          tags: ["test"],
          trusted: true,
          enabled: true,
        },
        { portBindFn },
      ),
    (err) => {
      assert.ok(err instanceof LoopbackPortAllocationError, "Must be instance of LoopbackPortAllocationError");
      assert.match(err.message, /Failed to allocate ephemeral loopback port after 3 attempts/);
      return true;
    },
  );

  assert.equal(attemptCount, 3, "Must attempt exactly 3 times before giving up");
});

// ---------------------------------------------------------------------------
// 2. Missing Keychain Credential Pre-flight Failure
// ---------------------------------------------------------------------------

test("Recovery 3: Missing Keychain credentials surfaces CREDENTIALS_UNAVAILABLE with 0 upstream network I/O", async () => {
  // Spy upstream server: counts incoming TCP connections
  let upstreamConnectionCount = 0;
  const upstreamServer = net.createServer(() => {
    upstreamConnectionCount++;
  });
  upstreamServer.unref();
  await new Promise((resolve) => upstreamServer.listen(0, "127.0.0.1", resolve));
  const upstreamPort = upstreamServer.address().port;

  const memStore = new MemoryCredentialStore();
  // Notice: We intentionally do NOT populate the secret in memStore!
  const secretRef = "keychain://netaccess/missing-creds-transport";

  const supervisor = new CleanupSupervisor(false);
  const sessionManager = new SessionManager({ supervisor });
  sessionManager.setCredentialResolver((ref) => memStore.getSecret(ref));

  const transport = {
    id: "missing-creds-transport",
    name: "Missing Creds Proxy",
    type: "http_proxy",
    host: "127.0.0.1",
    port: upstreamPort,
    username: "alice",
    secretRef,
    tags: ["test"],
    trusted: true,
    enabled: true,
  };

  const target = parseTarget("http://internal.corp/secure");

  const pathConfig = {
    type: "alternate",
    transportId: transport.id,
    transportName: transport.name,
    transportType: "http_proxy",
  };

  let caughtError = null;
  try {
    await sessionManager.launchSession("sess-missing-keychain", target, pathConfig, transport);
  } catch (err) {
    caughtError = err;
  }

  try {
    // Assert 1: Threw structured error with CREDENTIALS_UNAVAILABLE
    assert.ok(caughtError, "Must throw an error when credentials missing");
    assert.equal(caughtError.code, "CREDENTIALS_UNAVAILABLE");
    assert.match(caughtError.message, /unavailable in macOS Keychain/);
    assert.ok(caughtError.suggestedAction, "Must include actionable remediation");

    // Assert 2: ZERO upstream network attempts
    assert.equal(upstreamConnectionCount, 0, "Must make zero network connections when credentials missing");

    // Assert 3: ZERO secret leakage
    const serialized = JSON.stringify(caughtError);
    assert.ok(!serialized.includes("supersecret"), "Must not leak secret values");
    assert.ok(!serialized.includes("password"), "Must not leak password fields");

    // Assert 4: Cleanup completed cleanly
    const tracked = supervisor.getTrackedCount();
    assert.equal(tracked.processes, 0, "No child processes orphaned");
    assert.equal(tracked.directories, 0, "No profile directories orphaned");
    assert.equal(tracked.sockets, 0, "No sockets orphaned");
  } finally {
    await new Promise((resolve) => upstreamServer.close(resolve));
    await supervisor.cleanupAll();
  }
});

test("Recovery 4: Controller prober pre-flight check executes zero probes when secretRef missing in Keychain", async () => {
  let upstreamConnectionCount = 0;
  const upstreamServer = net.createServer(() => {
    upstreamConnectionCount++;
  });
  upstreamServer.unref();
  await new Promise((resolve) => upstreamServer.listen(0, "127.0.0.1", resolve));
  const upstreamPort = upstreamServer.address().port;

  const memStore = new MemoryCredentialStore();
  const secretRef = "keychain://netaccess/unresolvable-proxy";

  const transportManager = new TransportManager({
    credentialStore: memStore,
    initialTransports: [
      {
        id: "unresolvable-proxy",
        name: "Unresolvable Proxy",
        type: "http_proxy",
        host: "127.0.0.1",
        port: upstreamPort,
        username: "corp_user",
        secretRef,
        tags: ["proxy"],
        trusted: true,
        enabled: true,
      },
    ],
  });

  const controller = new ApplicationController({
    transportManager,
    diagnostician: async (target) => [
      makeFinding("dns", true, "healthy", `Resolved ${target.host} to 1.2.3.4`),
      makeFinding("tcp", false, "tcp_timeout", "Direct TCP timeout"),
    ],
  });

  // Open target via controller - must reject with NO_WORKING_PATH
  await assert.rejects(
    () => controller.openTarget("https://secure.internal.bank", { skipBrowserLaunch: true }),
    (err) => {
      assert.equal(err.code, "NO_WORKING_PATH");
      return true;
    },
  );

  try {
    // Assert 1: Upstream proxy connection count is 0 (pre-flight prevented TCP probe)
    assert.equal(upstreamConnectionCount, 0, "Zero upstream connections must be made when credentials missing");

    // Assert 2: Controller status message reflects safe failure
    const status = controller.getStatus();
    assert.notEqual(status.state, "RUNNING", "Session must not run without credentials");

    // Assert 3: No secret material leaked in status or error
    const serializedStatus = JSON.stringify(status);
    assert.ok(!serializedStatus.includes("password"), "Status must not contain secret material");
  } finally {
    await controller.closeSession();
    await new Promise((resolve) => upstreamServer.close(resolve));
  }
});

// ---------------------------------------------------------------------------
// 3. Selective Orphan Profile Sweep
// ---------------------------------------------------------------------------

test("Recovery 5: Selective orphan profile sweep preserves active sessions and purges stale orphans", async () => {
  const supervisor = new CleanupSupervisor(false);
  const tmpDir = os.tmpdir();

  // 1. Create an active session directory tracked by the current supervisor
  const activeSessionId = "active-sess-999";
  const activeProfileDir = await supervisor.createEphemeralProfile(activeSessionId);

  // 2. Create a stale orphan directory (simulating an old crash 2 hours ago)
  const staleDirName = "netaccess-session-crashed-deadbeef1234";
  const staleProfileDir = path.join(tmpDir, staleDirName);
  await fs.mkdir(staleProfileDir, { recursive: true });
  // Set mtime to 2 hours in the past
  const twoHoursAgo = (Date.now() - 2 * 3600 * 1000) / 1000;
  await fs.utimes(staleProfileDir, twoHoursAgo, twoHoursAgo);

  // 3. Create a recent orphan directory (simulating another process started 5 minutes ago)
  const recentDirName = "netaccess-session-recent-feedbeef5678";
  const recentProfileDir = path.join(tmpDir, recentDirName);
  await fs.mkdir(recentProfileDir, { recursive: true });
  // Set mtime to 5 minutes ago
  const fiveMinAgo = (Date.now() - 5 * 60 * 1000) / 1000;
  await fs.utimes(recentProfileDir, fiveMinAgo, fiveMinAgo);

  try {
    // Run sweep with 1-hour threshold (3600000ms)
    const swept = await supervisor.sweepOrphanedProfiles(3600000);

    // Assertions:
    // 1. Stale profile MUST be swept
    assert.ok(
      swept.some((p) => p.includes(staleDirName)),
      "Stale orphan directory older than threshold must be swept",
    );
    const staleExists = await fs.stat(staleProfileDir).then(() => true).catch(() => false);
    assert.equal(staleExists, false, "Stale orphan directory must be removed from disk");

    // 2. Active profile MUST NOT be swept (protected by supervisor registration)
    assert.ok(
      !swept.some((p) => p.includes(path.basename(activeProfileDir))),
      "Active registered session must not be swept",
    );
    const activeExists = await fs.stat(activeProfileDir).then(() => true).catch(() => false);
    assert.equal(activeExists, true, "Active session profile directory must remain intact on disk");

    // 3. Recent orphan (< 1 hour) MUST NOT be swept
    assert.ok(
      !swept.some((p) => p.includes(recentDirName)),
      "Recent unregistered directory younger than threshold must not be swept",
    );
    const recentExists = await fs.stat(recentProfileDir).then(() => true).catch(() => false);
    assert.equal(recentExists, true, "Recent directory younger than threshold must remain intact");
  } finally {
    // Clean up active session and recent orphan
    await supervisor.cleanupSession(activeSessionId);
    await fs.rm(recentProfileDir, { recursive: true, force: true }).catch(() => {});
    await fs.rm(staleProfileDir, { recursive: true, force: true }).catch(() => {});
  }
});

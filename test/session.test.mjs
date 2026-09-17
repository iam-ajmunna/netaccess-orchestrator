import test from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs/promises";
import * as fsSync from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { spawn } from "node:child_process";
import { CleanupSupervisor } from "../src/netaccess/cleanupSupervisor.js";
import { SessionManager } from "../src/netaccess/sessionManager.js";
import { ApplicationController } from "../src/netaccess/controller.js";
import { parseTarget, redactCredentials } from "../src/netaccess/engine.js";

// Helper script that runs as a dummy browser for controlled testing
const NODE_BIN = process.execPath;

test("P3.5: Browser executable discovery on macOS", async () => {
  const sm = new SessionManager();
  const browsers = await sm.discoverBrowsers();
  
  // On this Mac, either Chrome or Brave should be present, or custom path fallback
  assert.ok(Array.isArray(browsers));
  for (const b of browsers) {
    assert.ok(b.name);
    assert.ok(b.executablePath);
    assert.strictEqual(b.isChromiumBased, true);
  }

  // Custom executable path discovery
  const smCustom = new SessionManager({ customBrowserPath: NODE_BIN });
  const customBrowsers = await smCustom.discoverBrowsers();
  const custom = customBrowsers.find((b) => b.name === "Custom");
  assert.ok(custom, "Should discover custom executable path");
  assert.strictEqual(custom.executablePath, NODE_BIN);
});

test("P3.6: Direct launch receives exact normalized target and touches no proxy or temp profile", async () => {
  const supervisor = new CleanupSupervisor(false);
  let spawnedCmd = "";
  let spawnedArgs = [];

  const mockSpawn = (cmd, args) => {
    spawnedCmd = cmd;
    spawnedArgs = args;
    // Spawn a quick exiting node script as mock
    return spawn(NODE_BIN, ["-e", "process.exit(0)"]);
  };

  const sm = new SessionManager({
    cleanupSupervisor: supervisor,
    openerCommand: "/usr/bin/open",
    spawnFn: mockSpawn,
  });

  const target = parseTarget("example.com/app?query=test#section");
  const selectedPath = {
    type: "direct",
    transportId: "direct",
    transportName: "Direct Connection",
    transportType: "direct",
    reason: "Direct healthy",
  };

  const session = await sm.launchSession("sess-direct-1", target, selectedPath);

  assert.strictEqual(session.sessionId, "sess-direct-1");
  assert.strictEqual(session.path.type, "direct");
  assert.strictEqual(session.profileDir, undefined, "Direct session must not create an ephemeral profile");
  assert.strictEqual(spawnedCmd, "/usr/bin/open");
  assert.deepStrictEqual(spawnedArgs, ["https://example.com/app?query=test#section"]);

  // Supervisor registered process
  assert.ok(session.process);
  await sm.closeSession("sess-direct-1");
});

test("P3.7: Alternate launch receives exact proxy configuration and isolated ephemeral profile", async () => {
  const supervisor = new CleanupSupervisor(false);
  let spawnedCmd = "";
  let spawnedArgs = [];

  const mockSpawn = (cmd, args) => {
    spawnedCmd = cmd;
    spawnedArgs = args;
    return spawn(NODE_BIN, ["-e", "setInterval(() => {}, 1000)"]);
  };

  const sm = new SessionManager({
    cleanupSupervisor: supervisor,
    customBrowserPath: NODE_BIN,
    spawnFn: mockSpawn,
  });

  const target = parseTarget("internal.service.org/dashboard");
  const selectedPath = {
    type: "alternate",
    transportId: "proxy-corp",
    transportName: "Corp HTTP Proxy",
    transportType: "http_proxy",
    reason: "Policy routing",
  };
  const transportConfig = {
    id: "proxy-corp",
    name: "Corp HTTP Proxy",
    type: "http_proxy",
    host: "10.0.0.1",
    port: 8080,
    enabled: true,
  };

  const session = await sm.launchSession("sess-alt-1", target, selectedPath, transportConfig);

  assert.strictEqual(session.sessionId, "sess-alt-1");
  assert.strictEqual(session.path.type, "alternate");
  assert.ok(session.profileDir, "Alternate session must have an ephemeral profile directory");
  assert.ok(fsSync.existsSync(session.profileDir), "Profile directory must exist on disk");

  // Verify proxy argument and user-data-dir in args
  const proxyArg = spawnedArgs.find((a) => a.startsWith("--proxy-server="));
  assert.strictEqual(proxyArg, "--proxy-server=http://10.0.0.1:8080");

  const userDataDirArg = spawnedArgs.find((a) => a.startsWith("--user-data-dir="));
  assert.strictEqual(userDataDirArg, `--user-data-dir=${session.profileDir}`);

  // Normal user profile is NEVER touched
  const userHome = os.homedir();
  assert.ok(!session.profileDir.startsWith(path.join(userHome, "Library/Application Support/Google/Chrome")));

  // Target URL is at the end
  assert.strictEqual(spawnedArgs[spawnedArgs.length - 1], "https://internal.service.org/dashboard");

  // Teardown
  await sm.closeSession("sess-alt-1");
  assert.ok(!fsSync.existsSync(session.profileDir), "Profile directory must be removed after close");
});

test("P3.4: Two sessions receive different profile directories", async () => {
  const supervisor = new CleanupSupervisor(false);
  const sm = new SessionManager({
    cleanupSupervisor: supervisor,
    customBrowserPath: NODE_BIN,
    spawnFn: () => spawn(NODE_BIN, ["-e", "setInterval(() => {}, 1000)"]),
  });

  const target = parseTarget("example.com");
  const selectedPath = {
    type: "alternate",
    transportId: "t1",
    transportName: "T1",
    transportType: "http_proxy",
    reason: "test",
  };
  const config = { id: "t1", name: "T1", type: "http_proxy", host: "127.0.0.1", port: 8080, enabled: true };

  const s1 = await sm.launchSession("sess-1", target, selectedPath, config);
  const s2 = await sm.launchSession("sess-2", target, selectedPath, config);

  assert.notStrictEqual(s1.profileDir, s2.profileDir);
  assert.ok(s1.profileDir.includes("sess-1"));
  assert.ok(s2.profileDir.includes("sess-2"));

  await sm.closeSession("sess-1");
  await sm.closeSession("sess-2");

  assert.ok(!fsSync.existsSync(s1.profileDir));
  assert.ok(!fsSync.existsSync(s2.profileDir));
});

test("P3.9: Cancel during launch cleans everything immediately", async () => {
  const supervisor = new CleanupSupervisor(false);
  const ac = new AbortController();
  ac.abort(); // pre-aborted

  const sm = new SessionManager({
    cleanupSupervisor: supervisor,
    customBrowserPath: NODE_BIN,
  });

  const target = parseTarget("example.com");
  const selectedPath = {
    type: "alternate",
    transportId: "t1",
    transportName: "T1",
    transportType: "http_proxy",
    reason: "test",
  };

  await assert.rejects(
    async () => {
      await sm.launchSession("sess-cancel-1", target, selectedPath, undefined, ac.signal);
    },
    { message: /aborted|cancelled/i },
  );

  // Verify no orphaned directory in supervisor
  const tracked = supervisor.getTrackedCount();
  assert.strictEqual(tracked.directories, 0);
  assert.strictEqual(tracked.processes, 0);
});

test("P3.9: Browser exits normally → clean teardown", async () => {
  const supervisor = new CleanupSupervisor(false);
  let sessionExited = false;

  const sm = new SessionManager({
    cleanupSupervisor: supervisor,
    customBrowserPath: NODE_BIN,
    // Process that exits cleanly after 80ms
    spawnFn: () => spawn(NODE_BIN, ["-e", "setTimeout(() => process.exit(0), 80)"]),
  });

  sm.setOnSessionExit(async (sessionId) => {
    sessionExited = true;
    await sm.closeSession(sessionId);
  });

  const target = parseTarget("example.com");
  const selectedPath = {
    type: "alternate",
    transportId: "t1",
    transportName: "T1",
    transportType: "http_proxy",
    reason: "test",
  };
  const config = { id: "t1", name: "T1", type: "http_proxy", host: "127.0.0.1", port: 8080, enabled: true };

  const session = await sm.launchSession("sess-exit-norm", target, selectedPath, config);
  const profileDir = session.profileDir;
  assert.ok(fsSync.existsSync(profileDir));

  // Wait for child process exit and callback
  await new Promise((resolve) => setTimeout(resolve, 250));

  assert.strictEqual(sessionExited, true);
  assert.ok(!fsSync.existsSync(profileDir), "Profile directory must be deleted after normal exit cleanup");
  assert.strictEqual(supervisor.getTrackedCount().processes, 0);
});

test("P3.9: Browser crashes → clean teardown", async () => {
  const supervisor = new CleanupSupervisor(false);
  let crashHandled = false;

  const sm = new SessionManager({
    cleanupSupervisor: supervisor,
    customBrowserPath: NODE_BIN,
    // Process that crashes with code 1 after 80ms
    spawnFn: () => spawn(NODE_BIN, ["-e", "setTimeout(() => { process.exit(1); }, 80)"]),
  });

  sm.setOnSessionExit(async (sessionId) => {
    crashHandled = true;
    await sm.closeSession(sessionId);
  });

  const target = parseTarget("example.com");
  const selectedPath = {
    type: "alternate",
    transportId: "t1",
    transportName: "T1",
    transportType: "http_proxy",
    reason: "test",
  };
  const config = { id: "t1", name: "T1", type: "http_proxy", host: "127.0.0.1", port: 8080, enabled: true };

  const session = await sm.launchSession("sess-crash-1", target, selectedPath, config);
  const profileDir = session.profileDir;

  await new Promise((resolve) => setTimeout(resolve, 250));

  assert.strictEqual(crashHandled, true);
  assert.ok(!fsSync.existsSync(profileDir), "Profile directory must be deleted after browser crash");
  assert.strictEqual(supervisor.getTrackedCount().processes, 0);
});

test("P3.3: Child process tree is terminated (SIGTERM -> SIGKILL)", async () => {
  const supervisor = new CleanupSupervisor(false);

  // Spawn a parent process that spawns a child process
  const parent = spawn(
    NODE_BIN,
    [
      "-e",
      `
      const { spawn } = require('child_process');
      const child = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)']);
      setInterval(() => {}, 1000);
      `,
    ],
    { detached: true },
  );

  const parentPid = parent.pid;
  assert.ok(parentPid > 0);

  supervisor.registerProcess(parentPid, "sess-tree-1", "parent-process");

  // Give child time to spawn
  await new Promise((r) => setTimeout(r, 150));
  assert.strictEqual(supervisor.isProcessAlive(parentPid), true);

  // Terminate process tree
  const terminated = await supervisor.terminateProcessTree(parentPid);
  assert.strictEqual(terminated, true);
  assert.strictEqual(supervisor.isProcessAlive(parentPid), false);

  supervisor.unregisterProcess(parentPid);
});

test("P3.3: Cleanup is idempotent", async () => {
  const supervisor = new CleanupSupervisor(false);
  const profileDir = await supervisor.createEphemeralProfile("sess-idemp-1");
  assert.ok(fsSync.existsSync(profileDir));

  // First cleanup
  const res1 = await supervisor.cleanupSession("sess-idemp-1");
  assert.strictEqual(res1.directoriesRemoved.length, 1);
  assert.ok(!fsSync.existsSync(profileDir));

  // Second cleanup (must not throw, must be clean)
  const res2 = await supervisor.cleanupSession("sess-idemp-1");
  assert.strictEqual(res2.directoriesRemoved.length, 0);
  assert.strictEqual(res2.processesKilled.length, 0);
});

test("P3.4: Cleanup does not delete unrelated /tmp data", async () => {
  const supervisor = new CleanupSupervisor(false);

  // Create unrelated folder in os.tmpdir()
  const unrelatedDir = path.join(os.tmpdir(), "unrelated-app-data-" + Date.now());
  await fs.mkdir(unrelatedDir, { recursive: true });
  assert.ok(fsSync.existsSync(unrelatedDir));

  // Attempt to delete it via supervisor with arbitrary session ID
  const removed = await supervisor.safelyRemoveDirectory(unrelatedDir, "some-session");
  assert.strictEqual(removed, false, "Supervisor must reject deleting unrelated temp directories");
  assert.ok(fsSync.existsSync(unrelatedDir), "Unrelated temp directory must remain untouched");

  // Also test path with directory traversal or wrong session ID
  const fakeSessionDir = path.join(os.tmpdir(), "netaccess-session-alice-123456abcdef");
  await fs.mkdir(fakeSessionDir, { recursive: true });
  const wrongSessionRemove = await supervisor.safelyRemoveDirectory(fakeSessionDir, "bob");
  assert.strictEqual(wrongSessionRemove, false, "Supervisor must reject deleting directory belonging to another session");
  assert.ok(fsSync.existsSync(fakeSessionDir));

  // Clean up test fixtures manually
  await fs.rm(unrelatedDir, { recursive: true, force: true });
  await fs.rm(fakeSessionDir, { recursive: true, force: true });
});

test("P3.7 & P3.12: Secrets never appear in process arguments, logs, or command line", async () => {
  let capturedArgs = [];
  const mockSpawn = (cmd, args) => {
    capturedArgs = args;
    return spawn(NODE_BIN, ["-e", "process.exit(0)"]);
  };

  const sm = new SessionManager({
    customBrowserPath: NODE_BIN,
    spawnFn: mockSpawn,
    credentialResolver: async () => "superSecretPassword123",
  });

  const target = parseTarget("api.example.com");
  const selectedPath = {
    type: "alternate",
    transportId: "proxy-secret",
    transportName: "Secret Proxy",
    transportType: "http_proxy",
    reason: "auth",
  };

  // Transport with password embedded in host field or secretRef
  const transportConfig = {
    id: "proxy-secret",
    name: "Secret Proxy",
    type: "http_proxy",
    host: "user:superSecretPassword123@proxy.secure.net",
    port: 8080,
    enabled: true,
    secretRef: "keychain://corp_proxy_pass",
  };

  const session = await sm.launchSession("sess-sec-1", target, selectedPath, transportConfig);

  // Assert secret NEVER appears in args
  const serializedArgs = JSON.stringify(capturedArgs);
  assert.ok(!serializedArgs.includes("superSecretPassword123"), "Password must never appear in process arguments");
  assert.ok(!serializedArgs.includes("keychain://"), "Keychain references must not appear in process arguments");
  assert.ok(
    capturedArgs.some((a) => a.startsWith("--proxy-server=http://127.0.0.1:")),
    "Authenticated proxy must use isolated local loopback bridge on 127.0.0.1",
  );

  // Check redactCredentials utility
  const loggedUrl = "Connecting to http://admin:verySecretKey@10.0.0.1:8080/proxy";
  const redacted = redactCredentials(loggedUrl);
  assert.strictEqual(redacted, "Connecting to http://***:***@10.0.0.1:8080/proxy");

  await sm.closeSession("sess-sec-1");
});

test("P3.8: ApplicationController full session lifecycle with SessionManager", async () => {
  const supervisor = new CleanupSupervisor(false);
  let mockBrowserSpawned = false;

  const mockSpawn = (cmd, args) => {
    mockBrowserSpawned = true;
    return spawn(NODE_BIN, ["-e", "setInterval(() => {}, 1000)"]);
  };

  const sm = new SessionManager({
    cleanupSupervisor: supervisor,
    customBrowserPath: NODE_BIN,
    spawnFn: mockSpawn,
  });

  const controller = new ApplicationController({
    sessionManager: sm,
    diagnostician: async () => [
      {
        id: "direct-dns",
        layer: "dns",
        ok: true,
        classHint: "healthy",
        weight: 1.0,
        evidence: "Resolved",
        startedAt: Date.now() - 10,
        endedAt: Date.now(),
      },
      {
        id: "direct-tcp",
        layer: "tcp",
        ok: true,
        classHint: "healthy",
        weight: 1.0,
        evidence: "Connected",
        latencyMs: 15,
        startedAt: Date.now() - 10,
        endedAt: Date.now(),
      },
      {
        id: "direct-http",
        layer: "http",
        ok: true,
        classHint: "healthy",
        weight: 1.0,
        evidence: "HTTP 200 OK",
        startedAt: Date.now() - 10,
        endedAt: Date.now(),
      },
    ],
  });

  assert.strictEqual(controller.getState(), "IDLE");

  // Open target
  const result = await controller.openTarget("my-service.local");
  assert.strictEqual(result.path.type, "direct");
  assert.strictEqual(result.browserLaunched, true);
  assert.strictEqual(controller.getState(), "MONITORING");

  // Active session exists in SessionManager
  const activeSession = sm.getActiveSession();
  assert.ok(activeSession);
  assert.strictEqual(activeSession.sessionId, result.sessionId);

  // Close session -> state transitions through CLEANUP -> IDLE
  await controller.closeSession();
  assert.strictEqual(controller.getState(), "IDLE");
  assert.strictEqual(sm.getActiveSession(), null);
  assert.strictEqual(supervisor.getTrackedCount().processes, 0);
});

test("P3.9: Failed launch cleans up ephemeral profile immediately", async () => {
  const supervisor = new CleanupSupervisor(false);
  const sm = new SessionManager({
    cleanupSupervisor: supervisor,
    customBrowserPath: NODE_BIN,
    // Spawn function that fails / throws error
    spawnFn: () => {
      throw new Error("Simulated browser launch binary exec error");
    },
  });

  const target = parseTarget("example.com");
  const selectedPath = {
    type: "alternate",
    transportId: "t1",
    transportName: "T1",
    transportType: "http_proxy",
    reason: "test",
  };

  await assert.rejects(
    async () => {
      await sm.launchSession("sess-fail-launch", target, selectedPath);
    },
    { message: /Simulated browser launch binary exec error/ },
  );

  // Profile directory was cleaned up and supervisor has zero tracked resources
  assert.strictEqual(supervisor.getTrackedCount().directories, 0);
  assert.strictEqual(supervisor.getTrackedCount().processes, 0);
});

test("P3.2: Sockets and timers registered to session are destroyed on cleanup", async () => {
  const supervisor = new CleanupSupervisor(false);
  let socketDestroyed = false;
  let timerFired = false;

  const mockSocket = {
    destroy: () => {
      socketDestroyed = true;
    },
  };

  const timer = setTimeout(() => {
    timerFired = true;
  }, 1000);

  supervisor.registerSocket(mockSocket, "sess-sock-1");
  supervisor.registerTimer(timer, "sess-sock-1");

  const tracked = supervisor.getTrackedCount();
  assert.strictEqual(tracked.sockets, 1);
  assert.strictEqual(tracked.timers, 1);

  await supervisor.cleanupSession("sess-sock-1");

  assert.strictEqual(socketDestroyed, true, "Socket destroy() must be called on cleanup");
  assert.strictEqual(supervisor.getTrackedCount().sockets, 0);
  assert.strictEqual(supervisor.getTrackedCount().timers, 0);

  // Wait a bit to ensure timer was indeed cancelled and did not fire
  await new Promise((r) => setTimeout(r, 50));
  assert.strictEqual(timerFired, false);
});

test("P3.9: Signal trapping cleanupAll cleans all sessions", async () => {
  const supervisor = new CleanupSupervisor(false);

  const dir1 = await supervisor.createEphemeralProfile("sess-sig-1");
  const dir2 = await supervisor.createEphemeralProfile("sess-sig-2");

  assert.ok(fsSync.existsSync(dir1));
  assert.ok(fsSync.existsSync(dir2));

  // Install signal handlers
  supervisor.installSignalHandlers();

  // Call cleanupAll (which signal handlers invoke)
  await supervisor.cleanupAll();

  assert.ok(!fsSync.existsSync(dir1), "Profile dir 1 must be removed");
  assert.ok(!fsSync.existsSync(dir2), "Profile dir 2 must be removed");
  assert.strictEqual(supervisor.getTrackedCount().directories, 0);

  supervisor.removeSignalHandlers();
});


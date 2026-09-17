import test from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import * as os from "node:os";
import { spawn } from "node:child_process";

import {
  parseAndValidateSecretRef,
  formatSecretRef,
  InvalidSecretRefError,
  KeychainPermissionError,
  KeychainDeletionError,
  KeychainOperationError,
  MemoryCredentialStore,
  MacOSKeychainStore,
} from "../src/netaccess/keychain.js";
import { TransportManager } from "../src/netaccess/transportManager.js";
import { ApplicationController } from "../src/netaccess/controller.js";
import { SessionManager } from "../src/netaccess/sessionManager.js";
import { parseTarget, redactCredentials } from "../src/netaccess/engine.js";
import { startLoopbackBridge } from "../src/netaccess/loopbackTunnel.js";

const NODE_BIN = process.execPath;

// ---------------------------------------------------------------------------
// 1. Ref Schema & Strict Validation
// ---------------------------------------------------------------------------

test("Keychain 1: SecretRef schema validation rejects path traversal and malformed schemes", () => {
  // Valid refs
  assert.equal(formatSecretRef("proxy-corp-1"), "keychain://netaccess/proxy-corp-1");
  assert.equal(parseAndValidateSecretRef("keychain://netaccess/proxy-corp-1"), "proxy-corp-1");
  assert.equal(parseAndValidateSecretRef("keychain://netaccess/corp_123-abc"), "corp_123-abc");

  // Invalid formats / Traversal
  assert.throws(() => parseAndValidateSecretRef("keychain://netaccess/../etc/passwd"), InvalidSecretRefError);
  assert.throws(() => parseAndValidateSecretRef("keychain://netaccess/user/foo"), InvalidSecretRefError);
  assert.throws(() => parseAndValidateSecretRef("keychain://other/proxy-1"), InvalidSecretRefError);
  assert.throws(() => parseAndValidateSecretRef("http://netaccess/proxy-1"), InvalidSecretRefError);
  assert.throws(() => parseAndValidateSecretRef("keychain://netaccess/"), InvalidSecretRefError);
  assert.throws(() => parseAndValidateSecretRef("keychain://netaccess/with spaces"), InvalidSecretRefError);
  assert.throws(() => parseAndValidateSecretRef("keychain://netaccess/control\x00char"), InvalidSecretRefError);
  assert.throws(() => parseAndValidateSecretRef(""), InvalidSecretRefError);
  assert.throws(() => parseAndValidateSecretRef(null), InvalidSecretRefError);

  // Invalid formatSecretRef inputs
  assert.throws(() => formatSecretRef("../traversal"), InvalidSecretRefError);
  assert.throws(() => formatSecretRef("has space"), InvalidSecretRefError);
  assert.throws(() => formatSecretRef(""), InvalidSecretRefError);
});

// ---------------------------------------------------------------------------
// 2. MemoryCredentialStore & MacOSKeychainStore CRUD
// ---------------------------------------------------------------------------

test("Keychain 2: MemoryCredentialStore CRUD and non-existent item handling", async () => {
  const store = new MemoryCredentialStore();
  const ref = "keychain://netaccess/mem-test-1";

  // Non-existent item returns null without throwing
  assert.equal(await store.getSecret(ref), null);

  // Deleting non-existent item returns false (idempotent)
  assert.equal(await store.deleteSecret(ref), false);

  // Set and get secret
  await store.setSecret(ref, "SuperSecretPassword456!");
  assert.equal(await store.getSecret(ref), "SuperSecretPassword456!");

  // Overwrite secret
  await store.setSecret(ref, "NewUpdatedPassword789!");
  assert.equal(await store.getSecret(ref), "NewUpdatedPassword789!");

  // Delete secret
  assert.equal(await store.deleteSecret(ref), true);
  assert.equal(await store.getSecret(ref), null);

  // Empty secret rejection
  await assert.rejects(
    () => store.setSecret(ref, ""),
    KeychainOperationError,
  );
});

test("Keychain 2b: Real macOS Keychain integration on macOS host", async (t) => {
  if (process.platform !== "darwin") {
    t.skip("macOS Keychain test skipped on non-darwin platform");
    return;
  }

  const store = new MacOSKeychainStore({ service: "netaccess.test.temporary" });
  const testId = `temp-test-${Date.now()}`;
  const ref = formatSecretRef(testId);

  try {
    // 1. Clean if existed previously
    await store.deleteSecret(ref);

    // 2. Non-existent returns null
    const initial = await store.getSecret(ref);
    assert.equal(initial, null);

    // 3. Set secret
    await store.setSecret(ref, "MacOSTestSecretP@ss999");

    // 4. Retrieve secret
    const retrieved = await store.getSecret(ref);
    assert.equal(retrieved, "MacOSTestSecretP@ss999");

    // 5. Delete secret
    const deleted = await store.deleteSecret(ref);
    assert.equal(deleted, true);

    // 6. Confirm absent
    const afterDelete = await store.getSecret(ref);
    assert.equal(afterDelete, null);
  } finally {
    // Teardown
    try {
      await store.deleteSecret(ref);
    } catch {
      // Best-effort
    }
  }
});

// ---------------------------------------------------------------------------
// 3. Transactional Persistence & Rollback
// ---------------------------------------------------------------------------

test("Keychain 3: Transactional persistence rolls back Keychain secret if disk write fails", async () => {
  const memStore = new MemoryCredentialStore();
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "netaccess-keychain-test-"));
  // Use a read-only directory path to guarantee disk write failure
  const readOnlyDir = path.join(tmpDir, "readonly");
  await fs.mkdir(readOnlyDir, { mode: 0o400 });
  const failingStoragePath = path.join(readOnlyDir, "transports.json");

  const tm = new TransportManager({
    credentialStore: memStore,
    storagePath: failingStoragePath,
  });

  const secretRef = formatSecretRef("trans-fail-1");

  // Attempt save: should throw due to disk write failure
  await assert.rejects(
    () =>
      tm.saveTransportWithSecret(
        {
          id: "trans-fail-1",
          name: "Failing Transport",
          type: "http_proxy",
          host: "10.0.0.1",
          port: 8080,
          tags: ["test"],
          trusted: true,
          enabled: true,
        },
        "MySecretToRollback",
      ),
    /EACCES|permission/i,
  );

  // Invariant: Keychain secret MUST have been rolled back
  const rolledBackSecret = await memStore.getSecret(secretRef);
  assert.equal(rolledBackSecret, null, "Keychain secret must be rolled back on disk persistence failure");

  // Invariant: Transport must NOT remain in memory
  assert.equal(tm.getTransport("trans-fail-1"), undefined);

  // Cleanup
  await fs.chmod(readOnlyDir, 0o700);
  await fs.rm(tmpDir, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// 4. Strict Deletion Semantics
// ---------------------------------------------------------------------------

test("Keychain 4: Strict deletion fails closed on permission/system errors to prevent credential abandonment", async () => {
  // Mock store that throws KeychainPermissionError on delete
  const failingStore = {
    async getSecret() {
      return "secret";
    },
    async setSecret() {},
    async deleteSecret() {
      throw new KeychainPermissionError("User interaction is not allowed / permission denied");
    },
  };

  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "netaccess-del-test-"));
  const storagePath = path.join(tmpDir, "transports.json");

  const tm = new TransportManager({
    credentialStore: failingStore,
    storagePath,
  });

  tm.addTransport({
    id: "locked-transport",
    name: "Locked Transport",
    type: "http_proxy",
    host: "10.0.0.1",
    port: 8080,
    tags: ["test"],
    trusted: true,
    enabled: true,
    secretRef: "keychain://netaccess/locked-transport",
  });
  await tm.saveToDisk();

  // Attempt delete: must fail-closed with KeychainPermissionError
  await assert.rejects(
    () => tm.deleteTransport("locked-transport"),
    KeychainPermissionError,
  );

  // Invariant: Transport metadata MUST NOT be deleted from memory
  assert.ok(tm.getTransport("locked-transport"), "Metadata must not be abandoned in Keychain while removed from disk");

  // Invariant: Disk file must still contain the transport metadata
  const diskRaw = await fs.readFile(storagePath, "utf8");
  assert.ok(diskRaw.includes("locked-transport"));

  await fs.rm(tmpDir, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// 5. Disk Boundary: transports.json Contains Only secretRef
// ---------------------------------------------------------------------------

test("Keychain 5: Disk persistence contains strictly metadata and secretRef, NEVER plaintext password", async () => {
  const memStore = new MemoryCredentialStore();
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "netaccess-disk-sec-"));
  const storagePath = path.join(tmpDir, "transports.json");

  const tm = new TransportManager({
    credentialStore: memStore,
    storagePath,
  });

  const secretPlaintext = "CRITICAL_PLAINTEXT_SECRET_xyz123";

  await tm.saveTransportWithSecret(
    {
      id: "proxy-corp",
      name: "Corp Proxy",
      type: "http_proxy",
      host: "proxy.corp.net",
      port: 8080,
      username: "corpuser",
      tags: ["corp"],
      trusted: true,
      enabled: true,
    },
    secretPlaintext,
  );

  // Read raw file from disk
  const content = await fs.readFile(storagePath, "utf8");
  const parsed = JSON.parse(content);

  // Plaintext password MUST NOT appear anywhere in the raw file
  assert.ok(!content.includes(secretPlaintext), "Plaintext secret must never appear on disk");

  // Secret reference MUST be present
  const transport = parsed.transports.find((t) => t.id === "proxy-corp");
  assert.ok(transport);
  assert.equal(transport.username, "corpuser");
  assert.equal(transport.secretRef, "keychain://netaccess/proxy-corp");
  assert.equal(transport.password, undefined);

  await fs.rm(tmpDir, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// 6. Process argv Boundary (Chromium Credential Isolation)
// ---------------------------------------------------------------------------

test("Keychain 6: Authenticated Chromium session launches via loopback bridge with ZERO credentials in argv", async () => {
  let capturedArgs = [];
  const mockSpawn = (cmd, args) => {
    capturedArgs = args;
    return spawn(NODE_BIN, ["-e", "process.exit(0)"]);
  };

  const memStore = new MemoryCredentialStore();
  const secretRef = formatSecretRef("proxy-auth-argv");
  const secretValue = "ArgvForbiddenPassword999";
  await memStore.setSecret(secretRef, secretValue);

  const sm = new SessionManager({
    customBrowserPath: NODE_BIN,
    spawnFn: mockSpawn,
    credentialResolver: (ref) => memStore.getSecret(ref),
  });

  const target = parseTarget("https://internal.corp.com");
  const selectedPath = {
    type: "alternate",
    transportId: "proxy-auth-argv",
    transportName: "Auth Proxy",
    transportType: "http_proxy",
    reason: "auth",
  };

  const transportConfig = {
    id: "proxy-auth-argv",
    name: "Auth Proxy",
    type: "http_proxy",
    host: "proxy.internal.net",
    port: 8080,
    username: "testuser",
    secretRef,
    tags: ["corp"],
    trusted: true,
    enabled: true,
  };

  await sm.launchSession("sess-argv-1", target, selectedPath, transportConfig);

  const serializedArgs = JSON.stringify(capturedArgs);

  // Secret MUST NOT appear anywhere in argv
  assert.ok(!serializedArgs.includes(secretValue), "Password must never appear in argv");
  assert.ok(!serializedArgs.includes("testuser:"), "Credentials must never appear in argv");
  assert.ok(!serializedArgs.includes("keychain://"), "secretRef must not appear in argv");

  // Chromium sees only --proxy-server=http://127.0.0.1:<port>
  const proxyArg = capturedArgs.find((a) => a.startsWith("--proxy-server="));
  assert.ok(proxyArg, "--proxy-server argument must be passed to Chromium");
  assert.match(
    proxyArg,
    /^--proxy-server=http:\/\/127\.0\.0\.1:\d+$/,
    "Proxy server argument must bind strictly to local ephemeral loopback bridge",
  );

  await sm.closeSession("sess-argv-1");
});

// ---------------------------------------------------------------------------
// 7. Environment (process.env) Boundary
// ---------------------------------------------------------------------------

test("Keychain 7: Secret resolution never pollutes process.env", async () => {
  const envSnapshot = { ...process.env };
  const secret = "UniqueEnvForbiddenSecret_12345";

  const memStore = new MemoryCredentialStore();
  const ref = formatSecretRef("env-check");
  await memStore.setSecret(ref, secret);

  // Resolve secret
  const resolved = await memStore.getSecret(ref);
  assert.equal(resolved, secret);

  // Verify process.env did not gain secret
  for (const [k, v] of Object.entries(process.env)) {
    assert.ok(
      !String(v).includes(secret),
      `process.env key "${k}" must not contain plaintext credentials`,
    );
  }
});

// ---------------------------------------------------------------------------
// 8. IPC Boundary: Credentials Never Cross Bridge
// ---------------------------------------------------------------------------

test("Keychain 8: Controller getTransports exposes only secretRef, never secrets", async () => {
  const memStore = new MemoryCredentialStore();
  const controller = new ApplicationController({
    initialSettings: { developerMode: true },
  });

  const secret = "SuperSecretIpcPass!";
  await controller.saveTransportWithSecret(
    {
      id: "proxy-ipc",
      name: "IPC Proxy",
      type: "http_proxy",
      host: "10.10.10.10",
      port: 8080,
      username: "ipcuser",
      tags: ["ipc"],
      trusted: true,
      enabled: true,
    },
    secret,
  );

  const transports = controller.getTransports();
  const found = transports.find((t) => t.id === "proxy-ipc");
  assert.ok(found);
  assert.equal(found.username, "ipcuser");
  assert.equal(found.secretRef, "keychain://netaccess/proxy-ipc");

  // Assert serialized transport has no secret
  const serialized = JSON.stringify(transports);
  assert.ok(!serialized.includes(secret), "IPC serialized transports must not contain plaintext secret");
  assert.ok(!("password" in found), "TransportConfig object must not have a password key");
});

// ---------------------------------------------------------------------------
// 9. CLI Listing (netaccess transports --json)
// ---------------------------------------------------------------------------

test("Keychain 9: CLI transports command displays only secretRef without secrets", async () => {
  const controller = new ApplicationController();
  const memStore = new MemoryCredentialStore();
  const secret = "CliSecret999888";

  await controller.saveTransportWithSecret(
    {
      id: "cli-proxy",
      name: "CLI Proxy",
      type: "socks5",
      host: "127.0.0.1",
      port: 1080,
      username: "socksuser",
      tags: ["socks"],
      trusted: true,
      enabled: true,
    },
    secret,
  );

  const transports = controller.getTransports();
  const jsonStr = JSON.stringify(transports);

  assert.ok(!jsonStr.includes(secret), "CLI JSON output must not contain secret");
  assert.ok(jsonStr.includes("keychain://netaccess/cli-proxy"));
});

// ---------------------------------------------------------------------------
// 10. Exception & Error Output Boundary
// ---------------------------------------------------------------------------

test("Keychain 10: Error redaction prevents secrets in logs and exception strings", () => {
  const rawError = "Connection to http://admin:superSecretPass123@proxy.domain.com:8080 failed: 407 Proxy Auth";
  const redacted = redactCredentials(rawError);

  assert.ok(!redacted.includes("superSecretPass123"));
  assert.ok(!redacted.includes("admin:superSecretPass123"));
  assert.strictEqual(redacted, "Connection to http://***:***@proxy.domain.com:8080 failed: 407 Proxy Auth");
});

// ---------------------------------------------------------------------------
// 11. Loopback Tunnel Live Connectivity
// ---------------------------------------------------------------------------

test("Keychain 11: Ephemeral loopback bridge binds strictly to 127.0.0.1 and cleans up", async () => {
  const bridge = await startLoopbackBridge({
    id: "loopback-test",
    name: "Loopback Test",
    type: "http_proxy",
    host: "127.0.0.1",
    port: 8888,
    username: "user",
    secretRef: "keychain://netaccess/loopback-test",
    tags: ["test"],
    trusted: true,
    enabled: true,
  }, {
    credentialResolver: async () => "resolvedPassword",
  });

  // Verify binding
  assert.equal(bridge.host, "127.0.0.1");
  assert.ok(bridge.port > 0, "Ephemeral port must be allocated");
  assert.equal(bridge.proxyUrl, `http://127.0.0.1:${bridge.port}`);

  // Close bridge cleanly
  await bridge.close();
});

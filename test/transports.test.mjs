/**
 * Unit & Integration Tests for NetAccess Transport Probing, EWMA Health,
 * Circuit Breakers, and Safe Persistence (P2)
 */

import assert from "node:assert/strict";
import * as fs from "node:fs/promises";
import * as http from "node:http";
import * as net from "node:net";
import * as os from "node:os";
import * as path from "node:path";
import test from "node:test";
import { parseTarget } from "../src/netaccess/engine.ts";
import {
  probeHttpProxy,
  probeSocks5,
  probeTransport,
} from "../src/netaccess/probes/transportProber.ts";
import { TransportManager } from "../src/netaccess/transportManager.ts";

test("P2 HTTP Proxy: Successful CONNECT tunnel", async () => {
  // Mock HTTP CONNECT Proxy
  const server = http.createServer();
  server.on("connect", (req, clientSocket, head) => {
    clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
    // Simple echo/close for the tunnel
    clientSocket.on("data", () => {
      clientSocket.end();
    });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const proxyPort = server.address().port;

  try {
    const transport = {
      id: "test-http-proxy",
      name: "Test HTTP Proxy",
      type: "http_proxy",
      host: "127.0.0.1",
      port: proxyPort,
      tags: ["test"],
      trusted: true,
      enabled: true,
    };

    const target = parseTarget("http://example.com:80/");
    const result = await probeTransport(transport, target, undefined, { timeoutMs: 2000 });

    assert.equal(result.ok, true);
    assert.equal(result.proxyReachable, true);
    assert.equal(result.targetReachable, true);
    assert.equal(result.statusCode, 200);
  } finally {
    server.close();
  }
});

test("P2 HTTP Proxy: 407 Proxy Authentication Required is distinguishable", async () => {
  // Mock HTTP Proxy requiring auth
  const server = http.createServer();
  server.on("connect", (req, clientSocket) => {
    clientSocket.write(
      "HTTP/1.1 407 Proxy Authentication Required\r\n" +
      "Proxy-Authenticate: Basic realm=\"Access to proxy\"\r\n\r\n"
    );
    clientSocket.end();
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const proxyPort = server.address().port;

  try {
    const transport = {
      id: "auth-proxy",
      name: "Auth Required Proxy",
      type: "http_proxy",
      host: "127.0.0.1",
      port: proxyPort,
      tags: ["test"],
      trusted: true,
      enabled: true,
    };

    const target = parseTarget("http://example.com:80/");
    const result = await probeTransport(transport, target, undefined, { timeoutMs: 2000 });

    assert.equal(result.ok, false);
    assert.equal(result.proxyReachable, true); // Proxy IS reachable
    assert.equal(result.targetReachable, false);
    assert.equal(result.failureReason, "PROXY_AUTH_REQUIRED");
    assert.equal(result.statusCode, 407);
    assert.match(result.error, /HTTP 407/i);
  } finally {
    server.close();
  }
});

test("P2 SOCKS5 Probing: RFC 1928 negotiation & proxy-side domain CONNECT", async () => {
  let domainRequested = "";

  // Mock SOCKS5 Server
  const server = net.createServer((socket) => {
    let state = "greeting";

    socket.on("data", (data) => {
      if (state === "greeting") {
        // Expect [0x05, NMETHODS, ...METHODS]
        assert.equal(data[0], 0x05);
        // Reply [0x05, 0x00] (No authentication required)
        socket.write(Buffer.from([0x05, 0x00]));
        state = "connect";
        return;
      }

      if (state === "connect") {
        // Expect [0x05, 0x01 (CONNECT), 0x00, 0x03 (DOMAIN), LEN, ...DOMAIN, PORT_HI, PORT_LO]
        assert.equal(data[0], 0x05);
        assert.equal(data[1], 0x01);
        assert.equal(data[3], 0x03); // ATYP: DOMAINNAME

        const domainLen = data[4];
        domainRequested = data.subarray(5, 5 + domainLen).toString("utf8");

        // Reply [0x05, 0x00 (SUCCESS), 0x00, 0x01, 127, 0, 0, 1, 0, 80]
        socket.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 80]));
        state = "tunnel";
      }
    });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const proxyPort = server.address().port;

  try {
    const transport = {
      id: "socks5-test",
      name: "Test SOCKS5 Proxy",
      type: "socks5",
      host: "127.0.0.1",
      port: proxyPort,
      tags: ["test"],
      trusted: true,
      enabled: true,
    };

    const target = parseTarget("http://server3.ftpbd.net:8080/");
    const result = await probeTransport(transport, target, undefined, { timeoutMs: 2000 });

    assert.equal(result.ok, true);
    assert.equal(result.proxyReachable, true);
    assert.equal(result.targetReachable, true);
    assert.equal(result.dnsResolutionMethod, "proxy_side");
    assert.equal(domainRequested, "server3.ftpbd.net");
  } finally {
    server.close();
  }
});

test("P2 TransportManager: EWMA health scoring & circuit breaker lifecycle", () => {
  const manager = new TransportManager({
    initialTransports: [
      { id: "direct", name: "Direct", type: "direct", tags: ["direct"], trusted: true, enabled: true },
      { id: "proxy-a", name: "Proxy A", type: "socks5", host: "127.0.0.1", port: 1080, tags: ["home"], trusted: true, enabled: true },
    ],
  });

  const initialRt = manager.getRuntime("proxy-a");
  assert.ok(initialRt);
  assert.equal(initialRt.circuit, "closed");
  assert.equal(initialRt.failures, 0);

  // 1. Record successful probe
  manager.recordProbeResult({
    ok: true,
    transportId: "proxy-a",
    latencyMs: 50,
    stage: "tunnel_established",
    proxyReachable: true,
    targetReachable: true,
  });

  const rt1 = manager.getRuntime("proxy-a");
  assert.ok(rt1.score > 0.5);
  assert.equal(rt1.circuit, "closed");

  // 2. Record 3 consecutive infrastructure failures -> trips circuit breaker to OPEN
  for (let i = 0; i < 3; i++) {
    manager.recordProbeResult({
      ok: false,
      transportId: "proxy-a",
      latencyMs: 1000,
      stage: "connect_proxy",
      proxyReachable: false,
      targetReachable: false,
      failureReason: "PROXY_UNREACHABLE",
    });
  }

  const rtOpen = manager.getRuntime("proxy-a");
  assert.equal(rtOpen.circuit, "open");
  assert.equal(rtOpen.failures, 3);
  assert.ok(rtOpen.cooldownUntil && rtOpen.cooldownUntil > Date.now());

  // 3. Destination-awareness: if proxy was reachable and failure was solely destination-side,
  // do NOT penalize proxy infrastructure.
  manager.addTransport({
    id: "proxy-b",
    name: "Proxy B",
    type: "http_proxy",
    host: "10.0.0.1",
    port: 8080,
    tags: ["work"],
    trusted: true,
    enabled: true,
  });

  manager.recordProbeResult({
    ok: false,
    transportId: "proxy-b",
    latencyMs: 60,
    stage: "tunnel_established",
    proxyReachable: true, // Proxy IS healthy
    targetReachable: false, // Target destination failed
    failureReason: "TARGET_UNREACHABLE_VIA_PROXY",
  });

  const rtB = manager.getRuntime("proxy-b");
  assert.equal(rtB.circuit, "closed"); // Circuit breaker NOT tripped
  assert.equal(rtB.failures, 0);
});

test("P2 Mock Diagnostic Transport: Test-only semantics", async () => {
  const mockTransport = {
    id: "mock-loopback",
    name: "Mock Diagnostic Transport",
    type: "plugin",
    tags: ["diagnostic", "testing"],
    trusted: false,
    enabled: true,
    diagnosticOnly: true,
  };

  const target = parseTarget("https://example.com/");

  // Disallowed in production mode
  const prodRes = await probeTransport(mockTransport, target, undefined, {
    allowDiagnosticTransports: false,
  });
  assert.equal(prodRes.ok, false);
  assert.match(prodRes.error, /diagnostic-only and is disabled for production/i);

  // Allowed when explicitly enabled for testing
  const testRes = await probeTransport(mockTransport, target, undefined, {
    allowDiagnosticTransports: true,
  });
  assert.equal(testRes.ok, true);
  assert.equal(testRes.latencyMs, 45);
});

test("P2 Persistence: Never stores plaintext credentials on disk", async () => {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "netaccess-test-"));
  const storagePath = path.join(tmpDir, "transports.json");

  try {
    const manager = new TransportManager({ storagePath });

    manager.addTransport({
      id: "secure-proxy",
      name: "Secure Corporate Proxy",
      type: "https_connect",
      host: "proxy.corp.example.com",
      port: 8443,
      tags: ["work", "trusted"],
      trusted: true,
      enabled: true,
      username: "employee_aj",
      secretRef: "keychain://netaccess/secure-proxy-pass",
      notes: "Production proxy",
    });

    await manager.saveToDisk();

    // Verify file exists
    const fileContent = await fs.readFile(storagePath, "utf8");
    const parsed = JSON.parse(fileContent);

    assert.equal(parsed.version, 1);
    assert.equal(parsed.transports.length, 1);
    assert.equal(parsed.transports[0].id, "secure-proxy");
    assert.equal(parsed.transports[0].username, "employee_aj");
    assert.equal(parsed.transports[0].secretRef, "keychain://netaccess/secure-proxy-pass");

    // Strictly verify: NO password or token keys present in saved JSON
    assert.equal(parsed.transports[0].password, undefined);
    assert.equal(parsed.transports[0].token, undefined);

    // Test loadFromDisk restores metadata correctly
    const newManager = new TransportManager({ storagePath });
    await newManager.loadFromDisk();

    const loaded = newManager.getTransport("secure-proxy");
    assert.ok(loaded);
    assert.equal(loaded.name, "Secure Corporate Proxy");
    assert.equal(loaded.secretRef, "keychain://netaccess/secure-proxy-pass");
  } finally {
    await fs.rm(tmpDir, { recursive: true, force: true });
  }
});

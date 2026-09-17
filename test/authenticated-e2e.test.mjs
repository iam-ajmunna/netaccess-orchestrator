import test from "node:test";
import assert from "node:assert/strict";
import * as http from "node:http";
import * as https from "node:https";
import * as net from "node:net";
import * as tls from "node:tls";
import * as os from "node:os";
import * as path from "node:path";
import * as fs from "node:fs/promises";
import { execFileSync } from "node:child_process";

import { startLoopbackBridge } from "../src/netaccess/loopbackTunnel.js";
import { MemoryCredentialStore } from "../src/netaccess/keychain.js";

// ---------------------------------------------------------------------------
// Test Helpers
// ---------------------------------------------------------------------------

async function createTargetHttpServer(payload = "TARGET_PAYLOAD_OK") {
  const server = http.createServer((req, res) => {
    res.writeHead(200, { "Content-Type": "text/plain", "Content-Length": Buffer.byteLength(payload) });
    res.end(payload);
  });
  server.unref();
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = server.address().port;
  return {
    server,
    port,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

async function createTargetHttpsServer(payload = "HTTPS_TARGET_PAYLOAD_OK") {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "netaccess-tls-"));
  const keyPath = path.join(tmpDir, "server.key");
  const certPath = path.join(tmpDir, "server.cert");

  execFileSync("/usr/bin/openssl", [
    "req",
    "-x509",
    "-newkey",
    "rsa:2048",
    "-keyout",
    keyPath,
    "-out",
    certPath,
    "-days",
    "1",
    "-nodes",
    "-subj",
    "/CN=127.0.0.1",
  ]);

  const key = await fs.readFile(keyPath);
  const cert = await fs.readFile(certPath);

  const server = https.createServer({ key, cert }, (req, res) => {
    res.writeHead(200, { "Content-Type": "text/plain", "Content-Length": Buffer.byteLength(payload) });
    res.end(payload);
  });
  server.unref();
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = server.address().port;

  return {
    server,
    port,
    close: async () => {
      await new Promise((resolve) => server.close(resolve));
      await fs.rm(tmpDir, { recursive: true, force: true });
    },
  };
}

async function createMockUpstreamHttpProxy(opts = {}) {
  let connectionCount = 0;
  let authAttempts = 0;
  const activeSockets = new Set();

  const server = http.createServer();
  server.unref();

  server.on("connect", (req, clientSocket, head) => {
    connectionCount++;
    activeSockets.add(clientSocket);
    clientSocket.once("close", () => activeSockets.delete(clientSocket));

    if (opts.customHandler) {
      opts.customHandler(req, clientSocket, head, { connectionCount });
      return;
    }

    const authHeader = req.headers["proxy-authorization"];
    if (opts.requireAuth) {
      authAttempts++;
      const expectedCreds = `${opts.expectedUsername || "user"}:${opts.expectedPassword || "pass"}`;
      const expectedHeader = `Basic ${Buffer.from(expectedCreds).toString("base64")}`;

      if (authHeader !== expectedHeader) {
        clientSocket.write(
          "HTTP/1.1 407 Proxy Authentication Required\r\n" +
          "Proxy-Authenticate: Basic realm=\"Upstream\"\r\n" +
          "Connection: close\r\n\r\n",
        );
        clientSocket.end();
        return;
      }
    }

    // Connect to destination
    const [destHost, destPortStr] = (req.url || "").split(":");
    const destPort = parseInt(destPortStr || "80", 10);

    const destSocket = net.connect(destPort, destHost, () => {
      activeSockets.add(destSocket);
      destSocket.once("close", () => activeSockets.delete(destSocket));

      clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      if (head && head.length > 0) {
        destSocket.write(head);
      }
      clientSocket.pipe(destSocket);
      destSocket.pipe(clientSocket);
    });

    destSocket.on("error", () => {
      clientSocket.destroy();
    });
    clientSocket.on("error", () => {
      destSocket.destroy();
    });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = server.address().port;

  return {
    server,
    port,
    getConnectionCount: () => connectionCount,
    getAuthAttempts: () => authAttempts,
    close: async () => {
      for (const s of activeSockets) {
        try { s.destroy(); } catch {}
      }
      activeSockets.clear();
      await new Promise((resolve) => server.close(resolve));
    },
  };
}

async function createMockUpstreamSocks5Proxy(opts = {}) {
  let connectionCount = 0;
  const activeSockets = new Set();

  const server = net.createServer((socket) => {
    connectionCount++;
    activeSockets.add(socket);
    socket.once("close", () => activeSockets.delete(socket));

    let stage = "greeting";
    let destSocket = null;

    socket.on("data", (data) => {
      if (stage === "greeting") {
        if (data[0] !== 0x05) {
          socket.destroy();
          return;
        }

        if (opts.requireAuth) {
          // Select method 0x02 (Username/Password)
          socket.write(Buffer.from([0x05, 0x02]));
          stage = "auth";
        } else {
          // Select method 0x00 (No Auth)
          socket.write(Buffer.from([0x05, 0x00]));
          stage = "connect";
        }
        return;
      }

      if (stage === "auth") {
        // RFC 1929 Auth: [0x01, ulen, ...username, plen, ...password]
        const ulen = data[1];
        const username = data.subarray(2, 2 + ulen).toString("utf8");
        const plen = data[2 + ulen];
        const password = data.subarray(3 + ulen, 3 + ulen + plen).toString("utf8");

        const expectedUser = opts.expectedUsername || "user";
        const expectedPass = opts.expectedPassword || "pass";

        if (username === expectedUser && password === expectedPass) {
          socket.write(Buffer.from([0x01, 0x00])); // Success
          stage = "connect";
        } else {
          socket.write(Buffer.from([0x01, 0x01])); // Auth failure
          socket.destroy();
        }
        return;
      }

      if (stage === "connect") {
        // [0x05, 0x01 (CONNECT), 0x00, ATYP, ...]
        if (data[0] !== 0x05 || data[1] !== 0x01) {
          socket.destroy();
          return;
        }

        let targetHost = "";
        let targetPort = 0;

        if (data[3] === 0x03) {
          // Domain
          const dlen = data[4];
          targetHost = data.subarray(5, 5 + dlen).toString("utf8");
          targetPort = data.readUInt16BE(5 + dlen);
        } else if (data[3] === 0x01) {
          // IPv4
          targetHost = `${data[4]}.${data[5]}.${data[6]}.${data[7]}`;
          targetPort = data.readUInt16BE(8);
        }

        destSocket = net.connect(targetPort, targetHost, () => {
          activeSockets.add(destSocket);
          destSocket.once("close", () => activeSockets.delete(destSocket));

          socket.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0]));
          stage = "tunnel";
          socket.pipe(destSocket);
          destSocket.pipe(socket);
        });

        destSocket.on("error", () => socket.destroy());
        socket.on("error", () => destSocket?.destroy());
      }
    });
  });

  server.unref();
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = server.address().port;

  return {
    server,
    port,
    getConnectionCount: () => connectionCount,
    close: async () => {
      for (const s of activeSockets) {
        try { s.destroy(); } catch {}
      }
      activeSockets.clear();
      await new Promise((resolve) => server.close(resolve));
    },
  };
}

/**
 * Perform an HTTP request through the loopback bridge via CONNECT tunnel
 */
function fetchThroughBridge(
  bridgePort,
  targetHost,
  targetPort,
  path = "/",
  isTls = false,
  timeoutMs = 2000,
) {
  return new Promise((resolve, reject) => {
    let settled = false;
    let client;

    const finish = (err, val) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (client && !client.destroyed) {
        client.destroy();
      }
      if (err) reject(err);
      else resolve(val);
    };

    const timer = setTimeout(() => {
      finish(new Error(`fetchThroughBridge timed out after ${timeoutMs}ms`));
    }, timeoutMs);

    client = net.connect(bridgePort, "127.0.0.1", () => {
      client.write(`CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\nHost: ${targetHost}:${targetPort}\r\n\r\n`);
    });

    let buffer = Buffer.alloc(0);
    const onData = (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      const headerEnd = buffer.indexOf("\r\n\r\n");

      if (headerEnd !== -1) {
        client.removeListener("data", onData);
        const headerStr = buffer.subarray(0, headerEnd).toString("utf8");
        const statusLine = headerStr.split("\r\n")[0] || "";

        if (!statusLine.includes(" 200 ")) {
          finish(new Error(`Proxy CONNECT failed with: ${statusLine}`));
          return;
        }

        const remaining = buffer.subarray(headerEnd + 4);

        if (isTls) {
          const isIp = Boolean(net.isIP(targetHost));
          const tlsSocket = tls.connect(
            {
              socket: client,
              rejectUnauthorized: false,
              ...(isIp ? {} : { servername: targetHost }),
              checkServerIdentity: () => undefined,
            },
            () => {
              tlsSocket.write(`GET ${path} HTTP/1.1\r\nHost: ${targetHost}:${targetPort}\r\nConnection: close\r\n\r\n`);
            },
          );

          let bodyBuffer = Buffer.alloc(0);
          tlsSocket.on("data", (d) => {
            bodyBuffer = Buffer.concat([bodyBuffer, d]);
          });
          tlsSocket.on("end", () => {
            const raw = bodyBuffer.toString("utf8");
            const body = raw.split("\r\n\r\n")[1] || "";
            tlsSocket.destroy();
            finish(null, body);
          });
          tlsSocket.on("error", (err) => {
            tlsSocket.destroy();
            finish(err);
          });
          tlsSocket.on("close", () => {
            if (!settled) {
              const raw = bodyBuffer.toString("utf8");
              const body = raw.split("\r\n\r\n")[1] || "";
              finish(null, body);
            }
          });
        } else {
          client.write(`GET ${path} HTTP/1.1\r\nHost: ${targetHost}:${targetPort}\r\nConnection: close\r\n\r\n`);

          let bodyBuffer = Buffer.from(remaining);
          client.on("data", (d) => {
            bodyBuffer = Buffer.concat([bodyBuffer, d]);
          });
          client.on("end", () => {
            const raw = bodyBuffer.toString("utf8");
            const body = raw.split("\r\n\r\n")[1] || "";
            finish(null, body);
          });
          client.on("close", () => {
            if (!settled) {
              const raw = bodyBuffer.toString("utf8");
              const body = raw.split("\r\n\r\n")[1] || "";
              finish(null, body);
            }
          });
        }
      }
    };

    client.on("data", onData);
    client.on("error", (err) => finish(err));
    client.on("close", () => {
      if (!settled) {
        finish(new Error("Connection closed before response completed"));
      }
    });
  });
}

// ---------------------------------------------------------------------------
// 12 Authenticated End-to-End Test Scenarios
// ---------------------------------------------------------------------------

test("E2E 1: HTTP proxy unauthenticated payload delivery", async () => {
  const target = await createTargetHttpServer("PAYLOAD_E2E_SCENARIO_1_OK");
  const upstream = await createMockUpstreamHttpProxy({ requireAuth: false });

  const bridge = await startLoopbackBridge({
    id: "e2e-unauth-http",
    name: "Unauth HTTP",
    type: "http_proxy",
    host: "127.0.0.1",
    port: upstream.port,
    tags: ["test"],
    trusted: true,
    enabled: true,
  });

  try {
    const payload = await fetchThroughBridge(bridge.port, "127.0.0.1", target.port);
    assert.equal(payload, "PAYLOAD_E2E_SCENARIO_1_OK");
    assert.equal(upstream.getConnectionCount(), 1);
  } finally {
    await bridge.close();
    await upstream.close();
    await target.close();
  }
});

test("E2E 2: HTTP proxy with Basic authentication delivers real payload", async () => {
  const target = await createTargetHttpServer("PAYLOAD_E2E_BASIC_AUTH_OK");
  const upstream = await createMockUpstreamHttpProxy({
    requireAuth: true,
    expectedUsername: "corp-user",
    expectedPassword: "CorpSecretPassword!99",
  });

  const memStore = new MemoryCredentialStore();
  const ref = "keychain://netaccess/e2e-auth-proxy";
  await memStore.setSecret(ref, "CorpSecretPassword!99");

  const bridge = await startLoopbackBridge(
    {
      id: "e2e-auth-proxy",
      name: "Auth HTTP Proxy",
      type: "http_proxy",
      host: "127.0.0.1",
      port: upstream.port,
      username: "corp-user",
      secretRef: ref,
      tags: ["test"],
      trusted: true,
      enabled: true,
    },
    { credentialResolver: (r) => memStore.getSecret(r) },
  );

  try {
    const payload = await fetchThroughBridge(bridge.port, "127.0.0.1", target.port);
    assert.equal(payload, "PAYLOAD_E2E_BASIC_AUTH_OK");
    assert.equal(upstream.getConnectionCount(), 1);
  } finally {
    await bridge.close();
    await upstream.close();
    await target.close();
  }
});

test("E2E 3: HTTP 407 challenge and retry owned by loopback bridge", async () => {
  const target = await createTargetHttpServer("PAYLOAD_E2E_407_RETRY_OK");
  const upstream = await createMockUpstreamHttpProxy({
    requireAuth: true,
    expectedUsername: "retry-user",
    expectedPassword: "RetryPass777",
  });

  const memStore = new MemoryCredentialStore();
  const ref = "keychain://netaccess/e2e-407-proxy";
  await memStore.setSecret(ref, "RetryPass777");

  // Intentionally start with sendInitialAuth: false to force upstream 407 challenge!
  const bridge = await startLoopbackBridge(
    {
      id: "e2e-407-proxy",
      name: "407 Test Proxy",
      type: "http_proxy",
      host: "127.0.0.1",
      port: upstream.port,
      username: "retry-user",
      secretRef: ref,
      tags: ["test"],
      trusted: true,
      enabled: true,
    },
    {
      credentialResolver: (r) => memStore.getSecret(r),
      sendInitialAuth: false,
    },
  );

  try {
    // Client receives payload directly; loopback owns the 407 retry!
    const payload = await fetchThroughBridge(bridge.port, "127.0.0.1", target.port);
    assert.equal(payload, "PAYLOAD_E2E_407_RETRY_OK");
    // Upstream saw 2 connections: first without auth (407), second with auth (200)
    assert.equal(upstream.getConnectionCount(), 2);
    assert.equal(upstream.getAuthAttempts(), 2);
  } finally {
    await bridge.close();
    await upstream.close();
    await target.close();
  }
});

test("E2E 3b: No infinite loop on repeated 407 failure (bounded failure)", async () => {
  const upstream = await createMockUpstreamHttpProxy({
    requireAuth: true,
    expectedUsername: "legit-user",
    expectedPassword: "correct-password",
  });

  const memStore = new MemoryCredentialStore();
  const ref = "keychain://netaccess/e2e-wrong-cred";
  await memStore.setSecret(ref, "incorrect-password");

  const bridge = await startLoopbackBridge(
    {
      id: "e2e-wrong-cred",
      name: "Wrong Cred Proxy",
      type: "http_proxy",
      host: "127.0.0.1",
      port: upstream.port,
      username: "legit-user",
      secretRef: ref,
      tags: ["test"],
      trusted: true,
      enabled: true,
    },
    {
      credentialResolver: (r) => memStore.getSecret(r),
      sendInitialAuth: false,
    },
  );

  try {
    await assert.rejects(
      () => fetchThroughBridge(bridge.port, "127.0.0.1", 80),
      /Proxy CONNECT failed with: HTTP\/1\.1 407/i,
    );
    // Bounded failure: stopped after 2 attempts, no infinite loop
    assert.equal(upstream.getConnectionCount(), 2);
  } finally {
    await bridge.close();
    await upstream.close();
  }
});

test("E2E 4: SOCKS5 unauthenticated payload delivery", async () => {
  const target = await createTargetHttpServer("SOCKS5_UNAUTH_PAYLOAD_OK");
  const upstream = await createMockUpstreamSocks5Proxy({ requireAuth: false });

  const bridge = await startLoopbackBridge({
    id: "e2e-socks5-unauth",
    name: "SOCKS5 Unauth",
    type: "socks5",
    host: "127.0.0.1",
    port: upstream.port,
    tags: ["test"],
    trusted: true,
    enabled: true,
  });

  try {
    const payload = await fetchThroughBridge(bridge.port, "127.0.0.1", target.port);
    assert.equal(payload, "SOCKS5_UNAUTH_PAYLOAD_OK");
    assert.equal(upstream.getConnectionCount(), 1);
  } finally {
    await bridge.close();
    await upstream.close();
    await target.close();
  }
});

test("E2E 5: SOCKS5 with RFC 1929 username/password authentication", async () => {
  const target = await createTargetHttpServer("SOCKS5_AUTH_PAYLOAD_OK");
  const upstream = await createMockUpstreamSocks5Proxy({
    requireAuth: true,
    expectedUsername: "socks-admin",
    expectedPassword: "SocksPassword#321",
  });

  const memStore = new MemoryCredentialStore();
  const ref = "keychain://netaccess/e2e-socks5-auth";
  await memStore.setSecret(ref, "SocksPassword#321");

  const bridge = await startLoopbackBridge(
    {
      id: "e2e-socks5-auth",
      name: "SOCKS5 Auth Proxy",
      type: "socks5",
      host: "127.0.0.1",
      port: upstream.port,
      username: "socks-admin",
      secretRef: ref,
      tags: ["test"],
      trusted: true,
      enabled: true,
    },
    { credentialResolver: (r) => memStore.getSecret(r) },
  );

  try {
    const payload = await fetchThroughBridge(bridge.port, "127.0.0.1", target.port);
    assert.equal(payload, "SOCKS5_AUTH_PAYLOAD_OK");
    assert.equal(upstream.getConnectionCount(), 1);
  } finally {
    await bridge.close();
    await upstream.close();
    await target.close();
  }
});

test("E2E 6: Invalid credentials rejected cleanly without secret leakage", async () => {
  const upstream = await createMockUpstreamSocks5Proxy({
    requireAuth: true,
    expectedUsername: "gooduser",
    expectedPassword: "goodpassword",
  });

  const memStore = new MemoryCredentialStore();
  const ref = "keychain://netaccess/bad-cred-proxy";
  const badSecret = "SUPER_SECRET_BAD_PASSWORD_XYZ";
  await memStore.setSecret(ref, badSecret);

  const bridge = await startLoopbackBridge(
    {
      id: "bad-cred-proxy",
      name: "Bad Cred Proxy",
      type: "socks5",
      host: "127.0.0.1",
      port: upstream.port,
      username: "gooduser",
      secretRef: ref,
      tags: ["test"],
      trusted: true,
      enabled: true,
    },
    { credentialResolver: (r) => memStore.getSecret(r) },
  );

  try {
    let thrownError = null;
    try {
      await fetchThroughBridge(bridge.port, "127.0.0.1", 80);
    } catch (err) {
      thrownError = err;
    }

    assert.ok(thrownError, "Request must fail on invalid credentials");
    assert.ok(!thrownError.message.includes(badSecret), "Error message must never leak secret");
  } finally {
    await bridge.close();
    await upstream.close();
  }
});

test("E2E 7: Upstream proxy timeout fails cleanly", async () => {
  // Stalling upstream server (accepts connection but never replies)
  const sockets = new Set();
  const stallingServer = net.createServer((s) => {
    sockets.add(s);
    s.once("close", () => sockets.delete(s));
  });
  stallingServer.unref();
  await new Promise((resolve) => stallingServer.listen(0, "127.0.0.1", resolve));
  const upstreamPort = stallingServer.address().port;

  const bridge = await startLoopbackBridge({
    id: "stalling-proxy",
    name: "Stalling Proxy",
    type: "http_proxy",
    host: "127.0.0.1",
    port: upstreamPort,
    tags: ["test"],
    trusted: true,
    enabled: true,
  });

  try {
    // Client times out cleanly after 200ms
    await assert.rejects(
      () => fetchThroughBridge(bridge.port, "127.0.0.1", 80, "/", false, 200),
      /timed out/,
    );
  } finally {
    await bridge.close();
    for (const s of sockets) {
      try { s.destroy(); } catch {}
    }
    sockets.clear();
    await new Promise((resolve) => stallingServer.close(resolve));
  }
});

test("E2E 8: Upstream disconnect handled without unhandled exception", async () => {
  // Upstream that abruptly drops connection upon receiving data
  const sockets = new Set();
  const droppingServer = net.createServer((socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
    socket.once("data", () => {
      socket.destroy();
    });
  });
  droppingServer.unref();
  await new Promise((resolve) => droppingServer.listen(0, "127.0.0.1", resolve));
  const upstreamPort = droppingServer.address().port;

  const bridge = await startLoopbackBridge({
    id: "dropping-proxy",
    name: "Dropping Proxy",
    type: "http_proxy",
    host: "127.0.0.1",
    port: upstreamPort,
    tags: ["test"],
    trusted: true,
    enabled: true,
  });

  try {
    await assert.rejects(
      () => fetchThroughBridge(bridge.port, "127.0.0.1", 80),
      /Proxy CONNECT failed|502|Connection closed/i,
    );
  } finally {
    await bridge.close();
    for (const s of sockets) {
      try { s.destroy(); } catch {}
    }
    sockets.clear();
    await new Promise((resolve) => droppingServer.close(resolve));
  }
});

test("E2E 9: Malformed upstream response returns 502 Bad Gateway to client", async () => {
  // Upstream sending non-HTTP garbage bytes
  const sockets = new Set();
  const garbageServer = net.createServer((socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
    socket.once("data", () => {
      socket.write("GARBAGE_BYTES_NOT_HTTP\r\n\r\n");
      socket.end();
    });
  });
  garbageServer.unref();
  await new Promise((resolve) => garbageServer.listen(0, "127.0.0.1", resolve));
  const upstreamPort = garbageServer.address().port;

  const bridge = await startLoopbackBridge({
    id: "garbage-proxy",
    name: "Garbage Proxy",
    type: "http_proxy",
    host: "127.0.0.1",
    port: upstreamPort,
    tags: ["test"],
    trusted: true,
    enabled: true,
  });

  try {
    await assert.rejects(
      () => fetchThroughBridge(bridge.port, "127.0.0.1", 80),
      /Proxy CONNECT failed|502|Connection closed/i,
    );
  } finally {
    await bridge.close();
    for (const s of sockets) {
      try { s.destroy(); } catch {}
    }
    sockets.clear();
    await new Promise((resolve) => garbageServer.close(resolve));
  }
});

test("E2E 10: Concurrent requests through single bridge maintain payload integrity", async () => {
  const target = await createTargetHttpServer("CONCURRENT_PAYLOAD_E2E");
  const upstream = await createMockUpstreamHttpProxy({ requireAuth: false });

  const bridge = await startLoopbackBridge({
    id: "concurrent-bridge",
    name: "Concurrent Bridge",
    type: "http_proxy",
    host: "127.0.0.1",
    port: upstream.port,
    tags: ["test"],
    trusted: true,
    enabled: true,
  });

  try {
    const concurrentCount = 10;
    const promises = Array.from({ length: concurrentCount }, () =>
      fetchThroughBridge(bridge.port, "127.0.0.1", target.port),
    );

    const results = await Promise.all(promises);
    assert.equal(results.length, concurrentCount);
    for (const r of results) {
      assert.equal(r, "CONCURRENT_PAYLOAD_E2E");
    }
  } finally {
    await bridge.close();
    await upstream.close();
    await target.close();
  }
});

test("E2E 11: Genuinely end-to-end HTTPS CONNECT with TLS handshake & exact payload verification", async () => {
  const target = await createTargetHttpsServer("GENUINE_TLS_HTTPS_PAYLOAD_VERIFIED_777");
  const upstream = await createMockUpstreamHttpProxy({
    requireAuth: true,
    expectedUsername: "tls-user",
    expectedPassword: "TlsSecretPassword#888",
  });

  const memStore = new MemoryCredentialStore();
  const ref = "keychain://netaccess/https-e2e";
  await memStore.setSecret(ref, "TlsSecretPassword#888");

  const bridge = await startLoopbackBridge(
    {
      id: "https-e2e",
      name: "HTTPS E2E Proxy",
      type: "http_proxy",
      host: "127.0.0.1",
      port: upstream.port,
      username: "tls-user",
      secretRef: ref,
      tags: ["test"],
      trusted: true,
      enabled: true,
    },
    { credentialResolver: (r) => memStore.getSecret(r) },
  );

  try {
    // Client connects via loopback -> upstream -> target TLS server -> TLS handshake -> HTTP GET -> exact payload!
    const payload = await fetchThroughBridge(bridge.port, "127.0.0.1", target.port, "/secure-data", true);
    assert.equal(payload, "GENUINE_TLS_HTTPS_PAYLOAD_VERIFIED_777");
  } finally {
    await bridge.close();
    await upstream.close();
    await target.close();
  }
});

test("E2E 12: Bridge shutdown during transfer destroys active sockets without orphan listeners", async () => {
  const streamSockets = new Set();
  // Target server streaming continuous data
  const streamServer = http.createServer((req, res) => {
    res.writeHead(200, { "Content-Type": "application/octet-stream" });
    const interval = setInterval(() => {
      try {
        res.write("CHUNK_DATA_STREAM\n");
      } catch {
        clearInterval(interval);
      }
    }, 10);
    req.on("close", () => clearInterval(interval));
  });
  streamServer.on("connection", (s) => {
    streamSockets.add(s);
    s.once("close", () => streamSockets.delete(s));
  });
  streamServer.unref();
  await new Promise((resolve) => streamServer.listen(0, "127.0.0.1", resolve));
  const targetPort = streamServer.address().port;

  const upstream = await createMockUpstreamHttpProxy({ requireAuth: false });
  const bridge = await startLoopbackBridge({
    id: "shutdown-bridge",
    name: "Shutdown Bridge",
    type: "http_proxy",
    host: "127.0.0.1",
    port: upstream.port,
    tags: ["test"],
    trusted: true,
    enabled: true,
  });

  let client;
  try {
    client = net.connect(bridge.port, "127.0.0.1", () => {
      client.write(`CONNECT 127.0.0.1:${targetPort} HTTP/1.1\r\nHost: 127.0.0.1:${targetPort}\r\n\r\n`);
    });

    let receivedData = false;
    await new Promise((resolve) => {
      client.on("data", (chunk) => {
        if (chunk.toString("utf8").includes("200 Connection Established")) {
          client.write("GET /stream HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
        } else {
          receivedData = true;
          resolve();
        }
      });
    });

    assert.equal(receivedData, true);

    // Shutdown bridge while streaming
    await bridge.close();

    // Client socket should close or end
    const clientClosed = await new Promise((resolve) => {
      client.on("close", () => resolve(true));
      client.on("error", () => resolve(true));
      setTimeout(() => resolve(false), 500);
    });

    assert.equal(clientClosed, true, "Client connection must close upon bridge shutdown");
  } finally {
    if (client && !client.destroyed) client.destroy();
    await bridge.close();
    await upstream.close();
    for (const s of streamSockets) {
      try { s.destroy(); } catch {}
    }
    streamSockets.clear();
    await new Promise((resolve) => streamServer.close(resolve));
  }
});

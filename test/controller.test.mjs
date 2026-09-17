/**
 * Unit tests for NetAccess ApplicationController (P0)
 * Verifies state machine transitions, event emissions, error mapping,
 * transport selection, reachability vs authorization, and cancellation.
 */

import assert from "node:assert/strict";
import test from "node:test";
import { ApplicationController } from "../src/netaccess/controller.ts";
import { makeFinding } from "../src/netaccess/engine.ts";

test("ApplicationController: Target validation and normalization", async () => {
  const controller = new ApplicationController();

  // Test bare host
  const res1 = await controller.openTarget("example.com", { skipBrowserLaunch: true });
  assert.equal(res1.target.host, "example.com");
  assert.equal(res1.target.scheme, "https");
  assert.equal(res1.target.port, 443);
  assert.equal(res1.target.href, "https://example.com/");

  await controller.closeSession();

  // Test custom port and query
  const res2 = await controller.openTarget("http://example.com:80/", {
    skipBrowserLaunch: true,
  });
  assert.equal(res2.target.host, "example.com");
  assert.equal(res2.target.scheme, "http");
  assert.equal(res2.target.port, 80);
  assert.equal(res2.target.pathname, "/");

  await controller.closeSession();

  // Test invalid target raises structured INVALID_TARGET error
  await assert.rejects(
    async () => {
      await controller.openTarget("   ", { skipBrowserLaunch: true });
    },
    (err) => {
      assert.equal(err.code, "INVALID_TARGET");
      assert.match(err.message, /check the destination address/i);
      return true;
    }
  );
});

test("ApplicationController: Direct path success workflow & event emissions", async () => {
  const events = [];
  const controller = new ApplicationController();

  controller.on("stateChanged", (state, msg) => events.push({ event: "stateChanged", state, msg }));
  controller.on("diagnosisUpdated", (diag) => events.push({ event: "diagnosisUpdated", diag }));
  controller.on("transportChanged", (path) => events.push({ event: "transportChanged", path }));
  controller.on("verificationUpdated", (ver) => events.push({ event: "verificationUpdated", ver }));
  controller.on("completed", (res) => events.push({ event: "completed", res }));

  const result = await controller.openTarget("example.com", { skipBrowserLaunch: true });

  assert.equal(result.path.type, "direct");
  assert.equal(result.path.transportId, "direct");
  assert.equal(result.state, "CONNECTED");
  assert.equal(result.diagnosis.classification.class, "healthy");

  // Verify event sequence
  const stateNames = events.filter((e) => e.event === "stateChanged").map((e) => e.state);
  assert.deepEqual(stateNames, ["VALIDATING", "DIAGNOSING", "CONNECTED"]);

  // Verify recent targets updated
  const recent = controller.getRecentTargets();
  assert.equal(recent.length, 1);
  assert.equal(recent[0].host, "example.com");
  assert.equal(recent[0].success, true);
  assert.equal(recent[0].lastPathType, "direct");
});

test("ApplicationController: Direct failure with working authorized alternate proxy", async () => {
  // Mock diagnostician: direct TCP connection timeout
  const mockDiagnostician = async (target) => [
    makeFinding("dns", true, "healthy", `Resolved ${target.host} to 1.2.3.4`),
    makeFinding("tcp", false, "tcp_timeout", "TCP SYN timeout: 3000ms elapsed without ACK", {
      weight: 1.5,
    }),
  ];

  // Mock transport prober: proxy-home succeeds
  const mockProber = async (transport, _target) => {
    if (transport.id === "proxy-home") {
      return { ok: true, latencyMs: 72 };
    }
    return { ok: false, latencyMs: 500, error: "Connection refused" };
  };

  const controller = new ApplicationController({
    diagnostician: mockDiagnostician,
    transportProber: mockProber,
    initialTransports: [
      {
        id: "direct",
        name: "Direct Connection",
        type: "direct",
        tags: ["direct"],
        trusted: true,
        enabled: true,
      },
      {
        id: "proxy-home",
        name: "Home SOCKS5 Proxy",
        type: "socks5",
        tags: ["home", "trusted"],
        trusted: true,
        enabled: true,
      },
    ],
  });

  const stateChanges = [];
  controller.on("stateChanged", (state) => stateChanges.push(state));

  const result = await controller.openTarget("server3.ftpbd.net", { skipBrowserLaunch: true });

  assert.equal(result.path.type, "alternate");
  assert.equal(result.path.transportId, "proxy-home");
  assert.equal(result.path.transportName, "Home SOCKS5 Proxy");
  assert.equal(result.path.latencyMs, 72);

  // Verify state transitions passed through FINDING_PATH and TESTING_PATHS
  assert.ok(stateChanges.includes("FINDING_PATH"));
  assert.ok(stateChanges.includes("TESTING_PATHS"));
  assert.ok(stateChanges.includes("CONNECTED"));
});

test("ApplicationController: All paths fail surfaces structured NO_WORKING_PATH", async () => {
  const mockDiagnostician = async () => [
    makeFinding("dns", false, "dns_nxdomain", "Name not found (NXDOMAIN)", { weight: 2.0 }),
  ];

  const mockProber = async () => ({ ok: false, latencyMs: 300, error: "Remote host unreachable" });

  const controller = new ApplicationController({
    diagnostician: mockDiagnostician,
    transportProber: mockProber,
    initialTransports: [
      { id: "direct", name: "Direct", type: "direct", tags: ["direct"], trusted: true, enabled: true },
      { id: "proxy-fail", name: "Failing Proxy", type: "http_proxy", tags: ["proxy"], trusted: true, enabled: true },
    ],
  });

  let capturedError = null;
  controller.on("failed", (err) => {
    capturedError = err;
  });

  await assert.rejects(
    async () => {
      await controller.openTarget("nonexistent.local.test", { skipBrowserLaunch: true });
    },
    (err) => {
      assert.equal(err.code, "NO_WORKING_PATH");
      assert.match(err.message, /couldn't establish a connection/i);
      // Ensure we NEVER use internal jargon in the user-facing message
      assert.doesNotMatch(err.message, /transport selection failed/i);
      return true;
    }
  );

  assert.ok(capturedError);
  assert.equal(controller.getState(), "FAILED");
});

test("ApplicationController: Reachability vs Authorization (HTTP 403 / 451)", async () => {
  const mockDiagnostician = async (target) => [
    makeFinding("dns", true, "healthy", `Resolved ${target.host}`),
    makeFinding("tcp", true, "healthy", "TCP connect ok"),
    makeFinding("tls", true, "healthy", "TLS handshake ok"),
    makeFinding("http", false, "destination_restriction", "HTTP 403 Forbidden: Access Denied by destination", {
      weight: 1.8,
    }),
  ];

  const mockProber = async () => ({ ok: false, latencyMs: 100 });

  const controller = new ApplicationController({
    diagnostician: mockDiagnostician,
    transportProber: mockProber,
  });

  await assert.rejects(
    async () => {
      await controller.openTarget("restricted-internal.org", { skipBrowserLaunch: true });
    },
    (err) => {
      assert.equal(err.code, "DESTINATION_REJECTED");
      assert.match(err.message, /service rejected the request/i);
      assert.match(err.suggestedAction, /authorization restriction, not a network failure/i);
      return true;
    }
  );
});

test("ApplicationController: Cancellation aborts cleanly", async () => {
  let resolveProbe;
  const probePromise = new Promise((resolve) => {
    resolveProbe = resolve;
  });

  const hangingDiagnostician = async (_target, signal) => {
    return new Promise((resolve, reject) => {
      signal?.addEventListener("abort", () => reject(new Error("aborted")));
      probePromise.then(resolve);
    });
  };

  const controller = new ApplicationController({
    diagnostician: hangingDiagnostician,
  });

  // Launch target asynchronously
  const openPromise = controller.openTarget("slow-target.org", { skipBrowserLaunch: true });

  // Cancel immediately
  setTimeout(() => {
    controller.cancelSession();
  }, 10);

  await assert.rejects(openPromise, /cancelled by user|aborted/i);
  assert.equal(controller.getState(), "IDLE");

  // Clean up hanging probe
  resolveProbe([]);
});

test("ApplicationController: Transport and EWMA circuit breaker tracking", () => {
  const controller = new ApplicationController();

  // Add user-configured transport
  controller.addTransport({
    id: "my-proxy",
    name: "My Custom Proxy",
    type: "http_proxy",
    host: "10.0.0.1",
    port: 8080,
    tags: ["custom"],
    trusted: true,
    enabled: true,
  });

  const transports = controller.getTransports();
  assert.equal(transports.length, 2); // direct + my-proxy

  const runtimes = controller.getTransportRuntimes();
  assert.ok(runtimes["my-proxy"]);
  assert.equal(runtimes["my-proxy"].circuit, "closed");

  // Remove transport
  const removed = controller.removeTransport("my-proxy");
  assert.equal(removed, true);
  assert.equal(controller.getTransports().length, 1);

  // Cannot remove direct
  assert.equal(controller.removeTransport("direct"), false);
});

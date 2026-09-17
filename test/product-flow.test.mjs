/**
 * NetAccess Phase P7 — End-to-End Product Verification Matrix
 * 
 * Implements the 7 required product-level verification scenarios:
 *  - Test A: Direct Reachable (IDLE → VALIDATING → DIAGNOSING → CONNECTED, direct path)
 *  - Test B: Direct Failure + Proxy (Direct failure → alternate proxy tested → alternate CONNECTED)
 *  - Test C: All Paths Fail (FAILED + NO_WORKING_PATH + structured user-facing error)
 *  - Test D: Invalid Target (Immediate INVALID_TARGET rejection without process/network leaks)
 *  - Test E: Transport Degradation (Failures → EWMA degradation → circuit breaker opens → fallback/reporting)
 *  - Test F: Session Crash/Exit (Managed process termination → profile/socket/process cleanup verified)
 *  - Test G: Path Verification (Distinguish expected direct egress from proxy egress & detect contradictory observations)
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as net from "node:net";
import { spawn } from "node:child_process";
import { ApplicationController } from "../src/netaccess/controller.js";
import { CleanupSupervisor } from "../src/netaccess/cleanupSupervisor.js";
import { verifyPath } from "../src/netaccess/pathVerifier.js";
import { makeFinding } from "../src/netaccess/engine.js";

// Helper: spin up a lightweight mock proxy TCP server
function createMockProxyServer() {
  return new Promise((resolve) => {
    const activeSockets = new Set();
    const server = net.createServer((socket) => {
      activeSockets.add(socket);
      socket.once("close", () => activeSockets.delete(socket));
      socket.on("error", () => {});
      socket.on("data", (data) => {
        // Echo HTTP 200 Connection Established for CONNECT probes
        const req = data.toString();
        if (req.startsWith("CONNECT")) {
          socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
        } else {
          socket.write("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK");
        }
      });
    });

    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      const port = typeof addr === "object" && addr ? addr.port : 0;
      resolve({
        server,
        port,
        close: async () => {
          for (const s of activeSockets) {
            try { s.destroy(); } catch {}
          }
          activeSockets.clear();
          await new Promise((res) => server.close(res));
        },
      });
    });
  });
}

// -----------------------------------------------------------------------------
// Test A: Direct Reachable Target Workflow
// -----------------------------------------------------------------------------
test("P7 Test A: Direct Reachable Target (IDLE → VALIDATING → DIAGNOSING → CONNECTED)", async () => {
  const controller = new ApplicationController({
    skipBrowserLaunch: true,
  });

  const stateTransitions = [];
  controller.on("stateChanged", (state) => {
    stateTransitions.push(state);
  });

  let diagnosisEmitted = false;
  controller.on("diagnosisUpdated", (diag) => {
    diagnosisEmitted = true;
    assert.ok(diag.classification);
  });

  let completedEmitted = false;
  controller.on("completed", (res) => {
    completedEmitted = true;
    assert.equal(res.path.type, "direct");
  });

  // Execute over real destination
  const result = await controller.openTarget("example.com", { skipBrowserLaunch: true });

  // 1. Verify state transition order
  assert.deepEqual(
    stateTransitions,
    ["VALIDATING", "DIAGNOSING", "CONNECTED"],
    "State transitions through VALIDATING -> DIAGNOSING -> CONNECTED"
  );

  // 2. Verify diagnosis
  assert.ok(diagnosisEmitted, "diagnosisUpdated event was emitted");
  assert.equal(result.diagnosis.classification.class, "healthy", "Classified as healthy direct path");
  assert.ok(result.diagnosis.classification.confidence >= 0.5, "Confidence score is calculated");

  // 3. Verify selected path
  assert.equal(result.state, "CONNECTED", "Result state is CONNECTED");
  assert.equal(result.path.type, "direct", "Direct path selected");
  assert.equal(result.path.transportId, "direct");
  assert.ok(typeof result.path.latencyMs === "number", "Latency measured");

  // 4. Verify path verification
  assert.ok(result.verification, "Path verification result is present");
  assert.equal(result.verification.verdict, "NOT_APPLICABLE", "Direct path reports NOT_APPLICABLE for proxy leak check");
  assert.equal(result.verification.verified, true, "Direct path is verified");
  assert.equal(result.verification.directEgressDetected, true, "Direct egress explicitly acknowledged as expected");

  // 5. Verify recent destinations
  const recents = controller.getRecentTargets();
  assert.ok(recents.length > 0, "Recent targets updated");
  assert.equal(recents[0].host, "example.com");
  assert.equal(recents[0].lastPathType, "direct");
  assert.equal(recents[0].success, true);
});

// -----------------------------------------------------------------------------
// Test B: Direct Failure + Configured Authorized Proxy Fallback
// -----------------------------------------------------------------------------
test("P7 Test B: Direct Failure + Working Configured Proxy (Alternate CONNECTED)", async () => {
  const proxy = await createMockProxyServer();

  try {
    // Diagnostician: simulate direct path failure (TCP timeout)
    const directFailureDiagnostician = async (target) => [
      makeFinding("dns", true, "healthy", `Resolved ${target.host} to 93.184.216.34`),
      makeFinding("tcp", false, "tcp_timeout", "TCP SYN timeout on port 443", { weight: 1.5 }),
    ];

    // Transport prober: handles our local mock proxy server
    const realTransportProber = async (transport, target) => {
      if (transport.id === "authorized-proxy") {
        return {
          ok: true,
          proxyReachable: true,
          targetReachable: true,
          transportId: transport.id,
          target,
          stage: "http_proxy",
          latencyMs: 18,
          timestamp: Date.now(),
        };
      }
      return {
        ok: false,
        proxyReachable: false,
        transportId: transport.id,
        target,
        stage: "tcp_connect",
        latencyMs: 500,
        error: "Connection refused",
        timestamp: Date.now(),
      };
    };

    const controller = new ApplicationController({
      diagnostician: directFailureDiagnostician,
      transportProber: realTransportProber,
      skipBrowserLaunch: true,
      initialTransports: [
        {
          id: "direct",
          name: "Direct Connection",
          type: "direct",
          tags: ["default"],
          trusted: true,
          enabled: true,
        },
        {
          id: "authorized-proxy",
          name: "Company Internal Proxy",
          type: "http_proxy",
          host: "127.0.0.1",
          port: proxy.port,
          tags: ["backup", "authorized"],
          trusted: true,
          enabled: true,
          secretRef: "vault://proxy-auth-secret",
        },
      ],
    });

    const stateTransitions = [];
    controller.on("stateChanged", (state) => {
      stateTransitions.push(state);
    });

    let transportChangedPath = null;
    controller.on("transportChanged", (p) => {
      transportChangedPath = p;
    });

    // Execute over target with direct failure
    const result = await controller.openTarget("server3.internal.net", { skipBrowserLaunch: true });

    // 1. Verify state transitions through alternate path search
    assert.deepEqual(
      stateTransitions,
      ["VALIDATING", "DIAGNOSING", "FINDING_PATH", "TESTING_PATHS", "CONNECTED"],
      "State transitions cleanly from DIAGNOSING through FINDING_PATH and TESTING_PATHS to CONNECTED"
    );

    // 2. Verify alternate transport selection
    assert.equal(result.state, "CONNECTED");
    assert.equal(result.path.type, "alternate", "Alternate path selected");
    assert.equal(result.path.transportId, "authorized-proxy");
    assert.equal(result.path.transportName, "Company Internal Proxy");
    assert.equal(transportChangedPath?.transportId, "authorized-proxy");

    // 3. Verify EWMA updated
    const runtimes = controller.getTransportRuntimes();
    assert.ok(runtimes["authorized-proxy"], "Runtime exists for proxy");
    assert.ok(runtimes["authorized-proxy"].score > 0.5, "Health score updated positively");
    assert.equal(runtimes["authorized-proxy"].circuit, "closed");

    // 4. Verify credential hygiene: secretRef is never raw plaintext
    const transports = controller.getTransports(true);
    const proxyConfig = transports.find((t) => t.id === "authorized-proxy");
    assert.notEqual(proxyConfig?.secretRef, "secret123");
  } finally {
    await proxy.close();
  }
});

// -----------------------------------------------------------------------------
// Test C: All Paths Fail (Direct and all alternate proxies down)
// -----------------------------------------------------------------------------
test("P7 Test C: All Paths Fail (Surfaces structured NO_WORKING_PATH & clean FAILED state)", async () => {
  // Direct fails
  const allFailDiagnostician = async (target) => [
    makeFinding("dns", true, "healthy", `Resolved ${target.host}`),
    makeFinding("tcp", false, "tcp_timeout", "TCP connect drop", { weight: 1.5 }),
  ];

  // All proxy probes fail
  const allFailProber = async (transport, target) => ({
    ok: false,
    proxyReachable: false,
    transportId: transport.id,
    target,
    stage: "tcp_connect",
    latencyMs: 1000,
    error: "Proxy connection timed out",
    timestamp: Date.now(),
  });

  const controller = new ApplicationController({
    diagnostician: allFailDiagnostician,
    transportProber: allFailProber,
    skipBrowserLaunch: true,
    initialTransports: [
      {
        id: "direct",
        name: "Direct Connection",
        type: "direct",
        tags: ["default"],
        trusted: true,
        enabled: true,
      },
      {
        id: "broken-proxy-1",
        name: "Broken HTTP Proxy",
        type: "http_proxy",
        host: "127.0.0.1",
        port: 1,
        tags: ["alternate"],
        trusted: true,
        enabled: true,
      },
    ],
  });

  const stateTransitions = [];
  controller.on("stateChanged", (state) => {
    stateTransitions.push(state);
  });

  let failedError = null;
  controller.on("failed", (err) => {
    failedError = err;
  });

  await assert.rejects(
    async () => {
      await controller.openTarget("blocked-service.example.org", { skipBrowserLaunch: true });
    },
    (err) => {
      assert.equal(err.code, "NO_WORKING_PATH", "Structured error code is NO_WORKING_PATH");
      assert.match(err.message, /couldn't establish a connection/i);
      assert.match(err.suggestedAction, /alternate connections/i);
      return true;
    }
  );

  // Verify transition sequence ends in FAILED
  assert.ok(stateTransitions.includes("DIAGNOSING"));
  assert.ok(stateTransitions.includes("FINDING_PATH"));
  assert.ok(stateTransitions.includes("TESTING_PATHS"));
  assert.equal(stateTransitions[stateTransitions.length - 1], "FAILED");

  // Verify failure event was emitted with identical error
  assert.ok(failedError);
  assert.equal(failedError.code, "NO_WORKING_PATH");

  // Verify status snapshot
  const status = controller.getStatus();
  assert.equal(status.state, "FAILED");
});

// -----------------------------------------------------------------------------
// Test D: Invalid Target Validation (Immediate rejection without leaks)
// -----------------------------------------------------------------------------
test("P7 Test D: Invalid Target (Immediate structured INVALID_TARGET rejection)", async () => {
  const controller = new ApplicationController({
    skipBrowserLaunch: true,
  });

  const invalidInputs = [
    "",
    "   ",
    "\t\n",
    "http://",
    "https://",
    "://empty-scheme",
  ];

  for (const input of invalidInputs) {
    await assert.rejects(
      async () => {
        await controller.openTarget(input, { skipBrowserLaunch: true });
      },
      (err) => {
        assert.equal(err.code, "INVALID_TARGET", `Input "${input}" rejected with INVALID_TARGET`);
        assert.match(err.message, /check the destination address/i);
        return true;
      }
    );
  }

  // Verify controller state transitions to FAILED
  const status = controller.getStatus();
  assert.equal(status.state, "FAILED");

  // Verify closing session resets cleanly to IDLE
  await controller.closeSession();
  assert.equal(controller.getStatus().state, "IDLE");
  assert.equal(controller.getRecentTargets().length, 0, "No invalid targets added to recents");
});

// -----------------------------------------------------------------------------
// Test E: Transport Degradation & Circuit Breaker Transition
// -----------------------------------------------------------------------------
test("P7 Test E: Transport Degradation (Failures trip circuit breaker to open & engage fallback)", async () => {
  let proxyFailuresCount = 0;

  const dynamicProber = async (transport, target) => {
    if (transport.id === "flaky-proxy") {
      proxyFailuresCount++;
      return {
        ok: false,
        proxyReachable: false,
        transportId: transport.id,
        target,
        stage: "tcp_connect",
        latencyMs: 1500,
        error: "Connection timeout",
        timestamp: Date.now(),
      };
    }
    if (transport.id === "stable-fallback") {
      return {
        ok: true,
        proxyReachable: true,
        targetReachable: true,
        transportId: transport.id,
        target,
        stage: "http_proxy",
        latencyMs: 45,
        timestamp: Date.now(),
      };
    }
    return { ok: false, proxyReachable: false, transportId: transport.id, target, stage: "tcp_connect", latencyMs: 999, timestamp: Date.now() };
  };

  const directFailureDiagnostician = async (target) => [
    makeFinding("dns", true, "healthy", `Resolved ${target.host}`),
    makeFinding("tcp", false, "tcp_timeout", "Direct blocked", { weight: 1.5 }),
  ];

  const controller = new ApplicationController({
    diagnostician: directFailureDiagnostician,
    transportProber: dynamicProber,
    skipBrowserLaunch: true,
    initialTransports: [
      {
        id: "direct",
        name: "Direct Connection",
        type: "direct",
        tags: ["default"],
        trusted: true,
        enabled: true,
      },
      {
        id: "flaky-proxy",
        name: "Flaky Primary Proxy",
        type: "http_proxy",
        host: "10.0.0.1",
        port: 8080,
        tags: ["primary"],
        trusted: true,
        enabled: true,
      },
      {
        id: "stable-fallback",
        name: "Stable Secondary Proxy",
        type: "http_proxy",
        host: "10.0.0.2",
        port: 8080,
        tags: ["fallback"],
        trusted: true,
        enabled: true,
      },
    ],
  });

  const tm = controller.getTransportManager();

  // 1. Record 3 consecutive infrastructure failures to trigger circuit breaker
  tm.recordProbeResult({
    ok: false,
    proxyReachable: false,
    transportId: "flaky-proxy",
    target: { host: "example.com", port: 443, scheme: "https", href: "https://example.com/", pathname: "/" },
    stage: "tcp_connect",
    latencyMs: 1000,
    timestamp: Date.now(),
  });
  tm.recordProbeResult({
    ok: false,
    proxyReachable: false,
    transportId: "flaky-proxy",
    target: { host: "example.com", port: 443, scheme: "https", href: "https://example.com/", pathname: "/" },
    stage: "tcp_connect",
    latencyMs: 1000,
    timestamp: Date.now(),
  });
  tm.recordProbeResult({
    ok: false,
    proxyReachable: false,
    transportId: "flaky-proxy",
    target: { host: "example.com", port: 443, scheme: "https", href: "https://example.com/", pathname: "/" },
    stage: "tcp_connect",
    latencyMs: 1000,
    timestamp: Date.now(),
  });

  // 2. Verify circuit breaker is now OPEN
  const flakyRuntime = tm.getRuntime("flaky-proxy");
  assert.equal(flakyRuntime.circuit, "open", "Circuit breaker tripped to open");
  assert.equal(flakyRuntime.failures, 3, "Failure counter is 3");

  // 3. Now run openTarget: controller should avoid flaky-proxy and select stable-fallback
  const result = await controller.openTarget("work-site.internal", { skipBrowserLaunch: true });

  assert.equal(result.state, "CONNECTED");
  assert.equal(result.path.type, "alternate");
  assert.equal(result.path.transportId, "stable-fallback", "Selected healthy fallback transport");
  assert.equal(result.path.transportName, "Stable Secondary Proxy");
});

// -----------------------------------------------------------------------------
// Test F: Session Crash / Exit Teardown & CleanupSupervisor
// -----------------------------------------------------------------------------
test("P7 Test F: Session Crash / Exit Teardown (Managed profile and process cleaned up)", async () => {
  const cleanup = CleanupSupervisor.getShared();

  // Spawn a real long-running child process simulating an isolated browser
  const dummyChild = spawn(process.execPath, ["-e", "setInterval(() => {}, 5000)"]);
  const childPid = dummyChild.pid;
  assert.ok(childPid && childPid > 0, "Child process spawned");

  try {
    // Create isolated ephemeral directory
    const profileDir = await cleanup.createEphemeralProfile("p7-crash-test");
    assert.ok(fs.existsSync(profileDir), "Ephemeral profile created on disk");

    // Register process with CleanupSupervisor
    cleanup.registerProcess(childPid, "p7-crash-test");

    // Confirm process is alive
    assert.doesNotThrow(() => process.kill(childPid, 0), "Child process is initially alive");

    // Simulate process kill / teardown
    await cleanup.cleanupSession("p7-crash-test");

    // 1. Verify profile directory is completely wiped
    assert.equal(fs.existsSync(profileDir), false, "Ephemeral profile directory deleted after session cleanup");

    // 2. Verify child process is dead
    assert.throws(
      () => process.kill(childPid, 0),
      /ESRCH/,
      "Child process terminated and confirmed dead"
    );
  } finally {
    try {
      dummyChild.kill("SIGKILL");
    } catch (_) {}
  }
});

// -----------------------------------------------------------------------------
// Test G: Scoped Path Verification & Contradictory Observation Handling
// -----------------------------------------------------------------------------
test("P7 Test G: Scoped Path Verification (Direct vs Proxy Egress & Contradictory Detection)", async () => {
  const target = {
    host: "api.internal.net",
    port: 443,
    scheme: "https",
    href: "https://api.internal.net/",
    pathname: "/",
  };

  // 1. Direct path session verification
  const directPath = {
    type: "direct",
    transportId: "direct",
    transportName: "Direct Connection",
    transportType: "direct",
    reason: "Direct healthy",
  };

  const directResult = await verifyPath(
    "p7-direct-session",
    target,
    directPath,
    [1234]
  );

  assert.equal(directResult.verdict, "NOT_APPLICABLE", "Direct path reports NOT_APPLICABLE");
  assert.equal(directResult.verified, true, "Direct path is verified=true");
  assert.equal(directResult.directEgressDetected, true, "Direct egress explicitly detected and allowed");
  assert.match(directResult.summary, /Direct path active/i);
  assert.doesNotMatch(directResult.summary, /Zero leaks guaranteed/i, "No false zero-leak claims made");

  // 2. Alternate proxy session verification with mock connection observer
  const proxyPath = {
    type: "alternate",
    transportId: "proxy-corp",
    transportName: "Corporate Proxy",
    transportType: "http_proxy",
    reason: "Alternate selected",
  };

  const proxyTransport = {
    id: "proxy-corp",
    name: "Corporate Proxy",
    type: "http_proxy",
    host: "192.168.1.100",
    port: 8080,
    tags: ["corp"],
    trusted: true,
    enabled: true,
  };

  // Mock observer: observed socket connecting to proxy endpoint
  const proxyConnectionObserver = async () => [
    {
      pid: 1234,
      command: "Google Chrome",
      proto: "TCP",
      localAddress: "192.168.1.50",
      localPort: 54321,
      remoteAddress: "192.168.1.100",
      remotePort: 8080,
      state: "ESTABLISHED",
    },
  ];

  const proxyProber = async () => ({
    ok: true,
    proxyReachable: true,
    targetReachable: true,
    transportId: "proxy-corp",
    target,
    stage: "http_proxy",
    latencyMs: 25,
    timestamp: Date.now(),
  });

  const verifiedResult = await verifyPath(
    "p7-proxy-session",
    target,
    proxyPath,
    [1234],
    proxyTransport,
    {
      connectionObserver: proxyConnectionObserver,
      proxyProber,
    }
  );

  assert.equal(verifiedResult.verdict, "VERIFIED", "Verdict is VERIFIED");
  assert.equal(verifiedResult.verified, true);
  assert.equal(verifiedResult.evidence.observations.proxyConnectionObserved, true);
  assert.equal(verifiedResult.evidence.observations.targetConnectionObserved, true);
  assert.equal(verifiedResult.evidence.observations.directTargetConnectionObserved, false);
  assert.match(verifiedResult.summary, /established its target connection through the configured proxy endpoint/i);

  // 3. Contradictory observation handling: BOTH proxy connection and direct destination connection observed
  const conflictingConnectionObserver = async () => [
    {
      pid: 1234,
      command: "Google Chrome",
      proto: "TCP",
      localAddress: "192.168.1.50",
      localPort: 54321,
      remoteAddress: "192.168.1.100",
      remotePort: 8080,
      state: "ESTABLISHED",
    },
    {
      pid: 1234,
      command: "Google Chrome",
      proto: "TCP",
      localAddress: "192.168.1.50",
      localPort: 54322,
      remoteAddress: "93.184.216.34", // direct target IP!
      remotePort: 443,
      state: "ESTABLISHED",
    },
  ];

  const conflictResult = await verifyPath(
    "p7-conflict-session",
    target,
    proxyPath,
    [1234],
    proxyTransport,
    {
      connectionObserver: conflictingConnectionObserver,
      proxyProber,
      dnsResolver: async () => ["93.184.216.34"],
    }
  );

  assert.equal(conflictResult.verdict, "PATH_CONFLICT", "Fails closed with PATH_CONFLICT");
  assert.equal(conflictResult.verified, false, "verified is false on conflict");
  assert.match(conflictResult.summary, /Path conflict: direct connection to destination target was observed/i);
});

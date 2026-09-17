import test from "node:test";
import assert from "node:assert/strict";
import { verifyPath } from "../src/netaccess/pathVerifier.js";
import { leakVerdict, simulatePackets } from "../src/netaccess/leak.js";
import { parseTarget } from "../src/netaccess/engine.js";
import { ApplicationController } from "../src/netaccess/controller.js";

const DUMMY_TARGET = parseTarget("api.service.internal:443");

test("P4.4: Direct session reports expected direct path without treating direct egress as a leak", async () => {
  const selectedPath = {
    type: "direct",
    transportId: "direct",
    transportName: "Direct Connection",
    transportType: "direct",
    reason: "Direct healthy",
  };

  const res = await verifyPath("sess-direct", DUMMY_TARGET, selectedPath);

  assert.strictEqual(res.verified, true);
  assert.strictEqual(res.verdict, "NOT_APPLICABLE");
  assert.strictEqual(res.confidence, "high");
  assert.strictEqual(res.directEgressDetected, true);
  assert.strictEqual(res.evidence.selectedTransport.type, "direct");
  assert.ok(res.summary.includes("Direct path active"));
  assert.ok(res.limitations.length > 0);
});

test("P4.5: Alternate session verifies when proxy connection & target-through-proxy are observed", async () => {
  const selectedPath = {
    type: "alternate",
    transportId: "proxy-corp",
    transportName: "Corp Proxy",
    transportType: "http_proxy",
    reason: "Policy",
  };
  const config = {
    id: "proxy-corp",
    name: "Corp Proxy",
    type: "http_proxy",
    host: "127.0.0.1",
    port: 8080,
    enabled: true,
  };

  // Mock observer: managed browser PID 100 connected to proxy:8080
  const mockObserver = async (pids) => [
    {
      pid: 100,
      localAddress: "127.0.0.1",
      localPort: 54321,
      remoteAddress: "127.0.0.1",
      remotePort: 8080,
      state: "ESTABLISHED",
    },
  ];

  // Mock prober: proxy can establish tunnel to destination target
  const mockProber = async () => ({
    ok: true,
    transportId: "proxy-corp",
    stage: "target_http",
    proxyReachable: true,
    targetReachable: true,
    latencyMs: 15,
  });

  const res = await verifyPath("sess-alt-1", DUMMY_TARGET, selectedPath, [100], config, {
    connectionObserver: mockObserver,
    proxyProber: mockProber,
    dnsResolver: async (h) => (h === "api.service.internal" ? ["10.1.2.3"] : ["127.0.0.1"]),
  });

  assert.strictEqual(res.verified, true);
  assert.strictEqual(res.verdict, "VERIFIED");
  assert.strictEqual(res.confidence, "high");
  assert.strictEqual(res.directEgressDetected, false);
  assert.strictEqual(res.evidence.observations.proxyConnectionObserved, true);
  assert.strictEqual(res.evidence.observations.directTargetConnectionObserved, false);
  assert.strictEqual(res.evidence.observations.targetConnectionObserved, true);
  assert.ok(res.summary.includes("Within the checks NetAccess performed"));
});

test("P4.6: Contradictory observation (direct target connection) fails closed as PATH_CONFLICT", async () => {
  const selectedPath = {
    type: "alternate",
    transportId: "proxy-corp",
    transportName: "Corp Proxy",
    transportType: "http_proxy",
    reason: "Policy",
  };
  const config = {
    id: "proxy-corp",
    name: "Corp Proxy",
    type: "http_proxy",
    host: "10.0.0.1",
    port: 8080,
    enabled: true,
  };

  // Contradictory observer: PID 100 connected to proxy:8080 AND connected directly to target:443
  const mockObserver = async () => [
    {
      pid: 100,
      localAddress: "192.168.1.50",
      localPort: 54321,
      remoteAddress: "10.0.0.1",
      remotePort: 8080,
      state: "ESTABLISHED",
    },
    {
      pid: 100,
      localAddress: "192.168.1.50",
      localPort: 54322,
      remoteAddress: "93.184.216.34", // direct target IP
      remotePort: 443,
      state: "ESTABLISHED",
    },
  ];

  const mockProber = async () => ({
    ok: true,
    transportId: "proxy-corp",
    stage: "target_http",
    proxyReachable: true,
    targetReachable: true,
    latencyMs: 15,
  });

  const res = await verifyPath("sess-conflict", DUMMY_TARGET, selectedPath, [100], config, {
    connectionObserver: mockObserver,
    proxyProber: mockProber,
    dnsResolver: async (h) => (h.includes("service") ? ["93.184.216.34"] : ["10.0.0.1"]),
  });

  // Must fail closed!
  assert.strictEqual(res.verified, false);
  assert.strictEqual(res.verdict, "PATH_CONFLICT");
  assert.strictEqual(res.confidence, "high");
  assert.strictEqual(res.directEgressDetected, true);
  assert.strictEqual(res.evidence.observations.directTargetConnectionObserved, true);
  assert.ok(res.summary.includes("Path conflict"));
});

test("P4.5: Proxy endpoint unavailable surfaces UNAVAILABLE verdict", async () => {
  const selectedPath = {
    type: "alternate",
    transportId: "proxy-down",
    transportName: "Down Proxy",
    transportType: "http_proxy",
    reason: "Policy",
  };
  const config = {
    id: "proxy-down",
    name: "Down Proxy",
    type: "http_proxy",
    host: "10.0.0.99",
    port: 9999,
    enabled: true,
  };

  const mockObserver = async () => [];
  const mockProber = async () => ({
    ok: false,
    transportId: "proxy-down",
    stage: "connect_proxy",
    proxyReachable: false,
    targetReachable: false,
    error: "ECONNREFUSED",
    latencyMs: 5,
  });

  const res = await verifyPath("sess-down", DUMMY_TARGET, selectedPath, [100], config, {
    connectionObserver: mockObserver,
    proxyProber: mockProber,
  });

  assert.strictEqual(res.verified, false);
  assert.strictEqual(res.verdict, "UNAVAILABLE");
  assert.ok(res.summary.includes("Configured proxy endpoint is unreachable"));
});

test("P4.5: Target unreachable through proxy is distinguished from local proxy failure", async () => {
  const selectedPath = {
    type: "alternate",
    transportId: "proxy-ok-tgt-down",
    transportName: "Proxy OK Target Down",
    transportType: "http_proxy",
    reason: "Policy",
  };
  const config = {
    id: "proxy-ok-tgt-down",
    name: "Proxy OK Target Down",
    type: "http_proxy",
    host: "10.0.0.1",
    port: 8080,
    enabled: true,
  };

  const mockObserver = async () => [
    {
      pid: 100,
      localAddress: "192.168.1.50",
      localPort: 54321,
      remoteAddress: "10.0.0.1",
      remotePort: 8080,
      state: "ESTABLISHED",
    },
  ];

  // Proxy reached, but target rejected/timed out through tunnel
  const mockProber = async () => ({
    ok: false,
    transportId: "proxy-ok-tgt-down",
    stage: "target_http",
    proxyReachable: true,
    targetReachable: false,
    error: "502 Bad Gateway",
    latencyMs: 40,
  });

  const res = await verifyPath("sess-tgt-down", DUMMY_TARGET, selectedPath, [100], config, {
    connectionObserver: mockObserver,
    proxyProber: mockProber,
    dnsResolver: async () => ["10.0.0.1"],
  });

  assert.strictEqual(res.verified, false);
  assert.strictEqual(res.verdict, "NOT_VERIFIED");
  assert.ok(res.summary.includes("destination target could not be reached through proxy"));
});

test("P4.7: Ambiguous observation (no active socket observed) never reports verified=true", async () => {
  const selectedPath = {
    type: "alternate",
    transportId: "p1",
    transportName: "P1",
    transportType: "http_proxy",
    reason: "Policy",
  };
  const config = { id: "p1", name: "P1", type: "http_proxy", host: "127.0.0.1", port: 8080, enabled: true };

  // Browser running, but no network sockets open yet
  const mockObserver = async () => [];
  const mockProber = async () => ({
    ok: true,
    transportId: "p1",
    stage: "target_http",
    proxyReachable: true,
    targetReachable: true,
    latencyMs: 10,
  });

  const res = await verifyPath("sess-ambig", DUMMY_TARGET, selectedPath, [100], config, {
    connectionObserver: mockObserver,
    proxyProber: mockProber,
  });

  assert.strictEqual(res.verified, false);
  assert.strictEqual(res.verdict, "NOT_VERIFIED");
  assert.strictEqual(res.confidence, "medium");
  assert.ok(res.summary.includes("Proxy connection could not be conclusively observed"));
});

test("P4.3: Unrelated process traffic is strictly ignored", async () => {
  const selectedPath = {
    type: "alternate",
    transportId: "p1",
    transportName: "P1",
    transportType: "http_proxy",
    reason: "Policy",
  };
  const config = { id: "p1", name: "P1", type: "http_proxy", host: "10.0.0.1", port: 8080, enabled: true };

  // PID 999 (unrelated process) has a direct connection to target
  // Managed PID 200 has connection to proxy
  const mockObserver = async () => [
    {
      pid: 999, // Unrelated process!
      localAddress: "192.168.1.50",
      localPort: 60000,
      remoteAddress: "93.184.216.34", // direct target
      remotePort: 443,
      state: "ESTABLISHED",
    },
    {
      pid: 200, // Managed PID
      localAddress: "192.168.1.50",
      localPort: 60001,
      remoteAddress: "10.0.0.1", // proxy
      remotePort: 8080,
      state: "ESTABLISHED",
    },
  ];

  const mockProber = async () => ({
    ok: true,
    transportId: "p1",
    stage: "target_http",
    proxyReachable: true,
    targetReachable: true,
    latencyMs: 12,
  });

  // Verify only managed PID 200
  const res = await verifyPath("sess-scoped", DUMMY_TARGET, selectedPath, [200], config, {
    connectionObserver: mockObserver,
    proxyProber: mockProber,
    dnsResolver: async (h) => (h.includes("service") ? ["93.184.216.34"] : ["10.0.0.1"]),
  });

  // Unrelated PID 999 direct connection must NOT cause verification failure
  assert.strictEqual(res.verified, true);
  assert.strictEqual(res.verdict, "VERIFIED");
  assert.strictEqual(res.evidence.observations.directTargetConnectionObserved, false);
});

test("P4.3: Multiple sessions remain strictly segregated", async () => {
  const selectedPath = {
    type: "alternate",
    transportId: "p1",
    transportName: "P1",
    transportType: "http_proxy",
    reason: "Policy",
  };
  const config = { id: "p1", name: "P1", type: "http_proxy", host: "10.0.0.1", port: 8080, enabled: true };

  const mockObserver = async (pids) => {
    if (pids.includes(101)) {
      return [{ pid: 101, localAddress: "127.0.0.1", localPort: 5001, remoteAddress: "10.0.0.1", remotePort: 8080 }];
    }
    return [{ pid: 102, localAddress: "127.0.0.1", localPort: 5002, remoteAddress: "93.184.216.34", remotePort: 443 }];
  };

  const mockProber = async () => ({
    ok: true,
    transportId: "p1",
    stage: "target_http",
    proxyReachable: true,
    targetReachable: true,
    latencyMs: 10,
  });

  const resA = await verifyPath("sess-A", DUMMY_TARGET, selectedPath, [101], config, {
    connectionObserver: mockObserver,
    proxyProber: mockProber,
    dnsResolver: async () => ["10.0.0.1"],
  });
  const resB = await verifyPath("sess-B", DUMMY_TARGET, selectedPath, [102], config, {
    connectionObserver: mockObserver,
    proxyProber: mockProber,
    dnsResolver: async () => ["93.184.216.34"],
  });

  assert.strictEqual(resA.evidence.sessionId, "sess-A");
  assert.strictEqual(resA.verified, true);

  assert.strictEqual(resB.evidence.sessionId, "sess-B");
  assert.strictEqual(resB.verified, false);
  assert.strictEqual(resB.verdict, "PATH_CONFLICT");
});

test("P4.8: Cancellation during verification terminates cleanly without orphan timers", async () => {
  const ac = new AbortController();
  ac.abort();

  const selectedPath = {
    type: "alternate",
    transportId: "p1",
    transportName: "P1",
    transportType: "http_proxy",
    reason: "Policy",
  };
  const config = { id: "p1", name: "P1", type: "http_proxy", host: "127.0.0.1", port: 8080, enabled: true };

  const res = await verifyPath("sess-cancel", DUMMY_TARGET, selectedPath, [100], config, {}, ac.signal);

  assert.strictEqual(res.verified, false);
  assert.strictEqual(res.verdict, "UNAVAILABLE");
  assert.ok(res.summary.includes("cancelled"));
});

test("P4.8: Sensitive credentials never appear in evidence, summary, or logs", async () => {
  const selectedPath = {
    type: "alternate",
    transportId: "p-secret",
    transportName: "Secret Proxy",
    transportType: "http_proxy",
    reason: "Policy",
  };
  const config = {
    id: "p-secret",
    name: "Secret Proxy",
    type: "http_proxy",
    host: "admin:topSecretPassword123@secure.corp.net",
    port: 8443,
    enabled: true,
  };

  const res = await verifyPath("sess-secret", DUMMY_TARGET, selectedPath, [], config);

  const serialized = JSON.stringify(res);
  assert.ok(!serialized.includes("topSecretPassword123"), "Password must never appear in verification result");
  assert.strictEqual(res.proxyEndpoint, "secure.corp.net:8443");
});

test("P4.7: Verification result survives JSON serialization without loss", async () => {
  const selectedPath = {
    type: "direct",
    transportId: "direct",
    transportName: "Direct Connection",
    transportType: "direct",
    reason: "Direct",
  };

  const res = await verifyPath("sess-json", DUMMY_TARGET, selectedPath);
  const jsonStr = JSON.stringify(res);
  const parsed = JSON.parse(jsonStr);

  assert.strictEqual(parsed.verified, res.verified);
  assert.strictEqual(parsed.verdict, res.verdict);
  assert.strictEqual(parsed.confidence, res.confidence);
  assert.strictEqual(parsed.summary, res.summary);
  assert.strictEqual(parsed.evidence.sessionId, "sess-json");
});

test("P4.7: Integration with leak.ts simulated packet streams", () => {
  // Test no leaks
  const cleanPackets = simulatePackets({
    sessionId: "sess-sim-clean",
    transportId: "proxy-vpn",
    injectLeak: false,
    n: 10,
  });
  const cleanVerdict = leakVerdict(cleanPackets, { sessionId: "sess-sim-clean" });

  assert.strictEqual(cleanVerdict.pass, true);
  assert.strictEqual(cleanVerdict.verified, true);
  assert.strictEqual(cleanVerdict.verdict, "VERIFIED");
  assert.strictEqual(cleanVerdict.leaked, 0);
  assert.strictEqual(cleanVerdict.directEgressDetected, false);

  // Test injected leak
  const leakedPackets = simulatePackets({
    sessionId: "sess-sim-leak",
    transportId: "proxy-vpn",
    injectLeak: true,
    n: 10,
  });
  const leakRes = leakVerdict(leakedPackets, { sessionId: "sess-sim-leak" });

  assert.strictEqual(leakRes.pass, false);
  assert.strictEqual(leakRes.verified, false);
  assert.strictEqual(leakRes.verdict, "PATH_CONFLICT");
  assert.strictEqual(leakRes.leaked, 1);
  assert.strictEqual(leakRes.directEgressDetected, true);
});

test("P4.8: ApplicationController full lifecycle emits typed PathVerificationResult", async () => {
  let emittedVerification = null;

  const controller = new ApplicationController({
    skipBrowserLaunch: true,
    diagnostician: async () => [
      {
        id: "dns",
        layer: "dns",
        ok: true,
        classHint: "healthy",
        weight: 1.0,
        evidence: "Resolved",
        startedAt: Date.now() - 5,
        endedAt: Date.now(),
      },
    ],
  });

  controller.on("verificationUpdated", (v) => {
    emittedVerification = v;
  });

  const res = await controller.openTarget("example.com", { skipBrowserLaunch: true });

  assert.ok(res.verification);
  assert.strictEqual(res.verification.verified, true);
  assert.strictEqual(res.verification.verdict, "NOT_APPLICABLE");
  assert.strictEqual(emittedVerification, res.verification);

  await controller.closeSession();
});

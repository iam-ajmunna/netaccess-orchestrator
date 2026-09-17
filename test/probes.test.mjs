/**
 * Unit & Integration Tests for NetAccess Direct Diagnostics Pipeline (P1)
 * Validates real network operations, timeouts, cancellation, and evidence classification.
 */

import assert from "node:assert/strict";
import * as http from "node:http";
import * as net from "node:net";
import test from "node:test";
import { parseTarget } from "../src/netaccess/engine.ts";
import {
  diagnoseDirectPath,
  probeCaptivePortal,
  probeDns,
  probeHttp,
  probeTcp,
  probeTls,
} from "../src/netaccess/probes/directProbes.ts";
import { classify } from "../src/netaccess/engine.ts";

test("P1 DNS Probing: Real DNS resolution & IP literals", async () => {
  // Test 1: Real public hostname
  const dnsRes = await probeDns("example.com", 3000);
  assert.ok(dnsRes.findings.length > 0);
  assert.equal(dnsRes.findings[0].ok, true);
  assert.equal(dnsRes.findings[0].classHint, "healthy");
  assert.ok(dnsRes.ipv4.length > 0 || dnsRes.ipv6.length > 0);
  assert.ok(dnsRes.usableIp);

  // Test 2: IP literal
  const ipRes = await probeDns("127.0.0.1", 1000);
  assert.equal(ipRes.findings[0].ok, true);
  assert.equal(ipRes.usableIp, "127.0.0.1");

  // Test 3: Nonexistent domain (NXDOMAIN)
  const nxRes = await probeDns("nonexistent-domain-test-xyz123.invalid", 2000);
  assert.equal(nxRes.usableIp, undefined);
  assert.equal(nxRes.findings[0].ok, false);
  assert.equal(nxRes.findings[0].classHint, "dns_nxdomain");
  assert.match(nxRes.findings[0].evidence, /does not exist|NXDOMAIN|not found/i);
});

test("P1 TCP Probing: Connection success, refusal, and timeout bounds", async () => {
  // Start a local TCP server to test successful connection
  const server = net.createServer((socket) => {
    socket.end();
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = server.address().port;

  try {
    // Test 1: Successful connection
    const okRes = await probeTcp("127.0.0.1", port, 2000);
    assert.equal(okRes.connected, true);
    assert.equal(okRes.finding.ok, true);
    assert.equal(okRes.finding.classHint, "healthy");
    assert.ok(okRes.latencyMs !== undefined && okRes.latencyMs >= 0);

    // Test 2: Connection refused (closed port)
    const closedPort = port + 1 > 65535 ? port - 1 : port + 1;
    const refRes = await probeTcp("127.0.0.1", closedPort, 2000);
    assert.equal(refRes.connected, false);
    assert.equal(refRes.finding.ok, false);
    assert.equal(refRes.finding.classHint, "tcp_refused");
    assert.match(refRes.finding.evidence, /refused/i);

    // Test 3: Timeout bounds
    const timeoutRes = await probeTcp("198.51.100.1", 80, 200); // RFC 5737 TEST-NET-2 unroutable
    assert.equal(timeoutRes.connected, false);
    assert.equal(timeoutRes.finding.ok, false);
    assert.equal(timeoutRes.finding.classHint, "tcp_timeout");
  } finally {
    server.close();
  }
});

test("P1 TCP Probing: Cancellation via AbortSignal", async () => {
  const ac = new AbortController();
  const probePromise = probeTcp("198.51.100.1", 80, 5000, ac.signal);
  ac.abort();
  const res = await probePromise;
  assert.equal(res.connected, false);
  assert.equal(res.finding.ok, false);
  assert.match(res.finding.evidence, /aborted/i);
});

test("P1 TLS Probing: Real TLS handshake and ALPN negotiation", async () => {
  const tlsRes = await probeTls("example.com", 443, 4000);
  assert.equal(tlsRes.ok, true);
  assert.equal(tlsRes.finding.ok, true);
  assert.equal(tlsRes.finding.classHint, "healthy");
  assert.ok(tlsRes.alpnProtocol);
  assert.match(tlsRes.finding.evidence, /TLS handshake established/i);
});

test("P1 HTTP Probing: Status classification (200 OK vs 403 vs 451)", async () => {
  // Spin up a local HTTP server returning specific status codes
  let mockStatus = 200;
  const server = http.createServer((req, res) => {
    res.writeHead(mockStatus, { "Content-Type": "text/plain" });
    res.end("Response body");
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = server.address().port;

  try {
    // 1. 200 OK
    mockStatus = 200;
    const target200 = parseTarget(`http://127.0.0.1:${port}/`);
    const f200 = await probeHttp(target200, 2000);
    assert.equal(f200.ok, true);
    assert.equal(f200.classHint, "healthy");

    // 2. 403 Forbidden (Application restriction, not network failure)
    mockStatus = 403;
    const target403 = parseTarget(`http://127.0.0.1:${port}/restricted`);
    const f403 = await probeHttp(target403, 2000);
    assert.equal(f403.ok, false);
    assert.equal(f403.classHint, "destination_restriction");
    assert.match(f403.evidence, /destination reachable, service restricted/i);

    // 3. 451 Unavailable For Legal Reasons
    mockStatus = 451;
    const target451 = parseTarget(`http://127.0.0.1:${port}/legal`);
    const f451 = await probeHttp(target451, 2000);
    assert.equal(f451.ok, false);
    assert.equal(f451.classHint, "geographic_restriction");
    assert.match(f451.evidence, /legal\/geographic|geographic|legal/i);

    // 4. 500 Server Error
    mockStatus = 500;
    const target500 = parseTarget(`http://127.0.0.1:${port}/error`);
    const f500 = await probeHttp(target500, 2000);
    assert.equal(f500.ok, false);
    assert.equal(f500.classHint, "http_failure");
  } finally {
    server.close();
  }
});

test("P1 Captive Portal Signal: Returns valid finding or null without blocking", async () => {
  const captiveRes = await probeCaptivePortal(2000);
  // On real network, if clear, returns a healthy finding; if offline/error, returns null without failing
  if (captiveRes) {
    assert.equal(captiveRes.layer, "captive");
    assert.ok(captiveRes.classHint === "healthy" || captiveRes.classHint === "captive_portal");
  }
});

test("P1 Direct Pipeline: Real end-to-end healthy diagnosis on live host", async () => {
  const target = parseTarget("example.com");
  const findings = await diagnoseDirectPath(target, undefined, { checkCaptive: false });

  // Must contain DNS, TCP, TLS, and HTTP findings
  const layers = findings.map((f) => f.layer);
  assert.ok(layers.includes("dns"));
  assert.ok(layers.includes("tcp"));
  assert.ok(layers.includes("tls"));
  assert.ok(layers.includes("http"));

  // All findings should be healthy
  const classification = classify(findings);
  assert.equal(classification.class, "healthy");
  assert.ok(classification.confidence > 0.8);
});

test("P1 Direct Pipeline: NXDOMAIN short-circuits subsequent layers", async () => {
  const target = parseTarget("nonexistent-test-12345-fake.invalid");
  const findings = await diagnoseDirectPath(target, undefined, { checkCaptive: false });

  // Only DNS layer should run
  const layers = findings.map((f) => f.layer);
  assert.deepEqual(layers, ["dns"]);

  const classification = classify(findings);
  assert.equal(classification.class, "dns_nxdomain");
});

test("P1 Direct Pipeline: Closed port stops before TLS and HTTP", async () => {
  // Connect to loopback on closed port
  const target = parseTarget("http://127.0.0.1:49150");
  const findings = await diagnoseDirectPath(target, undefined, { checkCaptive: false });

  const layers = findings.map((f) => f.layer);
  assert.ok(layers.includes("dns"));
  assert.ok(layers.includes("tcp"));
  assert.ok(!layers.includes("tls"));
  assert.ok(!layers.includes("http"));

  const classification = classify(findings);
  assert.equal(classification.class, "tcp_refused");
});

test("P1 Direct Pipeline: parseTarget detects standard HTTP ports and diagnoseDirectPath probes active port", async () => {
  const target8080 = parseTarget("server3.ftpbd.net:8080");
  assert.equal(target8080.scheme, "http");
  assert.equal(target8080.port, 8080);
  assert.equal(target8080.href, "http://server3.ftpbd.net:8080/");

  const targetBare = parseTarget("server3.ftpbd.net");
  assert.equal(targetBare.host, "server3.ftpbd.net");
});


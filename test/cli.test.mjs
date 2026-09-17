import test from "node:test";
import assert from "node:assert/strict";
import { runCli, execCli, CLI_EXIT_CODES } from "../src/netaccess/cli.js";
import { ApplicationController } from "../src/netaccess/controller.js";
import { makeFinding, parseTarget } from "../src/netaccess/engine.js";

function createTestIO(controller) {
  const stdoutLines = [];
  const stderrLines = [];
  return {
    io: {
      controller,
      stdout: (m) => stdoutLines.push(m),
      stderr: (m) => stderrLines.push(m),
    },
    getStdout: () => stdoutLines.join("\n"),
    getStderr: () => stderrLines.join("\n"),
    getCombined: () => [...stdoutLines, ...stderrLines].join("\n"),
  };
}

test("P5.1: CLI command parsing and help output", async () => {
  const { io, getStdout } = createTestIO();
  const code = await runCli(["help"], io);

  assert.strictEqual(code, CLI_EXIT_CODES.SUCCESS);
  const out = getStdout();
  assert.ok(out.includes("netaccess open"));
  assert.ok(out.includes("netaccess check"));
  assert.ok(out.includes("netaccess transports"));
  assert.ok(out.includes("netaccess doctor"));
});

test("P5.2: netaccess open <target> success on direct path", async () => {
  const controller = new ApplicationController({
    diagnostician: async () => [
      makeFinding("dns", true, "healthy", "Resolved", { latencyMs: 10 }),
      makeFinding("tcp", true, "healthy", "Connected", { latencyMs: 15 }),
      makeFinding("http", true, "healthy", "200 OK", { latencyMs: 20 }),
    ],
  });

  const { io, getStdout } = createTestIO(controller);
  const code = await runCli(["open", "example.com", "--skip-launch"], io);

  assert.strictEqual(code, CLI_EXIT_CODES.SUCCESS);
  const out = getStdout();
  assert.ok(out.includes("NetAccess"));
  assert.ok(out.includes("Connection established"));
  assert.ok(out.includes("Direct Connection"));
  assert.ok(out.includes("Path verification"));
});

test("P5.3: netaccess open direct failure with working alternate fallback", async () => {
  const controller = new ApplicationController({
    initialTransports: [
      {
        id: "proxy-corp",
        name: "Corp HTTP Proxy",
        type: "http_proxy",
        host: "10.0.0.1",
        port: 8080,
        enabled: true,
      },
    ],
    diagnostician: async () => [
      makeFinding("dns", true, "healthy", "Resolved"),
      makeFinding("tcp", false, "tcp_timeout", "Connection timed out"),
    ],
    transportProber: async (t) => ({
      ok: true,
      transportId: t.id,
      stage: "target_http",
      proxyReachable: true,
      targetReachable: true,
      latencyMs: 35,
    }),
  });

  const { io, getStdout } = createTestIO(controller);
  const code = await runCli(["open", "internal-portal.org", "--skip-launch"], io);

  assert.strictEqual(code, CLI_EXIT_CODES.SUCCESS);
  const out = getStdout();
  assert.ok(out.includes("Corp HTTP Proxy"));
  assert.ok(out.includes("Selected path:     Corp HTTP Proxy (alternate)"));
});

test("P5.4: netaccess open all-path failure returns NO_WORKING_PATH (code 3)", async () => {
  const controller = new ApplicationController({
    initialTransports: [
      {
        id: "proxy-dead",
        name: "Dead Proxy",
        type: "http_proxy",
        host: "10.0.0.99",
        port: 8080,
        enabled: true,
      },
    ],
    diagnostician: async () => [
      makeFinding("dns", true, "healthy", "Resolved"),
      makeFinding("tcp", false, "tcp_refused", "Connection refused"),
    ],
    transportProber: async () => ({
      ok: false,
      transportId: "proxy-dead",
      stage: "connect_proxy",
      proxyReachable: false,
      targetReachable: false,
      latencyMs: 5,
    }),
  });

  const { io, getStderr } = createTestIO(controller);
  const code = await runCli(["open", "unreachable.org", "--skip-launch"], io);

  assert.strictEqual(code, CLI_EXIT_CODES.NO_WORKING_PATH);
  const errOut = getStderr();
  assert.ok(errOut.includes("NO_WORKING_PATH"));
  assert.ok(errOut.includes("couldn't establish a connection"));
});

test("P5.5: netaccess open invalid target returns INVALID_TARGET (code 1)", async () => {
  const { io, getStderr } = createTestIO();
  const code = await runCli(["open", ""], io);

  assert.strictEqual(code, CLI_EXIT_CODES.INVALID_TARGET);
  assert.ok(getStderr().includes("Missing destination target"));

  const { io: io2, getStderr: getStderr2 } = createTestIO();
  const code2 = await runCli(["open", "https://"], io2);
  assert.strictEqual(code2, CLI_EXIT_CODES.INVALID_TARGET);
});

test("P5.6: netaccess open destination rejection returns DESTINATION_REJECTED (code 4)", async () => {
  const controller = new ApplicationController({
    diagnostician: async () => [
      makeFinding("dns", true, "healthy", "Resolved"),
      makeFinding("tcp", true, "healthy", "Connected"),
      makeFinding("http", false, "destination_restriction", "HTTP 403 Forbidden"),
    ],
  });

  const { io, getStderr } = createTestIO(controller);
  const code = await runCli(["open", "restricted-service.org", "--skip-launch"], io);

  assert.strictEqual(code, CLI_EXIT_CODES.DESTINATION_REJECTED);
  const errOut = getStderr();
  assert.ok(errOut.includes("DESTINATION_REJECTED"));
  assert.ok(errOut.includes("rejected the request"));
});

test("P5.7: netaccess cancellation returns CANCELLED (code 7)", async () => {
  const controller = new ApplicationController({
    diagnostician: async (target, signal) => {
      // Simulate cancelled probe
      throw new Error("Session aborted");
    },
  });

  const { io, getCombined } = createTestIO(controller);
  const code = await runCli(["open", "cancelled.org", "--skip-launch"], io);

  assert.strictEqual(code, CLI_EXIT_CODES.CANCELLED);
});

test("P5.8: Deterministic exit codes cover all expected categories", () => {
  assert.strictEqual(CLI_EXIT_CODES.SUCCESS, 0);
  assert.strictEqual(CLI_EXIT_CODES.INVALID_TARGET, 1);
  assert.strictEqual(CLI_EXIT_CODES.DESTINATION_UNREACHABLE, 2);
  assert.strictEqual(CLI_EXIT_CODES.NO_WORKING_PATH, 3);
  assert.strictEqual(CLI_EXIT_CODES.DESTINATION_REJECTED, 4);
  assert.strictEqual(CLI_EXIT_CODES.TRANSPORT_UNAVAILABLE, 5);
  assert.strictEqual(CLI_EXIT_CODES.PERMISSION_REQUIRED, 6);
  assert.strictEqual(CLI_EXIT_CODES.CANCELLED, 7);
  assert.strictEqual(CLI_EXIT_CODES.CLEANUP_FAILED, 8);
  assert.strictEqual(CLI_EXIT_CODES.UNEXPECTED_ERROR, 9);
});

test("P5.9: netaccess open --json produces parseable schema-typed output", async () => {
  const controller = new ApplicationController({
    diagnostician: async () => [
      makeFinding("dns", true, "healthy", "Resolved"),
      makeFinding("tcp", true, "healthy", "Connected"),
      makeFinding("http", true, "healthy", "200 OK"),
    ],
  });

  const { io, getStdout } = createTestIO(controller);
  const code = await runCli(["open", "example.com", "--skip-launch", "--json"], io);

  assert.strictEqual(code, CLI_EXIT_CODES.SUCCESS);
  const out = getStdout();
  const json = JSON.parse(out);
  assert.strictEqual(json.target.host, "example.com");
  assert.strictEqual(json.path.type, "direct");
  assert.strictEqual(json.verification.verified, true);
  assert.strictEqual(json.verification.verdict, "NOT_APPLICABLE");
});

test("P5.10: Secrets never leak in stdout, stderr, or JSON output", async () => {
  const secretHost = "admin:superSecretToken987@secure.proxy.net";
  const controller = new ApplicationController({
    initialTransports: [
      {
        id: "proxy-secret",
        name: "Secret Proxy",
        type: "http_proxy",
        host: secretHost,
        port: 8080,
        enabled: true,
        secretRef: "keychain://proxy_pass",
      },
    ],
  });

  // Test transports list command
  const { io: ioTransports, getStdout: getStdoutTransports } = createTestIO(controller);
  await runCli(["transports", "--scores"], ioTransports);
  const outTransports = getStdoutTransports();
  assert.ok(!outTransports.includes("superSecretToken987"));
  assert.ok(!outTransports.includes("keychain://"));

  // Test transports --json command
  const { io: ioJson, getStdout: getStdoutJson } = createTestIO(controller);
  await runCli(["transports", "--json"], ioJson);
  const jsonStr = getStdoutJson();
  assert.ok(!jsonStr.includes("superSecretToken987"));
  assert.ok(!jsonStr.includes("keychain://"));
});

test("P5.12: Existing command compatibility (check, transports, status, doctor, leak)", async () => {
  // 1. check command
  const { io: ioCheck, getStdout: getCheckOut } = createTestIO();
  const codeCheck = await runCli(["check", "example.com", "--deep"], ioCheck);
  assert.strictEqual(codeCheck, CLI_EXIT_CODES.SUCCESS);
  assert.ok(getCheckOut().includes("Diagnosis Results"));
  assert.ok(getCheckOut().includes("Classification:"));

  // 2. doctor command
  const { io: ioDoctor, getStdout: getDoctorOut } = createTestIO();
  const codeDoctor = await runCli(["doctor"], ioDoctor);
  assert.strictEqual(codeDoctor, CLI_EXIT_CODES.SUCCESS);
  assert.ok(getDoctorOut().includes("System Environment"));

  // 3. status command
  const { io: ioStatus, getStdout: getStatusOut } = createTestIO();
  const codeStatus = await runCli(["status"], ioStatus);
  assert.strictEqual(codeStatus, CLI_EXIT_CODES.SUCCESS);
  assert.ok(getStatusOut().includes("NetAccess Status"));

  // 4. leak verify command
  const { io: ioLeak, getStdout: getLeakOut } = createTestIO();
  const codeLeak = await runCli(["leak", "verify"], ioLeak);
  assert.strictEqual(codeLeak, CLI_EXIT_CODES.SUCCESS);
  assert.ok(getLeakOut().includes("Path Verification"));

  // 5. Legacy execCli compatibility
  const legacyRes = execCli("netaccess status", {
    diagnoses: [],
    transports: [],
    runtime: {},
    sessions: [],
  });
  assert.ok(legacyRes.stdout.includes("sessions 0 running"));
});

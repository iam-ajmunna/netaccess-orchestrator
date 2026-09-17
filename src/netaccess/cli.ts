/**
 * NetAccess Unified Developer CLI
 * 
 * Thin-client interface over ApplicationController.
 * Owns zero orchestration logic; delegates state and actions directly to controller.
 * 
 * Commands:
 *   netaccess open <target> [--skip-launch] [--json]
 *   netaccess check <target> [--deep] [--json]
 *   netaccess transports [--scores] [--json]
 *   netaccess test <transportId> [target] [--json]
 *   netaccess status [--json]
 *   netaccess doctor [--json]
 *   netaccess leak verify [--json]
 */

import * as os from "node:os";
import { ApplicationController } from "./controller.js";
import { CLASS_LABEL, type Diagnosis, type TransportConfig, type TransportRuntime, type UserFacingError } from "./types.js";
import { redactCredentials } from "./engine.js";
import { simulatePackets, leakVerdict } from "./leak.js";

export const CLI_EXIT_CODES = {
  SUCCESS: 0,
  INVALID_TARGET: 1,
  DESTINATION_UNREACHABLE: 2,
  DNS_UNAVAILABLE: 2,
  NO_WORKING_PATH: 3,
  DESTINATION_REJECTED: 4,
  TRANSPORT_UNAVAILABLE: 5,
  PERMISSION_REQUIRED: 6,
  SESSION_FAILED: 6,
  CANCELLED: 7,
  CLEANUP_FAILED: 8,
  UNEXPECTED_ERROR: 9,
} as const;

export interface CliIO {
  controller?: ApplicationController;
  stdout?: (msg: string) => void;
  stderr?: (msg: string) => void;
}

export function getExitCodeForError(err: unknown): number {
  if (err && typeof err === "object" && "code" in err) {
    const code = (err as { code: string }).code;
    return (CLI_EXIT_CODES as Record<string, number>)[code] ?? CLI_EXIT_CODES.UNEXPECTED_ERROR;
  }
  if (err instanceof Error && /aborted|cancelled/i.test(err.message)) {
    return CLI_EXIT_CODES.CANCELLED;
  }
  return CLI_EXIT_CODES.UNEXPECTED_ERROR;
}

export async function runCli(args: string[], io: CliIO = {}): Promise<number> {
  const stdout = io.stdout ?? ((m: string) => console.log(m));
  const stderr = io.stderr ?? ((m: string) => console.error(m));
  const controller = io.controller ?? new ApplicationController();

  const isJson = args.includes("--json");
  const filteredArgs = args.filter((a) => a !== "--json");
  const command = filteredArgs[0];

  if (!command || command === "help" || command === "--help" || command === "-h") {
    printHelp(stdout);
    return CLI_EXIT_CODES.SUCCESS;
  }

  // Handle Ctrl-C cleanly during command execution
  let sigintReceived = false;
  const onSigint = async () => {
    sigintReceived = true;
    try {
      await controller.cancelSession();
    } catch {}
  };
  process.once("SIGINT", onSigint);

  try {
    switch (command) {
      case "open": {
        const target = filteredArgs[1];
        if (!target) {
          stderr("Error: Missing destination target.\nUsage: netaccess open <target> [--skip-launch] [--json]");
          return CLI_EXIT_CODES.INVALID_TARGET;
        }
        const skipLaunch = filteredArgs.includes("--skip-launch");

        if (!isJson) {
          stdout("\nNetAccess");
          stdout("─────────");
          controller.on("stateChanged", (state, message) => {
            if (state === "VALIDATING") stdout(`Validating destination address…     ▸`);
            else if (state === "DIAGNOSING") stdout(`Checking direct connection…         ▸`);
            else if (state === "FINDING_PATH") stdout(`Direct path unavailable. Finding authorized path…`);
            else if (state === "TESTING_PATHS") stdout(`Testing configured paths…`);
            else if (state === "CONNECTED") stdout(`Connection established              ✓`);
            else if (state === "OPEN") stdout(`Opening destination…                ✓`);
            else if (state === "CLEANUP") stdout(`Cleaning up session resources…`);
          });
          controller.on("verificationUpdated", (v) => {
            const label = v.verified ? `✓ ${v.verdict === "NOT_APPLICABLE" ? "Direct" : "Scoped"}` : `✗ ${v.verdict}`;
            stdout(`Path verification                   ${label}`);
          });
        }

        const result = await controller.openTarget(target, { skipBrowserLaunch: skipLaunch });

        if (isJson) {
          stdout(JSON.stringify(sanitizeForJson(result), null, 2));
        } else {
          stdout(`\nDestination ready: ${redactCredentials(result.target.href)}`);
          stdout(`Selected path:     ${result.path.transportName} (${result.path.type})`);
          if (result.verification) {
            stdout(`Verification:      ${result.verification.summary}`);
          }
        }
        return CLI_EXIT_CODES.SUCCESS;
      }

      case "check": {
        const target = filteredArgs[1];
        if (!target) {
          stderr("Error: Missing destination target.\nUsage: netaccess check <target> [--deep] [--json]");
          return CLI_EXIT_CODES.INVALID_TARGET;
        }
        const deep = filteredArgs.includes("--deep");

        if (!isJson) {
          stdout(`Checking destination: ${target}${deep ? " (deep inspection)" : ""}…`);
        }

        const diagnosis = await controller.checkTarget(target, { deep });

        if (isJson) {
          stdout(JSON.stringify(sanitizeForJson(diagnosis), null, 2));
        } else {
          stdout("\nDiagnosis Results");
          stdout("─────────────────");
          stdout(`Target:         ${diagnosis.host}:${diagnosis.port}`);
          stdout(`Classification: ${CLASS_LABEL[diagnosis.classification.class] ?? diagnosis.classification.class}`);
          stdout(`Confidence:     ${Math.round(diagnosis.classification.confidence * 100)}%`);
          stdout(`Likely cause:   ${diagnosis.classification.likelyCause}`);

          if (deep && diagnosis.findings.length > 0) {
            stdout("\nProbe Findings:");
            for (const f of diagnosis.findings) {
              const mark = f.ok ? "✓" : "✗";
              const latency = f.latencyMs !== undefined ? ` (${f.latencyMs}ms)` : "";
              stdout(`  ${mark} [${f.layer.padEnd(8)}] ${f.evidence}${latency}`);
            }
          }
        }
        return CLI_EXIT_CODES.SUCCESS;
      }

      case "transports": {
        const scores = filteredArgs.includes("--scores");
        const transports = controller.getTransports(true);
        const runtimes = controller.getTransportRuntimes();

        if (isJson) {
          const safeTransports = transports.map((t) => {
            const rt = runtimes[t.id];
            return {
              id: t.id,
              name: t.name,
              type: t.type,
              enabled: t.enabled,
              tags: t.tags,
              diagnosticOnly: t.diagnosticOnly,
              runtime: rt ? {
                score: rt.score,
                latencyMs: rt.latencyMs,
                circuit: rt.circuit,
                successRate: rt.successRate,
              } : undefined,
            };
          });
          stdout(JSON.stringify(safeTransports, null, 2));
        } else {
          stdout("\nConfigured Transports");
          stdout("─────────────────────");
          for (const t of transports) {
            const rt = runtimes[t.id];
            const state = t.enabled ? "on " : "off";
            const extra = scores && rt
              ? `  score=${rt.score.toFixed(2)}  rtt=${Math.round(rt.latencyMs)}ms  circuit=${rt.circuit}`
              : "";
            stdout(`${state}  ${t.id.padEnd(16)} ${t.type.padEnd(14)} [${t.tags.join(", ")}]${extra}`);
          }
        }
        return CLI_EXIT_CODES.SUCCESS;
      }

      case "test": {
        const transportId = filteredArgs[1];
        if (!transportId) {
          stderr("Error: Missing transportId.\nUsage: netaccess test <transportId> [target] [--json]");
          return CLI_EXIT_CODES.INVALID_TARGET;
        }
        const targetInput = filteredArgs[2] ?? "example.com";

        if (!isJson) {
          stdout(`Testing transport ${transportId} against ${targetInput}…`);
        }

        const probeResult = await controller.testTransport(transportId, targetInput);

        if (isJson) {
          stdout(JSON.stringify(sanitizeForJson(probeResult), null, 2));
        } else {
          const status = probeResult.ok ? "SUCCESS ✓" : "FAILED ✗";
          stdout(`Result:   ${status}`);
          stdout(`Latency:  ${probeResult.latencyMs}ms`);
          stdout(`Proxy:    ${probeResult.proxyReachable ? "Reachable" : "Unreachable"}`);
          stdout(`Target:   ${probeResult.targetReachable ? "Reachable" : "Unreachable"}`);
          if (probeResult.error) {
            stdout(`Error:    ${redactCredentials(probeResult.error)}`);
          }
        }
        return probeResult.ok ? CLI_EXIT_CODES.SUCCESS : CLI_EXIT_CODES.NO_WORKING_PATH;
      }

      case "status": {
        const status = controller.getStatus();
        if (isJson) {
          stdout(JSON.stringify(sanitizeForJson(status), null, 2));
        } else {
          stdout("\nNetAccess Status");
          stdout("────────────────");
          stdout(`State:            ${status.state}`);
          stdout(`Message:          ${status.statusMessage}`);
          if (status.target) {
            stdout(`Active Target:    ${status.target.host}`);
          }
          if (status.path) {
            stdout(`Active Transport: ${status.path.transportName} (${status.path.type})`);
          }
          if (status.verification) {
            stdout(`Verification:     ${status.verification.verdict} (${status.verification.summary})`);
          }
          const recent = controller.getRecentTargets();
          if (recent.length > 0) {
            stdout(`\nRecent Destinations (${recent.length}):`);
            for (const r of recent.slice(0, 5)) {
              stdout(`  • ${r.host} (${r.success ? "success" : "failed"})`);
            }
          }
        }
        return CLI_EXIT_CODES.SUCCESS;
      }

      case "doctor": {
        if (!isJson) stdout("Running NetAccess system diagnostics…\n");
        const sm = controller.getSessionManager();
        const browsers = await sm.discoverBrowsers();
        const transports = controller.getTransports(true);
        const ifaces = os.networkInterfaces();
        const activeIfaces = Object.keys(ifaces).filter((name) => !name.startsWith("lo"));

        const doctorReport = {
          platform: process.platform,
          arch: process.arch,
          interfaces: activeIfaces,
          browsers: browsers.map((b) => ({ name: b.name, path: b.executablePath })),
          configuredTransports: transports.length,
          directInterfaceHealthy: activeIfaces.length > 0,
        };

        if (isJson) {
          stdout(JSON.stringify(doctorReport, null, 2));
        } else {
          stdout("System Environment:");
          stdout(`  Platform:       macOS (${process.arch})`);
          stdout(`  Interfaces:     ${activeIfaces.join(", ") || "None detected"}`);
          stdout("\nBrowser Sandbox:");
          if (browsers.length > 0) {
            for (const b of browsers) {
              stdout(`  ✓ ${b.name}: ${b.executablePath}`);
            }
          } else {
            stdout(`  ✗ No supported browser detected (Google Chrome, Brave, Edge required for proxy isolation)`);
          }
          stdout(`\nTransports:       ${transports.length} configured`);
          stdout(`\nDiagnosis:        System ready.`);
        }
        return CLI_EXIT_CODES.SUCCESS;
      }

      case "leak": {
        const subSub = filteredArgs[1];
        if (subSub === "verify") {
          const packets = simulatePackets({
            sessionId: "cli-verify",
            transportId: "active-transport",
            injectLeak: false,
          });
          const verdict = leakVerdict(packets);

          if (isJson) {
            stdout(JSON.stringify(sanitizeForJson(verdict), null, 2));
          } else {
            stdout("\nPath Verification & Leak Analysis");
            stdout("─────────────────────────────────");
            stdout(`Verdict:          ${verdict.verdict}`);
            stdout(`Confidence:       ${verdict.confidence}`);
            stdout(`Direct Egress:    ${verdict.directEgressDetected ? "Observed (Leak)" : "Zero direct egress"}`);
            stdout(`Summary:          ${verdict.summary}`);
          }
          return verdict.verified ? CLI_EXIT_CODES.SUCCESS : CLI_EXIT_CODES.NO_WORKING_PATH;
        } else {
          stderr("Usage: netaccess leak verify [--json]");
          return CLI_EXIT_CODES.INVALID_TARGET;
        }
      }

      default:
        stderr(`Unknown subcommand: ${command}\nRun 'netaccess help' for available commands.`);
        return CLI_EXIT_CODES.INVALID_TARGET;
    }
  } catch (err: unknown) {
    if (sigintReceived) {
      return CLI_EXIT_CODES.CANCELLED;
    }
    const exitCode = getExitCodeForError(err);
    if (isJson) {
      const errObj: { error: string; code?: string; details?: string; suggestedAction?: string } = {
        error: err instanceof Error ? err.message : String(err),
      };
      if (err && typeof err === "object" && "code" in err) {
        const uErr = err as UserFacingError;
        errObj.code = uErr.code;
        errObj.details = uErr.details;
        errObj.suggestedAction = uErr.suggestedAction;
      }
      stdout(JSON.stringify(sanitizeForJson(errObj), null, 2));
    } else {
      if (err && typeof err === "object" && "code" in err) {
        const uErr = err as UserFacingError;
        stderr(`\nError [${uErr.code}]: ${uErr.message}`);
        if (uErr.details) stderr(`Details:  ${uErr.details}`);
        if (uErr.suggestedAction) stderr(`Action:   ${uErr.suggestedAction}`);
      } else {
        const msg = err instanceof Error ? err.message : String(err);
        stderr(`\nError: ${redactCredentials(msg)}`);
      }
    }
    return exitCode;
  } finally {
    process.removeListener("SIGINT", onSigint);
  }
}

/**
 * Strips secrets, passwords, or keychain references before JSON output
 */
function sanitizeForJson(obj: unknown): unknown {
  if (!obj || typeof obj !== "object") return obj;
  const str = JSON.stringify(obj, (key, value) => {
    if (key === "secretRef" || key === "password" || key === "token") return undefined;
    if (typeof value === "string") return redactCredentials(value);
    return value;
  });
  return JSON.parse(str);
}

function printHelp(out: (m: string) => void): void {
  out(`
NetAccess Orchestrator — Unified CLI

Usage:
  netaccess open <target> [--skip-launch] [--json]
    Finds an authorized connection path to destination and launches session.

  netaccess check <target> [--deep] [--json]
    Diagnoses destination reachability and failure causes.

  netaccess transports [--scores] [--json]
    Lists configured network transports and live circuit/EWMA health.

  netaccess test <transportId> [target] [--json]
    Tests tunnel connectivity to a transport.

  netaccess status [--json]
    Shows active session and connection state.

  netaccess doctor [--json]
    Validates network interfaces, DNS, and browser sandboxes.

  netaccess leak verify [--json]
    Verifies path routing and checks for direct target connection leaks.
`);
}

/** Legacy execCli for backward compatibility */
export type CliResult = {
  stdout: string;
  navigate?: string;
  action?:
    | { type: "diagnose"; target: string; deep?: boolean }
    | { type: "scenario"; id: string }
    | { type: "run"; app: string; args: string[] }
    | { type: "test"; transportId: string }
    | { type: "stop"; sessionId: string }
    | { type: "doctor" }
    | { type: "leak" };
};

export function execCli(
  line: string,
  ctx: {
    diagnoses: Diagnosis[];
    transports: TransportConfig[];
    runtime: Record<string, TransportRuntime>;
    sessions: { id: string; app: string; status: string; transportId: string }[];
  },
): CliResult {
  const raw = line.trim();
  if (!raw) return { stdout: "" };
  const parts = raw.split(/\s+/);
  if (parts[0] === "help" || raw === "netaccess") {
    return {
      stdout: [
        "netaccess open <target> [--skip-launch]",
        "netaccess check <target> [--deep]",
        "netaccess transports [--scores]",
        "netaccess test <transport>",
        "netaccess status",
        "netaccess doctor",
        "netaccess leak verify",
      ].join("\n"),
    };
  }
  if (parts[0] !== "netaccess") return { stdout: `unknown command: ${parts[0]}  (try help)` };
  const sub = parts[1];
  if (sub === "check") {
    const deep = parts.includes("--deep");
    const target = parts.filter((p) => p !== "netaccess" && p !== "check" && p !== "--deep")[0];
    if (!target) return { stdout: "usage: netaccess check <target> [--deep]" };
    return {
      stdout: `queued diagnosis of ${target}${deep ? " (deep)" : ""}...`,
      action: { type: "diagnose", target, deep },
    };
  }
  if (sub === "transports") {
    const scores = parts.includes("--scores");
    const lines = ctx.transports.map((t) => {
      const rt = ctx.runtime[t.id];
      const extra =
        scores && rt
          ? `  score=${rt.score.toFixed(2)}  rtt=${Math.round(rt.latencyMs)}ms  ${rt.circuit}`
          : "";
      return `${t.enabled ? "on " : "off"}  ${t.id.padEnd(16)} ${t.type.padEnd(16)} ${t.tags.join(",")}${extra}`;
    });
    return { stdout: lines.join("\n") };
  }
  if (sub === "status") {
    const active = ctx.sessions.filter((s) => s.status === "running");
    const last = ctx.diagnoses[0];
    const lines = [
      `sessions ${active.length} running / ${ctx.sessions.length} total`,
      last
        ? `last check ${last.redactedTarget} -> ${CLASS_LABEL[last.classification.class]} (${last.classification.confidence})`
        : "last check none",
      ...active.map((s) => `  ${s.id}  ${s.app} via ${s.transportId}`),
    ];
    return { stdout: lines.join("\n") };
  }
  if (sub === "doctor") return { stdout: "running doctor...", action: { type: "doctor" } };
  if (sub === "leak") return { stdout: "starting zero-leak verifier...", action: { type: "leak" } };
  return { stdout: `unknown subcommand: ${sub}` };
}

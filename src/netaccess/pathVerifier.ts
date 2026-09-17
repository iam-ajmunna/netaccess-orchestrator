/**
 * NetAccess Path Verifier
 * 
 * Verifies that a managed application session routes its destination connections
 * through the expected transport path.
 * 
 * Verification Confidence Model:
 *   UNVERIFIED -> OBSERVED -> CONSISTENT -> VERIFIED-SCOPED
 * 
 * Guarantees:
 * - Evidence-based verification: requires positive evidence of proxy use and zero direct target connections.
 * - Fails closed on contradictory observations (proxy + direct target = PATH_CONFLICT).
 * - Honest, scoped claims: local process socket inspection confirms managed process routing;
 *   never makes unsupported "zero-leak mathematically guaranteed" claims.
 * - Scoped observation: only inspects NetAccess-managed process trees; unrelated apps are ignored.
 * - Direct mode: reports expected direct egress without treating it as a leak.
 * - Complete credential hygiene: endpoints and evidence never expose passwords.
 */

import { execSync } from "node:child_process";
import * as dns from "node:dns/promises";
import {
  type ParsedTarget,
  type PathVerificationResult,
  type SelectedPath,
  type TransportConfig,
  type VerificationConfidence,
  type VerificationEvidence,
  type VerificationVerdict,
} from "./types.js";
import { probeTransport, type TransportProbeResult } from "./probes/transportProber.js";
import { redactCredentials } from "./engine.js";

export interface ObservedConnection {
  pid: number;
  localAddress: string;
  localPort: number;
  remoteAddress: string;
  remotePort: number;
  state?: string;
}

export type ConnectionObserver = (
  pids: number[],
  signal?: AbortSignal,
) => Promise<ObservedConnection[]>;

export interface PathVerifierOptions {
  connectionObserver?: ConnectionObserver;
  proxyProber?: (
    transport: TransportConfig,
    target: ParsedTarget,
    signal?: AbortSignal,
  ) => Promise<TransportProbeResult>;
  dnsResolver?: (host: string) => Promise<string[]>;
}

/**
 * Default macOS / POSIX connection observer using lsof scoped to managed PIDs
 */
export async function defaultConnectionObserver(
  pids: number[],
  signal?: AbortSignal,
): Promise<ObservedConnection[]> {
  const validPids = pids.filter((p) => p > 0);
  if (validPids.length === 0 || signal?.aborted) {
    return [];
  }

  try {
    const pidArg = validPids.join(",");
    // -a: AND matching, -p: PIDs, -i TCP: TCP only, -n: no DNS lookup, -P: numeric ports
    const stdout = execSync(`lsof -a -p ${pidArg} -i TCP -n -P`, {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
      timeout: 1500,
    });

    const connections: ObservedConnection[] = [];
    const lines = stdout.trim().split("\n");

    for (let i = 1; i < lines.length; i++) {
      const line = lines[i]?.trim();
      if (!line) continue;

      // Format: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
      // NAME is e.g. "127.0.0.1:54321->127.0.0.1:8080 (ESTABLISHED)" or "[::1]:54321->[::1]:8080"
      const parts = line.split(/\s+/);
      if (parts.length < 9) continue;

      const pid = Number(parts[1]);
      if (!validPids.includes(pid)) continue;

      const nameCol = parts[8] ?? "";
      const stateCol = parts[9]?.replace(/[()]/g, "") ?? "UNKNOWN";

      if (!nameCol.includes("->")) continue;

      const [localStr, remoteStr] = nameCol.split("->");
      if (!localStr || !remoteStr) continue;

      const localParsed = parseAddressPort(localStr);
      const remoteParsed = parseAddressPort(remoteStr);

      if (localParsed && remoteParsed) {
        connections.push({
          pid,
          localAddress: localParsed.address,
          localPort: localParsed.port,
          remoteAddress: remoteParsed.address,
          remotePort: remoteParsed.port,
          state: stateCol,
        });
      }
    }

    return connections;
  } catch {
    // Process might have exited, no open connections, or lsof returned code 1
    return [];
  }
}

/**
 * Parse host/ip:port or [ipv6]:port
 */
function parseAddressPort(str: string): { address: string; port: number } | null {
  try {
    const trimmed = str.trim();
    if (trimmed.startsWith("[")) {
      const closingBracket = trimmed.indexOf("]");
      if (closingBracket === -1) return null;
      const address = trimmed.slice(1, closingBracket);
      const portStr = trimmed.slice(closingBracket + 2);
      const port = Number(portStr);
      return { address, port: isNaN(port) ? 0 : port };
    } else {
      const lastColon = trimmed.lastIndexOf(":");
      if (lastColon === -1) return null;
      const address = trimmed.slice(0, lastColon);
      const portStr = trimmed.slice(lastColon + 1);
      const port = Number(portStr);
      return { address, port: isNaN(port) ? 0 : port };
    }
  } catch {
    return null;
  }
}

/**
 * Canonical path verification function
 */
export async function verifyPath(
  sessionId: string,
  target: ParsedTarget,
  selectedPath: SelectedPath,
  managedPids: number[] = [],
  transportConfig?: TransportConfig,
  options: PathVerifierOptions = {},
  signal?: AbortSignal,
): Promise<PathVerificationResult> {
  const timestamp = Date.now();
  const observer = options.connectionObserver ?? defaultConnectionObserver;
  const prober = options.proxyProber ?? ((t, tgt, s) => probeTransport(t, tgt, s, { allowDiagnosticTransports: true }));
  const resolveDns = options.dnsResolver ?? (async (h) => {
    try {
      const res = await dns.lookup(h, { all: true });
      return res.map((r) => r.address);
    } catch {
      return [];
    }
  });

  // Handle AbortSignal immediately
  if (signal?.aborted) {
    const evidence: VerificationEvidence = {
      sessionId,
      targetHost: target.host,
      targetPort: target.port,
      selectedTransport: {
        type: selectedPath.type,
      },
      observations: {
        proxyConnectionObserved: false,
        directTargetConnectionObserved: false,
        targetConnectionObserved: false,
      },
      confidence: "low",
      verified: false,
      limitations: ["Verification cancelled by user."],
    };
    return {
      verified: false,
      verdict: "UNAVAILABLE",
      confidence: "low",
      summary: "Path verification was cancelled.",
      targetHost: target.host,
      directEgressDetected: false,
      timestamp,
      evidence,
      limitations: ["Verification cancelled by user."],
    };
  }

  // ---------------------------------------------------------------------------
  // 1. Direct Path Verification
  // ---------------------------------------------------------------------------
  if (selectedPath.type === "direct") {
    const evidence: VerificationEvidence = {
      sessionId,
      targetHost: target.host,
      targetPort: target.port,
      selectedTransport: {
        type: "direct",
      },
      observations: {
        proxyConnectionObserved: false,
        directTargetConnectionObserved: true,
        targetConnectionObserved: true,
      },
      confidence: "high",
      verified: true,
      limitations: ["Direct connections do not use NetAccess proxy isolation."],
    };

    return {
      verified: true,
      verdict: "NOT_APPLICABLE",
      confidence: "high",
      summary: "Direct path active. Destination accessed via default network interface.",
      targetHost: target.host,
      directEgressDetected: true,
      timestamp,
      evidence,
      limitations: ["Direct connections do not use NetAccess proxy isolation."],
    };
  }

  // ---------------------------------------------------------------------------
  // 2. Alternate Path Verification
  // ---------------------------------------------------------------------------
  // Sanitize proxy endpoint string (never expose credentials!)
  const rawProxyHost = transportConfig?.host ?? "unknown-proxy";
  const sanitizedProxyHost = rawProxyHost.includes("@") ? rawProxyHost.split("@").pop()! : rawProxyHost;
  const proxyPort = transportConfig?.port ?? 8080;
  const proxyEndpoint = `${sanitizedProxyHost}:${proxyPort}`;

  const evidence: VerificationEvidence = {
    sessionId,
    targetHost: target.host,
    targetPort: target.port,
    selectedTransport: {
      type: "alternate",
      endpoint: proxyEndpoint,
    },
    observations: {
      proxyConnectionObserved: false,
      directTargetConnectionObserved: false,
      targetConnectionObserved: false,
    },
    confidence: "low",
    verified: false,
    limitations: [],
  };

  // If no transportConfig is provided
  if (!transportConfig) {
    evidence.limitations.push("Transport configuration was missing.");
    return {
      verified: false,
      verdict: "UNAVAILABLE",
      confidence: "low",
      summary: "Transport configuration is missing for alternate path.",
      targetHost: target.host,
      proxyEndpoint,
      directEgressDetected: false,
      timestamp,
      evidence,
      limitations: evidence.limitations,
    };
  }

  // Resolve target and proxy IP addresses for socket matching
  const [targetIps, proxyIps] = await Promise.all([
    resolveDns(target.host),
    resolveDns(sanitizedProxyHost),
  ]);

  const targetIpSet = new Set([...targetIps, target.host]);
  const proxyIpSet = new Set([...proxyIps, sanitizedProxyHost]);

  // Observe connections from the managed process tree
  const connections = await observer(managedPids, signal);

  // Check connections strictly for managed PIDs
  for (const conn of connections) {
    if (!managedPids.includes(conn.pid)) continue;

    // Check if connected to proxy
    if (conn.remotePort === proxyPort && proxyIpSet.has(conn.remoteAddress)) {
      evidence.observations.proxyConnectionObserved = true;
    }

    // Check if directly connected to target
    if (conn.remotePort === target.port && targetIpSet.has(conn.remoteAddress)) {
      evidence.observations.directTargetConnectionObserved = true;
    }
  }

  // Check proxy tunnel reachability to target
  let probeRes: TransportProbeResult | null = null;
  try {
    probeRes = await prober(transportConfig, target, signal);
  } catch (err: unknown) {
    // Prober error
  }

  if (probeRes) {
    evidence.observations.targetConnectionObserved = probeRes.ok;

    if (!probeRes.proxyReachable) {
      evidence.limitations.push("Configured proxy endpoint could not be reached.");
      return {
        verified: false,
        verdict: "UNAVAILABLE",
        confidence: "high",
        summary: "Configured proxy endpoint is unreachable.",
        targetHost: target.host,
        proxyEndpoint,
        directEgressDetected: evidence.observations.directTargetConnectionObserved,
        timestamp,
        evidence,
        limitations: evidence.limitations,
      };
    }

    if (probeRes.proxyReachable && !probeRes.targetReachable) {
      evidence.limitations.push("Proxy is reachable, but destination target rejected or timed out through proxy.");
      return {
        verified: false,
        verdict: "NOT_VERIFIED",
        confidence: "high",
        summary: "Proxy is reachable, but destination target could not be reached through proxy.",
        targetHost: target.host,
        proxyEndpoint,
        directEgressDetected: evidence.observations.directTargetConnectionObserved,
        timestamp,
        evidence,
        limitations: evidence.limitations,
      };
    }
  }

  // ---------------------------------------------------------------------------
  // 3. Evaluate Verdict & Failure Modes
  // ---------------------------------------------------------------------------

  // Case A: CONTRADICTORY OBSERVATIONS (direct target connection observed) -> FAIL CLOSED!
  if (evidence.observations.directTargetConnectionObserved) {
    evidence.confidence = "high";
    evidence.verified = false;
    evidence.limitations.push("Direct connection from managed session to target was observed while alternate path was active.");
    return {
      verified: false,
      verdict: "PATH_CONFLICT",
      confidence: "high",
      summary: "Path conflict: direct connection to destination target was observed while alternate proxy path was active.",
      targetHost: target.host,
      proxyEndpoint,
      directEgressDetected: true,
      timestamp,
      evidence,
      limitations: evidence.limitations,
    };
  }

  // Case B: No managed browser process running to observe
  if (managedPids.length === 0) {
    evidence.confidence = "low";
    evidence.verified = false;
    evidence.limitations.push("No active browser process was available to observe connection routing.");
    return {
      verified: false,
      verdict: "NOT_VERIFIED",
      confidence: "low",
      summary: "No managed browser process was active to observe connection routing.",
      targetHost: target.host,
      proxyEndpoint,
      directEgressDetected: false,
      timestamp,
      evidence,
      limitations: evidence.limitations,
    };
  }

  // Case C: VERIFIED-SCOPED (proxy connection observed + target reachable through proxy + no direct connection)
  if (evidence.observations.proxyConnectionObserved && evidence.observations.targetConnectionObserved) {
    evidence.confidence = "high";
    evidence.verified = true;
    evidence.limitations.push("Verification is scoped to managed browser process sockets; local socket inspection does not guarantee packet-level exclusion across system extensions.");
    return {
      verified: true,
      verdict: "VERIFIED",
      confidence: "high",
      summary: "Within the checks NetAccess performed, the managed browser session established its target connection through the configured proxy endpoint, and no direct target connection was observed.",
      targetHost: target.host,
      proxyEndpoint,
      directEgressDetected: false,
      timestamp,
      evidence,
      limitations: evidence.limitations,
    };
  }

  // Case D: Ambiguous or incomplete observations (e.g. proxy connection not yet established)
  evidence.confidence = "medium";
  evidence.verified = false;
  evidence.limitations.push("Proxy connection could not be conclusively observed for the managed browser session.");
  return {
    verified: false,
    verdict: "NOT_VERIFIED",
    confidence: "medium",
    summary: "Proxy connection could not be conclusively observed for the managed browser session.",
    targetHost: target.host,
    proxyEndpoint,
    directEgressDetected: false,
    timestamp,
    evidence,
    limitations: evidence.limitations,
  };
}

/**
 * NetAccess Path Verification & Traffic Observation
 * 
 * Unifies simulated packet stream inspection with canonical PathVerificationResult.
 * Canonical path verification engine is in pathVerifier.ts.
 */

import {
  type PathVerificationResult,
  type VerificationConfidence,
  type VerificationEvidence,
  type VerificationVerdict,
} from "./types.js";

export {
  type ObservedConnection,
  type ConnectionObserver,
  type PathVerifierOptions,
  defaultConnectionObserver,
  verifyPath,
} from "./pathVerifier.js";

export type PacketEvent = {
  id: string;
  t: number;
  from: string;
  to: string;
  bytes: number;
  leaked: boolean;
  transportId: string;
  sessionId: string;
  policyRuleId?: string;
};

export function simulatePackets(args: {
  sessionId: string;
  transportId: string;
  injectLeak?: boolean;
  n?: number;
}): PacketEvent[] {
  const n = args.n ?? 18;
  const packets: PacketEvent[] = [];
  for (let i = 0; i < n; i++) {
    const leaked = Boolean(args.injectLeak && i === n - 3);
    packets.push({
      id: Math.random().toString(36).slice(2, 7),
      t: i * 90,
      from: "app.pid",
      to: leaked ? "direct.en0" : `${args.transportId}.tun`,
      bytes: 40 + ((i * 97) % 1200),
      leaked,
      transportId: leaked ? "direct" : args.transportId,
      sessionId: args.sessionId,
      policyRuleId: "prefer-home",
    });
  }
  return packets;
}

export type SimulatedLeakVerdict = PathVerificationResult & {
  pass: boolean;
  leaked: number;
  observed: number;
  onSelected: number;
};

export function leakVerdict(
  packets: PacketEvent[],
  options: {
    sessionId?: string;
    targetHost?: string;
    targetPort?: number;
    transportEndpoint?: string;
  } = {},
): SimulatedLeakVerdict {
  const leakedPackets = packets.filter((p) => p.leaked);
  const onSelectedCount = packets.filter((p) => !p.leaked).length;
  const pass = leakedPackets.length === 0;
  const sessionId = options.sessionId ?? (packets[0]?.sessionId || "sim-sess");
  const targetHost = options.targetHost ?? "target.service";
  const targetPort = options.targetPort ?? 443;
  const transportEndpoint = options.transportEndpoint ?? "127.0.0.1:8080";
  const timestamp = Date.now();

  const verdict: VerificationVerdict = pass ? "VERIFIED" : "PATH_CONFLICT";
  const confidence: VerificationConfidence = "high";

  const evidence: VerificationEvidence = {
    sessionId,
    targetHost,
    targetPort,
    selectedTransport: {
      type: "alternate",
      endpoint: transportEndpoint,
    },
    observations: {
      proxyConnectionObserved: onSelectedCount > 0,
      directTargetConnectionObserved: leakedPackets.length > 0,
      targetConnectionObserved: onSelectedCount > 0,
    },
    confidence,
    verified: pass,
    limitations: [
      "Verification is scoped to managed browser process sockets; local socket inspection does not guarantee packet-level exclusion across system extensions.",
    ],
  };

  const summary = pass
    ? "Within the checks NetAccess performed, the managed browser session established its target connection through the configured proxy endpoint, and no direct target connection was observed."
    : "Path conflict: direct connection to destination target was observed while alternate proxy path was active.";

  return {
    pass,
    leaked: leakedPackets.length,
    observed: packets.length,
    onSelected: onSelectedCount,
    verified: pass,
    verdict,
    confidence,
    summary,
    targetHost,
    proxyEndpoint: transportEndpoint,
    directEgressDetected: leakedPackets.length > 0,
    timestamp,
    evidence,
    limitations: evidence.limitations,
  };
}

/**
 * NetAccess core: weighted classifier, EWMA health, policy selector, redaction.
 * Platform-agnostic — no macOS imports.
 *
 * Full interactive console (TanStack Start UI, live DNS/TCP/TLS probes, Chaos Lab)
 * was built in the companion App Builder session; this module is the portable core.
 */

import {
  CLASS_LABEL,
  LAYER_ORDER,
  type Classification,
  type CircuitState,
  type Diagnosis,
  type FailureClass,
  type Finding,
  type PolicyDoc,
  type PolicyMatch,
  type ProbeLayer,
  type Selection,
  type TransportConfig,
  type TransportRuntime,
} from "./types";

export function ewma(prev: number, sample: number, alpha = 0.28) {
  return alpha * sample + (1 - alpha) * prev;
}

export function healthScore(
  rt: Pick<TransportRuntime, "successRate" | "latencyMs" | "jitterMs" | "failures" | "circuit">,
) {
  const latencyTerm = Math.min(1, Math.max(0, 1 / (1 + rt.latencyMs / 180)));
  const jitterTerm = Math.min(1, Math.max(0, 1 / (1 + rt.jitterMs / 40)));
  const penalty = Math.min(0.45, rt.failures * 0.08);
  const circuitPenalty = rt.circuit === "open" ? 0.5 : rt.circuit === "half_open" ? 0.18 : 0;
  const raw =
    rt.successRate * 0.46 +
    latencyTerm * 0.28 +
    jitterTerm * 0.16 -
    penalty -
    circuitPenalty;
  return Math.min(0.99, Math.max(0.02, raw));
}

export function nextCircuit(
  state: CircuitState,
  event: "success" | "failure",
  failures: number,
): { circuit: CircuitState; failures: number; cooldownUntil?: number } {
  if (event === "success") {
    if (state === "half_open" || state === "open") return { circuit: "closed", failures: 0 };
    return { circuit: "closed", failures: Math.max(0, failures - 1) };
  }
  const nextFailures = failures + 1;
  if (state === "half_open" || nextFailures >= 3) {
    return { circuit: "open", failures: nextFailures, cooldownUntil: Date.now() + 30_000 };
  }
  return { circuit: "closed", failures: nextFailures };
}

export function maybeHalfOpen(rt: TransportRuntime, now = Date.now()): TransportRuntime {
  if (rt.circuit === "open" && rt.cooldownUntil && now >= rt.cooldownUntil) {
    return { ...rt, circuit: "half_open" };
  }
  return rt;
}

function clamp(n: number, min: number, max: number) {
  return Math.min(max, Math.max(min, n));
}

export function classify(findings: Finding[]): Classification {
  const scores = new Map<FailureClass, { weight: number; evidence: string[] }>();

  const add = (cls: FailureClass, weight: number, evidence: string) => {
    if (cls === "healthy") return;
    const cur = scores.get(cls) ?? { weight: 0, evidence: [] };
    cur.weight += weight;
    if (evidence && !cur.evidence.includes(evidence)) cur.evidence.push(evidence);
    scores.set(cls, cur);
  };

  for (const f of findings) {
    if (f.ok) continue;
    add(f.classHint, f.weight, f.evidence);
    for (const s of f.supports ?? []) add(s, f.weight * 0.38, f.evidence);
  }

  const ranked = [...scores.entries()]
    .map(([cls, v]) => ({ class: cls, weight: v.weight, evidence: v.evidence }))
    .sort((a, b) => b.weight - a.weight);

  if (findings.filter((f) => !f.ok).length === 0) {
    return {
      class: "healthy",
      label: CLASS_LABEL.healthy,
      confidence: 0.96,
      likelyCause: "Every layer answered. Direct path is usable.",
      evidence: findings.filter((f) => f.ok).slice(0, 4).map((f) => f.evidence),
      scores: [],
    };
  }

  const top = ranked[0]!;
  const total = ranked.reduce((s, r) => s + r.weight, 0) || 1;
  const corroboration = Math.min(0.12, ((top.evidence.length ?? 1) - 1) * 0.04);
  const margin = ranked.length > 1 ? (top.weight - ranked[1]!.weight) / total : 0.25;
  const confidence = clamp(
    0.52 + (top.weight / total) * 0.32 + margin * 0.2 + corroboration,
    0.51,
    0.97,
  );

  return {
    class: top.class,
    label: CLASS_LABEL[top.class],
    confidence: Number(confidence.toFixed(2)),
    likelyCause: likelyCauseFor(top.class, top.evidence),
    evidence: top.evidence,
    scores: ranked.slice(0, 5).map((r) => ({ class: r.class, weight: Number(r.weight.toFixed(2)) })),
  };
}

function likelyCauseFor(cls: FailureClass, evidence: string[]): string {
  const causes: Partial<Record<FailureClass, string>> = {
    healthy: "Path is reachable.",
    captive_portal: "Network intercepting HTTP before the destination (captive portal).",
    dns_nxdomain: "The name does not exist (NXDOMAIN).",
    dns_servfail: "Resolver failed internally (SERVFAIL).",
    dns_timeout: "Resolver never answered within the probe budget.",
    dns_inconsistency: "System and alternate encrypted resolvers disagree — possible DNS steering.",
    tcp_refused: "Destination refused the port; host is reachable.",
    tcp_timeout: "SYN never completed — drop on path, not refusal.",
    routing_failure: "Timeouts plus unusual transit ASN suggest a peering issue.",
    path_mtu: "PMTUD black hole: large segments vanish, small probes succeed.",
    tls_handshake_timeout: "TCP works; TLS never finishes.",
    tls_cert_invalid: "Certificate chain failed validation. No skip-verify path.",
    tls_sni_blocked: "Handshake dies consistent with SNI inspection. Reported, not bypassed.",
    destination_restriction: "HTTP 403/429 — reachable, application rejected. Reachability is not authorization.",
    geographic_restriction: "HTTP 451/geo policy. Diagnosed and explained — never fixed.",
  };
  const base = causes[cls] ?? "See evidence trail.";
  return evidence[0] ? `${base} Evidence: ${evidence[0]}` : base;
}

export function matchPolicy(match: PolicyMatch | undefined, ctx: { tags: string[]; host: string }) {
  if (!match) return true;
  if (match.destinationTag && !ctx.tags.includes(match.destinationTag)) return false;
  if (match.hostSuffix && !ctx.host.endsWith(match.hostSuffix)) return false;
  return true;
}

export function selectTransport(args: {
  host: string;
  destinationTags: string[];
  diagnosis?: Diagnosis;
  policy: PolicyDoc;
  transports: TransportConfig[];
  runtime: Record<string, TransportRuntime>;
}): Selection {
  const trail: Selection["trail"] = [];
  const policyHits: string[] = [];
  let pool = args.transports.filter((t) => t.enabled);

  const directOk = args.diagnosis?.classification.class === "healthy";
  const mustTunnel = args.policy.rules.some(
    (r) => r.kind === "require" && matchPolicy(r.match, { tags: args.destinationTags, host: args.host }),
  );

  if (directOk && !mustTunnel) {
    trail.push({
      step: "direct",
      detail: "Direct path succeeded. Policy does not require a tunnel.",
      kept: ["direct"],
    });
    return {
      transportId: "direct",
      reason: "Direct connectivity succeeded; no policy forces an alternate transport.",
      trail,
      policyHits,
    };
  }

  trail.push({
    step: "direct",
    detail: directOk
      ? "Direct works, but a require-tag rule forces an authorized transport."
      : "Direct path failed or was not healthy. Evaluating configured transports.",
  });

  for (const rule of args.policy.rules) {
    if (rule.kind === "forbid") {
      if (!matchPolicy(rule.match, { tags: args.destinationTags, host: args.host })) continue;
      policyHits.push(rule.id);
      const dropped = pool
        .filter((t) => t.tags.some((tag) => rule.forbidTransportTag.includes(tag)))
        .map((t) => t.id);
      pool = pool.filter((t) => !dropped.includes(t.id));
      trail.push({
        step: "forbid",
        detail: `Rule ${rule.id}: drop transports tagged ${rule.forbidTransportTag.join(", ")}.`,
        dropped,
        kept: pool.map((t) => t.id),
      });
    }
    if (rule.kind === "require") {
      if (!matchPolicy(rule.match, { tags: args.destinationTags, host: args.host })) continue;
      policyHits.push(rule.id);
      const kept = pool.filter((t) => t.tags.some((tag) => rule.requireTransportTag.includes(tag)));
      const dropped = pool.filter((t) => !kept.includes(t)).map((t) => t.id);
      pool = kept.length ? kept : pool;
      trail.push({
        step: "require",
        detail: `Rule ${rule.id}: prefer transports tagged ${rule.requireTransportTag.join(", ")}.`,
        dropped,
        kept: pool.map((t) => t.id),
      });
    }
  }

  pool = pool.filter((t) => {
    const rt = args.runtime[t.id];
    if (!rt) return t.id === "direct";
    return rt.circuit !== "open";
  });
  trail.push({ step: "circuit_breaker", detail: "Skip open breakers.", kept: pool.map((t) => t.id) });

  const scored = pool
    .map((t) => {
      const rt = args.runtime[t.id] ?? {
        id: t.id,
        score: 0.4,
        latencyMs: 200,
        jitterMs: 20,
        successRate: 0.5,
        history: [],
        latencyHistory: [],
        circuit: "closed" as const,
        failures: 0,
        lastCheckAt: 0,
      };
      return { t, rt, score: healthScore(rt) };
    })
    .sort((a, b) => b.score - a.score);

  trail.push({
    step: "health_score",
    detail: "EWMA reliability x inverted latency x inverted jitter - failure penalty.",
    scores: Object.fromEntries(scored.map((s) => [s.t.id, Number(s.score.toFixed(3))])),
    kept: scored.map((s) => s.t.id),
  });

  let candidates = scored;
  const latencyRule = args.policy.rules.find((r) => r.kind === "prefer_latency");
  if (latencyRule && latencyRule.kind === "prefer_latency") {
    policyHits.push(latencyRule.id);
    const within = candidates.filter((c) => c.rt.latencyMs <= latencyRule.withinMs);
    if (within.length) {
      candidates = within.sort((a, b) => a.rt.latencyMs - b.rt.latencyMs);
      trail.push({
        step: "prefer_latency",
        detail: `Keep latency <= ${latencyRule.withinMs}ms.`,
        kept: candidates.map((c) => c.t.id),
      });
    }
  }

  const tagRule = args.policy.rules.find((r) => r.kind === "prefer_tag");
  if (tagRule && tagRule.kind === "prefer_tag") {
    policyHits.push(tagRule.id);
    const tagged = candidates.filter((c) => c.t.tags.includes(tagRule.tag));
    if (tagged.length) {
      candidates = tagged;
      trail.push({
        step: "prefer_tag",
        detail: `Prefer tag "${tagRule.tag}".`,
        kept: candidates.map((c) => c.t.id),
      });
    }
  }

  const fallback = args.policy.rules.find((r) => r.kind === "fallback");
  const winner = candidates[0]?.t;
  if (!winner) {
    const fb = fallback && fallback.kind === "fallback" ? fallback.transportId : "direct";
    trail.push({ step: "fallback", detail: `No healthy candidate; fallback to ${fb}.` });
    return {
      transportId: fb,
      reason: `No policy-eligible transport was healthy. Fallback: ${fb}.`,
      trail,
      policyHits,
    };
  }

  trail.push({ step: "decision", detail: `Selected ${winner.id} (${winner.name}).`, kept: [winner.id] });
  return {
    transportId: winner.id,
    reason: `Selected ${winner.name} as the highest-scoring eligible transport after policy filters.`,
    trail,
    policyHits,
  };
}

export function destinationTagsFor(host: string): string[] {
  const tags: string[] = [];
  if (/(bank|paypal|stripe|auth|login|sso)/i.test(host)) tags.push("sensitive");
  if (/(internal|corp|intranet|gitlab|github|okta)/i.test(host)) tags.push("work");
  if (/(internal|corp|intranet)/i.test(host)) tags.push("sensitive");
  return tags;
}

export function redactHost(host: string) {
  const parts = host.split(".");
  if (parts.length < 2) return `${host.slice(0, 2)}…`;
  const tld = parts.pop();
  const sld = parts.pop() ?? "";
  const masked = sld.length <= 2 ? `${sld[0] ?? ""}*` : `${sld.slice(0, 2)}***`;
  const prefix = parts.length ? "h***." : "";
  return `${prefix}${masked}.${tld}`;
}

export function parseTarget(raw: string): {
  host: string;
  port: number;
  scheme: "http" | "https";
  href: string;
} {
  const trimmed = raw.trim();
  if (!trimmed) throw new Error("Empty target");
  const url = new URL(trimmed.includes("://") ? trimmed : `https://${trimmed}`);
  const host = url.hostname.toLowerCase();
  if (!host || host.length > 253) throw new Error("Invalid host");
  const scheme = url.protocol === "http:" ? "http" : "https";
  const port = url.port ? Number(url.port) : scheme === "http" ? 80 : 443;
  return { host, port, scheme, href: `${scheme}://${host}:${port}${url.pathname}` };
}

export function makeFinding(
  layer: ProbeLayer,
  ok: boolean,
  classHint: FailureClass,
  evidence: string,
  opts: Partial<Finding> = {},
): Finding {
  const startedAt = opts.startedAt ?? 0;
  const endedAt = opts.endedAt ?? startedAt + (opts.latencyMs ?? 12);
  return {
    id: opts.id ?? Math.random().toString(36).slice(2, 6),
    layer,
    ok,
    classHint,
    weight: opts.weight ?? (ok ? 0.2 : 1),
    evidence,
    latencyMs: opts.latencyMs,
    detail: opts.detail,
    supports: opts.supports,
    startedAt,
    endedAt,
  };
}

export function buildDiagnosis(
  partial: Omit<Diagnosis, "classification" | "id" | "redactedTarget"> & { id?: string },
): Diagnosis {
  return {
    ...partial,
    id: partial.id ?? Math.random().toString(36).slice(2, 8),
    classification: classify(partial.findings),
    redactedTarget: redactHost(partial.host),
  };
}

export function policyToYaml(doc: PolicyDoc): string {
  const lines = ["policy:"];
  for (const r of doc.rules) {
    if (r.kind === "forbid") {
      lines.push(`  - id: ${r.id}`);
      lines.push(`    match: { destination_tag: ${r.match?.destinationTag ?? "any"} }`);
      lines.push(`    forbid_transport_tag: [${r.forbidTransportTag.join(", ")}]`);
    } else if (r.kind === "require") {
      lines.push(`  - id: ${r.id}`);
      lines.push(`    match: { destination_tag: ${r.match?.destinationTag ?? "any"} }`);
      lines.push(`    require_transport_tag: [${r.requireTransportTag.join(", ")}]`);
    } else if (r.kind === "prefer_latency") {
      lines.push(`  - id: ${r.id}`);
      lines.push(`    prefer: lowest_latency`);
      lines.push(`    within_ms: ${r.withinMs}`);
    } else if (r.kind === "prefer_tag") {
      lines.push(`  - id: ${r.id}`);
      lines.push(`    prefer_tag: ${r.tag}`);
    } else {
      lines.push(`  - id: ${r.id}`);
      lines.push(`    fallback: ${r.transportId}`);
    }
  }
  return lines.join("\n");
}

export function layerTimings(findings: Finding[]) {
  return LAYER_ORDER.map((layer) => {
    const items = findings.filter((f) => f.layer === layer);
    const start = items.length ? Math.min(...items.map((i) => i.startedAt)) : 0;
    const end = items.length ? Math.max(...items.map((i) => i.endedAt)) : 0;
    const ok =
      items.length === 0 ? ("skip" as const) : items.every((i) => i.ok) ? ("ok" as const) : ("fail" as const);
    return { layer, start, end, ok, ms: Math.max(0, end - start) };
  });
}

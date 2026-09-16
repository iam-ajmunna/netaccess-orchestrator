/** CLI command surface (mirrored by the local automation API). */

import { CLASS_LABEL } from "./types";
import type { Diagnosis, TransportConfig, TransportRuntime } from "./types";

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
        "netaccess check <target> [--deep]",
        "netaccess run <app> [args...]",
        "netaccess transports [--scores]",
        "netaccess test <transport>",
        "netaccess status",
        "netaccess stop <session>",
        "netaccess policy validate",
        "netaccess doctor",
        "netaccess chaos inject <scenario>",
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

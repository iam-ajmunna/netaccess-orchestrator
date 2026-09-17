/**
 * NetAccess Real Direct Diagnostics Pipeline
 * 
 * Performs real, bounded diagnostic probing across all network layers:
 * 1. Captive portal signal (Apple hotspot-detect)
 * 2. DNS resolution (independent IPv4 + IPv6 + timings + error classification)
 * 3. TCP connectivity (SYN RTT, connection refusal, timeout, reset)
 * 4. TLS handshake (ALPN protocol negotiation, cert validity, SNI checks)
 * 5. HTTP application probe (HEAD/GET, status classification: 200 vs 401/403/429/451 vs 5xx)
 * 
 * Pure production networking using Node standard libraries. Zero mocks or fake data.
 */

import * as dns from "node:dns/promises";
import * as http from "node:http";
import * as https from "node:https";
import * as net from "node:net";
import * as tls from "node:tls";
import {
  type FailureClass,
  type Finding,
  type ParsedTarget,
  type ProbeLayer,
} from "../types.js";
import { makeFinding } from "../engine.js";

export interface DirectProbeOptions {
  dnsTimeoutMs?: number;
  tcpTimeoutMs?: number;
  tlsTimeoutMs?: number;
  httpTimeoutMs?: number;
  captiveTimeoutMs?: number;
  checkCaptive?: boolean;
}

const DEFAULT_OPTIONS: Required<DirectProbeOptions> = {
  dnsTimeoutMs: 3000,
  tcpTimeoutMs: 3500,
  tlsTimeoutMs: 4000,
  httpTimeoutMs: 4000,
  captiveTimeoutMs: 2000,
  checkCaptive: true,
};

/**
 * Main Direct Diagnostic Pipeline
 * Returns structured findings ready for existing classify()
 */
export async function diagnoseDirectPath(
  target: ParsedTarget,
  signal?: AbortSignal,
  opts: DirectProbeOptions = {},
): Promise<Finding[]> {
  const options = { ...DEFAULT_OPTIONS, ...opts };
  const findings: Finding[] = [];

  // Check cancellation before start
  if (signal?.aborted) {
    throw new Error("Diagnosis aborted before start");
  }

  // Layer 1: Captive portal check (signal only, parallel with DNS)
  const captivePromise = options.checkCaptive
    ? probeCaptivePortal(options.captiveTimeoutMs, signal)
    : Promise.resolve(null);

  // Layer 2: DNS resolution (IPv4 + IPv6)
  const dnsResult = await probeDns(target.host, options.dnsTimeoutMs, signal);
  findings.push(...dnsResult.findings);

  // If captive portal returned a finding, include it
  const captiveFinding = await captivePromise;
  if (captiveFinding) {
    findings.unshift(captiveFinding);
  }

  // If DNS resolution produced no usable addresses, return findings immediately
  if (!dnsResult.usableIp) {
    return findings;
  }

  if (signal?.aborted) throw new Error("Diagnosis aborted after DNS");

  // Layer 3: TCP connect probe
  const tcpResult = await probeTcp(
    dnsResult.usableIp,
    target.port,
    options.tcpTimeoutMs,
    signal,
  );
  findings.push(tcpResult.finding);

  // If TCP connect failed, skip TLS and HTTP
  if (!tcpResult.connected) {
    return findings;
  }

  if (signal?.aborted) throw new Error("Diagnosis aborted after TCP");

  // Layer 4: TLS handshake probe (for HTTPS / port 443)
  if (target.scheme === "https" || target.port === 443) {
    const tlsResult = await probeTls(
      target.host,
      target.port,
      options.tlsTimeoutMs,
      signal,
    );
    findings.push(tlsResult.finding);

    // If TLS failed, skip HTTP
    if (!tlsResult.ok) {
      return findings;
    }
  }

  if (signal?.aborted) throw new Error("Diagnosis aborted after TLS");

  // Layer 5: HTTP application probe
  const httpFinding = await probeHttp(
    target,
    options.httpTimeoutMs,
    signal,
  );
  findings.push(httpFinding);

  // If destination TCP succeeded and TLS/HTTP answered, captive portal check failure
  // was an external false-positive or redirect on captive.apple.com that does not block this target.
  if (tcpResult.connected) {
    const isHttps = target.scheme === "https" || target.port === 443;
    const tlsOk = !isHttps || findings.some((f) => f.layer === "tls" && f.ok);
    const httpOk = findings.some((f) => f.layer === "http" && f.ok);
    if (tlsOk || httpOk) {
      for (const f of findings) {
        if (f.layer === "captive" && !f.ok) {
          f.ok = true;
          f.classHint = "healthy";
          f.weight = 0.1;
          f.evidence = "Captive check inconclusive, but destination answered directly over TCP/TLS.";
        }
      }
    }
  }

  return findings;
}

// -------------------------------------------------------------------------
// Layer 1: Captive Portal Signal Probe
// -------------------------------------------------------------------------

export async function probeCaptivePortal(
  timeoutMs: number,
  signal?: AbortSignal,
): Promise<Finding | null> {
  const t0 = Date.now();
  const captiveUrl = "http://captive.apple.com/hotspot-detect.html";

  return new Promise<Finding | null>((resolve) => {
    let finished = false;
    const finish = (finding: Finding | null) => {
      if (finished) return;
      finished = true;
      resolve(finding);
    };

    const timer = setTimeout(() => {
      // Captive check timeout: do not block or fail the diagnosis
      finish(null);
    }, timeoutMs);

    const abortHandler = () => {
      clearTimeout(timer);
      finish(null);
    };

    if (signal) {
      if (signal.aborted) {
        clearTimeout(timer);
        return resolve(null);
      }
      signal.addEventListener("abort", abortHandler, { once: true });
    }

    try {
      const req = http.get(captiveUrl, { timeout: timeoutMs }, (res) => {
        let body = "";
        res.setEncoding("utf8");
        res.on("data", (chunk) => {
          body += chunk;
          if (body.length > 512) {
            req.destroy();
          }
        });
        res.on("end", () => {
          clearTimeout(timer);
          const t1 = Date.now();
          const latencyMs = Math.max(1, t1 - t0);

          // Apple hotspot-detect returns 200 with "Success" in body
          const isSuccess =
            res.statusCode === 200 &&
            /success/i.test(body) &&
            !body.includes("<form");

          if (isSuccess) {
            // Normal internet connectivity
            finish(
              makeFinding(
                "captive",
                true,
                "healthy",
                "Captive portal check clear (hotspot-detect: Success)",
                { latencyMs, startedAt: t0, endedAt: t1 },
              ),
            );
          } else {
            // Interception or redirect
            finish(
              makeFinding(
                "captive",
                false,
                "captive_portal",
                `Captive portal intercepted HTTP request (status ${res.statusCode ?? "redirect"})`,
                { weight: 2.2, latencyMs, startedAt: t0, endedAt: t1 },
              ),
            );
          }
        });
      });

      req.on("error", () => {
        clearTimeout(timer);
        // On error (e.g. offline or DNS fail on apple), do not declare captive portal
        finish(null);
      });

      req.on("timeout", () => {
        req.destroy();
        clearTimeout(timer);
        finish(null);
      });
    } catch {
      clearTimeout(timer);
      finish(null);
    }
  });
}

// -------------------------------------------------------------------------
// Layer 2: DNS Resolution Probes (IPv4 + IPv6)
// -------------------------------------------------------------------------

export interface DnsProbeResult {
  findings: Finding[];
  ipv4: string[];
  ipv6: string[];
  usableIp?: string;
}

export async function probeDns(
  host: string,
  timeoutMs: number,
  signal?: AbortSignal,
): Promise<DnsProbeResult> {
  const t0 = Date.now();

  // If host is already an IP address, return immediately
  if (net.isIP(host)) {
    const isV6 = net.isIPv6(host);
    const finding = makeFinding(
      "dns",
      true,
      "healthy",
      `Target host is already an IP literal (${host})`,
      {
        latencyMs: 1,
        startedAt: t0,
        endedAt: t0 + 1,
        detail: isV6 ? { aaaa: [host] } : { a: [host] },
      },
    );
    return {
      findings: [finding],
      ipv4: isV6 ? [] : [host],
      ipv6: isV6 ? [host] : [],
      usableIp: host,
    };
  }

  // Run IPv4 and IPv6 queries with individual timeouts
  const [v4Result, v6Result] = await Promise.all([
    resolveFamilyWithTimeout("A", () => dns.resolve4(host), timeoutMs, signal),
    resolveFamilyWithTimeout("AAAA", () => dns.resolve6(host), timeoutMs, signal),
  ]);

  const t1 = Date.now();
  const latencyMs = Math.max(1, t1 - t0);
  const findings: Finding[] = [];

  const v4Ips = [...v4Result.ips];
  const v6Ips = [...v6Result.ips];

  // If C-Ares direct resolution produced no addresses, query native OS resolver (getaddrinfo via dns.lookup).
  // On macOS, system networking uses mDNSResponder and SystemConfiguration rather than /etc/resolv.conf.
  if (v4Ips.length === 0 && v6Ips.length === 0 && !signal?.aborted) {
    try {
      const lookupPromise = dns.lookup(host, { all: true });
      const timeoutPromise = new Promise<{ address: string; family: number }[]>((_, reject) => {
        setTimeout(() => reject(new Error("System lookup timeout")), Math.min(timeoutMs, 2000));
      });
      const entries = await Promise.race([lookupPromise, timeoutPromise]);
      for (const entry of entries) {
        if (entry.family === 4 && !v4Ips.includes(entry.address)) {
          v4Ips.push(entry.address);
        } else if (entry.family === 6 && !v6Ips.includes(entry.address)) {
          v6Ips.push(entry.address);
        }
      }
    } catch {
      // System lookup also failed; will proceed to failure classification
    }
  }

  // Evaluate findings
  if (v4Ips.length > 0 || v6Ips.length > 0) {
    // At least one address family resolved successfully
    const details: string[] = [];
    if (v4Ips.length > 0) details.push(`IPv4: ${v4Ips.slice(0, 3).join(", ")}`);
    if (v6Ips.length > 0) details.push(`IPv6: ${v6Ips.slice(0, 2).join(", ")}`);

    findings.push(
      makeFinding(
        "dns",
        true,
        "healthy",
        `Resolved ${host} in ${latencyMs}ms (${details.join(" | ")})`,
        {
          latencyMs,
          startedAt: t0,
          endedAt: t1,
          detail: { a: v4Ips, aaaa: v6Ips },
        },
      ),
    );

    // Prefer IPv4 for direct local test predictability, or IPv6 if only v6 is available
    const usableIp = v4Ips[0] ?? v6Ips[0];
    return { findings, ipv4: v4Ips, ipv6: v6Ips, usableIp };
  }

  // Both address families failed: classify failure
  const primaryError = v4Result.error ?? v6Result.error;
  const errCode = (primaryError as NodeJS.ErrnoException)?.code ?? "UNKNOWN";

  let classHint: FailureClass = "address_resolution";
  let weight = 1.6;
  let likelyMsg = `Failed to resolve ${host}: ${primaryError?.message ?? "unknown DNS error"}`;

  if (errCode === "ENOTFOUND" || errCode === "ENODATA" || /nxdomain/i.test(primaryError?.message ?? "")) {
    classHint = "dns_nxdomain";
    weight = 2.0;
    likelyMsg = `The domain name "${host}" does not exist (NXDOMAIN).`;
  } else if (errCode === "ESERVFAIL") {
    classHint = "dns_servfail";
    weight = 1.9;
    likelyMsg = `DNS server failed internally while resolving ${host} (SERVFAIL).`;
  } else if (errCode === "ETIMEOUT" || v4Result.timedOut || v6Result.timedOut) {
    classHint = "dns_timeout";
    weight = 1.7;
    likelyMsg = `DNS query for ${host} timed out after ${timeoutMs}ms.`;
  }

  findings.push(
    makeFinding("dns", false, classHint, likelyMsg, {
      weight,
      latencyMs,
      startedAt: t0,
      endedAt: t1,
    }),
  );

  return { findings, ipv4: [], ipv6: [] };
}

async function resolveFamilyWithTimeout(
  type: "A" | "AAAA",
  fn: () => Promise<string[]>,
  timeoutMs: number,
  signal?: AbortSignal,
): Promise<{ ips: string[]; error?: Error; timedOut?: boolean }> {
  let timeoutId: NodeJS.Timeout | undefined;

  const timeoutPromise = new Promise<{ ips: string[]; error?: Error; timedOut?: boolean }>((resolve) => {
    timeoutId = setTimeout(() => {
      resolve({ ips: [], error: new Error(`DNS ${type} timeout`), timedOut: true });
    }, timeoutMs);
  });

  const abortPromise = new Promise<{ ips: string[]; error?: Error }>((resolve) => {
    if (signal) {
      signal.addEventListener(
        "abort",
        () => resolve({ ips: [], error: new Error("DNS resolution aborted") }),
        { once: true },
      );
    }
  });

  try {
    const workPromise = fn()
      .then((ips) => ({ ips }))
      .catch((err: Error) => ({ ips: [], error: err }));

    const res = await Promise.race([workPromise, timeoutPromise, abortPromise]);
    return res;
  } finally {
    if (timeoutId) clearTimeout(timeoutId);
  }
}

// -------------------------------------------------------------------------
// Layer 3: TCP Connectivity Probe
// -------------------------------------------------------------------------

export interface TcpProbeResult {
  finding: Finding;
  connected: boolean;
  latencyMs?: number;
}

export async function probeTcp(
  ip: string,
  port: number,
  timeoutMs: number,
  signal?: AbortSignal,
): Promise<TcpProbeResult> {
  const t0 = Date.now();

  return new Promise<TcpProbeResult>((resolve) => {
    let finished = false;
    const finish = (result: TcpProbeResult) => {
      if (finished) return;
      finished = true;
      socket.destroy();
      resolve(result);
    };

    const socket = new net.Socket();

    // Bound with timeout
    socket.setTimeout(timeoutMs);

    const abortHandler = () => {
      finish({
        connected: false,
        finding: makeFinding("tcp", false, "timeout", "TCP connection probe aborted", {
          latencyMs: Date.now() - t0,
          startedAt: t0,
          endedAt: Date.now(),
        }),
      });
    };

    if (signal) {
      if (signal.aborted) {
        return abortHandler();
      }
      signal.addEventListener("abort", abortHandler, { once: true });
    }

    socket.on("connect", () => {
      const t1 = Date.now();
      const latencyMs = Math.max(1, t1 - t0);
      finish({
        connected: true,
        latencyMs,
        finding: makeFinding(
          "tcp",
          true,
          "healthy",
          `TCP SYN-ACK completed to ${ip}:${port} in ${latencyMs}ms`,
          { latencyMs, startedAt: t0, endedAt: t1 },
        ),
      });
    });

    socket.on("timeout", () => {
      const t1 = Date.now();
      finish({
        connected: false,
        finding: makeFinding(
          "tcp",
          false,
          "tcp_timeout",
          `TCP SYN timeout: no response from ${ip}:${port} within ${timeoutMs}ms (SYN dropped on path)`,
          { weight: 1.6, latencyMs: timeoutMs, startedAt: t0, endedAt: t1 },
        ),
      });
    });

    socket.on("error", (err: NodeJS.ErrnoException) => {
      const t1 = Date.now();
      const latencyMs = Math.max(1, t1 - t0);

      let classHint: FailureClass = "tcp_timeout";
      let weight = 1.5;
      let msg = `TCP connection failed to ${ip}:${port}: ${err.message}`;

      if (err.code === "ECONNREFUSED") {
        classHint = "tcp_refused";
        weight = 1.8;
        msg = `TCP connection refused by ${ip}:${port} (port closed or firewall rejection)`;
      } else if (err.code === "ECONNRESET") {
        classHint = "tcp_reset";
        weight = 1.6;
        msg = `TCP connection reset by peer on ${ip}:${port}`;
      } else if (err.code === "EHOSTUNREACH" || err.code === "ENETUNREACH") {
        classHint = "routing_failure";
        weight = 1.7;
        msg = `Host or network unreachable for ${ip}:${port} (${err.code})`;
      }

      finish({
        connected: false,
        finding: makeFinding("tcp", false, classHint, msg, {
          weight,
          latencyMs,
          startedAt: t0,
          endedAt: t1,
        }),
      });
    });

    try {
      socket.connect(port, ip);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      finish({
        connected: false,
        finding: makeFinding("tcp", false, "tcp_timeout", `Failed to initiate TCP connect: ${msg}`, {
          startedAt: t0,
          endedAt: Date.now(),
        }),
      });
    }
  });
}

// -------------------------------------------------------------------------
// Layer 4: TLS Handshake Probe
// -------------------------------------------------------------------------

export interface TlsProbeResult {
  finding: Finding;
  ok: boolean;
  alpnProtocol?: string;
  latencyMs?: number;
}

export async function probeTls(
  host: string,
  port: number,
  timeoutMs: number,
  signal?: AbortSignal,
): Promise<TlsProbeResult> {
  const t0 = Date.now();

  return new Promise<TlsProbeResult>((resolve) => {
    let finished = false;
    const finish = (result: TlsProbeResult) => {
      if (finished) return;
      finished = true;
      tlsSocket.destroy();
      resolve(result);
    };

    const abortHandler = () => {
      finish({
        ok: false,
        finding: makeFinding("tls", false, "timeout", "TLS handshake aborted by user", {
          startedAt: t0,
          endedAt: Date.now(),
        }),
      });
    };

    if (signal) {
      if (signal.aborted) {
        return abortHandler();
      }
      signal.addEventListener("abort", abortHandler, { once: true });
    }

    const tlsSocket = tls.connect(
      {
        host,
        port,
        servername: host,
        timeout: timeoutMs,
        ALPNProtocols: ["h2", "http/1.1"],
        rejectUnauthorized: true,
      },
      () => {
        const t1 = Date.now();
        const latencyMs = Math.max(1, t1 - t0);
        const alpn = tlsSocket.alpnProtocol || "http/1.1";
        const authorized = tlsSocket.authorized;

        if (!authorized) {
          const authError = tlsSocket.authorizationError?.message || "Certificate authorization failed";
          finish({
            ok: false,
            finding: makeFinding(
              "tls",
              false,
              "tls_cert_invalid",
              `TLS certificate invalid for ${host}: ${authError}`,
              { weight: 1.8, latencyMs, startedAt: t0, endedAt: t1 },
            ),
          });
          return;
        }

        finish({
          ok: true,
          alpnProtocol: alpn,
          latencyMs,
          finding: makeFinding(
            "tls",
            true,
            "healthy",
            `TLS handshake established (${tlsSocket.getProtocol() ?? "TLS"}, ALPN: ${alpn}) in ${latencyMs}ms`,
            { latencyMs, startedAt: t0, endedAt: t1 },
          ),
        });
      },
    );

    tlsSocket.on("timeout", () => {
      const t1 = Date.now();
      finish({
        ok: false,
        finding: makeFinding(
          "tls",
          false,
          "tls_handshake_timeout",
          `TLS handshake timed out after ${timeoutMs}ms for ${host} (path/inspection timeout)`,
          { weight: 1.5, latencyMs: timeoutMs, startedAt: t0, endedAt: t1 },
        ),
      });
    });

    tlsSocket.on("error", (err: Error) => {
      const t1 = Date.now();
      const latencyMs = Math.max(1, t1 - t0);
      const msg = err.message || "";

      let classHint: FailureClass = "tls_handshake_timeout";
      let weight = 1.4;

      if (/certificate|depth|self-signed|expired/i.test(msg)) {
        classHint = "tls_cert_invalid";
        weight = 1.8;
      } else if (/reset|econnreset|packet/i.test(msg)) {
        classHint = "tls_sni_blocked";
        weight = 1.5;
      }

      finish({
        ok: false,
        finding: makeFinding("tls", false, classHint, `TLS handshake failed: ${msg}`, {
          weight,
          latencyMs,
          startedAt: t0,
          endedAt: t1,
        }),
      });
    });
  });
}

// -------------------------------------------------------------------------
// Layer 5: HTTP Application Probe
// -------------------------------------------------------------------------

export async function probeHttp(
  target: ParsedTarget,
  timeoutMs: number,
  signal?: AbortSignal,
): Promise<Finding> {
  const t0 = Date.now();
  const isHttps = target.scheme === "https";
  const requestLib = isHttps ? https : http;

  return new Promise<Finding>((resolve) => {
    let finished = false;
    const finish = (finding: Finding) => {
      if (finished) return;
      finished = true;
      resolve(finding);
    };

    const abortHandler = () => {
      finish(
        makeFinding("http", false, "timeout", "HTTP probe aborted by user", {
          startedAt: t0,
          endedAt: Date.now(),
        }),
      );
    };

    if (signal) {
      if (signal.aborted) {
        return abortHandler();
      }
      signal.addEventListener("abort", abortHandler, { once: true });
    }

    const reqOptions: https.RequestOptions = {
      method: "HEAD",
      host: target.host,
      port: target.port,
      path: target.pathname,
      timeout: timeoutMs,
      headers: {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) NetAccess/1.0",
        Accept: "*/*",
        Connection: "close",
      },
    };

    const req = requestLib.request(reqOptions, (res) => {
      const t1 = Date.now();
      const latencyMs = Math.max(1, t1 - t0);
      const status = res.statusCode ?? 0;
      res.resume(); // Discard body

      // Status classification
      if (status >= 200 && status < 400) {
        finish(
          makeFinding(
            "http",
            true,
            "healthy",
            `HTTP application answered ${status} ${res.statusMessage ?? "OK"} in ${latencyMs}ms`,
            {
              latencyMs,
              detail: { status },
              startedAt: t0,
              endedAt: t1,
            },
          ),
        );
      } else if (status === 401 || status === 403 || status === 429) {
        finish(
          makeFinding(
            "http",
            false,
            "destination_restriction",
            `HTTP ${status} ${res.statusMessage ?? "Forbidden"}: Destination reachable, service restricted request`,
            {
              weight: 1.8,
              latencyMs,
              detail: { status },
              startedAt: t0,
              endedAt: t1,
            },
          ),
        );
      } else if (status === 451) {
        finish(
          makeFinding(
            "http",
            false,
            "geographic_restriction",
            `HTTP 451 Unavailable For Legal Reasons: Destination reported legal/geographic policy`,
            {
              weight: 1.8,
              latencyMs,
              detail: { status },
              startedAt: t0,
              endedAt: t1,
            },
          ),
        );
      } else {
        finish(
          makeFinding(
            "http",
            false,
            "http_failure",
            `HTTP ${status} ${res.statusMessage ?? "Error"} returned by destination`,
            {
              weight: 1.2,
              latencyMs,
              detail: { status },
              startedAt: t0,
              endedAt: t1,
            },
          ),
        );
      }
    });

    req.on("timeout", () => {
      req.destroy();
      const t1 = Date.now();
      finish(
        makeFinding(
          "http",
          false,
          "timeout",
          `HTTP request timed out after ${timeoutMs}ms`,
          { weight: 1.4, latencyMs: timeoutMs, startedAt: t0, endedAt: t1 },
        ),
      );
    });

    req.on("error", (err: Error) => {
      const t1 = Date.now();
      finish(
        makeFinding(
          "http",
          false,
          "http_failure",
          `HTTP request failed: ${err.message}`,
          { weight: 1.3, latencyMs: Math.max(1, t1 - t0), startedAt: t0, endedAt: t1 },
        ),
      );
    });

    req.end();
  });
}

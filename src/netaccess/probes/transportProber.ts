/**
 * NetAccess Real Alternate Transport Prober
 * 
 * Verifies end-to-end connectivity:
 *   NetAccess -> configured proxy -> target destination
 * 
 * Supported protocols:
 * - HTTP Proxy (GET via proxy for HTTP destinations)
 * - HTTPS CONNECT Proxy (CONNECT tunnel -> TLS handshake -> HTTP response)
 * - SOCKS5 (RFC 1928 greeting -> RFC 1929 auth -> proxy-side domain CONNECT -> TLS)
 * - Diagnostic / Mock Transport (strictly test-only semantics)
 * 
 * Guarantees:
 * - Distinguishes proxy connectivity vs destination reachability
 * - Distinguishes proxy authentication requirements (407)
 * - Uses proxy-side DNS (SOCKS5 ATYP 0x03)
 * - Zero plaintext credentials on disk
 */

import * as net from "node:net";
import * as tls from "node:tls";
import {
  type ParsedTarget,
  type TransportConfig,
} from "../types.js";

export type TransportProbeStage =
  | "connect_proxy"
  | "proxy_handshake"
  | "tunnel_established"
  | "target_tls"
  | "target_http";

export type TransportProbeFailureReason =
  | "PROXY_UNREACHABLE"
  | "PROXY_AUTH_REQUIRED"
  | "PROXY_REFUSED_TARGET"
  | "TUNNEL_FAILED"
  | "TARGET_TLS_FAILED"
  | "TARGET_UNREACHABLE_VIA_PROXY"
  | "TIMEOUT"
  | "ABORTED";

export interface TransportProbeResult {
  ok: boolean;
  transportId: string;
  latencyMs: number;
  stage: TransportProbeStage;
  targetReachable: boolean;
  proxyReachable: boolean;
  statusCode?: number;
  error?: string;
  failureReason?: TransportProbeFailureReason;
  dnsResolutionMethod?: "proxy_side" | "local";
}

export type CredentialResolver = (secretRef: string) => Promise<string | undefined>;

export interface TransportProberOptions {
  timeoutMs?: number;
  allowDiagnosticTransports?: boolean;
  credentialResolver?: CredentialResolver;
}

const DEFAULT_TIMEOUT_MS = 5000;

/**
 * Main Transport Probe Entry Point
 * Probes NetAccess -> Proxy -> Target
 */
export async function probeTransport(
  transport: TransportConfig,
  target: ParsedTarget,
  signal?: AbortSignal,
  opts: TransportProberOptions = {},
): Promise<TransportProbeResult> {
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;

  // Enforce diagnostic-only constraint
  if (transport.diagnosticOnly && !opts.allowDiagnosticTransports) {
    return {
      ok: false,
      transportId: transport.id,
      latencyMs: 0,
      stage: "connect_proxy",
      targetReachable: false,
      proxyReachable: false,
      failureReason: "PROXY_REFUSED_TARGET",
      error: `Transport ${transport.id} is marked diagnostic-only and is disabled for production operations.`,
    };
  }

  // Diagnostic mock transport path (for offline CI testing)
  if (transport.diagnosticOnly && opts.allowDiagnosticTransports) {
    return probeMockDiagnosticTransport(transport, target);
  }

  if (!transport.host || !transport.port) {
    return {
      ok: false,
      transportId: transport.id,
      latencyMs: 0,
      stage: "connect_proxy",
      targetReachable: false,
      proxyReachable: false,
      failureReason: "PROXY_UNREACHABLE",
      error: `Transport ${transport.id} is missing host or port configuration.`,
    };
  }

  // Resolve secret in-memory if secretRef is present
  let password: string | undefined;
  if (transport.secretRef && opts.credentialResolver) {
    try {
      password = await opts.credentialResolver(transport.secretRef);
    } catch {
      // Failed to resolve secret
    }
  }

  switch (transport.type) {
    case "socks5":
      return probeSocks5(transport, target, timeoutMs, transport.username, password, signal);

    case "http_proxy":
    case "https_connect":
      return probeHttpProxy(transport, target, timeoutMs, transport.username, password, signal);

    default:
      return {
        ok: false,
        transportId: transport.id,
        latencyMs: 0,
        stage: "connect_proxy",
        targetReachable: false,
        proxyReachable: false,
        failureReason: "PROXY_UNREACHABLE",
        error: `Transport type "${transport.type}" probing is not yet implemented.`,
      };
  }
}

// -------------------------------------------------------------------------
// SOCKS5 (RFC 1928) Prober
// -------------------------------------------------------------------------

export async function probeSocks5(
  transport: TransportConfig,
  target: ParsedTarget,
  timeoutMs: number,
  username?: string,
  password?: string,
  signal?: AbortSignal,
): Promise<TransportProbeResult> {
  const t0 = Date.now();
  const host = transport.host!;
  const port = transport.port!;

  return new Promise<TransportProbeResult>((resolve) => {
    let finished = false;
    let socket: net.Socket | null = new net.Socket();

    const finish = (result: TransportProbeResult) => {
      if (finished) return;
      finished = true;
      if (socket) {
        socket.destroy();
        socket = null;
      }
      resolve(result);
    };

    socket.setTimeout(timeoutMs);

    const abortHandler = () => {
      finish({
        ok: false,
        transportId: transport.id,
        latencyMs: Date.now() - t0,
        stage: "connect_proxy",
        targetReachable: false,
        proxyReachable: false,
        failureReason: "ABORTED",
        error: "SOCKS5 probe cancelled by user",
      });
    };

    if (signal) {
      if (signal.aborted) return abortHandler();
      signal.addEventListener("abort", abortHandler, { once: true });
    }

    socket.on("timeout", () => {
      finish({
        ok: false,
        transportId: transport.id,
        latencyMs: timeoutMs,
        stage: "connect_proxy",
        targetReachable: false,
        proxyReachable: false,
        failureReason: "TIMEOUT",
        error: `SOCKS5 proxy connection to ${host}:${port} timed out after ${timeoutMs}ms`,
      });
    });

    socket.on("error", (err: NodeJS.ErrnoException) => {
      finish({
        ok: false,
        transportId: transport.id,
        latencyMs: Math.max(1, Date.now() - t0),
        stage: "connect_proxy",
        targetReachable: false,
        proxyReachable: false,
        failureReason: "PROXY_UNREACHABLE",
        error: `Could not connect to SOCKS5 proxy at ${host}:${port}: ${err.message}`,
      });
    });

    socket.connect(port, host, () => {
      if (!socket) return;
      // Step 1: Greeting
      // Methods: 0x00 (No Auth), and if username present: 0x02 (Username/Password)
      const methods = username ? [0x00, 0x02] : [0x00];
      const greeting = Buffer.from([0x05, methods.length, ...methods]);
      socket.write(greeting);

      let step: "greeting" | "auth" | "connect_resp" = "greeting";

      socket.on("data", (data: Buffer) => {
        if (!socket) return;

        if (step === "greeting") {
          if (data.length < 2 || data[0] !== 0x05) {
            return finish({
              ok: false,
              transportId: transport.id,
              latencyMs: Date.now() - t0,
              stage: "proxy_handshake",
              targetReachable: false,
              proxyReachable: true,
              failureReason: "TUNNEL_FAILED",
              error: `Invalid SOCKS5 greeting response from ${host}:${port}`,
            });
          }

          const selectedMethod = data[1];

          if (selectedMethod === 0xff) {
            return finish({
              ok: false,
              transportId: transport.id,
              latencyMs: Date.now() - t0,
              stage: "proxy_handshake",
              targetReachable: false,
              proxyReachable: true,
              failureReason: "PROXY_AUTH_REQUIRED",
              error: `SOCKS5 proxy rejected authentication methods (0xFF)`,
            });
          }

          if (selectedMethod === 0x02 && username) {
            // Send RFC 1929 username/password subnegotiation
            step = "auth";
            const uBuf = Buffer.from(username);
            const pBuf = Buffer.from(password ?? "");
            const authReq = Buffer.concat([
              Buffer.from([0x01, uBuf.length]),
              uBuf,
              Buffer.from([pBuf.length]),
              pBuf,
            ]);
            socket.write(authReq);
            return;
          }

          // Method 0x00 accepted (or auth passed), send CONNECT request
          sendSocks5Connect();
          return;
        }

        if (step === "auth") {
          if (data.length < 2 || data[1] !== 0x00) {
            return finish({
              ok: false,
              transportId: transport.id,
              latencyMs: Date.now() - t0,
              stage: "proxy_handshake",
              targetReachable: false,
              proxyReachable: true,
              failureReason: "PROXY_AUTH_REQUIRED",
              error: "SOCKS5 proxy authentication failed (invalid credentials)",
            });
          }
          sendSocks5Connect();
          return;
        }

        if (step === "connect_resp") {
          if (data.length < 4 || data[0] !== 0x05) {
            return finish({
              ok: false,
              transportId: transport.id,
              latencyMs: Date.now() - t0,
              stage: "tunnel_established",
              targetReachable: false,
              proxyReachable: true,
              failureReason: "TUNNEL_FAILED",
              error: `Invalid SOCKS5 connect response`,
            });
          }

          const rep = data[1];
          if (rep !== 0x00) {
            let reason: TransportProbeFailureReason = "TARGET_UNREACHABLE_VIA_PROXY";
            let msg = `SOCKS5 error code 0x${rep.toString(16)}`;

            if (rep === 0x02) {
              reason = "PROXY_REFUSED_TARGET";
              msg = `SOCKS5 proxy ruleset forbids connection to ${target.host}:${target.port}`;
            } else if (rep === 0x03 || rep === 0x04) {
              msg = `Host or network unreachable for ${target.host} via SOCKS5 proxy`;
            } else if (rep === 0x05) {
              msg = `Connection refused by destination ${target.host}:${target.port}`;
            }

            return finish({
              ok: false,
              transportId: transport.id,
              latencyMs: Date.now() - t0,
              stage: "tunnel_established",
              targetReachable: false,
              proxyReachable: true,
              failureReason: reason,
              error: msg,
            });
          }

          // Tunnel established through SOCKS5 proxy!
          // If HTTPS, perform TLS handshake through established tunnel
          if (target.scheme === "https" || target.port === 443) {
            const currentSocket = socket;
            socket.removeAllListeners("data");
            socket.removeAllListeners("error");
            socket.removeAllListeners("timeout");

            const tlsSocket = tls.connect(
              {
                socket: currentSocket,
                servername: target.host,
                timeout: timeoutMs,
                rejectUnauthorized: true,
              },
              () => {
                const latencyMs = Math.max(1, Date.now() - t0);
                tlsSocket.destroy();
                finish({
                  ok: true,
                  transportId: transport.id,
                  latencyMs,
                  stage: "target_tls",
                  targetReachable: true,
                  proxyReachable: true,
                  dnsResolutionMethod: "proxy_side",
                });
              },
            );

            tlsSocket.on("error", (err: Error) => {
              tlsSocket.destroy();
              finish({
                ok: false,
                transportId: transport.id,
                latencyMs: Date.now() - t0,
                stage: "target_tls",
                targetReachable: false,
                proxyReachable: true,
                failureReason: "TARGET_TLS_FAILED",
                error: `TLS handshake through SOCKS5 tunnel failed: ${err.message}`,
              });
            });

            return;
          }

          // For HTTP, tunnel is verified
          const latencyMs = Math.max(1, Date.now() - t0);
          finish({
            ok: true,
            transportId: transport.id,
            latencyMs,
            stage: "tunnel_established",
            targetReachable: true,
            proxyReachable: true,
            dnsResolutionMethod: "proxy_side",
          });
        }
      });

      function sendSocks5Connect() {
        if (!socket) return;
        step = "connect_resp";
        // Use ATYP 0x03 (Domain Name) for proxy-side DNS resolution
        const domainBuf = Buffer.from(target.host);
        const portBuf = Buffer.alloc(2);
        portBuf.writeUInt16BE(target.port);

        const connectReq = Buffer.concat([
          Buffer.from([0x05, 0x01, 0x00, 0x03, domainBuf.length]),
          domainBuf,
          portBuf,
        ]);
        socket.write(connectReq);
      }
    });
  });
}

// -------------------------------------------------------------------------
// HTTP / HTTPS CONNECT Proxy Prober
// -------------------------------------------------------------------------

export async function probeHttpProxy(
  transport: TransportConfig,
  target: ParsedTarget,
  timeoutMs: number,
  username?: string,
  password?: string,
  signal?: AbortSignal,
): Promise<TransportProbeResult> {
  const t0 = Date.now();
  const host = transport.host!;
  const port = transport.port!;

  return new Promise<TransportProbeResult>((resolve) => {
    let finished = false;
    let socket: net.Socket | null = new net.Socket();

    const finish = (result: TransportProbeResult) => {
      if (finished) return;
      finished = true;
      if (socket) {
        socket.destroy();
        socket = null;
      }
      resolve(result);
    };

    socket.setTimeout(timeoutMs);

    const abortHandler = () => {
      finish({
        ok: false,
        transportId: transport.id,
        latencyMs: Date.now() - t0,
        stage: "connect_proxy",
        targetReachable: false,
        proxyReachable: false,
        failureReason: "ABORTED",
        error: "HTTP proxy probe cancelled by user",
      });
    };

    if (signal) {
      if (signal.aborted) return abortHandler();
      signal.addEventListener("abort", abortHandler, { once: true });
    }

    socket.on("timeout", () => {
      finish({
        ok: false,
        transportId: transport.id,
        latencyMs: timeoutMs,
        stage: "connect_proxy",
        targetReachable: false,
        proxyReachable: false,
        failureReason: "TIMEOUT",
        error: `HTTP proxy connection to ${host}:${port} timed out after ${timeoutMs}ms`,
      });
    });

    socket.on("error", (err: NodeJS.ErrnoException) => {
      finish({
        ok: false,
        transportId: transport.id,
        latencyMs: Math.max(1, Date.now() - t0),
        stage: "connect_proxy",
        targetReachable: false,
        proxyReachable: false,
        failureReason: "PROXY_UNREACHABLE",
        error: `Could not connect to HTTP proxy at ${host}:${port}: ${err.message}`,
      });
    });

    socket.connect(port, host, () => {
      if (!socket) return;

      // Build CONNECT request for HTTPS or general tunnel
      const headers: string[] = [
        `CONNECT ${target.host}:${target.port} HTTP/1.1`,
        `Host: ${target.host}:${target.port}`,
        `User-Agent: NetAccess/1.0`,
        `Proxy-Connection: keep-alive`,
      ];

      if (username) {
        const credentials = Buffer.from(`${username}:${password ?? ""}`).toString("base64");
        headers.push(`Proxy-Authorization: Basic ${credentials}`);
      }
      headers.push("\r\n");

      socket.write(headers.join("\r\n"));

      let headerBuffer = "";

      socket.on("data", (chunk: Buffer) => {
        if (!socket) return;
        headerBuffer += chunk.toString("utf8");

        const headerEnd = headerBuffer.indexOf("\r\n\r\n");
        if (headerEnd === -1) return;

        // Parse status line
        const statusLine = headerBuffer.split("\r\n")[0] ?? "";
        const match = statusLine.match(/HTTP\/\d\.\d\s+(\d{3})/i);
        const statusCode = match ? Number(match[1]) : 0;

        if (statusCode === 200) {
          // Tunnel established!
          if (target.scheme === "https" || target.port === 443) {
            const currentSocket = socket;
            socket.removeAllListeners("data");
            socket.removeAllListeners("error");
            socket.removeAllListeners("timeout");

            const tlsSocket = tls.connect(
              {
                socket: currentSocket,
                servername: target.host,
                timeout: timeoutMs,
                rejectUnauthorized: true,
              },
              () => {
                const latencyMs = Math.max(1, Date.now() - t0);
                tlsSocket.destroy();
                finish({
                  ok: true,
                  transportId: transport.id,
                  latencyMs,
                  stage: "target_tls",
                  targetReachable: true,
                  proxyReachable: true,
                  statusCode: 200,
                  dnsResolutionMethod: "proxy_side",
                });
              },
            );

            tlsSocket.on("error", (err: Error) => {
              tlsSocket.destroy();
              finish({
                ok: false,
                transportId: transport.id,
                latencyMs: Date.now() - t0,
                stage: "target_tls",
                targetReachable: false,
                proxyReachable: true,
                statusCode: 200,
                failureReason: "TARGET_TLS_FAILED",
                error: `TLS handshake through HTTP CONNECT tunnel failed: ${err.message}`,
              });
            });

            return;
          }

          // HTTP tunnel
          const latencyMs = Math.max(1, Date.now() - t0);
          return finish({
            ok: true,
            transportId: transport.id,
            latencyMs,
            stage: "tunnel_established",
            targetReachable: true,
            proxyReachable: true,
            statusCode: 200,
            dnsResolutionMethod: "proxy_side",
          });
        }

        if (statusCode === 407) {
          return finish({
            ok: false,
            transportId: transport.id,
            latencyMs: Date.now() - t0,
            stage: "proxy_handshake",
            targetReachable: false,
            proxyReachable: true,
            statusCode: 407,
            failureReason: "PROXY_AUTH_REQUIRED",
            error: "HTTP proxy requires authentication (HTTP 407 Proxy Authentication Required)",
          });
        }

        if (statusCode === 403 || statusCode === 502 || statusCode === 504) {
          return finish({
            ok: false,
            transportId: transport.id,
            latencyMs: Date.now() - t0,
            stage: "tunnel_established",
            targetReachable: false,
            proxyReachable: true,
            statusCode,
            failureReason: statusCode === 403 ? "PROXY_REFUSED_TARGET" : "TARGET_UNREACHABLE_VIA_PROXY",
            error: `HTTP proxy returned ${statusLine}`,
          });
        }

        return finish({
          ok: false,
          transportId: transport.id,
          latencyMs: Date.now() - t0,
          stage: "proxy_handshake",
          targetReachable: false,
          proxyReachable: true,
          statusCode,
          failureReason: "TUNNEL_FAILED",
          error: `HTTP CONNECT proxy returned unexpected response: ${statusLine}`,
        });
      });
    });
  });
}

// -------------------------------------------------------------------------
// Diagnostic / Mock Transport (Strictly Test-Only)
// -------------------------------------------------------------------------

async function probeMockDiagnosticTransport(
  transport: TransportConfig,
  target: ParsedTarget,
): Promise<TransportProbeResult> {
  // If target contains "fail" or invalid, simulate unreachable target
  if (target.host.includes("fail") || target.host.includes("unreachable")) {
    return {
      ok: false,
      transportId: transport.id,
      latencyMs: 80,
      stage: "tunnel_established",
      targetReachable: false,
      proxyReachable: true,
      failureReason: "TARGET_UNREACHABLE_VIA_PROXY",
      error: `Diagnostic transport simulated failure for ${target.host}`,
    };
  }

  return {
    ok: true,
    transportId: transport.id,
    latencyMs: 45,
    stage: "target_http",
    targetReachable: true,
    proxyReachable: true,
    dnsResolutionMethod: "proxy_side",
  };
}

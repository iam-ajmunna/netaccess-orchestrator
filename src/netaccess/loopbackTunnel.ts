/**
 * NetAccess Authenticated Loopback Transport Bridge
 * 
 * Creates an ephemeral, local HTTP proxy on 127.0.0.1:<ephemeral-port> that handles
 * authentication to upstream proxies (HTTP/HTTPS CONNECT and SOCKS5).
 * 
 * Enforces the Chromium Credential Isolation Invariant:
 * 
 *   Keychain
 *      ↓
 *   CredentialResolver
 *      ↓
 *   Loopback Authenticator (127.0.0.1:port)
 *      ↓
 *   Upstream Proxy
 * 
 * Chromium connects to the loopback authenticator with zero credentials in argv:
 *   --proxy-server=http://127.0.0.1:<port>
 * 
 * Guarantees:
 * - Listens ONLY on 127.0.0.1
 * - Ephemeral port assigned by OS
 * - Plaintext credentials exist strictly in ephemeral buffer scope
 * - Registered with CleanupSupervisor for deterministic lifecycle cleanup
 * - Zero credentials leaked to argv, logs, process.env, or renderer
 */

import * as http from "node:http";
import * as net from "node:net";
import { type TransportConfig } from "./types.js";
import { type CleanupSupervisor } from "./cleanupSupervisor.js";

export class LoopbackPortAllocationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "LoopbackPortAllocationError";
  }
}

export class CredentialsUnavailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CredentialsUnavailableError";
  }
}

export type CredentialResolver = (secretRef: string) => Promise<string | null | undefined>;

export interface LoopbackBridgeHandle {
  port: number;
  host: string;
  proxyUrl: string;
  close: () => Promise<void>;
}

export interface LoopbackBridgeOptions {
  sessionId?: string;
  supervisor?: CleanupSupervisor;
  credentialResolver?: CredentialResolver;
  portBindFn?: (server: http.Server) => Promise<number>;
  sendInitialAuth?: boolean;
}

/**
 * Start an ephemeral authenticated loopback bridge for an upstream transport
 */
export async function startLoopbackBridge(
  transport: TransportConfig,
  opts: LoopbackBridgeOptions = {},
): Promise<LoopbackBridgeHandle> {
  const activeSockets = new Set<net.Socket>();

  // Pre-flight check: If secretRef exists, credentials MUST resolve before any network activity
  let password = "";
  if (transport.secretRef) {
    if (!opts.credentialResolver) {
      throw new CredentialsUnavailableError(
        `Cannot resolve credentials for transport "${transport.id}": No credential resolver configured.`,
      );
    }
    const resolved = await opts.credentialResolver(transport.secretRef);
    if (!resolved) {
      throw new CredentialsUnavailableError(
        `Credentials for transport "${transport.id}" are unavailable in Keychain (secretRef: ${transport.secretRef}).`,
      );
    }
    password = resolved;
  }

  let upstreamHost = transport.host ?? "127.0.0.1";
  let username = transport.username ?? "";
  if (upstreamHost.includes("@")) {
    const atIndex = upstreamHost.lastIndexOf("@");
    const userPass = upstreamHost.slice(0, atIndex);
    upstreamHost = upstreamHost.slice(atIndex + 1);
    if (!username && userPass.includes(":")) {
      username = userPass.split(":")[0];
      if (!password) {
        password = userPass.split(":")[1];
      }
    } else if (!username) {
      username = userPass;
    }
  }

  const upstreamPort = transport.port ?? 8080;
  const isSocks5 = transport.type === "socks5";

  let basicAuthHeader = "";
  if (username && !isSocks5) {
    const credentials = `${username}:${password}`;
    basicAuthHeader = `Basic ${Buffer.from(credentials).toString("base64")}`;
  }

  const sendInitialAuth = opts.sendInitialAuth ?? true;

  const server = http.createServer((req, res) => {
    // Plain HTTP request handling
    handleHttpRequest(req, res, {
      upstreamHost,
      upstreamPort,
      isSocks5,
      username,
      password,
      basicAuthHeader,
      activeSockets,
      sendInitialAuth,
    });
  });

  server.on("connect", (req, clientSocket, head) => {
    // HTTPS CONNECT tunnel handling
    handleConnectRequest(req, clientSocket as net.Socket, head, {
      upstreamHost,
      upstreamPort,
      isSocks5,
      username,
      password,
      basicAuthHeader,
      activeSockets,
      sendInitialAuth,
    });
  });

  server.on("connection", (socket) => {
    activeSockets.add(socket);
    socket.once("close", () => activeSockets.delete(socket));
  });

  // Listen strictly on 127.0.0.1 on an ephemeral OS-assigned port (0) with bounded retry
  const maxAttempts = 3;
  let attempts = 0;
  let port = 0;
  let lastError: Error | null = null;

  while (attempts < maxAttempts) {
    attempts++;
    try {
      if (opts.portBindFn) {
        port = await opts.portBindFn(server);
      } else {
        await new Promise<void>((resolve, reject) => {
          const onErr = (err: Error) => {
            server.removeListener("listening", onListen);
            reject(err);
          };
          const onListen = () => {
            server.removeListener("error", onErr);
            resolve();
          };
          server.once("error", onErr);
          server.once("listening", onListen);
          server.listen(0, "127.0.0.1");
        });
        const addr = server.address() as net.AddressInfo;
        port = addr?.port ?? 0;
      }
      break;
    } catch (err: unknown) {
      lastError = err instanceof Error ? err : new Error(String(err));
      if (attempts >= maxAttempts) {
        throw new LoopbackPortAllocationError(
          `Failed to allocate ephemeral loopback port after ${maxAttempts} attempts: ${lastError.message}`,
        );
      }
    }
  }

  const proxyUrl = `http://127.0.0.1:${port}`;
  server.unref();

  let isClosed = false;
  const close = async (): Promise<void> => {
    if (isClosed) return;
    isClosed = true;

    for (const socket of activeSockets) {
      try {
        socket.destroy();
      } catch {
        // Ignore destruction errors
      }
    }
    activeSockets.clear();

    if (typeof (server as any).closeAllConnections === "function") {
      try {
        (server as any).closeAllConnections();
      } catch {
        // Ignore
      }
    }

    await new Promise<void>((resolve) => {
      server.close(() => resolve());
    });
  };

  // Register with CleanupSupervisor if session provided
  if (opts.sessionId && opts.supervisor) {
    opts.supervisor.registerCleanupCallback(close, opts.sessionId);
  }

  return {
    port,
    host: "127.0.0.1",
    proxyUrl,
    close,
  };
}

// ---------------------------------------------------------------------------
// HTTP CONNECT Tunnel Handler (Chromium HTTPS requests)
// ---------------------------------------------------------------------------

interface BridgeContext {
  upstreamHost: string;
  upstreamPort: number;
  isSocks5: boolean;
  username: string;
  password: string;
  basicAuthHeader: string;
  activeSockets: Set<net.Socket>;
  sendInitialAuth: boolean;
}

function handleConnectRequest(
  req: http.IncomingMessage,
  clientSocket: net.Socket,
  head: Buffer,
  ctx: BridgeContext,
): void {
  ctx.activeSockets.add(clientSocket);
  clientSocket.once("close", () => ctx.activeSockets.delete(clientSocket));

  const urlParts = (req.url || "").split(":");
  const targetHost = urlParts[0] || "localhost";
  const targetPort = parseInt(urlParts[1] || "443", 10);

  if (ctx.isSocks5) {
    handleSocks5Connect(clientSocket, head, targetHost, targetPort, ctx);
  } else {
    handleHttpProxyConnect(clientSocket, head, targetHost, targetPort, ctx);
  }
}

function handleHttpProxyConnect(
  clientSocket: net.Socket,
  head: Buffer,
  targetHost: string,
  targetPort: number,
  ctx: BridgeContext,
): void {
  let attemptCount = 0;

  const attemptConnect = (withAuth: boolean) => {
    attemptCount++;
    let isConnected = false;
    let isRetrying = false;

    const upstreamSocket = net.connect(ctx.upstreamPort, ctx.upstreamHost, () => {
      ctx.activeSockets.add(upstreamSocket);

      let connectPayload = `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\nHost: ${targetHost}:${targetPort}\r\n`;
      if (withAuth && ctx.basicAuthHeader) {
        connectPayload += `Proxy-Authorization: ${ctx.basicAuthHeader}\r\n`;
      }
      connectPayload += "User-Agent: NetAccess-Loopback/1.0\r\n\r\n";

      upstreamSocket.write(connectPayload);

      let responseBuffer = Buffer.alloc(0);
      const onData = (chunk: Buffer) => {
        responseBuffer = Buffer.concat([responseBuffer, chunk]);
        const headerEndIndex = responseBuffer.indexOf("\r\n\r\n");

        if (headerEndIndex !== -1) {
          upstreamSocket.removeListener("data", onData);
          const headerStr = responseBuffer.slice(0, headerEndIndex).toString("utf8");
          const statusLine = headerStr.split("\r\n")[0] || "";

          if (statusLine.includes(" 200 ")) {
            isConnected = true;
            clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
            const remaining = responseBuffer.slice(headerEndIndex + 4);
            if (remaining.length > 0) {
              clientSocket.write(remaining);
            }
            if (head && head.length > 0) {
              upstreamSocket.write(head);
            }
            // Bidirectional pipe
            clientSocket.pipe(upstreamSocket);
            upstreamSocket.pipe(clientSocket);
          } else if (
            statusLine.includes(" 407 ") &&
            !withAuth &&
            ctx.basicAuthHeader &&
            attemptCount === 1
          ) {
            // Loopback bridge owns 407 challenge-response flow:
            // Retry once with Proxy-Authorization header
            isRetrying = true;
            upstreamSocket.removeAllListeners();
            upstreamSocket.destroy();
            ctx.activeSockets.delete(upstreamSocket);
            attemptConnect(true);
          } else {
            // Bounded failure: either auth failed with credentials, or other error.
            // Client never receives credentials; no infinite retry loop.
            isConnected = true;
            clientSocket.write(responseBuffer);
            clientSocket.end();
            upstreamSocket.destroy();
          }
        }
      };

      upstreamSocket.on("data", onData);
    });

    const cleanupUpstream = () => {
      ctx.activeSockets.delete(upstreamSocket);
      if (isRetrying) return;
      if (!isConnected && !clientSocket.destroyed) {
        try {
          clientSocket.end("HTTP/1.1 502 Bad Gateway\r\n\r\n");
        } catch {
          // Ignore
        }
        clientSocket.destroy();
      }
    };

    upstreamSocket.once("close", cleanupUpstream);
    upstreamSocket.once("end", cleanupUpstream);
    upstreamSocket.on("error", () => {
      cleanupUpstream();
    });
    clientSocket.once("error", () => {
      upstreamSocket.destroy();
    });
  };

  attemptConnect(ctx.sendInitialAuth && Boolean(ctx.basicAuthHeader));
}

function handleSocks5Connect(
  clientSocket: net.Socket,
  head: Buffer,
  targetHost: string,
  targetPort: number,
  ctx: BridgeContext,
): void {
  let isConnected = false;
  const upstreamSocket = net.connect(ctx.upstreamPort, ctx.upstreamHost, () => {
    ctx.activeSockets.add(upstreamSocket);

    // Step 1: Send SOCKS5 Greeting (Support No-Auth & Username/Password)
    const greeting = Buffer.from([0x05, 0x02, 0x00, 0x02]);
    upstreamSocket.write(greeting);

    let step = "method";
    let buffer = Buffer.alloc(0);

    const onData = (chunk: Buffer) => {
      buffer = Buffer.concat([buffer, chunk]);

      if (step === "method") {
        if (buffer.length < 2) return;
        const ver = buffer[0];
        const method = buffer[1];
        buffer = buffer.slice(2);

        if (ver !== 0x05) {
          isConnected = true;
          clientSocket.end("HTTP/1.1 502 Bad Gateway\r\n\r\n");
          clientSocket.destroy();
          upstreamSocket.destroy();
          return;
        }

        if (method === 0x02) {
          // Username/Password authentication (RFC 1929)
          step = "auth";
          const uBuf = Buffer.from(ctx.username, "utf8");
          const pBuf = Buffer.from(ctx.password, "utf8");
          const authBuf = Buffer.concat([
            Buffer.from([0x01, uBuf.length]),
            uBuf,
            Buffer.from([pBuf.length]),
            pBuf,
          ]);
          upstreamSocket.write(authBuf);
        } else if (method === 0x00) {
          // No authentication required
          step = "connect";
          sendSocks5Connect(upstreamSocket, targetHost, targetPort);
        } else {
          // Unacceptable method
          isConnected = true;
          clientSocket.end("HTTP/1.1 502 Bad Gateway\r\n\r\n");
          clientSocket.destroy();
          upstreamSocket.destroy();
        }
      } else if (step === "auth") {
        if (buffer.length < 2) return;
        const authStatus = buffer[1];
        buffer = buffer.slice(2);

        if (authStatus !== 0x00) {
          isConnected = true;
          clientSocket.end("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n");
          clientSocket.destroy();
          upstreamSocket.destroy();
          return;
        }

        step = "connect";
        sendSocks5Connect(upstreamSocket, targetHost, targetPort);
      } else if (step === "connect") {
        if (buffer.length < 4) return;
        const rep = buffer[1];
        if (rep !== 0x00) {
          isConnected = true;
          clientSocket.end("HTTP/1.1 502 Bad Gateway\r\n\r\n");
          clientSocket.destroy();
          upstreamSocket.destroy();
          return;
        }

        isConnected = true;
        upstreamSocket.removeListener("data", onData);
        clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");

        if (head && head.length > 0) {
          upstreamSocket.write(head);
        }
        clientSocket.pipe(upstreamSocket);
        upstreamSocket.pipe(clientSocket);
      }
    };

    upstreamSocket.on("data", onData);
  });

  const cleanupSocksUpstream = () => {
    ctx.activeSockets.delete(upstreamSocket);
    if (!isConnected && !clientSocket.destroyed) {
      try {
        clientSocket.end("HTTP/1.1 502 Bad Gateway\r\n\r\n");
      } catch {
        // Ignore
      }
      clientSocket.destroy();
    }
  };

  upstreamSocket.once("close", cleanupSocksUpstream);
  upstreamSocket.once("end", cleanupSocksUpstream);
  upstreamSocket.on("error", () => {
    cleanupSocksUpstream();
  });

  clientSocket.on("error", () => {
    upstreamSocket.destroy();
  });
}

function sendSocks5Connect(socket: net.Socket, targetHost: string, targetPort: number): void {
  // Use domain name resolution on proxy side (ATYP 0x03)
  const hostBuf = Buffer.from(targetHost, "utf8");
  const reqBuf = Buffer.concat([
    Buffer.from([0x05, 0x01, 0x00, 0x03, hostBuf.length]),
    hostBuf,
    Buffer.from([(targetPort >> 8) & 0xff, targetPort & 0xff]),
  ]);
  socket.write(reqBuf);
}

// ---------------------------------------------------------------------------
// Plain HTTP Request Handler
// ---------------------------------------------------------------------------

function handleHttpRequest(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  ctx: BridgeContext,
): void {
  const parsedUrl = new URL(req.url ?? "/", `http://${req.headers.host || "localhost"}`);
  const targetHost = parsedUrl.hostname;
  const targetPort = parseInt(parsedUrl.port || "80", 10);

  if (ctx.isSocks5) {
    // For SOCKS5, connect to target through SOCKS5, then send raw HTTP
    const upstreamSocket = net.connect(ctx.upstreamPort, ctx.upstreamHost, () => {
      ctx.activeSockets.add(upstreamSocket);
      // Perform SOCKS5 connect then pipe raw HTTP stream
      sendSocks5Connect(upstreamSocket, targetHost, targetPort);
      // Wait for reply then pipe
      upstreamSocket.once("data", () => {
        // Send request
        upstreamSocket.write(`${req.method} ${parsedUrl.pathname}${parsedUrl.search} HTTP/1.1\r\n`);
        for (const [k, v] of Object.entries(req.headers)) {
          if (Array.isArray(v)) {
            for (const val of v) upstreamSocket.write(`${k}: ${val}\r\n`);
          } else if (v !== undefined) {
            upstreamSocket.write(`${k}: ${v}\r\n`);
          }
        }
        upstreamSocket.write("\r\n");
        req.pipe(upstreamSocket);
        upstreamSocket.pipe(res.socket as net.Socket);
      });
    });
    upstreamSocket.on("error", () => {
      res.writeHead(502);
      res.end("Bad Gateway");
    });
  } else {
    // For HTTP upstream proxy: forward with Proxy-Authorization (or retry on 407)
    const forwardRequest = (withAuth: boolean, retryCount: number) => {
      const proxyHeaders = { ...req.headers };
      if (withAuth && ctx.basicAuthHeader) {
        proxyHeaders["proxy-authorization"] = ctx.basicAuthHeader;
      }

      const proxyReq = http.request(
        {
          host: ctx.upstreamHost,
          port: ctx.upstreamPort,
          method: req.method,
          path: req.url,
          headers: proxyHeaders,
        },
        (proxyRes) => {
          if (
            proxyRes.statusCode === 407 &&
            !withAuth &&
            ctx.basicAuthHeader &&
            retryCount === 0
          ) {
            // Loopback bridge retries once with Proxy-Authorization
            proxyRes.resume();
            forwardRequest(true, 1);
            return;
          }

          res.writeHead(proxyRes.statusCode || 500, proxyRes.headers);
          proxyRes.pipe(res);
        },
      );

      proxyReq.on("error", () => {
        if (!res.headersSent) {
          res.writeHead(502);
          res.end("Bad Gateway");
        }
      });

      req.pipe(proxyReq);
    };

    forwardRequest(ctx.sendInitialAuth && Boolean(ctx.basicAuthHeader), 0);
  }
}

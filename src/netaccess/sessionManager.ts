/**
 * NetAccess Session Manager
 * 
 * Manages the full lifecycle of target application sessions:
 * - Direct path: simple system launch via /usr/bin/open
 * - Alternate transport: isolated Chromium sandbox with ephemeral --user-data-dir
 * - Automatic browser discovery on macOS
 * - Child process tracking and clean teardown integration
 * 
 * Guarantees:
 * - User's normal browser profiles are never touched
 * - No credentials exposed in process command line arguments
 * - All child PIDs and temp directories registered with CleanupSupervisor
 */

import { spawn } from "node:child_process";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import {
  type DiscoveredBrowser,
  type ManagedProcess,
  type ParsedTarget,
  type SelectedPath,
  type SessionHandle,
  type TransportConfig,
  type UserFacingError,
} from "./types.js";
import { CleanupSupervisor } from "./cleanupSupervisor.js";
import {
  startLoopbackBridge,
  type CredentialResolver,
  CredentialsUnavailableError,
} from "./loopbackTunnel.js";

const CANDIDATE_BROWSER_PATHS: { name: DiscoveredBrowser["name"]; relativePath: string }[] = [
  { name: "Google Chrome", relativePath: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" },
  { name: "Brave Browser", relativePath: "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser" },
  { name: "Microsoft Edge", relativePath: "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge" },
  { name: "Chromium", relativePath: "/Applications/Chromium.app/Contents/MacOS/Chromium" },
];

export interface SessionManagerOptions {
  cleanupSupervisor?: CleanupSupervisor;
  customBrowserPath?: string;
  openerCommand?: string;
  spawnFn?: typeof spawn;
  credentialResolver?: CredentialResolver;
}

export class SessionManager {
  private supervisor: CleanupSupervisor;
  private customBrowserPath?: string;
  private openerCommand?: string;
  private spawnFn?: typeof spawn;
  private credentialResolver?: CredentialResolver;
  private sessions: Map<string, SessionHandle> = new Map();
  private activeSession: SessionHandle | null = null;
  private onSessionExitCallback?: (sessionId: string) => void;

  constructor(opts: SessionManagerOptions = {}) {
    this.supervisor = opts.cleanupSupervisor ?? CleanupSupervisor.getShared();
    this.customBrowserPath = opts.customBrowserPath;
    this.openerCommand = opts.openerCommand;
    this.spawnFn = opts.spawnFn;
    this.credentialResolver = opts.credentialResolver;
  }

  public setCredentialResolver(resolver: CredentialResolver): void {
    this.credentialResolver = resolver;
  }

  public getSupervisor(): CleanupSupervisor {
    return this.supervisor;
  }

  public getActiveSession(): SessionHandle | null {
    return this.activeSession;
  }

  public getSession(sessionId: string): SessionHandle | undefined {
    return this.sessions.get(sessionId);
  }

  public getAllSessions(): SessionHandle[] {
    return Array.from(this.sessions.values());
  }

  public setOnSessionExit(cb: (sessionId: string) => void): void {
    this.onSessionExitCallback = cb;
  }

  /**
   * Discover installed Chromium-based browsers on macOS
   */
  public async discoverBrowsers(): Promise<DiscoveredBrowser[]> {
    const discovered: DiscoveredBrowser[] = [];

    if (this.customBrowserPath) {
      try {
        await fs.access(this.customBrowserPath, fs.constants.X_OK);
        discovered.push({
          name: "Custom",
          executablePath: this.customBrowserPath,
          isChromiumBased: true,
        });
      } catch {
        // Custom path not executable
      }
    }

    const homeDir = os.homedir();
    for (const cand of CANDIDATE_BROWSER_PATHS) {
      // Check system /Applications
      try {
        await fs.access(cand.relativePath, fs.constants.X_OK);
        discovered.push({
          name: cand.name,
          executablePath: cand.relativePath,
          isChromiumBased: true,
        });
        continue;
      } catch {
        // Not in system Applications
      }

      // Check user ~/Applications
      const userPath = path.join(homeDir, cand.relativePath);
      try {
        await fs.access(userPath, fs.constants.X_OK);
        discovered.push({
          name: cand.name,
          executablePath: userPath,
          isChromiumBased: true,
        });
      } catch {
        // Not in user Applications
      }
    }

    return discovered;
  }

  /**
   * Launch destination session
   * - Direct path: opens in user's default browser via /usr/bin/open
   * - Alternate transport: opens in isolated browser sandbox with scoped proxy
   */
  public async launchSession(
    sessionId: string,
    target: ParsedTarget,
    selectedPath: SelectedPath,
    transportConfig?: TransportConfig,
    signal?: AbortSignal,
  ): Promise<SessionHandle> {
    if (signal?.aborted) {
      throw new Error("Session launch aborted by user");
    }

    if (selectedPath.type === "direct") {
      return this.launchDirectSession(sessionId, target, selectedPath);
    } else {
      return this.launchAlternateSession(sessionId, target, selectedPath, transportConfig, signal);
    }
  }

  /**
   * Close active session and trigger comprehensive cleanup
   */
  public async closeSession(sessionId?: string): Promise<void> {
    const targetSessionId = sessionId ?? this.activeSession?.sessionId;
    if (!targetSessionId) return;

    const session = this.sessions.get(targetSessionId);
    if (session) {
      session.state = "CLEANUP";
    }

    await this.supervisor.cleanupSession(targetSessionId);

    if (session) {
      session.state = "IDLE";
    }
    this.sessions.delete(targetSessionId);

    if (this.activeSession?.sessionId === targetSessionId) {
      this.activeSession = null;
    }
  }

  // -------------------------------------------------------------------------
  // Direct Launch (macOS /usr/bin/open)
  // -------------------------------------------------------------------------

  private async launchDirectSession(
    sessionId: string,
    target: ParsedTarget,
    selectedPath: SelectedPath,
  ): Promise<SessionHandle> {
    const opener = this.openerCommand ?? "/usr/bin/open";
    const spawnFunc = this.spawnFn ?? spawn;

    const child = spawnFunc(opener, [target.href], {
      stdio: "ignore",
    });

    const pid = child.pid ?? 0;
    if (pid > 0) {
      this.supervisor.registerProcess(pid, sessionId, opener);
      child.on("exit", () => {
        this.supervisor.unregisterProcess(pid);
        if (this.onSessionExitCallback) {
          this.onSessionExitCallback(sessionId);
        }
      });
    }

    const managedProcess: ManagedProcess = {
      pid,
      command: opener,
      args: [target.href],
      startedAt: Date.now(),
      kill: (sig = "SIGTERM") => {
        if (pid > 0) {
          try {
            return process.kill(pid, sig);
          } catch {
            return false;
          }
        }
        return false;
      },
    };

    const session: SessionHandle = {
      sessionId,
      target,
      path: selectedPath,
      state: "OPEN",
      process: managedProcess,
      startedAt: Date.now(),
      browserLaunched: true,
    };

    this.sessions.set(sessionId, session);
    this.activeSession = session;
    return session;
  }

  // -------------------------------------------------------------------------
  // Alternate Launch (Isolated Chromium Profile Sandbox)
  // -------------------------------------------------------------------------

  private async launchAlternateSession(
    sessionId: string,
    target: ParsedTarget,
    selectedPath: SelectedPath,
    transportConfig?: TransportConfig,
    signal?: AbortSignal,
  ): Promise<SessionHandle> {
    const browsers = await this.discoverBrowsers();
    if (browsers.length === 0) {
      const error: UserFacingError = {
        code: "PERMISSION_REQUIRED",
        message: "No supported browser found on this Mac to launch an isolated alternate session.",
        details: "NetAccess requires Google Chrome, Brave Browser, Microsoft Edge, or Chromium for per-process proxy isolation.",
        suggestedAction: "Please install a supported browser or use direct connectivity.",
      };
      throw error;
    }

    const browser = browsers[0];

    // Create unique, disposable ephemeral profile in /tmp
    const profileDir = await this.supervisor.createEphemeralProfile(sessionId);

    // Format proxy argument safely:
    // Chromium Credential Isolation:
    // Passwords MUST NEVER appear in argv! If transport requires authentication,
    // start an ephemeral loopback bridge binding strictly to 127.0.0.1:<ephemeral-port>.
    let proxyArg = "";
    if (transportConfig?.host && transportConfig.port) {
      const needsAuth = Boolean(transportConfig.username || transportConfig.secretRef);
      if (needsAuth) {
        try {
          const bridge = await startLoopbackBridge(transportConfig, {
            sessionId,
            supervisor: this.supervisor,
            credentialResolver: this.credentialResolver,
          });
          proxyArg = bridge.proxyUrl;
        } catch (err: unknown) {
          await this.supervisor.cleanupSession(sessionId);
          if (err instanceof CredentialsUnavailableError) {
            const userErr: UserFacingError = {
              code: "CREDENTIALS_UNAVAILABLE",
              message: `Credentials for transport "${transportConfig.name}" are unavailable in macOS Keychain.`,
              details: "The credential could not be retrieved from the secure credential store.",
              suggestedAction: "Please re-enter your credentials or select a different transport.",
            };
            throw userErr;
          }
          throw err;
        }
      } else {
        const cleanHost = transportConfig.host.includes("@")
          ? transportConfig.host.split("@").pop()!
          : transportConfig.host;
        if (transportConfig.type === "socks5") {
          proxyArg = `socks5://${cleanHost}:${transportConfig.port}`;
        } else {
          proxyArg = `http://${cleanHost}:${transportConfig.port}`;
        }
      }
    }

    const args: string[] = [
      `--user-data-dir=${profileDir}`,
      "--no-first-run",
      "--no-default-browser-check",
      "--disable-background-networking",
      "--disable-sync",
      "--disable-default-apps",
      "--disable-quic",
      "--disable-component-update",
      "--disable-features=Translate,OptimizationHints,MediaRouter",
      "--no-pings",
    ];

    if (proxyArg) {
      args.push(`--proxy-server=${proxyArg}`);
    }

    args.push(target.href);

    if (signal?.aborted) {
      await this.supervisor.cleanupSession(sessionId);
      throw new Error("Session launch cancelled before process spawn");
    }

    const spawnFunc = this.spawnFn ?? spawn;
    let child;
    try {
      child = spawnFunc(browser.executablePath, args, {
        detached: true,
        stdio: "ignore",
      });
    } catch (err: unknown) {
      await this.supervisor.cleanupSession(sessionId);
      throw new Error(`Failed to spawn browser process (${browser.name}): ${err instanceof Error ? err.message : String(err)}`);
    }

    const pid = child.pid ?? 0;
    if (pid <= 0) {
      await this.supervisor.cleanupSession(sessionId);
      throw new Error(`Failed to spawn browser process (${browser.name})`);
    }

    this.supervisor.registerProcess(pid, sessionId, browser.name);

    // Handle browser exit
    child.on("exit", async () => {
      this.supervisor.unregisterProcess(pid);
      if (this.onSessionExitCallback) {
        this.onSessionExitCallback(sessionId);
      }
    });

    const managedProcess: ManagedProcess = {
      pid,
      command: browser.executablePath,
      args: args.filter((a) => !a.startsWith("http")), // Exclude URL from process description
      startedAt: Date.now(),
      kill: (sig = "SIGTERM") => {
        try {
          return process.kill(pid, sig);
        } catch {
          return false;
        }
      },
    };

    const session: SessionHandle = {
      sessionId,
      target,
      path: selectedPath,
      state: "OPEN",
      process: managedProcess,
      profileDir,
      startedAt: Date.now(),
      browserLaunched: true,
    };

    this.sessions.set(sessionId, session);
    this.activeSession = session;
    return session;
  }
}

/**
 * NetAccess Application Controller
 * Single orchestration authority and state machine for both macOS GUI and CLI.
 * 
 * Guarantees:
 * - Owns unified SessionState machine
 * - Emits typed lifecycle events
 * - Pure orchestration over Core Engine without UI or transport coupling
 * - Respects reachability vs authorization distinctions
 */

import { EventEmitter } from "node:events";
import {
  type AppSettings,
  type CircuitState,
  type Diagnosis,
  type Finding,
  type OpenTargetResult,
  type ParsedTarget,
  type PathVerificationResult,
  type PolicyDoc,
  type RecentDestination,
  type SelectedPath,
  type SessionHandle,
  type SessionSnapshot,
  type SessionState,
  type TransportConfig,
  type TransportRuntime,
  type UserFacingError,
  type UserFacingErrorCode,
} from "./types.js";
import {
  buildDiagnosis,
  classify,
  destinationTagsFor,
  ewma,
  healthScore,
  makeFinding,
  maybeHalfOpen,
  nextCircuit,
  parseTarget,
  selectTransport,
} from "./engine.js";
import { diagnoseDirectPath } from "./probes/directProbes.js";
import {
  probeTransport,
  type TransportProbeResult,
} from "./probes/transportProber.js";
import { SessionManager } from "./sessionManager.js";
import { TransportManager } from "./transportManager.js";
import { verifyPath } from "./pathVerifier.js";

export type Diagnostician = (
  target: ParsedTarget,
  signal?: AbortSignal,
) => Promise<Finding[]>;

export type TransportProber = (
  transport: TransportConfig,
  target: ParsedTarget,
  signal?: AbortSignal,
) => Promise<TransportProbeResult | { ok: boolean; latencyMs: number; error?: string }>;

export type BrowserLauncher = (
  url: string,
  path: SelectedPath,
  signal?: AbortSignal,
) => Promise<{ launched: boolean; pid?: number }>;

export type PathVerifier = (
  target: ParsedTarget,
  path: SelectedPath,
  sessionId?: string,
  sessionHandle?: SessionHandle | null,
  signal?: AbortSignal,
) => Promise<PathVerificationResult>;

export interface ControllerOptions {
  diagnostician?: Diagnostician;
  transportProber?: TransportProber;
  browserLauncher?: BrowserLauncher;
  sessionManager?: SessionManager;
  pathVerifier?: PathVerifier;
  transportManager?: TransportManager;
  initialTransports?: TransportConfig[];
  initialSettings?: Partial<AppSettings>;
  initialPolicy?: PolicyDoc;
  allowDiagnosticTransports?: boolean;
}

const DEFAULT_SETTINGS: AppSettings = {
  openInDefaultBrowser: true,
  autoLaunchOnConnect: true,
  autoUseAlternate: true,
  rememberRecent: true,
  maxRecent: 10,
  developerMode: false,
  localDiagnostics: true,
};

const DEFAULT_POLICY: PolicyDoc = {
  rules: [
    { id: "drop-untrusted-for-sensitive", kind: "forbid", match: { destinationTag: "sensitive" }, forbidTransportTag: ["untrusted"] },
    { id: "prefer-low-latency", kind: "prefer_latency", withinMs: 250 },
    { id: "fallback-direct", kind: "fallback", transportId: "direct" },
  ],
};

export class ApplicationController extends EventEmitter {
  private state: SessionState = "IDLE";
  private statusMessage = "Ready";
  private currentSessionId: string | null = null;
  private currentTarget: ParsedTarget | null = null;
  private currentPath: SelectedPath | null = null;
  private currentDiagnosis: Diagnosis | null = null;
  private currentError: UserFacingError | null = null;
  private currentVerification: PathVerificationResult | null = null;
  private browserLaunched = false;
  private sessionStartedAt = 0;
  private abortController: AbortController | null = null;

  private transportManager: TransportManager;
  private sessionManager: SessionManager;
  private settings: AppSettings;
  private policy: PolicyDoc;
  private recentTargets: RecentDestination[] = [];
  private sessionMutex: Promise<any> = Promise.resolve();

  // Pluggable dependencies with baseline defaults
  private diagnostician: Diagnostician;
  private transportProber: TransportProber;
  private browserLauncher: BrowserLauncher;
  private pathVerifier: PathVerifier;

  constructor(opts: ControllerOptions = {}) {
    super();
    this.settings = { ...DEFAULT_SETTINGS, ...opts.initialSettings };
    this.policy = opts.initialPolicy ? { ...opts.initialPolicy } : { ...DEFAULT_POLICY };

    this.transportManager =
      opts.transportManager ?? new TransportManager({ initialTransports: opts.initialTransports });

    this.sessionManager = opts.sessionManager ?? new SessionManager();
    this.sessionManager.setCredentialResolver((ref) =>
      this.transportManager.getSecretResolver()(ref),
    );
    this.sessionManager.setOnSessionExit(async (sessionId: string) => {
      if (this.currentSessionId === sessionId) {
        await this.closeSession();
      }
    });

    // Default diagnostician: real direct diagnostics pipeline (P1)
    this.diagnostician = opts.diagnostician ?? ((target, signal) => diagnoseDirectPath(target, signal));

    // Default prober: real alternate transport prober (P2)
    const allowDiag = Boolean(opts.allowDiagnosticTransports || this.settings.developerMode);
    this.transportProber =
      opts.transportProber ??
      (async (transport, target, signal) => {
        // Pre-flight check: If transport requires secretRef, verify credentials exist first.
        // Fails immediately with zero network I/O if secret cannot be retrieved.
        if (transport.secretRef) {
          const secret = await this.transportManager.getSecretResolver()(transport.secretRef);
          if (!secret) {
            return {
              ok: false,
              transportId: transport.id,
              latencyMs: 0,
              stage: "connect_proxy" as const,
              targetReachable: false,
              proxyReachable: false,
              failureReason: "PROXY_AUTH_REQUIRED" as const,
              error: `Credentials for transport "${transport.id}" are unavailable in Keychain.`,
            };
          }
        }
        return probeTransport(transport, target, signal, {
          allowDiagnosticTransports: allowDiag,
          credentialResolver: (ref) =>
            this.transportManager.getSecretResolver()(ref).then((s) => s ?? undefined),
        });
      });

    // Default launcher: real SessionManager integration (P3)
    this.browserLauncher =
      opts.browserLauncher ??
      (async (url: string, path: SelectedPath, signal?: AbortSignal) => {
        if (!this.currentTarget || !this.currentSessionId) {
          return { launched: false };
        }
        const transport = path.transportId ? this.transportManager.getTransport(path.transportId) : undefined;
        const sessionHandle = await this.sessionManager.launchSession(
          this.currentSessionId,
          this.currentTarget,
          path,
          transport,
          signal,
        );
        return { launched: sessionHandle.browserLaunched, pid: sessionHandle.process?.pid };
      });

    // Default verifier: canonical PathVerifier integration (P4)
    this.pathVerifier =
      opts.pathVerifier ??
      (async (target, path, sessId, handle, signal) => {
        const sId = sessId ?? this.currentSessionId ?? "session-default";
        const transport = path.transportId ? this.transportManager.getTransport(path.transportId) : undefined;
        const pids = handle?.process?.pid ? [handle.process.pid] : [];
        return verifyPath(sId, target, path, pids, transport, {}, signal);
      });
  }

  // State inspection
  public getState(): SessionState {
    return this.state;
  }

  public getStatus(): SessionSnapshot {
    return {
      sessionId: this.currentSessionId ?? "none",
      target: this.currentTarget ?? undefined,
      state: this.state,
      statusMessage: this.statusMessage,
      path: this.currentPath ?? undefined,
      diagnosis: this.currentDiagnosis ?? undefined,
      error: this.currentError ?? undefined,
      latencyMs: this.currentPath?.latencyMs,
      verification: this.currentVerification ?? undefined,
      browserLaunched: this.browserLaunched,
      startedAt: this.sessionStartedAt,
      updatedAt: Date.now(),
    };
  }

  public getSettings(): AppSettings {
    return { ...this.settings };
  }

  public updateSettings(updates: Partial<AppSettings>): AppSettings {
    this.settings = { ...this.settings, ...updates };
    return { ...this.settings };
  }

  public getTransports(includeDisabled = false): TransportConfig[] {
    return this.transportManager.getTransports(includeDisabled);
  }

  public getTransportRuntimes(): Record<string, TransportRuntime> {
    return this.transportManager.getAllRuntimes();
  }

  public addTransport(config: TransportConfig): void {
    this.transportManager.addTransport(config);
  }

  public removeTransport(id: string): boolean {
    return this.transportManager.deleteTransportSync(id);
  }

  public async deleteTransport(id: string, targetFile?: string): Promise<boolean> {
    return this.transportManager.deleteTransport(id, targetFile);
  }

  public async saveTransportWithSecret(
    config: TransportConfig,
    secret?: string,
    targetFile?: string,
  ): Promise<void> {
    await this.transportManager.saveTransportWithSecret(config, secret, targetFile);
  }

  public getTransportManager(): TransportManager {
    return this.transportManager;
  }

  public getSessionManager(): SessionManager {
    return this.sessionManager;
  }

  public getPolicy(): PolicyDoc {
    return { ...this.policy };
  }

  public setPolicy(doc: PolicyDoc): void {
    this.policy = { ...doc };
  }

  /**
   * Run standalone diagnostics on destination
   */
  public async checkTarget(rawInput: string, opts: { deep?: boolean } = {}): Promise<Diagnosis> {
    const target = parseTarget(rawInput);
    const findings = await this.diagnostician(target);
    const diagnosis = buildDiagnosis({
      target: target.raw,
      host: target.host,
      port: target.port,
      scheme: target.scheme,
      mode: "live",
      startedAt: Date.now() - 50,
      finishedAt: Date.now(),
      findings,
      happyEyeballs: {},
      hops: [],
    });
    this.currentDiagnosis = diagnosis;
    return diagnosis;
  }

  /**
   * Test a specific configured transport
   */
  public async testTransport(
    transportId: string,
    targetInput = "example.com",
  ): Promise<TransportProbeResult> {
    const transport = this.transportManager.getTransport(transportId);
    if (!transport) {
      throw new Error(`Transport not found: ${transportId}`);
    }
    const target = parseTarget(targetInput);
    const res = await this.transportProber(transport, target);
    if ("stage" in res) {
      this.transportManager.recordProbeResult(res as TransportProbeResult);
      return res as TransportProbeResult;
    }
    const probeRes: TransportProbeResult = {
      ok: res.ok,
      transportId,
      stage: res.ok ? "target_http" : "connect_proxy",
      proxyReachable: res.ok,
      targetReachable: res.ok,
      latencyMs: res.latencyMs,
      error: res.error,
    };
    this.transportManager.recordProbeResult(probeRes);
    return probeRes;
  }

  public getRecentTargets(): RecentDestination[] {
    return [...this.recentTargets];
  }

  public clearRecentTargets(): void {
    this.recentTargets = [];
  }

  /**
   * Set dependency providers (for P1-P4 integration & testing)
   */
  public setDiagnostician(fn: Diagnostician): void {
    this.diagnostician = fn;
  }

  public setTransportProber(fn: TransportProber): void {
    this.transportProber = fn;
  }

  public setBrowserLauncher(fn: BrowserLauncher): void {
    this.browserLauncher = fn;
  }

  public setPathVerifier(fn: PathVerifier): void {
    this.pathVerifier = fn;
  }

  /**
   * Cancel ongoing session
   */
  public async cancelSession(): Promise<void> {
    if (this.abortController) {
      this.abortController.abort();
      this.abortController = null;
    }
    await this.transitionTo("CLEANUP", "Cancelling connection session…");
    if (this.currentSessionId) {
      await this.sessionManager.closeSession(this.currentSessionId);
    }
    this.resetSessionState();
    await this.transitionTo("IDLE", "Ready");
  }

  /**
   * Close completed session and return to IDLE
   */
  public async closeSession(): Promise<void> {
    if (this.state === "CONNECTED" || this.state === "OPEN" || this.state === "MONITORING") {
      await this.transitionTo("CLEANUP", "Closing connection session…");
    }
    if (this.currentSessionId) {
      await this.sessionManager.closeSession(this.currentSessionId);
    }
    this.resetSessionState();
    await this.transitionTo("IDLE", "Ready");
  }

  /**
   * Primary Application API: openTarget(target)
   * Executes the complete unified state machine:
   * IDLE -> VALIDATING -> DIAGNOSING -> (DIRECT_SUCCESS -> CONNECTED)
   *                                   | (DIRECT_FAILURE -> FINDING_PATH -> TESTING_PATHS -> CONNECTED | FAILED)
   * CONNECTED -> OPEN -> MONITORING -> CLEANUP -> IDLE
   */
  public async openTarget(
    rawInput: string,
    opts: { skipBrowserLaunch?: boolean } = {},
  ): Promise<OpenTargetResult> {
    // Instantiate abort controller synchronously so immediate cancellation is captured
    this.abortController = new AbortController();
    const activeAbort = this.abortController;

    const previousMutex = this.sessionMutex;
    let releaseMutex: () => void = () => {};
    this.sessionMutex = new Promise<void>((resolve) => {
      releaseMutex = resolve;
    });

    await previousMutex.catch(() => {});

    try {
      if (activeAbort.signal.aborted) {
        throw new Error("Session was cancelled by user.");
      }
      return await this.executeOpenTarget(rawInput, opts, activeAbort);
    } finally {
      releaseMutex();
    }
  }

  private async executeOpenTarget(
    rawInput: string,
    opts: { skipBrowserLaunch?: boolean } = {},
    activeAbort: AbortController = new AbortController(),
  ): Promise<OpenTargetResult> {
    // Orderly Preemption:
    // 1. If currently connected, open, or monitoring, close cleanly before starting new target
    if (this.state === "CONNECTED" || this.state === "OPEN" || this.state === "MONITORING") {
      await this.closeSession();
    } else if (
      this.state === "VALIDATING" ||
      this.state === "DIAGNOSING" ||
      this.state === "FINDING_PATH" ||
      this.state === "TESTING_PATHS"
    ) {
      // 2. If session in-flight, cancel cleanly
      await this.cancelSession();
    } else if (this.state === "CLEANUP") {
      // 3. If currently cleaning up, await return to IDLE
      const startWait = Date.now();
      while (this.state === "CLEANUP" && Date.now() - startWait < 1500) {
        await new Promise((r) => setTimeout(r, 25));
      }
      if (this.state === "CLEANUP") {
        this.resetSessionState();
        this.state = "IDLE";
      }
    }

    if (activeAbort.signal.aborted) {
      throw new Error("Session was cancelled by user.");
    }

    const sessionId = Math.random().toString(36).slice(2, 10);
    this.currentSessionId = sessionId;
    this.sessionStartedAt = Date.now();
    this.currentError = null;
    this.currentPath = null;
    this.currentDiagnosis = null;
    this.currentVerification = null;
    this.browserLaunched = false;
    this.abortController = activeAbort;
    const { signal } = activeAbort;

    try {
      // Step 1: VALIDATING
      await this.transitionTo("VALIDATING", "Validating destination address…");
      let target: ParsedTarget;
      try {
        target = parseTarget(rawInput);
      } catch (err: unknown) {
        const errorMsg = err instanceof Error ? err.message : String(err);
        const userErr = this.makeUserError("INVALID_TARGET", "Please check the destination address.", errorMsg);
        await this.failSession(userErr);
        throw userErr;
      }
      this.currentTarget = target;
      this.checkAborted(signal);

      // Step 2: DIAGNOSING direct path
      await this.transitionTo("DIAGNOSING", `Checking direct connection to ${target.host}…`);
      const findings = await this.diagnostician(target, signal);
      this.checkAborted(signal);

      const diagnosis = buildDiagnosis({
        target: target.raw,
        host: target.host,
        port: target.port,
        scheme: target.scheme,
        mode: "live",
        startedAt: this.sessionStartedAt,
        finishedAt: Date.now(),
        findings,
        happyEyeballs: {},
        hops: [],
      });
      this.currentDiagnosis = diagnosis;
      this.emit("diagnosisUpdated", diagnosis);

      // Check if direct path is healthy
      const isDirectHealthy = diagnosis.classification.class === "healthy";

      let selectedPath: SelectedPath;

      if (isDirectHealthy) {
        selectedPath = {
          type: "direct",
          transportId: "direct",
          transportName: "Direct Connection",
          transportType: "direct",
          latencyMs: findings.find((f) => f.ok && f.latencyMs)?.latencyMs ?? 24,
          reason: "Direct path is healthy and responsive.",
        };
      } else {
        // Step 3: FINDING_PATH & evaluating policy
        if (!this.settings.autoUseAlternate) {
          const userErr = this.makeUserError(
            "DESTINATION_UNREACHABLE",
            `Direct connection to ${target.host} is unavailable and alternate paths are disabled.`,
            diagnosis.classification.likelyCause,
          );
          await this.failSession(userErr);
          throw userErr;
        }

        await this.transitionTo("FINDING_PATH", "Finding an available, authorized connection path…");
        this.checkAborted(signal);

        // Step 4: TESTING_PATHS
        await this.transitionTo("TESTING_PATHS", "Testing configured connection paths…");
        const availableTransports = this.getTransports().filter((t) => t.enabled);
        const destinationTags = destinationTagsFor(target.host);

        // Exclude diagnosticOnly transports unless developerMode is enabled
        const alternateCandidates = availableTransports.filter(
          (t) => t.id !== "direct" && (!t.diagnosticOnly || this.settings.developerMode),
        );
        const testResults: Record<string, { ok: boolean; latencyMs: number; error?: string }> = {};

        for (const candidate of alternateCandidates) {
          this.checkAborted(signal);
          const res = await this.transportProber(candidate, target, signal);
          testResults[candidate.id] = res;

          if ("stage" in res) {
            this.transportManager.recordProbeResult(res as TransportProbeResult);
          } else {
            this.transportManager.recordProbeResult({
              ok: res.ok,
              transportId: candidate.id,
              latencyMs: res.latencyMs,
              stage: res.ok ? "target_http" : "connect_proxy",
              targetReachable: res.ok,
              proxyReachable: res.ok,
              error: res.error,
            });
          }
        }

        // Evaluate policy-based selection with updated runtime
        const selection = selectTransport({
          host: target.host,
          destinationTags,
          diagnosis,
          policy: this.policy,
          transports: availableTransports,
          runtime: this.getTransportRuntimes(),
        });

        const chosenTransport = availableTransports.find((t) => t.id === selection.transportId);
        const chosenResult = testResults[selection.transportId];

        if (!chosenTransport || selection.transportId === "direct" || !chosenResult?.ok) {
          // Check if failure is actually an application-level rejection
          if (diagnosis.classification.class === "destination_restriction") {
            const userErr = this.makeUserError(
              "DESTINATION_REJECTED",
              `The destination is reachable, but the service rejected the request (${diagnosis.classification.label}).`,
              diagnosis.classification.likelyCause,
              "This is an application or authorization restriction, not a network failure.",
            );
            await this.failSession(userErr);
            throw userErr;
          }

          const userErr = this.makeUserError(
            "NO_WORKING_PATH",
            `NetAccess couldn't establish a connection to ${target.host}.`,
            diagnosis.classification.likelyCause,
            "We checked direct connectivity and all configured alternate connections.",
          );
          await this.failSession(userErr);
          throw userErr;
        }

        selectedPath = {
          type: "alternate",
          transportId: chosenTransport.id,
          transportName: chosenTransport.name,
          transportType: chosenTransport.type,
          latencyMs: chosenResult.latencyMs,
          reason: selection.reason,
        };
      }

      this.currentPath = selectedPath;
      this.emit("transportChanged", selectedPath);

      this.checkAborted(signal);

      // Step 5: CONNECTED
      await this.transitionTo("CONNECTED", `Connection established via ${selectedPath.transportName}.`);
      this.recordRecentTarget(target, true, selectedPath.type);

      // Step 6: Launch browser session if configured
      let sessionHandle: SessionHandle | null = null;
      const shouldLaunch = !opts.skipBrowserLaunch && this.settings.autoLaunchOnConnect;
      if (shouldLaunch) {
        await this.transitionTo("OPEN", `Opening ${target.host}…`);
        const launchResult = await this.browserLauncher(target.href, selectedPath, signal);
        this.browserLaunched = launchResult.launched;
        sessionHandle = this.sessionManager.getActiveSession();
      }

      // Step 7: Path Verification
      const verification = await this.pathVerifier(
        target,
        selectedPath,
        sessionId,
        sessionHandle,
        signal,
      );
      this.currentVerification = verification;
      this.emit("verificationUpdated", verification);

      if (shouldLaunch) {
        await this.transitionTo("MONITORING", `Active session connected to ${target.host}.`);
      }

      const result: OpenTargetResult = {
        sessionId,
        target,
        state: this.state,
        path: selectedPath,
        diagnosis,
        selection: selectTransport({
          host: target.host,
          destinationTags: destinationTagsFor(target.host),
          diagnosis,
          policy: this.policy,
          transports: this.getTransports(),
          runtime: this.getTransportRuntimes(),
        }),
        verification,
        browserLaunched: this.browserLaunched,
      };

      this.emit("completed", result);
      return result;
    } catch (err: unknown) {
      if (this.currentSessionId) {
        await this.sessionManager.closeSession(this.currentSessionId);
      }
      if (signal.aborted) {
        await this.cancelSession();
        throw new Error("Session was cancelled by user.");
      }
      if (this.state !== "FAILED") {
        const userErr: UserFacingError = (err && typeof err === "object" && "code" in err && "message" in err)
          ? (err as UserFacingError)
          : this.makeUserError(
              "DESTINATION_UNREACHABLE",
              err instanceof Error ? err.message : `Connection error to ${rawInput}`,
              "An unexpected error occurred while establishing connection.",
            );
        await this.failSession(userErr);
      }
      throw err;
    } finally {
      this.abortController = null;
    }
  }

  // --- Internal Helpers ---

  private async transitionTo(newState: SessionState, message: string): Promise<void> {
    this.state = newState;
    this.statusMessage = message;
    this.emit("stateChanged", newState, message);
  }

  private async failSession(err: UserFacingError): Promise<void> {
    this.currentError = err;
    if (this.currentTarget) {
      this.recordRecentTarget(this.currentTarget, false);
    }
    if (this.currentSessionId) {
      await this.sessionManager.closeSession(this.currentSessionId);
    }
    await this.transitionTo("FAILED", err.message);
    this.emit("failed", err);
  }

  private checkAborted(signal: AbortSignal): void {
    if (signal.aborted) {
      throw new Error("Session aborted");
    }
  }

  private recordRecentTarget(target: ParsedTarget, success: boolean, pathType?: "direct" | "alternate"): void {
    if (!this.settings.rememberRecent) return;
    // Deduplicate by host
    this.recentTargets = this.recentTargets.filter((r) => r.host !== target.host);
    this.recentTargets.unshift({
      raw: target.raw,
      host: target.host,
      scheme: target.scheme,
      port: target.port,
      lastAccessedAt: Date.now(),
      success,
      lastPathType: pathType,
    });
    if (this.recentTargets.length > this.settings.maxRecent) {
      this.recentTargets = this.recentTargets.slice(0, this.settings.maxRecent);
    }
  }

  private makeUserError(
    code: UserFacingErrorCode,
    message: string,
    details?: string,
    suggestedAction?: string,
  ): UserFacingError {
    return { code, message, details, suggestedAction };
  }

  private resetSessionState(): void {
    this.currentSessionId = null;
    this.currentTarget = null;
    this.currentPath = null;
    this.currentDiagnosis = null;
    this.currentError = null;
    this.currentVerification = null;
    this.browserLaunched = false;
  }
}

/**
 * NetAccess Transport Manager
 * 
 * Manages authorized transport configurations, persistent storage,
 * and live EWMA health / circuit-breaker runtime states.
 * 
 * Guarantees:
 * - Never persists plaintext credentials or secrets to disk
 * - Destination-aware health scoring (proxy reachability ≠ destination reachability)
 * - Circuit breaker lifecycle (closed -> open -> cooldown -> half_open -> recovery)
 * - Initial neutral baseline (no artificial perfection for untested transports)
 */

import * as fs from "node:fs/promises";
import * as path from "node:path";
import {
  type CircuitState,
  type TransportConfig,
  type TransportRuntime,
} from "./types.js";
import {
  ewma,
  healthScore,
  maybeHalfOpen,
  nextCircuit,
} from "./engine.js";
import { type TransportProbeResult } from "./probes/transportProber.js";
import {
  type CredentialStore,
  getDefaultCredentialStore,
  formatSecretRef,
  KeychainDeletionError,
  KeychainPermissionError,
} from "./keychain.js";

export class TransportManager {
  private transports: Map<string, TransportConfig> = new Map();
  private runtimes: Map<string, TransportRuntime> = new Map();
  private storagePath: string | null = null;
  private credentialStore: CredentialStore;

  constructor(
    opts: {
      initialTransports?: TransportConfig[];
      storagePath?: string;
      credentialStore?: CredentialStore;
    } = {},
  ) {
    this.storagePath = opts.storagePath ?? null;
    this.credentialStore = opts.credentialStore ?? getDefaultCredentialStore();

    const initial = opts.initialTransports ?? [
      {
        id: "direct",
        name: "Direct Connection",
        type: "direct",
        tags: ["direct", "default"],
        trusted: true,
        enabled: true,
        notes: "Default local network interface",
      },
    ];

    for (const t of initial) {
      this.addTransport(t);
    }
  }

  public getTransports(includeDisabled = false): TransportConfig[] {
    const list = Array.from(this.transports.values());
    if (includeDisabled) return list;
    return list.filter((t) => t.enabled);
  }

  public getTransport(id: string): TransportConfig | undefined {
    return this.transports.get(id);
  }

  public getRuntime(id: string): TransportRuntime | undefined {
    const rt = this.runtimes.get(id);
    if (!rt) return undefined;
    const updated = maybeHalfOpen(rt);
    this.runtimes.set(id, updated);
    return { ...updated };
  }

  public getAllRuntimes(): Record<string, TransportRuntime> {
    const result: Record<string, TransportRuntime> = {};
    for (const [id, rt] of this.runtimes.entries()) {
      const updated = maybeHalfOpen(rt);
      this.runtimes.set(id, updated);
      result[id] = { ...updated };
    }
    return result;
  }

  public addTransport(config: TransportConfig): void {
    // Sanitize config: remove any accidental inline passwords
    const sanitized: TransportConfig = {
      id: config.id,
      name: config.name,
      type: config.type,
      host: config.host,
      port: config.port,
      tags: [...(config.tags ?? [])],
      trusted: Boolean(config.trusted),
      enabled: Boolean(config.enabled),
      username: config.username,
      secretRef: config.secretRef,
      notes: config.notes,
      diagnosticOnly: config.diagnosticOnly,
    };

    this.transports.set(config.id, sanitized);
    if (!this.runtimes.has(config.id)) {
      this.runtimes.set(config.id, this.createInitialRuntime(config.id));
    }
  }

  public updateTransport(id: string, updates: Partial<TransportConfig>): boolean {
    const existing = this.transports.get(id);
    if (!existing) return false;

    // Prevent overwriting id
    const updated: TransportConfig = {
      ...existing,
      ...updates,
      id,
    };

    this.transports.set(id, updated);
    return true;
  }

  /**
   * Synchronous removal from memory (for fast in-memory lifecycle without Keychain I/O)
   */
  public deleteTransportSync(id: string): boolean {
    if (id === "direct") return false; // Cannot delete direct connection
    this.runtimes.delete(id);
    return this.transports.delete(id);
  }

  /**
   * Full transactional transport deletion:
   * 1. Remove credential from Keychain if secretRef is present.
   *    If Keychain delete fails with permission/system error, fail-closed: do NOT delete metadata.
   * 2. Remove from memory and persist metadata changes to disk.
   */
  public async deleteTransport(id: string, targetFile?: string): Promise<boolean> {
    if (id === "direct") return false; // Cannot delete direct connection
    const existing = this.transports.get(id);
    if (!existing) return false;

    if (existing.secretRef) {
      try {
        await this.credentialStore.deleteSecret(existing.secretRef);
      } catch (err: unknown) {
        if (err instanceof KeychainPermissionError || err instanceof KeychainDeletionError) {
          throw err;
        }
        throw new KeychainDeletionError(
          `Cannot delete transport "${id}": ${err instanceof Error ? err.message : String(err)}`,
        );
      }
    }

    this.runtimes.delete(id);
    this.transports.delete(id);

    const targetPath = targetFile ?? this.storagePath;
    if (targetPath) {
      await this.saveToDisk(targetPath);
    }
    return true;
  }

  /**
   * Save transport with secret transactionally:
   * 1. If secret is provided, save to Keychain with formatted secretRef
   * 2. Persist metadata to disk
   * 3. On disk error, rollback secret from Keychain
   */
  public async saveTransportWithSecret(
    config: TransportConfig,
    secret?: string,
    targetFile?: string,
  ): Promise<void> {
    const preparedConfig: TransportConfig = { ...config };

    if (secret) {
      const secretRef = formatSecretRef(config.id);
      preparedConfig.secretRef = secretRef;

      // 1. Write to Keychain
      await this.credentialStore.setSecret(secretRef, secret);

      // 2. Write metadata to memory and disk
      const targetPath = targetFile ?? this.storagePath;
      try {
        this.addTransport(preparedConfig);
        if (targetPath) {
          await this.saveToDisk(targetPath);
        }
      } catch (diskErr) {
        // Rollback Keychain on failure to prevent orphaned secrets
        try {
          await this.credentialStore.deleteSecret(secretRef);
        } catch {
          // Best-effort rollback
        }
        this.transports.delete(config.id);
        this.runtimes.delete(config.id);
        throw diskErr;
      }
    } else {
      this.addTransport(preparedConfig);
      const targetPath = targetFile ?? this.storagePath;
      if (targetPath) {
        await this.saveToDisk(targetPath);
      }
    }
  }

  /**
   * Returns a CredentialResolver for probe or loopback bridge authentication
   */
  public getSecretResolver(): (secretRef: string) => Promise<string | null> {
    return (secretRef: string) => this.credentialStore.getSecret(secretRef);
  }

  public getCredentialStore(): CredentialStore {
    return this.credentialStore;
  }

  /**
   * Record probe result and update EWMA health score and circuit breaker state.
   * Preserves destination awareness: if the proxy is healthy but the destination rejected
   * the request, do not penalize proxy infrastructure.
   */
  public recordProbeResult(result: TransportProbeResult): void {
    const rt = this.runtimes.get(result.transportId);
    if (!rt) return;

    // Destination awareness check:
    // If the proxy itself was reachable and the failure was solely destination-side,
    // we do not increment proxy infrastructure circuit breaker failures.
    const isInfrastructureFailure =
      !result.ok && (!result.proxyReachable || result.failureReason === "PROXY_AUTH_REQUIRED");

    const event = isInfrastructureFailure ? ("failure" as const) : ("success" as const);
    const circuitUpdate = nextCircuit(rt.circuit, event, rt.failures);

    // Update EWMA success rate
    const prevSuccess = rt.successRate;
    const sampleSuccess = result.ok ? 1.0 : isInfrastructureFailure ? 0.0 : 0.8;
    const newSuccess = ewma(prevSuccess, sampleSuccess);

    // Update EWMA latency & jitter
    const prevLatency = rt.latencyMs;
    const sampleLatency = result.latencyMs > 0 ? result.latencyMs : prevLatency;
    const newLatency = ewma(prevLatency, sampleLatency);
    const sampleJitter = Math.abs(sampleLatency - prevLatency);
    const newJitter = ewma(rt.jitterMs, sampleJitter);

    const newHistory = [...rt.history, result.ok ? 1 : 0].slice(-20);
    const newLatencyHistory = [...rt.latencyHistory, Math.round(sampleLatency)].slice(-20);

    const updated: TransportRuntime = {
      ...rt,
      successRate: Number(newSuccess.toFixed(3)),
      latencyMs: Math.round(newLatency),
      jitterMs: Math.round(newJitter),
      circuit: circuitUpdate.circuit,
      failures: circuitUpdate.failures,
      cooldownUntil: circuitUpdate.cooldownUntil,
      history: newHistory,
      latencyHistory: newLatencyHistory,
      lastCheckAt: Date.now(),
      lastError: result.error,
      score: 0,
    };
    updated.score = Number(healthScore(updated).toFixed(3));

    this.runtimes.set(result.transportId, updated);
  }

  /**
   * Safe persistence to disk (metadata only, zero plaintext secrets)
   */
  public async saveToDisk(filepath?: string): Promise<void> {
    const targetPath = filepath ?? this.storagePath;
    if (!targetPath) return;

    // Ensure directory exists
    await fs.mkdir(path.dirname(targetPath), { recursive: true });

    // Exclude direct connection and strip any sensitive fields
    const toSave = Array.from(this.transports.values())
      .filter((t) => t.id !== "direct")
      .map((t) => ({
        id: t.id,
        name: t.name,
        type: t.type,
        host: t.host,
        port: t.port,
        tags: t.tags,
        trusted: t.trusted,
        enabled: t.enabled,
        username: t.username,
        secretRef: t.secretRef,
        notes: t.notes,
        diagnosticOnly: t.diagnosticOnly,
      }));

    const json = JSON.stringify({ version: 1, transports: toSave }, null, 2);
    await fs.writeFile(targetPath, json, "utf8");
  }

  /**
   * Load metadata from disk
   */
  public async loadFromDisk(filepath?: string): Promise<void> {
    const targetPath = filepath ?? this.storagePath;
    if (!targetPath) return;

    try {
      const content = await fs.readFile(targetPath, "utf8");
      const data = JSON.parse(content);
      if (Array.isArray(data.transports)) {
        for (const t of data.transports) {
          if (t.id && t.name && t.type) {
            this.addTransport(t);
          }
        }
      }
    } catch (err: unknown) {
      if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
        throw err;
      }
    }
  }

  /**
   * Neutral initial runtime state (never artificially perfect)
   */
  private createInitialRuntime(id: string): TransportRuntime {
    const isDirect = id === "direct";
    return {
      id,
      score: isDirect ? 0.90 : 0.50,
      latencyMs: isDirect ? 25 : 150,
      jitterMs: 10,
      successRate: isDirect ? 0.95 : 0.50,
      history: isDirect ? [1, 1] : [],
      latencyHistory: isDirect ? [25, 25] : [],
      circuit: "closed" as CircuitState,
      failures: 0,
      lastCheckAt: 0,
    };
  }
}

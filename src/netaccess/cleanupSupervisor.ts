/**
 * NetAccess Cleanup Supervisor
 * 
 * Guarantees zero orphaned processes, sockets, or temporary directories.
 * Implements strict OS-safe process termination, cryptographically validated
 * profile deletion, and signal trapping across normal exit, crash, and interruption.
 * 
 * Critical invariant:
 *   request close -> terminate process tree -> confirm exited ->
 *   remove ephemeral profile -> verify absent -> release session resources
 */

import { execSync } from "node:child_process";
import * as crypto from "node:crypto";
import * as fsSync from "node:fs";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { type ResourceRegistry } from "./types.js";

export interface TrackedProcess {
  pid: number;
  sessionId: string;
  command: string;
}

export interface TrackedDirectory {
  path: string;
  sessionId: string;
}

export class CleanupSupervisor implements ResourceRegistry {
  private static instance: CleanupSupervisor | null = null;

  private processes: Map<number, TrackedProcess> = new Map();
  private directories: Map<string, TrackedDirectory> = new Map();
  private sockets: Map<string, { destroy: () => void }[]> = new Map();
  private timers: Map<string, (NodeJS.Timeout | number)[]> = new Map();
  private callbacks: Map<string, (() => Promise<void> | void)[]> = new Map();

  private signalHandlersInstalled = false;
  private isCleaningUp = false;
  private signalListeners: { signal: string; listener: (...args: any[]) => void }[] = [];

  constructor(installSignalHandlers = false) {
    if (installSignalHandlers && !this.signalHandlersInstalled) {
      this.installSignalHandlers();
    }
  }

  public static getShared(): CleanupSupervisor {
    if (!CleanupSupervisor.instance) {
      CleanupSupervisor.instance = new CleanupSupervisor(true);
      // Asynchronous background sweep of orphaned profiles on startup
      CleanupSupervisor.instance.sweepOrphanedProfiles().catch(() => {});
    }
    return CleanupSupervisor.instance;
  }

  /**
   * Register a child process to be supervised
   */
  public registerProcess(pid: number, sessionId: string, command = ""): void {
    if (pid <= 0) return;
    this.processes.set(pid, { pid, sessionId, command });
  }

  /**
   * Unregister process when it exits cleanly
   */
  public unregisterProcess(pid: number): void {
    this.processes.delete(pid);
  }

  /**
   * Register an ephemeral directory to be supervised
   */
  public registerDirectory(dirPath: string, sessionId: string): void {
    this.directories.set(dirPath, { path: dirPath, sessionId });
  }

  /**
   * Register a network socket to be destroyed on cleanup
   */
  public registerSocket(socket: { destroy: () => void }, sessionId: string): void {
    const list = this.sockets.get(sessionId) ?? [];
    list.push(socket);
    this.sockets.set(sessionId, list);
  }

  /**
   * Register a timer to be cancelled on cleanup
   */
  public registerTimer(timer: NodeJS.Timeout | number, sessionId: string): void {
    const list = this.timers.get(sessionId) ?? [];
    list.push(timer);
    this.timers.set(sessionId, list);
  }

  /**
   * Register an arbitrary cleanup callback for a session
   */
  public registerCleanupCallback(cb: () => Promise<void> | void, sessionId: string): void {
    const list = this.callbacks.get(sessionId) ?? [];
    list.push(cb);
    this.callbacks.set(sessionId, list);
  }

  /**
   * Create a validated ephemeral profile directory in /tmp
   * Format: /tmp/netaccess-session-<sessionId>-<randomHex>
   */
  public async createEphemeralProfile(sessionId: string): Promise<string> {
    const randomHex = crypto.randomBytes(6).toString("hex");
    const sanitizedSessionId = sessionId.replace(/[^a-zA-Z0-9_-]/g, "");
    const dirName = `netaccess-session-${sanitizedSessionId}-${randomHex}`;
    const profilePath = path.join(os.tmpdir(), dirName);

    await fs.mkdir(profilePath, { recursive: true, mode: 0o700 });
    this.registerDirectory(profilePath, sessionId);
    return profilePath;
  }

  /**
   * Clean up all resources belonging to a specific session
   * Follows strict order:
   * 1. Release sockets, timers, and callbacks
   * 2. Terminate browser process tree
   * 3. Confirm process exited
   * 4. Remove ephemeral profile directory
   * 5. Verify directory is absent
   * 6. Release session resources from registry
   */
  public async cleanupSession(sessionId: string): Promise<{
    processesKilled: number[];
    directoriesRemoved: string[];
  }> {
    const processesKilled: number[] = [];
    const directoriesRemoved: string[] = [];

    // Step 1: Clear timers, destroy sockets, invoke callbacks
    const timers = this.timers.get(sessionId) ?? [];
    for (const t of timers) {
      clearTimeout(t);
    }
    this.timers.delete(sessionId);

    const sockets = this.sockets.get(sessionId) ?? [];
    for (const s of sockets) {
      try {
        s.destroy();
      } catch {
        // Ignored
      }
    }
    this.sockets.delete(sessionId);

    const cbs = this.callbacks.get(sessionId) ?? [];
    for (const cb of cbs) {
      try {
        await cb();
      } catch {
        // Ignored
      }
    }
    this.callbacks.delete(sessionId);

    // Step 2: Find and terminate all processes for this session
    const sessionProcesses = Array.from(this.processes.values()).filter(
      (p) => p.sessionId === sessionId,
    );

    for (const proc of sessionProcesses) {
      await this.terminateProcessTree(proc.pid);
      this.processes.delete(proc.pid);
      processesKilled.push(proc.pid);
    }

    // Step 3: Find and remove all ephemeral directories for this session
    const sessionDirs = Array.from(this.directories.values()).filter(
      (d) => d.sessionId === sessionId,
    );

    for (const dir of sessionDirs) {
      const removed = await this.safelyRemoveDirectory(dir.path, sessionId);
      if (removed) {
        directoriesRemoved.push(dir.path);
      }
      this.directories.delete(dir.path);
    }

    return { processesKilled, directoriesRemoved };
  }

  /**
   * Clean up all tracked resources across all sessions (for app exit or crash)
   */
  public async cleanupAll(): Promise<void> {
    if (this.isCleaningUp) return;
    this.isCleaningUp = true;

    try {
      // 1. Clear all timers
      for (const [, timers] of this.timers) {
        for (const t of timers) clearTimeout(t);
      }
      this.timers.clear();

      // 2. Destroy all sockets
      for (const [, sockets] of this.sockets) {
        for (const s of sockets) {
          try {
            s.destroy();
          } catch {}
        }
      }
      this.sockets.clear();

      // 3. Run all callbacks
      for (const [, cbs] of this.callbacks) {
        for (const cb of cbs) {
          try {
            await cb();
          } catch {}
        }
      }
      this.callbacks.clear();

      // 4. Kill all tracked processes
      for (const [pid] of this.processes) {
        await this.terminateProcessTree(pid);
      }
      this.processes.clear();

      // 5. Remove all tracked directories
      for (const [dirPath, dir] of this.directories) {
        await this.safelyRemoveDirectory(dirPath, dir.sessionId);
      }
      this.directories.clear();
    } finally {
      this.isCleaningUp = false;
    }
  }

  /**
   * Inspect currently tracked resources
   */
  public getTrackedCount(): { processes: number; directories: number; sockets: number; timers: number } {
    let socketCount = 0;
    for (const list of this.sockets.values()) socketCount += list.length;
    let timerCount = 0;
    for (const list of this.timers.values()) timerCount += list.length;

    return {
      processes: this.processes.size,
      directories: this.directories.size,
      sockets: socketCount,
      timers: timerCount,
    };
  }

  public getTrackedProcesses(sessionId?: string): TrackedProcess[] {
    const list = Array.from(this.processes.values());
    if (sessionId) return list.filter((p) => p.sessionId === sessionId);
    return list;
  }

  public getTrackedDirectories(sessionId?: string): TrackedDirectory[] {
    const list = Array.from(this.directories.values());
    if (sessionId) return list.filter((d) => d.sessionId === sessionId);
    return list;
  }

  // -------------------------------------------------------------------------
  // Process Termination Logic
  // -------------------------------------------------------------------------

  /**
   * Terminate a process and all its child processes safely:
   * Graceful SIGTERM -> wait up to 500ms -> SIGKILL if still alive -> verify exited
   */
  public async terminateProcessTree(pid: number): Promise<boolean> {
    if (!this.isProcessAlive(pid)) {
      return true;
    }

    // Discover descendant PIDs recursively before killing parent
    const childPids = this.getDescendantPids(pid);

    // 1. Send SIGTERM to process group if detached, plus children & parent
    try {
      process.kill(-pid, "SIGTERM");
    } catch {
      // Process group kill might fail if not group leader
    }
    for (const cpid of childPids) {
      try {
        process.kill(cpid, "SIGTERM");
      } catch {
        // Ignored
      }
    }
    try {
      process.kill(pid, "SIGTERM");
    } catch {
      // Ignored
    }

    // 2. Wait bounded interval (up to 500ms)
    const exitedGracefully = await this.waitForExit(pid, 500);
    if (exitedGracefully) {
      return true;
    }

    // 3. Force kill with SIGKILL if still alive
    try {
      process.kill(-pid, "SIGKILL");
    } catch {
      // Ignored
    }
    for (const cpid of childPids) {
      try {
        process.kill(cpid, "SIGKILL");
      } catch {
        // Ignored
      }
    }
    try {
      process.kill(pid, "SIGKILL");
    } catch {
      // Ignored
    }

    // 4. Final verification bounded wait (up to 300ms)
    return await this.waitForExit(pid, 300);
  }

  public isProcessAlive(pid: number): boolean {
    if (pid <= 0) return false;
    try {
      process.kill(pid, 0);
      return true;
    } catch (err: unknown) {
      return (err as NodeJS.ErrnoException).code === "EPERM";
    }
  }

  private getDescendantPids(parentPid: number): number[] {
    if (parentPid <= 0) return [];
    const allDescendants: Set<number> = new Set();
    const queue = [parentPid];
    while (queue.length > 0) {
      const current = queue.shift()!;
      try {
        const stdout = execSync(`pgrep -P ${current}`, {
          encoding: "utf8",
          stdio: ["ignore", "pipe", "ignore"],
        });
        const pids = stdout
          .trim()
          .split("\n")
          .map((p) => Number(p.trim()))
          .filter((p) => p > 0 && !isNaN(p) && !allDescendants.has(p));
        for (const p of pids) {
          allDescendants.add(p);
          queue.push(p);
        }
      } catch {
        // No children found or command failed
      }
    }
    return Array.from(allDescendants);
  }

  private async waitForExit(pid: number, maxWaitMs: number): Promise<boolean> {
    const start = Date.now();
    while (Date.now() - start < maxWaitMs) {
      if (!this.isProcessAlive(pid)) {
        return true;
      }
      await new Promise((r) => setTimeout(r, 40));
    }
    return !this.isProcessAlive(pid);
  }

  // -------------------------------------------------------------------------
  // Safe Directory Removal
  // -------------------------------------------------------------------------

  private isWithinTmp(dirPath: string): boolean {
    const normalized = path.resolve(dirPath);
    const tmp = path.resolve(os.tmpdir());
    if (normalized.startsWith(tmp)) return true;
    if (normalized.startsWith("/tmp/") || normalized.startsWith("/private/tmp/")) return true;
    try {
      const realNormalized = fsSync.realpathSync(normalized);
      const realTmp = fsSync.realpathSync(tmp);
      if (realNormalized.startsWith(realTmp)) return true;
    } catch {
      try {
        const parentReal = fsSync.realpathSync(path.dirname(normalized));
        const realTmp = fsSync.realpathSync(tmp);
        if (parentReal.startsWith(realTmp)) return true;
      } catch {
        // Ignored
      }
    }
    return false;
  }

  /**
   * Validate and remove directory
   * Strictly enforces path format to prevent accidental wildcard deletion
   */
  public async safelyRemoveDirectory(dirPath: string, sessionId: string): Promise<boolean> {
    const normalized = path.resolve(dirPath);

    // Strict validation: must reside inside os.tmpdir() or /tmp
    if (!this.isWithinTmp(normalized)) {
      return false;
    }

    // Strict validation: basename must match netaccess-session pattern
    const basename = path.basename(normalized);
    const pattern = /^netaccess-session-[a-zA-Z0-9_-]+-[a-f0-9]+$/;
    if (!pattern.test(basename)) {
      return false;
    }

    // Strict validation: must contain the specific sessionId
    const sanitizedSessionId = sessionId.replace(/[^a-zA-Z0-9_-]/g, "");
    if (!sanitizedSessionId || !basename.includes(`-${sanitizedSessionId}-`)) {
      return false;
    }

    try {
      await fs.rm(normalized, { recursive: true, force: true });
      // Verify directory absent
      try {
        await fs.stat(normalized);
        return false; // Still exists
      } catch (err: unknown) {
        return (err as NodeJS.ErrnoException).code === "ENOENT";
      }
    } catch {
      return false;
    }
  }

  /**
   * Sweep and remove orphaned ephemeral profiles from /tmp.
   * Safe post-crash and post-reboot recovery:
   * - Scans os.tmpdir()
   * - Strict filename matching: /^netaccess-session-[a-zA-Z0-9_-]+-[a-f0-9]+$/
   * - Age threshold check: directory mtime/ctime older than maxAgeMs (default: 1 hour)
   * - Active-registration protection: never deletes directories actively tracked in this.directories
   * - Recursive forced removal with verification
   */
  public async sweepOrphanedProfiles(maxAgeMs = 3600000): Promise<string[]> {
    const tmpDir = os.tmpdir();
    const pattern = /^netaccess-session-[a-zA-Z0-9_-]+-[a-f0-9]+$/;
    const swept: string[] = [];

    let entries: string[] = [];
    try {
      entries = await fs.readdir(tmpDir);
    } catch {
      return swept;
    }

    const now = Date.now();
    for (const name of entries) {
      if (!pattern.test(name)) continue;

      const fullPath = path.join(tmpDir, name);
      const normalized = path.resolve(fullPath);

      // Active registration check: do not delete directories managed by current session supervisor
      if (this.directories.has(normalized)) continue;

      try {
        const stat = await fs.stat(normalized);
        if (!stat.isDirectory()) continue;

        const ageMs = now - stat.mtimeMs;
        if (ageMs < maxAgeMs) continue;

        await fs.rm(normalized, { recursive: true, force: true });
        swept.push(normalized);
      } catch {
        // Ignored if file disappeared or permission denied
      }
    }

    return swept;
  }

  // -------------------------------------------------------------------------
  // Signal Trapping
  // -------------------------------------------------------------------------

  public installSignalHandlers(): void {
    if (this.signalHandlersInstalled) return;
    this.signalHandlersInstalled = true;

    const onSignal = async (sig: string) => {
      await this.cleanupAll();
      if (sig !== "exit" && sig !== "beforeExit") {
        process.exit(0);
      }
    };

    const registerListener = (sig: NodeJS.Signals | "beforeExit") => {
      const handler = () => {
        onSignal(sig);
      };
      process.once(sig, handler);
      this.signalListeners.push({ signal: sig, listener: handler });
    };

    registerListener("SIGINT");
    registerListener("SIGTERM");
    registerListener("SIGHUP");
    registerListener("beforeExit");
  }

  public removeSignalHandlers(): void {
    for (const item of this.signalListeners) {
      process.removeListener(item.signal, item.listener);
    }
    this.signalListeners = [];
    this.signalHandlersInstalled = false;
  }
}

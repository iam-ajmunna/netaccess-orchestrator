/**
 * NetAccess Electron Preload Bridge
 * 
 * Strict isolation boundary:
 * - Exposes ONLY typed NetAccess API via contextBridge
 * - Zero access to Node.js APIs (fs, child_process, net, tls)
 * - Whitelisted channels only
 */

import { contextBridge, ipcRenderer } from "electron";
import type {
  AppSettings,
  Diagnosis,
  OpenTargetResult,
  PathVerificationResult,
  RecentDestination,
  SelectedPath,
  SessionSnapshot,
  SessionState,
  TransportConfig,
  TransportProbeResult,
  TransportRuntime,
  UserFacingError,
} from "../netaccess/types.js";

export interface DoctorReport {
  platform: string;
  arch: string;
  interfaces: string[];
  browsers: { name: string; path: string }[];
  configuredTransports: number;
}

export interface NetAccessAPI {
  openTarget: (target: string, opts?: { skipBrowserLaunch?: boolean }) => Promise<OpenTargetResult>;
  cancelSession: () => Promise<void>;
  closeSession: () => Promise<void>;
  getStatus: () => Promise<SessionSnapshot>;
  
  getSettings: () => Promise<AppSettings>;
  updateSettings: (updates: Partial<AppSettings>) => Promise<AppSettings>;
  
  getTransports: () => Promise<TransportConfig[]>;
  getTransportRuntimes: () => Promise<Record<string, TransportRuntime>>;
  addTransport: (config: TransportConfig, password?: string) => Promise<void>;
  removeTransport: (id: string) => Promise<boolean>;
  testTransport: (transportId: string, target?: string) => Promise<TransportProbeResult>;
  
  getRecentTargets: () => Promise<RecentDestination[]>;
  clearRecentTargets: () => Promise<void>;
  getDoctorReport: () => Promise<DoctorReport>;

  onStateChanged: (cb: (state: SessionState, message: string) => void) => () => void;
  onDiagnosisUpdated: (cb: (diagnosis: Diagnosis) => void) => () => void;
  onTransportChanged: (cb: (path: SelectedPath) => void) => () => void;
  onVerificationUpdated: (cb: (verification: PathVerificationResult) => void) => () => void;
  onCompleted: (cb: (result: OpenTargetResult) => void) => () => void;
  onFailed: (cb: (error: UserFacingError) => void) => () => void;
}

const api: NetAccessAPI = {
  openTarget: (target, opts) => ipcRenderer.invoke("netaccess:open-target", target, opts),
  cancelSession: () => ipcRenderer.invoke("netaccess:cancel-session"),
  closeSession: () => ipcRenderer.invoke("netaccess:close-session"),
  getStatus: () => ipcRenderer.invoke("netaccess:get-status"),

  getSettings: () => ipcRenderer.invoke("netaccess:get-settings"),
  updateSettings: (updates) => ipcRenderer.invoke("netaccess:update-settings", updates),

  getTransports: () => ipcRenderer.invoke("netaccess:get-transports"),
  getTransportRuntimes: () => ipcRenderer.invoke("netaccess:get-transport-runtimes"),
  addTransport: (config, password) => ipcRenderer.invoke("netaccess:add-transport", config, password),
  removeTransport: (id) => ipcRenderer.invoke("netaccess:remove-transport", id),
  testTransport: (transportId, target) => ipcRenderer.invoke("netaccess:test-transport", transportId, target),

  getRecentTargets: () => ipcRenderer.invoke("netaccess:get-recent"),
  clearRecentTargets: () => ipcRenderer.invoke("netaccess:clear-recent"),
  getDoctorReport: () => ipcRenderer.invoke("netaccess:doctor"),

  onStateChanged: (cb) => {
    const handler = (_: unknown, state: SessionState, message: string) => cb(state, message);
    ipcRenderer.on("netaccess:state-changed", handler);
    return () => ipcRenderer.removeListener("netaccess:state-changed", handler);
  },
  onDiagnosisUpdated: (cb) => {
    const handler = (_: unknown, diagnosis: Diagnosis) => cb(diagnosis);
    ipcRenderer.on("netaccess:diagnosis-updated", handler);
    return () => ipcRenderer.removeListener("netaccess:diagnosis-updated", handler);
  },
  onTransportChanged: (cb) => {
    const handler = (_: unknown, path: SelectedPath) => cb(path);
    ipcRenderer.on("netaccess:transport-changed", handler);
    return () => ipcRenderer.removeListener("netaccess:transport-changed", handler);
  },
  onVerificationUpdated: (cb) => {
    const handler = (_: unknown, verification: PathVerificationResult) => cb(verification);
    ipcRenderer.on("netaccess:verification-updated", handler);
    return () => ipcRenderer.removeListener("netaccess:verification-updated", handler);
  },
  onCompleted: (cb) => {
    const handler = (_: unknown, result: OpenTargetResult) => cb(result);
    ipcRenderer.on("netaccess:completed", handler);
    return () => ipcRenderer.removeListener("netaccess:completed", handler);
  },
  onFailed: (cb) => {
    const handler = (_: unknown, error: UserFacingError) => cb(error);
    ipcRenderer.on("netaccess:failed", handler);
    return () => ipcRenderer.removeListener("netaccess:failed", handler);
  },
};

contextBridge.exposeInMainWorld("netaccess", api);

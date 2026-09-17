/**
 * NetAccess Electron Main Process
 * 
 * Orchestrates desktop application window, native menus, secure IPC bridge,
 * and lifecycle teardown over ApplicationController.
 */

import { app, BrowserWindow, ipcMain, Menu, nativeTheme } from "electron";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { ApplicationController } from "../netaccess/controller.js";
import { CleanupSupervisor } from "../netaccess/cleanupSupervisor.js";
import {
  type AppSettings,
  type OpenTargetResult,
  type SelectedPath,
  type TransportConfig,
} from "../netaccess/types.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

let mainWindow: BrowserWindow | null = null;
const controller = new ApplicationController();

function getRendererPath(): string {
  const localDistPath = path.join(__dirname, "../renderer/index.html");
  if (fs.existsSync(localDistPath)) {
    return localDistPath;
  }
  return path.resolve(__dirname, "../../src/renderer/index.html");
}

function getPreloadPath(): string {
  const cjsPath = path.join(__dirname, "preload.cjs");
  if (fs.existsSync(cjsPath)) return cjsPath;
  return path.join(__dirname, "preload.js");
}

function sanitizeTransport(transport: TransportConfig): TransportConfig {
  return {
    ...transport,
    secretRef: transport.secretRef ? "[REDACTED]" : undefined,
  };
}

function sanitizePath(selectedPath: SelectedPath): SelectedPath {
  return { ...selectedPath };
}

function sanitizeOpenTargetResult(res: OpenTargetResult): OpenTargetResult {
  return {
    ...res,
    path: sanitizePath(res.path),
  };
}

function createMainWindow(): BrowserWindow {
  const win = new BrowserWindow({
    width: 520,
    height: 680,
    minWidth: 440,
    minHeight: 520,
    maxWidth: 720,
    maxHeight: 900,
    titleBarStyle: "hiddenInset",
    trafficLightPosition: { x: 18, y: 18 },
    vibrancy: "under-window",
    visualEffectState: "active",
    backgroundColor: "#1c1c1e",
    show: false,
    webPreferences: {
      preload: getPreloadPath(),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });

  const rendererPath = getRendererPath();
  win.loadFile(rendererPath);

  win.webContents.on("did-fail-load", (_, errorCode, errorDescription) => {
    console.error(`[NetAccess Main] Failed to load renderer: ${errorDescription} (${errorCode})`);
    if (process.env.NETACCESS_SMOKE_TEST === "1") {
      process.exit(1);
    }
  });

  win.once("ready-to-show", () => {
    win.show();
    if (process.env.NETACCESS_SMOKE_TEST === "1") {
      console.log("[NetAccess Main] Renderer loaded and window ready-to-show successfully!");
      setTimeout(() => {
        app.quit();
      }, 500);
    }
  });

  win.webContents.on("console-message", (_, level, message) => {
    if (level >= 2) {
      console.warn(`[NetAccess UI] ${message}`);
    }
  });

  // Strict navigation security: prevent opening arbitrary new windows or navigating away
  win.webContents.setWindowOpenHandler(() => ({ action: "deny" }));
  win.webContents.on("will-navigate", (event) => {
    event.preventDefault();
  });

  return win;
}

function registerIpcHandlers(): void {
  ipcMain.handle("netaccess:open-target", async (_, rawTarget: unknown, opts: unknown) => {
    if (typeof rawTarget !== "string" || !rawTarget.trim()) {
      throw new Error("Invalid destination target parameter");
    }
    const options = (typeof opts === "object" && opts !== null) ? opts : {};
    try {
      const res = await controller.openTarget(rawTarget.trim(), options);
      return sanitizeOpenTargetResult(res);
    } catch (err: unknown) {
      if (err && typeof err === "object" && "code" in err && "message" in err) {
        const error = new Error(String((err as any).message));
        (error as any).code = (err as any).code;
        (error as any).details = (err as any).details;
        (error as any).suggestedAction = (err as any).suggestedAction;
        throw error;
      }
      throw err;
    }
  });

  ipcMain.handle("netaccess:cancel-session", async () => {
    await controller.cancelSession();
  });

  ipcMain.handle("netaccess:close-session", async () => {
    await controller.closeSession();
  });

  ipcMain.handle("netaccess:get-status", () => {
    return controller.getStatus();
  });

  ipcMain.handle("netaccess:get-settings", () => {
    return controller.getSettings();
  });

  ipcMain.handle("netaccess:update-settings", (_, updates: unknown) => {
    if (typeof updates !== "object" || updates === null) {
      throw new Error("Invalid settings payload");
    }
    return controller.updateSettings(updates as Partial<AppSettings>);
  });

  ipcMain.handle("netaccess:get-transports", () => {
    return controller.getTransports(true).map(sanitizeTransport);
  });

  ipcMain.handle("netaccess:get-transport-runtimes", () => {
    return controller.getTransportRuntimes();
  });

  ipcMain.handle("netaccess:add-transport", async (_, config: unknown, password?: unknown) => {
    if (typeof config !== "object" || config === null || !("id" in config)) {
      throw new Error("Invalid transport config payload");
    }
    const secret = typeof password === "string" && password.length > 0 ? password : undefined;
    if (secret) {
      await controller.saveTransportWithSecret(config as TransportConfig, secret);
    } else {
      controller.addTransport(config as TransportConfig);
    }
  });

  ipcMain.handle("netaccess:remove-transport", async (_, id: unknown) => {
    if (typeof id !== "string") {
      throw new Error("Invalid transport ID");
    }
    return await controller.deleteTransport(id);
  });

  ipcMain.handle("netaccess:test-transport", async (_, transportId: unknown, target: unknown) => {
    if (typeof transportId !== "string") {
      throw new Error("Invalid transport ID");
    }
    const tgt = typeof target === "string" ? target : "example.com";
    return await controller.testTransport(transportId, tgt);
  });

  ipcMain.handle("netaccess:get-recent", () => {
    return controller.getRecentTargets();
  });

  ipcMain.handle("netaccess:clear-recent", () => {
    controller.clearRecentTargets();
  });

  ipcMain.handle("netaccess:doctor", async () => {
    const sm = controller.getSessionManager();
    const browsers = await sm.discoverBrowsers();
    const transports = controller.getTransports(true);
    const ifaces = os.networkInterfaces();
    const activeIfaces = Object.keys(ifaces).filter((name) => !name.startsWith("lo"));

    return {
      platform: process.platform,
      arch: process.arch,
      interfaces: activeIfaces,
      browsers: browsers.map((b) => ({ name: b.name, path: b.executablePath })),
      configuredTransports: transports.length,
    };
  });
}

function wireControllerEvents(): void {
  controller.on("stateChanged", (state, message) => {
    mainWindow?.webContents.send("netaccess:state-changed", state, message);
  });

  controller.on("diagnosisUpdated", (diagnosis) => {
    mainWindow?.webContents.send("netaccess:diagnosis-updated", diagnosis);
  });

  controller.on("transportChanged", (path) => {
    mainWindow?.webContents.send("netaccess:transport-changed", sanitizePath(path));
  });

  controller.on("verificationUpdated", (verification) => {
    mainWindow?.webContents.send("netaccess:verification-updated", verification);
  });

  controller.on("completed", (result) => {
    mainWindow?.webContents.send("netaccess:completed", sanitizeOpenTargetResult(result));
  });

  controller.on("failed", (error) => {
    mainWindow?.webContents.send("netaccess:failed", error);
  });
}

function buildNativeMenu(): void {
  const isMac = process.platform === "darwin";
  const template: Electron.MenuItemConstructorOptions[] = [
    ...(isMac
      ? [
          {
            label: app.name,
            submenu: [
              { role: "about" as const },
              { type: "separator" as const },
              {
                label: "Settings…",
                accelerator: "CmdOrCtrl+,",
                click: () => mainWindow?.webContents.send("netaccess:menu-settings"),
              },
              { type: "separator" as const },
              { role: "services" as const },
              { type: "separator" as const },
              { role: "hide" as const },
              { role: "hideOthers" as const },
              { role: "unhide" as const },
              { type: "separator" as const },
              { role: "quit" as const },
            ],
          },
        ]
      : []),
    {
      label: "File",
      submenu: [
        {
          label: "Open Destination…",
          accelerator: "CmdOrCtrl+O",
          click: () => mainWindow?.webContents.send("netaccess:menu-focus-input"),
        },
        { type: "separator" },
        isMac ? { role: "close" } : { role: "quit" },
      ],
    },
    {
      label: "View",
      submenu: [
        {
          label: "Toggle Developer Mode",
          accelerator: "CmdOrCtrl+D",
          click: () => mainWindow?.webContents.send("netaccess:menu-toggle-dev"),
        },
        { role: "reload" },
        { role: "toggleDevTools" },
      ],
    },
    {
      label: "Window",
      submenu: [
        { role: "minimize" },
        { role: "zoom" },
        ...(isMac ? [{ type: "separator" as const }, { role: "front" as const }] : []),
      ],
    },
  ];

  const menu = Menu.buildFromTemplate(template);
  Menu.setApplicationMenu(menu);
}

app.whenReady().then(() => {
  registerIpcHandlers();
  wireControllerEvents();
  buildNativeMenu();
  mainWindow = createMainWindow();

  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      mainWindow = createMainWindow();
    }
  });
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") {
    app.quit();
  }
});

app.on("before-quit", async () => {
  // Guarantee clean teardown across all sessions
  await CleanupSupervisor.getShared().cleanupAll();
});

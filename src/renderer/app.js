/**
 * NetAccess Electron Renderer Application
 * 
 * Strictly renders from ApplicationController events received via window.netaccess.
 * Does NOT maintain an independent frontend state machine.
 */

(function () {
  // DOM Elements
  const viewInitial = document.getElementById("view-initial");
  const viewConnecting = document.getElementById("view-connecting");
  const viewConnected = document.getElementById("view-connected");
  const viewFailed = document.getElementById("view-failed");

  const targetForm = document.getElementById("target-form");
  const targetInput = document.getElementById("target-input");
  const btnOpen = document.getElementById("btn-open");
  const recentList = document.getElementById("recent-list");

  const connectingTarget = document.getElementById("connecting-target");
  const stepChecking = document.getElementById("step-checking");
  const stepFinding = document.getElementById("step-finding");
  const stepOpening = document.getElementById("step-opening");
  const btnCancelConnecting = document.getElementById("btn-cancel-connecting");

  const connectedTarget = document.getElementById("connected-target");
  const pathType = document.getElementById("path-type");
  const pathTransport = document.getElementById("path-transport");
  const pathLatency = document.getElementById("path-latency");
  const pathDiagnosisReason = document.getElementById("path-diagnosis-reason");
  const pathConfidence = document.getElementById("path-confidence");
  const verificationStatusText = document.getElementById("verification-status-text");
  const verificationBadge = document.getElementById("verification-badge");
  const verificationSummaryText = document.getElementById("verification-summary-text");
  const btnViewDetails = document.getElementById("btn-view-details");
  const btnNewTarget = document.getElementById("btn-new-target");

  const failedCodePill = document.getElementById("failed-code-pill");
  const failedTitle = document.getElementById("failed-title");
  const failedMessage = document.getElementById("failed-message");
  const failedSuggestion = document.getElementById("failed-suggestion");
  const btnFailedBack = document.getElementById("btn-failed-back");
  const btnFailedRetry = document.getElementById("btn-failed-retry");
  const btnFailedSettings = document.getElementById("btn-failed-settings");

  // Dev Drawer Elements
  const drawerDev = document.getElementById("drawer-dev");
  const btnToggleDev = document.getElementById("btn-toggle-dev");
  const btnCloseDev = document.getElementById("btn-close-dev");
  const btnCopyDevJson = document.getElementById("btn-copy-dev-json");
  const devWaterfall = {
    captive: document.getElementById("wf-captive-val"),
    dns: document.getElementById("wf-dns-val"),
    tcp: document.getElementById("wf-tcp-val"),
    tls: document.getElementById("wf-tls-val"),
    http: document.getElementById("wf-http-val"),
  };
  const devClassification = document.getElementById("dev-classification");
  const devConfidence = document.getElementById("dev-confidence");
  const devReason = document.getElementById("dev-reason");
  const devRecommendation = document.getElementById("dev-recommendation");
  const devCandidateList = document.getElementById("dev-candidate-list");
  const devVerifyStatus = document.getElementById("dev-verify-status");
  const devVerifySockets = document.getElementById("dev-verify-sockets");
  const devVerifyConfidence = document.getElementById("dev-verify-confidence");

  // Settings Elements
  const modalSettings = document.getElementById("modal-settings");
  const btnToggleSettings = document.getElementById("btn-toggle-settings");
  const btnCloseSettings = document.getElementById("btn-close-settings");
  const settingOpenDefaultBrowser = document.getElementById("setting-open-default-browser");
  const settingAutoAlternate = document.getElementById("setting-auto-alternate");
  const settingRememberRecents = document.getElementById("setting-remember-recents");
  const settingDiagnosticLogging = document.getElementById("setting-diagnostic-logging");
  const settingDevMode = document.getElementById("setting-dev-mode");
  const btnClearRecents = document.getElementById("btn-clear-recents");
  const btnAddProxyToggle = document.getElementById("btn-add-proxy-toggle");
  const addProxyForm = document.getElementById("add-proxy-form");
  const btnCancelAddProxy = document.getElementById("btn-cancel-add-proxy");
  const transportsList = document.getElementById("transports-list");
  const systemDoctorContent = document.getElementById("system-doctor-content");

  // Internal store for latest technical telemetry (for Dev Mode and JSON copy)
  let latestTelemetry = {
    status: null,
    diagnosis: null,
    selectedPath: null,
    verification: null,
    lastResult: null,
    lastError: null,
    lastTarget: "",
  };

  // Friendly error dictionary preserving underlying category
  const ERROR_MAP = {
    INVALID_TARGET: {
      title: "Check the address and try again",
      suggestion: "Please check for typos or enter a valid domain or URL (e.g. server3.ftpbd.net).",
    },
    DNS_UNAVAILABLE: {
      title: "The destination couldn't be resolved",
      suggestion: "Check your local DNS resolver, Wi-Fi connection, or local network settings.",
    },
    DESTINATION_UNREACHABLE: {
      title: "The destination isn't reachable from this connection",
      suggestion: "The destination did not respond to TCP connect probes on port 80/443.",
    },
    NO_WORKING_PATH: {
      title: "No available connection path worked",
      suggestion: "Direct connection is not working, and no configured alternate proxies were able to reach the destination.",
    },
    DESTINATION_REJECTED: {
      title: "The destination refused the request",
      suggestion: "The server responded with an HTTP client error or access restriction (such as 403 Forbidden or 451 Unavailable For Legal Reasons).",
    },
    TRANSPORT_UNAVAILABLE: {
      title: "The configured connection isn't available",
      suggestion: "Check your configured proxy endpoints and credentials in Settings.",
    },
    PERMISSION_REQUIRED: {
      title: "NetAccess needs the required macOS/browser permission",
      suggestion: "Grant necessary permissions in macOS System Settings > Privacy & Security.",
    },
    SESSION_FAILED: {
      title: "The managed browser session couldn't be started",
      suggestion: "Make sure an approved browser (Chrome, Edge, or Brave) is installed on your Mac.",
    },
    CLEANUP_FAILED: {
      title: "NetAccess couldn't fully clean up the session",
      suggestion: "A temporary profile or child process could not be completely terminated. NetAccess will retry.",
    },
  };

  // View Switcher
  function showView(viewElement) {
    [viewInitial, viewConnecting, viewConnected, viewFailed].forEach((v) => {
      v.classList.remove("active");
    });
    viewElement.classList.add("active");
  }

  // Render State Changes from Controller
  function renderState(state, message) {
    console.log("[NetAccess UI] stateChanged:", state, message);

    switch (state) {
      case "IDLE":
        showView(viewInitial);
        resetConnectingSteps();
        refreshRecents();
        break;

      case "VALIDATING":
      case "DIAGNOSING":
      case "PROBING_DIRECT":
        showView(viewConnecting);
        setStepStatus(stepChecking, "active");
        setStepStatus(stepFinding, "pending");
        setStepStatus(stepOpening, "pending");
        break;

      case "FINDING_PATH":
      case "TESTING_PATHS":
      case "EVALUATING_TRANSPORTS":
        showView(viewConnecting);
        setStepStatus(stepChecking, "completed");
        setStepStatus(stepFinding, "active");
        setStepStatus(stepOpening, "pending");
        break;

      case "CONNECTED":
      case "OPEN":
      case "LAUNCHING_SESSION":
        showView(viewConnecting);
        setStepStatus(stepChecking, "completed");
        setStepStatus(stepFinding, "completed");
        setStepStatus(stepOpening, "active");
        break;

      case "MONITORING":
      case "ACTIVE":
        showView(viewConnected);
        break;

      case "FAILED":
        showView(viewFailed);
        break;

      case "CANCELLED":
      case "CLEANUP":
        showView(viewInitial);
        break;
    }
  }

  function resetConnectingSteps() {
    [stepChecking, stepFinding, stepOpening].forEach((step) => {
      step.className = "step-item pending";
    });
  }

  function setStepStatus(stepEl, status) {
    stepEl.className = `step-item ${status}`;
  }

  // Render Diagnosis Updates
  function renderDiagnosis(diagnosis) {
    latestTelemetry.diagnosis = diagnosis;
    if (!diagnosis) return;

    // Developer waterfall
    const probes = diagnosis.probes || [];
    const getProbe = (type) => probes.find((p) => p.type === type);

    const cp = getProbe("CAPTIVE_PORTAL");
    if (cp && devWaterfall.captive) {
      devWaterfall.captive.textContent = cp.success ? "Passed" : (cp.error || "Blocked");
      devWaterfall.captive.style.color = cp.success ? "var(--accent-green)" : "var(--accent-red)";
    }

    const dns = getProbe("DNS");
    if (dns && devWaterfall.dns) {
      devWaterfall.dns.textContent = dns.success ? `${dns.latencyMs}ms (Resolved)` : (dns.error || "Failed");
      devWaterfall.dns.style.color = dns.success ? "var(--accent-green)" : "var(--accent-red)";
    }

    const tcp = getProbe("TCP");
    if (tcp && devWaterfall.tcp) {
      devWaterfall.tcp.textContent = tcp.success ? `${tcp.latencyMs}ms` : (tcp.error || "Failed");
      devWaterfall.tcp.style.color = tcp.success ? "var(--accent-green)" : "var(--accent-red)";
    }

    const tls = getProbe("TLS");
    if (tls && devWaterfall.tls) {
      devWaterfall.tls.textContent = tls.success ? `${tls.latencyMs}ms (Valid)` : (tls.error || "Failed");
      devWaterfall.tls.style.color = tls.success ? "var(--accent-green)" : "var(--accent-red)";
    }

    const http = getProbe("HTTP");
    if (http && devWaterfall.http) {
      devWaterfall.http.textContent = http.success ? `${http.latencyMs}ms (HTTP ${http.details?.status || 200})` : (http.error || "Failed");
      devWaterfall.http.style.color = http.success ? "var(--accent-green)" : "var(--accent-red)";
    }

    // Diagnostic engine summary
    if (devClassification) devClassification.textContent = diagnosis.classification || "UNKNOWN";
    if (devConfidence) devConfidence.textContent = `${Math.round((diagnosis.confidence || 0) * 100)}%`;
    if (devReason) devReason.textContent = diagnosis.reason || "--";
    if (devRecommendation) devRecommendation.textContent = diagnosis.recommendedAction || "--";

    // Connected view summary
    if (pathDiagnosisReason) pathDiagnosisReason.textContent = diagnosis.reason || "Destination Verified";
    if (pathConfidence) pathConfidence.textContent = `${Math.round((diagnosis.confidence || 0) * 100)}%`;
  }

  // Render Selected Path Updates
  function renderTransport(path) {
    latestTelemetry.selectedPath = path;
    if (!path) return;

    const isDirect = path.type === "DIRECT";
    if (pathType) pathType.textContent = isDirect ? "Direct Connection" : "Alternate Path";
    if (pathTransport) {
      pathTransport.textContent = isDirect
        ? "Direct Network Interface"
        : (path.transport?.name || path.transport?.type?.toUpperCase() || "Authorized Proxy");
    }
    if (pathLatency) {
      const lat = path.latencyMs || (path.transport?.runtime?.ewmaLatencyMs);
      pathLatency.textContent = lat ? `${Math.round(lat)}ms` : "--";
    }
  }

  // Render Scoped Verification Updates
  function renderVerification(verification) {
    latestTelemetry.verification = verification;
    if (!verification) return;

    if (devVerifyStatus) devVerifyStatus.textContent = verification.status;
    if (devVerifySockets) devVerifySockets.textContent = `${verification.evidence?.observedSockets?.length || 0}`;
    if (devVerifyConfidence) devVerifyConfidence.textContent = `${Math.round((verification.confidence || 0) * 100)}%`;

    if (verificationBadge) {
      verificationBadge.textContent = verification.status;
      if (verification.status === "VERIFIED_SCOPED") {
        verificationBadge.style.background = "var(--accent-green-bg)";
        verificationBadge.style.color = "var(--accent-green)";
        if (verificationStatusText) verificationStatusText.textContent = "Path verified";
      } else if (verification.status === "PATH_CONFLICT") {
        verificationBadge.style.background = "var(--accent-red-bg)";
        verificationBadge.style.color = "var(--accent-red)";
        if (verificationStatusText) verificationStatusText.textContent = "Path conflict detected";
      } else {
        if (verificationStatusText) verificationStatusText.textContent = "Observing session path…";
      }
    }

    if (verificationSummaryText) {
      const count = verification.evidence?.observedSockets?.length || 0;
      if (verification.status === "VERIFIED_SCOPED") {
        verificationSummaryText.textContent = `Observed ${count} active socket(s) matching configured path.`;
      } else if (verification.status === "PATH_CONFLICT") {
        verificationSummaryText.textContent = `Contradictory destination sockets detected. Session closed.`;
      } else {
        verificationSummaryText.textContent = `Inspecting process network connections…`;
      }
    }
  }

  // Render Completed Session
  function renderCompleted(result) {
    latestTelemetry.lastResult = result;
    if (connectedTarget) connectedTarget.textContent = result.target;
    renderTransport(result.path);
    renderDiagnosis(result.diagnosis);
    if (result.verification) renderVerification(result.verification);
    showView(viewConnected);
    refreshCandidateList();
  }

  // Render Failed Session
  function renderFailed(error) {
    latestTelemetry.lastError = error;
    const mapped = ERROR_MAP[error.code] || {
      title: "An unexpected error occurred",
      suggestion: "Please try again or inspect technical details in Developer Mode.",
    };

    if (failedCodePill) failedCodePill.textContent = error.code;
    if (failedTitle) failedTitle.textContent = mapped.title;
    if (failedMessage) failedMessage.textContent = error.message;
    if (failedSuggestion) failedSuggestion.textContent = mapped.suggestion;

    showView(viewFailed);
    refreshCandidateList();
  }

  // Refresh Recent Destinations
  async function refreshRecents() {
    if (!window.netaccess) return;
    try {
      const recents = await window.netaccess.getRecentTargets();
      if (!recentList) return;
      recentList.replaceChildren();

      if (!recents || recents.length === 0) {
        const empty = document.createElement("span");
        empty.className = "empty-hint";
        empty.textContent = "No recent destinations yet";
        recentList.appendChild(empty);
        return;
      }

      recents.slice(0, 6).forEach((item) => {
        const dest = item.host || item.raw || item.target || "destination";
        const pill = document.createElement("button");
        pill.type = "button";
        pill.className = "recent-pill";
        pill.textContent = dest;
        pill.addEventListener("click", () => {
          if (targetInput) targetInput.value = dest;
          initiateOpen(dest);
        });
        recentList.appendChild(pill);
      });
    } catch (e) {
      console.warn("Failed to load recents:", e);
    }
  }

  // Refresh Candidate List in Dev Mode
  async function refreshCandidateList() {
    if (!window.netaccess || !devCandidateList) return;
    try {
      const transports = await window.netaccess.getTransports();
      const runtimes = await window.netaccess.getTransportRuntimes();
      devCandidateList.replaceChildren();

      if (!transports || transports.length === 0) {
        const emptyDiv = document.createElement("div");
        emptyDiv.className = "empty-hint";
        emptyDiv.textContent = "No alternate transports configured";
        devCandidateList.appendChild(emptyDiv);
        return;
      }

      transports.forEach((t) => {
        const rt = runtimes[t.id] || {};
        const card = document.createElement("div");
        card.className = "candidate-card";

        const header = document.createElement("div");
        header.className = "candidate-card-header";
        const nameSpan = document.createElement("span");
        nameSpan.textContent = t.name;
        const typeSpan = document.createElement("span");
        typeSpan.className = "candidate-type-badge";
        typeSpan.textContent = t.type;
        header.appendChild(nameSpan);
        header.appendChild(typeSpan);

        const metrics = document.createElement("div");
        metrics.className = "candidate-metrics";
        const ewma = rt.ewmaLatencyMs ? `${Math.round(rt.ewmaLatencyMs)}ms` : "--";
        const state = rt.circuitBreakerState || "CLOSED";
        const fails = rt.consecutiveFailures || 0;

        const ewmaSpan = document.createElement("span");
        ewmaSpan.textContent = `EWMA: ${ewma}`;
        const stateSpan = document.createElement("span");
        stateSpan.textContent = `Circuit: ${state}`;
        const failsSpan = document.createElement("span");
        failsSpan.textContent = `Fails: ${fails}`;
        metrics.appendChild(ewmaSpan);
        metrics.appendChild(stateSpan);
        metrics.appendChild(failsSpan);

        card.appendChild(header);
        card.appendChild(metrics);
        devCandidateList.appendChild(card);
      });
    } catch (e) {
      console.warn("Failed to load candidate transports:", e);
    }
  }

  // Initiate Open Target
  async function initiateOpen(target) {
    if (!target || !target.trim()) return;
    const cleanTarget = target.trim();
    latestTelemetry.lastTarget = cleanTarget;
    if (connectingTarget) connectingTarget.textContent = cleanTarget;

    try {
      if (window.netaccess) {
        await window.netaccess.openTarget(cleanTarget);
      }
    } catch (err) {
      console.error("openTarget failed:", err);
    }
  }

  // Event Listeners
  if (targetForm) {
    targetForm.addEventListener("submit", (e) => {
      e.preventDefault();
      const val = targetInput.value.trim();
      if (val) initiateOpen(val);
    });
  }

  if (btnCancelConnecting) {
    btnCancelConnecting.addEventListener("click", async () => {
      if (window.netaccess) {
        await window.netaccess.cancelSession();
      }
      showView(viewInitial);
    });
  }

  if (btnNewTarget) {
    btnNewTarget.addEventListener("click", () => {
      showView(viewInitial);
      if (targetInput) {
        targetInput.value = "";
        targetInput.focus();
      }
    });
  }

  if (btnFailedBack) {
    btnFailedBack.addEventListener("click", () => {
      showView(viewInitial);
    });
  }

  if (btnFailedRetry) {
    btnFailedRetry.addEventListener("click", () => {
      if (latestTelemetry.lastTarget) {
        initiateOpen(latestTelemetry.lastTarget);
      } else {
        showView(viewInitial);
      }
    });
  }

  if (btnFailedSettings) {
    btnFailedSettings.addEventListener("click", () => {
      openSettingsModal();
    });
  }

  // Developer Mode Drawer Controls
  function toggleDevDrawer(show) {
    if (show === undefined) {
      drawerDev.classList.toggle("open");
    } else if (show) {
      drawerDev.classList.add("open");
    } else {
      drawerDev.classList.remove("open");
    }
    drawerDev.setAttribute("aria-hidden", !drawerDev.classList.contains("open"));
    if (drawerDev.classList.contains("open")) {
      refreshCandidateList();
    }
  }

  if (btnToggleDev) {
    btnToggleDev.addEventListener("click", () => toggleDevDrawer());
  }

  if (btnCloseDev) {
    btnCloseDev.addEventListener("click", () => toggleDevDrawer(false));
  }

  if (btnViewDetails) {
    btnViewDetails.addEventListener("click", () => toggleDevDrawer(true));
  }

  if (btnCopyDevJson) {
    btnCopyDevJson.addEventListener("click", () => {
      // Credentials strictly omitted / redacted
      const dump = {
        target: latestTelemetry.lastTarget,
        diagnosis: latestTelemetry.diagnosis,
        selectedPath: latestTelemetry.selectedPath ? {
          type: latestTelemetry.selectedPath.type,
          transport: latestTelemetry.selectedPath.transport ? {
            id: latestTelemetry.selectedPath.transport.id,
            name: latestTelemetry.selectedPath.transport.name,
            type: latestTelemetry.selectedPath.transport.type,
            host: latestTelemetry.selectedPath.transport.host,
            port: latestTelemetry.selectedPath.transport.port,
          } : undefined,
          latencyMs: latestTelemetry.selectedPath.latencyMs,
        } : undefined,
        verification: latestTelemetry.verification,
      };

      navigator.clipboard.writeText(JSON.stringify(dump, null, 2))
        .then(() => {
          const orig = btnCopyDevJson.textContent;
          btnCopyDevJson.textContent = "Copied!";
          setTimeout(() => { btnCopyDevJson.textContent = orig; }, 1500);
        })
        .catch((err) => console.error("Clipboard copy failed:", err));
    });
  }

  // Settings Modal Controls
  async function openSettingsModal() {
    modalSettings.classList.add("open");
    modalSettings.setAttribute("aria-hidden", "false");
    await loadSettingsUI();
  }

  function closeSettingsModal() {
    modalSettings.classList.remove("open");
    modalSettings.setAttribute("aria-hidden", "true");
  }

  if (btnToggleSettings) btnToggleSettings.addEventListener("click", openSettingsModal);
  if (btnCloseSettings) btnCloseSettings.addEventListener("click", closeSettingsModal);

  // Settings Tabs
  const tabButtons = document.querySelectorAll(".settings-tabs .tab-btn");
  tabButtons.forEach((btn) => {
    btn.addEventListener("click", () => {
      tabButtons.forEach((b) => b.classList.remove("active"));
      document.querySelectorAll(".tab-pane").forEach((p) => p.classList.remove("active"));
      btn.classList.add("active");
      const targetPane = document.getElementById(btn.dataset.tab);
      if (targetPane) targetPane.classList.add("active");

      if (btn.dataset.tab === "tab-advanced") {
        loadDoctorReport();
      }
    });
  });

  // Settings Load & Save
  async function loadSettingsUI() {
    if (!window.netaccess) return;
    try {
      const settings = await window.netaccess.getSettings();
      if (settingOpenDefaultBrowser) settingOpenDefaultBrowser.checked = !!settings.openInDefaultBrowser;
      if (settingAutoAlternate) settingAutoAlternate.checked = !!(settings.autoUseAlternate ?? settings.autoUseAlternateTransports);
      if (settingRememberRecents) settingRememberRecents.checked = !!(settings.rememberRecent ?? settings.rememberRecentTargets);
      if (settingDiagnosticLogging) settingDiagnosticLogging.checked = !!(settings.localDiagnostics ?? settings.localDiagnosticLogging);
      if (settingDevMode) settingDevMode.checked = !!settings.developerMode;

      await loadTransportsUI();
    } catch (e) {
      console.warn("Error loading settings:", e);
    }
  }

  async function updateSettingValue(key, val) {
    if (!window.netaccess) return;
    try {
      await window.netaccess.updateSettings({ [key]: val });
    } catch (e) {
      console.warn("Failed updating setting:", key, e);
    }
  }

  if (settingOpenDefaultBrowser) {
    settingOpenDefaultBrowser.addEventListener("change", (e) => {
      updateSettingValue("openInDefaultBrowser", e.target.checked);
    });
  }

  if (settingAutoAlternate) {
    settingAutoAlternate.addEventListener("change", (e) => {
      updateSettingValue("autoUseAlternate", e.target.checked);
    });
  }

  if (settingRememberRecents) {
    settingRememberRecents.addEventListener("change", (e) => {
      updateSettingValue("rememberRecent", e.target.checked);
    });
  }

  if (settingDiagnosticLogging) {
    settingDiagnosticLogging.addEventListener("change", (e) => {
      updateSettingValue("localDiagnostics", e.target.checked);
    });
  }

  if (settingDevMode) {
    settingDevMode.addEventListener("change", (e) => {
      updateSettingValue("developerMode", e.target.checked);
      if (e.target.checked) toggleDevDrawer(true);
    });
  }

  if (btnClearRecents) {
    btnClearRecents.addEventListener("click", async () => {
      if (window.netaccess) {
        await window.netaccess.clearRecentTargets();
        await refreshRecents();
      }
    });
  }

  // Connections (Transports) Management
  async function loadTransportsUI() {
    if (!window.netaccess || !transportsList) return;
    try {
      transportsList.replaceChildren();

      if (!transports || transports.length === 0) {
        const emptyDiv = document.createElement("div");
        emptyDiv.className = "empty-hint";
        emptyDiv.textContent = 'No proxy connections configured. Click "+ Add Proxy" to add one.';
        transportsList.appendChild(emptyDiv);
        return;
      }

      transports.forEach((t) => {
        const item = document.createElement("div");
        item.className = "transport-item";

        const meta = document.createElement("div");
        meta.className = "transport-meta";
        const nameSpan = document.createElement("span");
        nameSpan.className = "transport-item-name";
        nameSpan.textContent = t.name;
        const detailsSpan = document.createElement("span");
        detailsSpan.className = "transport-item-details";
        detailsSpan.textContent = `${t.type.toUpperCase()} • ${t.host}:${t.port}`;
        meta.appendChild(nameSpan);
        meta.appendChild(detailsSpan);

        const actions = document.createElement("div");
        actions.className = "transport-item-actions";

        const btnTest = document.createElement("button");
        btnTest.type = "button";
        btnTest.className = "btn btn-xs btn-secondary";
        btnTest.textContent = "Test";
        btnTest.addEventListener("click", async () => {
          btnTest.textContent = "Testing…";
          btnTest.classList.remove("status-success", "status-failed");
          try {
            const res = await window.netaccess.testTransport(t.id);
            btnTest.textContent = res.success ? `${Math.round(res.latencyMs)}ms` : "Failed";
            btnTest.classList.add(res.success ? "status-success" : "status-failed");
          } catch (e) {
            btnTest.textContent = "Err";
            btnTest.classList.add("status-failed");
          }
        });

        const btnDelete = document.createElement("button");
        btnDelete.type = "button";
        btnDelete.className = "btn btn-xs btn-secondary";
        btnDelete.textContent = "Delete";
        btnDelete.addEventListener("click", async () => {
          await window.netaccess.removeTransport(t.id);
          await loadTransportsUI();
        });

        actions.appendChild(btnTest);
        actions.appendChild(btnDelete);
        item.appendChild(meta);
        item.appendChild(actions);
        transportsList.appendChild(item);
      });
    } catch (e) {
      console.warn("Failed loading transports:", e);
    }
  }

  if (btnAddProxyToggle) {
    btnAddProxyToggle.addEventListener("click", () => {
      addProxyForm.classList.toggle("hidden");
    });
  }

  if (btnCancelAddProxy) {
    btnCancelAddProxy.addEventListener("click", () => {
      addProxyForm.classList.add("hidden");
    });
  }

  if (addProxyForm) {
    addProxyForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const type = document.getElementById("proxy-type").value;
      const name = document.getElementById("proxy-name").value.trim();
      const host = document.getElementById("proxy-host").value.trim();
      const port = parseInt(document.getElementById("proxy-port").value, 10);
      const username = document.getElementById("proxy-user").value.trim();
      const password = document.getElementById("proxy-pass").value;

      if (!name || !host || isNaN(port)) return;

      const config = {
        id: `transport-${Date.now()}`,
        name,
        type,
        host,
        port,
        auth: (username || password) ? { username, password } : undefined,
        enabled: true,
      };

      if (window.netaccess) {
        await window.netaccess.addTransport(config);
        addProxyForm.reset();
        addProxyForm.classList.add("hidden");
        await loadTransportsUI();
      }
    });
  }

  // Doctor Report
  async function loadDoctorReport() {
    if (!window.netaccess || !systemDoctorContent) return;
    try {
      const doc = await window.netaccess.getDoctorReport();
      systemDoctorContent.textContent = [
        `Platform: ${doc.platform} (${doc.arch})`,
        `Interfaces: ${doc.interfaces.join(", ") || "None"}`,
        `Browsers Detected: ${doc.browsers.map((b) => b.name).join(", ") || "None"}`,
        `Transports: ${doc.configuredTransports} configured`,
      ].join("\n");
    } catch (e) {
      systemDoctorContent.textContent = "Failed to load environment report.";
    }
  }

  // Keyboard Shortcuts
  window.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      if (modalSettings.classList.contains("open")) {
        closeSettingsModal();
      } else if (drawerDev.classList.contains("open")) {
        toggleDevDrawer(false);
      }
    }
    if ((e.metaKey || e.ctrlKey) && e.key === "d") {
      e.preventDefault();
      toggleDevDrawer();
    }
    if ((e.metaKey || e.ctrlKey) && e.key === ",") {
      e.preventDefault();
      openSettingsModal();
    }
  });

  // Subscribe to ApplicationController IPC Events via window.netaccess
  if (window.netaccess) {
    window.netaccess.onStateChanged((state, msg) => renderState(state, msg));
    window.netaccess.onDiagnosisUpdated((diag) => renderDiagnosis(diag));
    window.netaccess.onTransportChanged((path) => renderTransport(path));
    window.netaccess.onVerificationUpdated((ver) => renderVerification(ver));
    window.netaccess.onCompleted((res) => renderCompleted(res));
    window.netaccess.onFailed((err) => renderFailed(err));

    // Initial setup
    refreshRecents();
    window.netaccess.getStatus().then((snapshot) => {
      renderState(snapshot.state, "Initial sync");
      if (snapshot.diagnosis) renderDiagnosis(snapshot.diagnosis);
      if (snapshot.selectedPath) renderTransport(snapshot.selectedPath);
      if (snapshot.verification) renderVerification(snapshot.verification);
    }).catch((e) => console.warn("Initial status fetch error:", e));
  } else {
    console.warn("window.netaccess is not available (running in non-Electron browser environment).");
  }
})();

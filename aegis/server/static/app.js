// Aegis-X Frontend Orchestrator

let networkInstance = null;
let currentGraphData = { nodes: [], edges: [] };
let activeIncidents = [];
let ws = null;

// Initialize on DOM load
document.addEventListener("DOMContentLoaded", () => {
  initLiveClock();
  initTabs();
  initDropdown();
  initWebSocket();
  fetchStatusAndData();

  document.getElementById("btnLiveScan").addEventListener("click", () => {
    runScan("live");
  });

  let resizeTimer;
  window.addEventListener("resize", () => {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(() => {
      if (networkInstance) {
        networkInstance.fit();
      }
    }, 250);
  });
});

// Live SOC UTC Clock
function initLiveClock() {
  const clockElem = document.getElementById("socClock");
  if (!clockElem) return;
  function update() {
    const now = new Date();
    const utcStr = now.toISOString().slice(11, 19) + " UTC";
    clockElem.textContent = utcStr;
  }
  update();
  setInterval(update, 1000);
}

// Tab Switcher
function initTabs() {
  const tabs = document.querySelectorAll(".nav-tab");
  tabs.forEach(tab => {
    tab.addEventListener("click", () => {
      tabs.forEach(t => t.classList.remove("active"));
      document.querySelectorAll(".tab-pane").forEach(p => p.classList.remove("active"));

      tab.classList.add("active");
      const target = document.getElementById(tab.dataset.tab);
      if (target) {
        target.classList.add("active");
        if (tab.dataset.tab === "tab-graph" && networkInstance) {
          setTimeout(() => { networkInstance.fit(); }, 120);
        }
        if (tab.dataset.tab === "tab-audit") {
          loadAuditLogs();
        }
      }
    });
  });
}

// Dropdown simulation menu
function initDropdown() {
  const btn = document.getElementById("btnSimulateDropdown");
  const dropdown = btn.parentElement;

  btn.addEventListener("click", (e) => {
    e.stopPropagation();
    dropdown.classList.toggle("open");
  });

  document.addEventListener("click", () => {
    dropdown.classList.remove("open");
  });
}

// WebSocket Live Telemetry
function initWebSocket() {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const wsUrl = `${protocol}//${window.location.host}/ws/telemetry`;

  try {
    ws = new WebSocket(wsUrl);
    ws.onopen = () => {
      appendAuditLine("system", "🟢 Telemetry WebSocket stream connected.");
    };
    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        handleStreamEvent(data);
      } catch (err) {
        console.error("WS Parse Error", err);
      }
    };
    ws.onclose = () => {
      appendAuditLine("system", "⚠️ WebSocket disconnected. Retrying in 5s...");
      setTimeout(initWebSocket, 5000);
    };
  } catch (e) {
    console.warn("WebSocket init error", e);
  }
}

function handleStreamEvent(data) {
  if (data.type === "SCAN_COMPLETED") {
    appendAuditLine("scan", `⚡ Scan completed. Score: ${data.score}/100 | Active Incidents: ${data.incidents}`);
    fetchStatusAndData();
  } else if (data.type === "INCIDENT_CONTAINED") {
    appendAuditLine("contain", `🚨 Containment directive executed for ${data.incident_id}`);
    fetchStatusAndData();
  } else if (data.type === "ATTACK_SIMULATED") {
    appendAuditLine("sim", `☣️ Adversary scenario '${data.scenario}' injected. Detected ${data.incidents} threats.`);
    fetchStatusAndData();
  }
}

// Fetch Full Posture State
async function fetchStatusAndData() {
  try {
    const [statusRes, incRes, graphRes, mitreRes] = await Promise.all([
      fetch("/api/status").then(r => r.json()),
      fetch("/api/incidents").then(r => r.json()),
      fetch("/api/graph").then(r => r.json()),
      fetch("/api/mitre-matrix").then(r => r.json()),
    ]);

    activeIncidents = incRes;
    updatePostureMetrics(statusRes.metrics);
    renderIncidents(incRes);
    renderVisGraph(graphRes);
    renderMitreMatrix(mitreRes);
    loadAuditLogs();
  } catch (err) {
    console.error("Failed to fetch EDR telemetry", err);
  }
}

// Update Score Ring and Metrics
function updatePostureMetrics(metrics) {
  if (!metrics) return;

  const scoreVal = document.getElementById("overallScoreVal");
  const scoreRing = document.getElementById("scoreRingProgress");
  const tierBadge = document.getElementById("postureTierBadge");

  const score = metrics.score;
  scoreVal.textContent = score;

  // Circle dash calculations: radius = 42 -> circumference = 2 * PI * 42 ~= 263.89
  const circumference = 264;
  const offset = circumference - (score / 100) * circumference;
  scoreRing.style.strokeDashoffset = offset;

  if (score >= 80) {
    scoreRing.style.stroke = "url(#scoreGradEmerald)";
    scoreRing.style.filter = "drop-shadow(0 0 8px rgba(16, 185, 129, 0.7))";
  } else if (score >= 50) {
    scoreRing.style.stroke = "url(#scoreGradAmber)";
    scoreRing.style.filter = "drop-shadow(0 0 8px rgba(245, 158, 11, 0.7))";
  } else {
    scoreRing.style.stroke = "url(#scoreGradRose)";
    scoreRing.style.filter = "drop-shadow(0 0 8px rgba(255, 0, 85, 0.7))";
  }

  tierBadge.textContent = metrics.posture_tier;
  tierBadge.style.color = metrics.tier_color;

  document.getElementById("metricIncidentCount").textContent = metrics.incident_count;
  document.getElementById("metricEntityCount").textContent = metrics.entity_count;
  document.getElementById("metricSignalCount").textContent = metrics.total_signals;
  document.getElementById("incidentBadgeCount").textContent = metrics.incident_count;
}

// Vis.js Graph Rendering
function renderVisGraph(graphData) {
  currentGraphData = graphData;
  const container = document.getElementById("visNetworkContainer");
  if (!container) return;

  if (typeof vis === "undefined") {
    console.error("Vis.js library is not loaded yet.");
    container.innerHTML = "<div style='color: var(--text-dim); text-align: center; padding: 40px;'>Loading Attack Graph Visualizer...</div>";
    return;
  }

  const styledNodes = (graphData.nodes || []).map(n => {
    let border = "#38bdf8";
    let bg = "rgba(15, 23, 42, 0.85)";
    let highlight = "#00f0ff";
    let glow = "rgba(56, 189, 248, 0.4)";

    if (n.severity === "critical") {
      border = "#ff0055";
      bg = "rgba(255, 0, 85, 0.25)";
      highlight = "#ff3366";
      glow = "rgba(255, 0, 85, 0.6)";
    } else if (n.severity === "high") {
      border = "#f59e0b";
      bg = "rgba(245, 158, 11, 0.25)";
      highlight = "#fbbf24";
      glow = "rgba(245, 158, 11, 0.6)";
    } else if (n.severity === "medium") {
      border = "#00f0ff";
      bg = "rgba(0, 240, 255, 0.2)";
      highlight = "#38bdf8";
      glow = "rgba(0, 240, 255, 0.5)";
    } else {
      border = "#10b981";
      bg = "rgba(16, 185, 129, 0.2)";
      highlight = "#34d399";
      glow = "rgba(16, 185, 129, 0.5)";
    }

    return {
      ...n,
      shape: "box",
      margin: 10,
      borderWidth: 2,
      borderWidthSelected: 3,
      color: {
        border: border,
        background: bg,
        highlight: {
          border: highlight,
          background: bg,
        },
        hover: {
          border: "#ffffff",
          background: bg,
        }
      },
      font: {
        face: "Inter, sans-serif",
        size: 11,
        color: "#ffffff",
        multi: true
      },
      shadow: {
        enabled: true,
        color: glow,
        size: 10,
        x: 0,
        y: 0
      }
    };
  });

  const styledEdges = (graphData.edges || []).map(e => ({
    ...e,
    color: {
      color: "rgba(56, 189, 248, 0.35)",
      highlight: "#00f0ff",
      hover: "#ffffff"
    },
    arrows: { to: { enabled: true, scaleFactor: 0.6 } },
    font: { face: "Fira Code", size: 9, color: "#94a3b8", align: "middle" }
  }));

  const data = {
    nodes: new vis.DataSet(styledNodes),
    edges: new vis.DataSet(styledEdges),
  };

  const options = {
    nodes: {
      shape: "box",
      margin: 10,
    },
    edges: {
      width: 1.5,
      smooth: { type: "continuous", roundness: 0.2 },
    },
    physics: {
      solver: "forceAtlas2Based",
      forceAtlas2Based: {
        gravitationalConstant: -70,
        centralGravity: 0.015,
        springLength: 130,
        springConstant: 0.08,
        damping: 0.4,
      },
      stabilization: { iterations: 100 },
    },
    interaction: {
      hover: true,
      tooltipDelay: 150,
      zoomView: true,
    },
  };

  if (networkInstance) {
    networkInstance.destroy();
  }

  networkInstance = new vis.Network(container, data, options);

  networkInstance.once("stabilizationIterationsDone", () => {
    networkInstance.fit();
  });

  networkInstance.on("selectNode", (params) => {
    if (params.nodes.length > 0) {
      const nodeId = params.nodes[0];
      inspectNode(nodeId);
    }
  });

  networkInstance.on("deselectNode", () => {
    clearInspector();
  });
}

function resetGraphPhysics() {
  if (networkInstance) {
    networkInstance.setOptions({ physics: { enabled: true } });
    setTimeout(() => {
      networkInstance.setOptions({ physics: { enabled: false } });
    }, 1500);
  }
}

function fitGraphView() {
  if (networkInstance) {
    networkInstance.fit({ animation: { duration: 600, easingFunction: "easeInOutQuad" } });
  }
}

// Node Inspector Sidebar
function inspectNode(nodeKey) {
  const node = currentGraphData.nodes.find(n => n.id === nodeKey);
  const inspector = document.getElementById("inspectorContent");
  if (!node) return;

  const associatedIncidents = activeIncidents.filter(inc => inc.entity && inc.entity.key === nodeKey);

  let html = `
    <div style="margin-bottom: 16px;">
      <div style="font-size: 16px; font-weight: 800; color: #fff; margin-bottom: 4px; font-family: var(--font-tech);">${node.label.split('\n')[0]}</div>
      <div style="font-family: var(--font-mono); font-size: 10px; color: var(--text-dim); word-break: break-all;">${node.id}</div>
    </div>

    <div style="background: rgba(0,0,0,0.35); padding: 14px; border-radius: var(--radius-md); margin-bottom: 16px; border: 1px solid var(--border-subtle);">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
        <span style="color: var(--text-muted); font-size: 11px;">Threat Severity:</span>
        <span class="severity-pill ${node.severity}">${node.severity.toUpperCase()}</span>
      </div>
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
        <span style="color: var(--text-muted); font-size: 11px;">Entity Category:</span>
        <span style="color: var(--neon-cyan); text-transform: uppercase; font-family: var(--font-mono); font-size: 11px;">${node.entity_type}</span>
      </div>
      <div style="display: flex; justify-content: space-between; align-items: center;">
        <span style="color: var(--text-muted); font-size: 11px;">Attached Signals:</span>
        <span style="font-weight: 700; color: #fff; font-family: var(--font-mono);">${node.signal_count}</span>
      </div>
    </div>
  `;

  if (associatedIncidents.length > 0) {
    html += `<div style="font-family: var(--font-display); font-size: 11px; margin-bottom: 10px; color: var(--neon-rose); letter-spacing: 0.8px;">CORRELATED THREAT INCIDENTS</div>`;
    associatedIncidents.forEach(inc => {
      html += `
        <div style="background: rgba(255,0,85,0.08); border: 1px solid rgba(255,0,85,0.35); border-radius: var(--radius-md); padding: 12px; margin-bottom: 10px;">
          <div style="font-weight: 700; color: #fff; margin-bottom: 4px; font-size: 13px;">${inc.title}</div>
          <div style="font-size: 11px; color: var(--text-muted); margin-bottom: 10px; line-height: 1.5;">${inc.explanation}</div>
          <button class="cyber-btn danger" style="padding: 7px 12px; font-size: 11px; width: 100%; justify-content: center;" onclick="executeContainment('${inc.incident_id}')">
            ⚡ EXECUTE SOAR ISOLATION
          </button>
        </div>
      `;
    });
  } else {
    html += `
      <div style="color: var(--neon-emerald); font-size: 12px; background: rgba(16,185,129,0.1); padding: 12px; border-radius: var(--radius-sm); border: 1px solid rgba(16,185,129,0.3);">
        ✓ No active multi-signal correlated threats for this node.
      </div>
    `;
  }

  inspector.innerHTML = html;

  if (window.innerWidth <= 1024) {
    const inspectorElem = document.getElementById("nodeInspector");
    if (inspectorElem) {
      inspectorElem.scrollIntoView({ behavior: "smooth", block: "nearest" });
    }
  }
}

function clearInspector() {
  document.getElementById("inspectorContent").innerHTML = `
    <div class="empty-hint">
      <div class="empty-hint-icon">🔍</div>
      <div class="empty-hint-title">No Entity Selected</div>
      <div class="empty-hint-sub">Select any node on the Attack Graph to inspect live process lineage, socket bindings, and raw telemetry signals.</div>
    </div>
  `;
}

// Render Incidents List
function renderIncidents(incidents) {
  const container = document.getElementById("incidentsList");
  if (!incidents || incidents.length === 0) {
    container.innerHTML = `
      <div style="text-align: center; padding: 60px 20px; background: var(--bg-card); border-radius: var(--radius-lg); border: 1px solid var(--border-subtle);">
        <div style="font-size: 36px; margin-bottom: 12px;">🛡️</div>
        <div style="font-family: var(--font-display); font-size: 16px; color: var(--neon-emerald); margin-bottom: 6px;">ZERO CORRELATED THREATS</div>
        <div style="color: var(--text-muted); font-size: 13px;">All monitored endpoint behaviors comply with benign baselines.</div>
      </div>
    `;
    return;
  }

  container.innerHTML = incidents.map(inc => {
    const isContained = inc.status === "CONTAINED_ISOLATED";
    return `
      <div class="incident-card ${inc.severity} ${isContained ? 'contained' : ''}">
        <div class="incident-top">
          <div class="incident-title-block">
            <span class="severity-pill ${inc.severity}">${inc.severity}</span>
            <div class="incident-title">${inc.title}</div>
          </div>
          <span class="incident-status-tag ${isContained ? 'contained' : 'open'}">
            ${isContained ? '✓ CONTAINED & ISOLATED' : '🚨 ACTIVE THREAT'}
          </span>
        </div>

        <div class="incident-plain-english">
          <div class="plain-english-header">
            <span class="plain-english-badge">💬 WHAT THIS MEANS IN SIMPLE TERMS</span>
          </div>
          <div class="plain-english-text">${inc.plain_english_summary || inc.explanation}</div>
        </div>

        <div class="incident-precautions">
          <div class="precautions-header">🛡️ NECESSARY PRECAUTIONS TO TAKE:</div>
          <ul class="precautions-list">
            ${(inc.user_precautions && inc.user_precautions.length > 0 ? inc.user_precautions : [inc.remediation]).map(p => `<li>${p}</li>`).join('')}
          </ul>
        </div>

        <div class="incident-tech-accordion">
          <div class="tech-detail-label">⚙️ Technical Detection Analysis: <span>${inc.explanation}</span></div>
        </div>

        <div class="incident-tags">
          ${(inc.mitre_tactics || []).map(t => `<span class="mitre-badge">🎯 ${t}</span>`).join('')}
          ${(inc.mitre_techniques || []).map(t => `<span class="mitre-badge" style="border-color: #38bdf8; color: #38bdf8;">⚙️ ${t}</span>`).join('')}
        </div>

        <div class="incident-actions">
          <div class="evidence-preview">
            🔍 <strong>Evidence:</strong> ${inc.evidence_count} signals correlated (Entity: <code>${inc.entity.name}</code>, PID: <code>${inc.entity.pid || 'N/A'}</code>)
          </div>
          <div>
            ${isContained ? 
              `<button class="cyber-btn secondary" disabled style="opacity: 0.6;">✓ THREAT NEUTRALIZED</button>` :
              `<button class="cyber-btn danger" onclick="executeContainment('${inc.incident_id}')">
                ⚡ EXECUTE SOAR ISOLATION
              </button>`
            }
          </div>
        </div>
      </div>
    `;
  }).join('');
}

// Render MITRE Matrix
function renderMitreMatrix(matrix) {
  const grid = document.getElementById("mitreGrid");
  if (!matrix) return;

  grid.innerHTML = matrix.map(col => {
    const isHit = col.hit_count > 0;
    return `
      <div class="mitre-tactic-col ${isHit ? 'compromised' : ''}">
        <div class="tactic-header">
          <div class="tactic-name">${col.tactic_name}</div>
          <span class="tactic-badge ${isHit ? 'hit' : 'clear'}">${isHit ? `${col.hit_count} HITS` : 'CLEAR'}</span>
        </div>
        <div style="font-size: 11px; color: var(--text-dim); margin-bottom: 6px;">${col.description}</div>
        <div style="display: flex; flex-direction: column; gap: 6px;">
          ${col.techniques.map(tech => `
            <div class="technique-box ${tech.triggered ? 'triggered' : ''}">
              <div style="font-family: var(--font-mono); font-size: 10px; opacity: 0.8;">${tech.technique_id}</div>
              <div>${tech.technique_name}</div>
            </div>
          `).join('')}
        </div>
      </div>
    `;
  }).join('');
}

// Containment Execution
async function executeContainment(incidentId) {
  try {
    appendAuditLine("contain", `Executing SOAR containment pipeline for incident ${incidentId}...`);
    const res = await fetch(`/api/contain/${incidentId}`, { method: "POST" });
    const data = await res.json();

    if (data.status === "success") {
      showModal(`
        <div style="margin-bottom: 14px;">
          <div style="font-weight: 700; color: #fff; margin-bottom: 6px; font-size: 15px;">Containment Successful</div>
          <div style="color: var(--text-muted); font-size: 12px;">Automated defensive containment actions executed across host telemetry nodes:</div>
        </div>
        <ul style="padding-left: 20px; font-size: 13px; line-height: 1.8; color: var(--neon-emerald); margin-bottom: 16px;">
          ${data.actions_taken.map(a => `<li>${a}</li>`).join('')}
        </ul>
        <div style="font-size: 11px; color: var(--text-dim); font-family: var(--font-mono);">Forensic Audit ID: ${data.audit_id || 'AUDIT-' + Date.now()}</div>
      `);
      fetchStatusAndData();
    }
  } catch (err) {
    console.error("Containment failed", err);
  }
}

// Contain All Threats
async function containAllThreats() {
  if (!confirm("Are you sure you want to execute emergency SOAR containment on ALL active incidents?")) return;

  try {
    appendAuditLine("contain", "🚨 EMERGENCY SOAR DIRECTIVE: Isolating all active adversary threats...");
    const res = await fetch("/api/contain-all", { method: "POST" });
    const data = await res.json();

    showModal(`
      <div style="margin-bottom: 14px;">
        <div style="font-weight: 700; color: #fff; margin-bottom: 6px; font-size: 15px;">Emergency Multi-Vector Containment Complete</div>
        <div style="color: var(--text-muted); font-size: 12px;">Successfully executed SOAR isolation routines across ${data.contained_count} incident vectors:</div>
      </div>
      <ul style="padding-left: 20px; font-size: 12px; line-height: 1.8; color: var(--neon-emerald); margin-bottom: 16px;">
        ${data.summary.map(s => `<li>${s}</li>`).join('')}
      </ul>
      <div style="color: var(--neon-cyan); font-weight: 600; font-size: 12px;">Host posture successfully restored to baseline security parameters.</div>
    `);
    fetchStatusAndData();
  } catch (err) {
    console.error("Contain all failed", err);
  }
}

// Adversary Simulation
async function triggerScenario(scenario) {
  try {
    appendAuditLine("sim", `Injecting attack scenario: ${scenario}...`);
    await fetch(`/api/simulate/${scenario}`, { method: "POST" });
    fetchStatusAndData();
  } catch (e) {
    console.error("Simulation error", e);
  }
}

// Run Scan
async function runScan(mode = "live") {
  const btn = document.getElementById("btnLiveScan");
  btn.disabled = true;
  btn.innerHTML = `<span class="btn-icon">⏳</span> <span class="btn-text">SCANNING OS...</span>`;

  try {
    appendAuditLine("scan", `Starting live telemetry harvest across processes, sockets, and persistence...`);
    const res = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ mode: mode, scenario: null }),
    });
    const data = await res.json();
    appendAuditLine("scan", `Harvested ${data.signal_count} signals across ${data.entity_count} entities.`);
    fetchStatusAndData();
  } catch (e) {
    console.error("Scan error", e);
  } finally {
    btn.disabled = false;
    btn.innerHTML = `<span class="btn-icon">⚡</span> <span class="btn-text">RUN SCAN</span>`;
  }
}

// Load Audit Logs
async function loadAuditLogs() {
  try {
    const res = await fetch("/api/audit-log");
    const audits = await res.json();
    const terminal = document.getElementById("auditOutput");

    if (!audits || audits.length === 0) {
      terminal.innerHTML = `<div class="log-line text-muted">// No historical containment events recorded yet.</div>`;
      return;
    }

    terminal.innerHTML = audits.map(a => `
      <div class="log-line">
        <span style="color: var(--text-dim);">[${a.timestamp.substring(11, 19)}]</span>
        <span style="color: var(--neon-rose); font-weight: 700;">[${a.action}]</span>
        <span style="color: var(--neon-cyan);">${a.incident_id}</span>
        <span style="color: #f1f5f9;">— ${a.details}</span>
      </div>
    `).join('');
  } catch (e) {
    console.error("Failed to load audit logs", e);
  }
}

function appendAuditLine(tag, msg) {
  const terminal = document.getElementById("auditOutput");
  if (!terminal) return;
  const time = new Date().toISOString().substring(11, 19);
  const div = document.createElement("div");
  div.className = "log-line";
  
  let tagColor = "var(--neon-amber)";
  if (tag === "contain") tagColor = "var(--neon-rose)";
  if (tag === "system") tagColor = "var(--neon-emerald)";
  if (tag === "scan") tagColor = "var(--neon-cyan)";
  if (tag === "sim") tagColor = "var(--neon-purple)";

  div.innerHTML = `<span style="color: var(--text-dim);">[${time}]</span> <span style="color: ${tagColor}; font-weight: 700;">[${tag.toUpperCase()}]</span> <span>${msg}</span>`;
  terminal.prepend(div);
}

// Modal handling
function showModal(content) {
  document.getElementById("modalContent").innerHTML = content;
  document.getElementById("containmentModal").classList.add("open");
}

function closeModal() {
  document.getElementById("containmentModal").classList.remove("open");
}

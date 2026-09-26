// Aegis-X Enterprise EDR Orchestrator

let networkInstance = null;
let currentGraphData = { nodes: [], edges: [] };
let activeIncidents = [];
let currentFilter = "all";
let currentSearchQuery = "";
let ws = null;

// Initialize on DOM load
document.addEventListener("DOMContentLoaded", () => {
  initLiveClock();
  initTabs();
  initIncidentFilters();
  initWebSocket();
  fetchStatusAndData();

  const scanBtn = document.getElementById("btnLiveScan");
  if (scanBtn) {
    scanBtn.addEventListener("click", () => {
      runScan("live");
    });
  }

  let resizeTimer;
  window.addEventListener("resize", () => {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(() => {
      if (networkInstance) {
        networkInstance.fit();
      }
    }, 200);
  });
});

// Live UTC Clock
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
  const tabButtons = document.querySelectorAll(".nav-link[data-tab]");
  tabButtons.forEach(btn => {
    btn.addEventListener("click", () => {
      tabButtons.forEach(b => {
        b.classList.remove("active");
        b.setAttribute("aria-selected", "false");
      });
      document.querySelectorAll(".tab-pane").forEach(pane => pane.classList.remove("active"));

      btn.classList.add("active");
      btn.setAttribute("aria-selected", "true");
      const target = document.getElementById(btn.dataset.tab);
      if (target) {
        target.classList.add("active");
        if (btn.dataset.tab === "tab-graph" && networkInstance) {
          setTimeout(() => { networkInstance.fit(); }, 120);
        }
        if (btn.dataset.tab === "tab-audit") {
          loadAuditLogs();
        }
      }
    });
  });
}

// Incident Search & Filtering
function initIncidentFilters() {
  const searchInput = document.getElementById("incidentSearchInput");
  if (searchInput) {
    searchInput.addEventListener("input", (e) => {
      currentSearchQuery = e.target.value.toLowerCase().trim();
      applyIncidentFilters();
    });
  }

  const filterBtns = document.querySelectorAll(".filter-pill");
  filterBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      filterBtns.forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      currentFilter = btn.dataset.filter;
      applyIncidentFilters();
    });
  });
}

function applyIncidentFilters() {
  let filtered = activeIncidents.slice();

  // Apply severity / containment filter
  if (currentFilter === "critical") {
    filtered = filtered.filter(i => i.severity === "critical" && i.status !== "CONTAINED_ISOLATED");
  } else if (currentFilter === "high") {
    filtered = filtered.filter(i => i.severity === "high" && i.status !== "CONTAINED_ISOLATED");
  } else if (currentFilter === "medium") {
    filtered = filtered.filter(i => i.severity === "medium" && i.status !== "CONTAINED_ISOLATED");
  } else if (currentFilter === "contained") {
    filtered = filtered.filter(i => i.status === "CONTAINED_ISOLATED");
  }

  // Apply text search filter
  if (currentSearchQuery) {
    filtered = filtered.filter(i => {
      const titleMatch = (i.title || "").toLowerCase().includes(currentSearchQuery);
      const entityMatch = (i.entity?.name || "").toLowerCase().includes(currentSearchQuery);
      const pidMatch = String(i.entity?.pid || "").includes(currentSearchQuery);
      const explMatch = (i.explanation || "").toLowerCase().includes(currentSearchQuery);
      const mitreMatch = (i.mitre_techniques || []).some(t => t.toLowerCase().includes(currentSearchQuery));
      return titleMatch || entityMatch || pidMatch || explMatch || mitreMatch;
    });
  }

  renderFilteredIncidents(filtered);
}

// WebSocket Live Telemetry Stream
function initWebSocket() {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const wsUrl = `${protocol}//${window.location.host}/ws/telemetry`;

  try {
    ws = new WebSocket(wsUrl);
    ws.onopen = () => {
      appendAuditLine("system", "Telemetry WebSocket stream connected to host agent.");
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
      appendAuditLine("system", "WebSocket disconnected. Reconnecting in 5s...");
      setTimeout(initWebSocket, 5000);
    };
  } catch (e) {
    console.warn("WebSocket init error", e);
  }
}

function handleStreamEvent(data) {
  if (data.type === "SCAN_COMPLETED") {
    appendAuditLine("scan", `Host scan finished. Security Score: ${data.score}/100 | Active Incidents: ${data.incidents}`);
    fetchStatusAndData();
  } else if (data.type === "INCIDENT_CONTAINED") {
    appendAuditLine("contain", `SOAR Containment directive executed for ${data.incident_id}`);
    fetchStatusAndData();
  } else if (data.type === "ATTACK_SIMULATED") {
    appendAuditLine("sim", `Adversary scenario '${data.scenario}' simulated. Detected ${data.incidents} threats.`);
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
    updateFilterCounts();
    applyIncidentFilters();
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

  const circumference = 251.3;
  const offset = circumference - (score / 100) * circumference;
  scoreRing.style.strokeDashoffset = offset;

  if (score >= 80) {
    scoreRing.style.stroke = "#10b981";
    tierBadge.className = "fw-bold fs-6 text-success font-heading";
  } else if (score >= 50) {
    scoreRing.style.stroke = "#f59e0b";
    tierBadge.className = "fw-bold fs-6 text-warning font-heading";
  } else {
    scoreRing.style.stroke = "#ef4444";
    tierBadge.className = "fw-bold fs-6 text-danger font-heading";
  }

  tierBadge.textContent = metrics.posture_tier;

  document.getElementById("metricIncidentCount").textContent = metrics.incident_count;
  document.getElementById("metricEntityCount").textContent = metrics.entity_count;
  document.getElementById("metricSignalCount").textContent = metrics.total_signals;
  document.getElementById("metricContainCount").textContent = metrics.active_containments || 0;
  document.getElementById("incidentBadgeCount").textContent = metrics.incident_count;
}

function updateFilterCounts() {
  const total = activeIncidents.length;
  const critical = activeIncidents.filter(i => i.severity === "critical" && i.status !== "CONTAINED_ISOLATED").length;
  const high = activeIncidents.filter(i => i.severity === "high" && i.status !== "CONTAINED_ISOLATED").length;
  const medium = activeIncidents.filter(i => i.severity === "medium" && i.status !== "CONTAINED_ISOLATED").length;
  const contained = activeIncidents.filter(i => i.status === "CONTAINED_ISOLATED").length;

  const setIfExists = (id, val) => {
    const el = document.getElementById(id);
    if (el) el.textContent = val;
  };

  setIfExists("filterCountAll", total);
  setIfExists("filterCountCritical", critical);
  setIfExists("filterCountHigh", high);
  setIfExists("filterCountMedium", medium);
  setIfExists("filterCountContained", contained);
}

// Vis.js Graph Rendering
function renderVisGraph(graphData) {
  currentGraphData = graphData;
  const container = document.getElementById("visNetworkContainer");
  if (!container) return;

  if (typeof vis === "undefined") {
    container.innerHTML = "<div class='text-secondary text-center p-5'>Loading Attack Graph Visualizer...</div>";
    return;
  }

  const styledNodes = (graphData.nodes || []).map(n => {
    let border = "#3b82f6";
    let bg = "#1e293b";
    let highlight = "#60a5fa";

    if (n.severity === "critical") {
      border = "#ef4444";
      bg = "#450a0a";
      highlight = "#f87171";
    } else if (n.severity === "high") {
      border = "#f59e0b";
      bg = "#451a03";
      highlight = "#fbbf24";
    } else if (n.severity === "medium") {
      border = "#0ea5e9";
      bg = "#082f49";
      highlight = "#38bdf8";
    } else {
      border = "#10b981";
      bg = "#064e3b";
      highlight = "#34d399";
    }

    return {
      ...n,
      shape: "box",
      margin: 10,
      borderWidth: 1.5,
      borderWidthSelected: 2.5,
      color: {
        border: border,
        background: bg,
        highlight: { border: highlight, background: bg },
        hover: { border: "#ffffff", background: bg }
      },
      font: {
        face: "Inter, sans-serif",
        size: 11,
        color: "#ffffff",
        multi: true
      }
    };
  });

  const styledEdges = (graphData.edges || []).map(e => ({
    ...e,
    color: {
      color: "rgba(148, 163, 184, 0.4)",
      highlight: "#3b82f6",
      hover: "#ffffff"
    },
    arrows: { to: { enabled: true, scaleFactor: 0.5 } },
    font: { face: "JetBrains Mono, monospace", size: 9, color: "#94a3b8", align: "middle" }
  }));

  const data = {
    nodes: new vis.DataSet(styledNodes),
    edges: new vis.DataSet(styledEdges),
  };

  const options = {
    nodes: {
      shape: "box",
      margin: 8,
    },
    edges: {
      width: 1.5,
      smooth: { type: "continuous", roundness: 0.2 },
    },
    physics: {
      solver: "forceAtlas2Based",
      forceAtlas2Based: {
        gravitationalConstant: -60,
        centralGravity: 0.015,
        springLength: 120,
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

function zoomGraph(factor) {
  if (!networkInstance) return;
  const currentScale = networkInstance.getScale();
  networkInstance.moveTo({
    scale: currentScale * factor,
    animation: { duration: 300, easingFunction: "easeInOutQuad" }
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
    networkInstance.fit({ animation: { duration: 500, easingFunction: "easeInOutQuad" } });
  }
}

// Node Inspector Sidebar & Mobile Offcanvas
function inspectNode(nodeKey) {
  const node = currentGraphData.nodes.find(n => n.id === nodeKey);
  const inspector = document.getElementById("inspectorContent");
  if (!node) return;

  const associatedIncidents = activeIncidents.filter(inc => inc.entity && inc.entity.key === nodeKey);

  let severityBadgeClass = "text-bg-secondary";
  if (node.severity === "critical") severityBadgeClass = "text-bg-danger-subtle text-danger border border-danger-subtle";
  else if (node.severity === "high") severityBadgeClass = "text-bg-warning-subtle text-warning border border-warning-subtle";
  else if (node.severity === "medium") severityBadgeClass = "text-bg-info-subtle text-info border border-info-subtle";
  else if (node.severity === "benign") severityBadgeClass = "text-bg-success-subtle text-success border border-success-subtle";

  let html = `
    <div class="mb-3">
      <h6 class="fw-bold text-white mb-1 font-heading">${node.label.split('\n')[0]}</h6>
      <code class="small text-secondary font-mono d-block text-break">${node.id}</code>
    </div>

    <div class="bg-body-secondary p-3 rounded border mb-3">
      <div class="d-flex justify-content-between align-items-center mb-2">
        <span class="text-secondary small">Severity:</span>
        <span class="badge ${severityBadgeClass}">${node.severity.toUpperCase()}</span>
      </div>
      <div class="d-flex justify-content-between align-items-center mb-2">
        <span class="text-secondary small">Category:</span>
        <span class="font-mono text-primary small text-uppercase fw-semibold">${node.entity_type}</span>
      </div>
      <div class="d-flex justify-content-between align-items-center">
        <span class="text-secondary small">Signals:</span>
        <span class="font-mono text-white fw-bold small">${node.signal_count}</span>
      </div>
    </div>
  `;

  if (associatedIncidents.length > 0) {
    html += `<div class="small fw-bold text-danger text-uppercase font-mono mb-2">Correlated Incidents</div>`;
    associatedIncidents.forEach(inc => {
      html += `
        <div class="card bg-danger-subtle border-danger-subtle p-3 mb-2">
          <div class="fw-semibold text-danger mb-1 small">${inc.title}</div>
          <div class="text-secondary small mb-2 lh-sm">${inc.explanation}</div>
          <button class="btn btn-sm btn-danger d-inline-flex align-items-center justify-content-center gap-1 w-100" onclick="executeContainment('${inc.incident_id}')">
            <i class="bi bi-shield-slash"></i>
            <span>Execute SOAR Isolation</span>
          </button>
        </div>
      `;
    });
  } else {
    html += `
      <div class="alert alert-success d-flex align-items-center gap-2 p-2 small m-0" role="alert">
        <i class="bi bi-check-circle-fill"></i>
        <span>No active multi-signal threats correlated for this node.</span>
      </div>
    `;
  }

  inspector.innerHTML = html;

  // On mobile screens (< 992px), open offcanvas drawer
  if (window.innerWidth < 992 && window.bootstrap && bootstrap.Offcanvas) {
    const offcanvasElem = document.getElementById("nodeInspector");
    if (offcanvasElem) {
      const offcanvasInstance = bootstrap.Offcanvas.getOrCreateInstance(offcanvasElem);
      offcanvasInstance.show();
    }
  }
}

function clearInspector() {
  document.getElementById("inspectorContent").innerHTML = `
    <div class="text-center py-5 text-secondary">
      <i class="bi bi-search fs-2 mb-2 d-block opacity-50"></i>
      <h6 class="fw-semibold text-white mb-1">No Entity Selected</h6>
      <p class="small opacity-75 m-0">Click any process, socket, or persistence node in the attack graph to inspect telemetry details.</p>
    </div>
  `;
}

// Render Filtered Incidents List
function renderFilteredIncidents(incidents) {
  const container = document.getElementById("incidentsList");
  if (!incidents || incidents.length === 0) {
    container.innerHTML = `
      <article class="card p-5 text-center bg-surface-card border">
        <div class="fs-1 text-success mb-2"><i class="bi bi-shield-check"></i></div>
        <h5 class="fw-bold text-white mb-1 font-heading">No Incidents Found</h5>
        <p class="text-secondary small mb-0">No active incidents matching the selected filter criteria.</p>
      </article>
    `;
    return;
  }

  container.innerHTML = incidents.map(inc => {
    const isContained = inc.status === "CONTAINED_ISOLATED";
    const sevClass = inc.severity === "critical" ? "critical" : (inc.severity === "high" ? "high" : "medium");

    let badgeClass = "text-bg-info-subtle text-info border border-info-subtle";
    if (inc.severity === "critical") badgeClass = "text-bg-danger-subtle text-danger border border-danger-subtle";
    else if (inc.severity === "high") badgeClass = "text-bg-warning-subtle text-warning border border-warning-subtle";

    return `
      <article class="incident-card ${sevClass}" data-incident-id="${inc.incident_id}">
        <div class="d-flex justify-content-between align-items-start gap-2 flex-wrap mb-3">
          <div class="d-flex align-items-center gap-2 flex-wrap">
            <span class="badge ${badgeClass} text-uppercase font-mono">${inc.severity}</span>
            <h6 class="fw-bold text-white mb-0 font-heading fs-6">${inc.title}</h6>
          </div>
          <span class="badge ${isContained ? 'text-bg-success-subtle text-success border border-success-subtle' : 'text-bg-danger-subtle text-danger border border-danger-subtle'}">
            ${isContained ? '✓ Contained & Isolated' : '● Active Threat'}
          </span>
        </div>

        <div class="plain-english-box mb-3">
          <div class="plain-english-badge mb-1">
            <i class="bi bi-chat-left-text-fill me-1"></i> Executive Briefing
          </div>
          <div class="plain-english-text">${inc.plain_english_summary || inc.explanation}</div>
        </div>

        <div class="precautions-box mb-3">
          <div class="precautions-header">
            <i class="bi bi-shield-fill-check"></i> Recommended Countermeasures:
          </div>
          <ul>
            ${(inc.user_precautions && inc.user_precautions.length > 0 ? inc.user_precautions : [inc.remediation]).map(p => `<li>${p}</li>`).join('')}
          </ul>
        </div>

        <div class="tech-details-box text-secondary font-mono mb-3">
          <span class="text-white fw-semibold">Technical Signature:</span> ${inc.explanation}
        </div>

        <div class="d-flex flex-wrap gap-2 mb-3">
          ${(inc.mitre_tactics || []).map(t => `<span class="mitre-pill"><i class="bi bi-bullseye me-1"></i>${t}</span>`).join('')}
          ${(inc.mitre_techniques || []).map(t => `<span class="mitre-pill" style="border-color: rgba(56,189,248,0.3); color: #38bdf8;"><i class="bi bi-gear me-1"></i>${t}</span>`).join('')}
        </div>

        <div class="d-flex justify-content-between align-items-center pt-2 border-top border-secondary-subtle flex-wrap gap-2 incident-actions-group">
          <div class="small text-secondary">
            <i class="bi bi-link-45deg me-1"></i> Evidence: ${inc.evidence_count} signals correlated (Entity: <code>${inc.entity.name}</code>, PID: <code>${inc.entity.pid || 'N/A'}</code>)
          </div>
          <div>
            ${isContained ? 
              `<button class="btn btn-sm btn-outline-success" disabled><i class="bi bi-check-lg me-1"></i>Threat Neutralized</button>` :
              `<button class="btn btn-sm btn-danger d-inline-flex align-items-center gap-1" onclick="executeContainment('${inc.incident_id}')">
                <i class="bi bi-shield-slash"></i>
                <span>Execute SOAR Containment</span>
              </button>`
            }
          </div>
        </div>
      </article>
    `;
  }).join('');
}

// Render MITRE Matrix
function renderMitreMatrix(matrix) {
  const grid = document.getElementById("mitreGrid");
  if (!grid || !matrix) return;

  grid.innerHTML = matrix.map(col => {
    const isHit = col.hit_count > 0;
    return `
      <div class="col-12 col-md-6 col-xl-3">
        <div class="mitre-tactic-card ${isHit ? 'compromised' : ''}">
          <div class="d-flex justify-content-between align-items-center border-bottom pb-2 mb-2">
            <span class="fw-bold small text-white font-heading">${col.tactic_name}</span>
            <span class="badge ${isHit ? 'bg-danger text-white' : 'bg-body-secondary text-secondary'} font-mono" style="font-size: 0.65rem;">
              ${isHit ? `${col.hit_count} Detected` : 'Clean'}
            </span>
          </div>
          <div class="text-secondary small mb-2 lh-sm" style="font-size: 0.75rem;">${col.description}</div>
          <div class="d-flex flex-column gap-2 mt-auto">
            ${col.techniques.map(tech => `
              <div class="technique-item ${tech.triggered ? 'triggered' : ''}">
                <div class="font-mono text-secondary" style="font-size: 0.7rem;">${tech.technique_id}</div>
                <div class="fw-medium">${tech.technique_name}</div>
              </div>
            `).join('')}
          </div>
        </div>
      </div>
    `;
  }).join('');
}

// Containment Execution
async function executeContainment(incidentId) {
  try {
    appendAuditLine("contain", `Executing SOAR containment routine for ${incidentId}...`);
    const res = await fetch(`/api/contain/${incidentId}`, { method: "POST" });
    const data = await res.json();

    if (data.status === "success") {
      showModal(`
        <div class="mb-3">
          <div class="fw-bold text-white mb-1">SOAR Containment Successful</div>
          <p class="text-secondary small mb-2">Defensive response actions executed across endpoint agent telemetry:</p>
          <ul class="text-success small mb-0 ps-3">
            ${data.actions_taken.map(a => `<li class="mb-1">${a}</li>`).join('')}
          </ul>
        </div>
        <div class="text-secondary small font-mono">Compliance Audit ID: ${data.audit_id || 'AUDIT-' + Date.now()}</div>
      `);
      fetchStatusAndData();
    }
  } catch (err) {
    console.error("Containment failed", err);
  }
}

// Contain All Threats
async function containAllThreats() {
  if (!confirm("Confirm execution of emergency SOAR containment across ALL active incidents?")) return;

  try {
    appendAuditLine("contain", "Executing emergency SOAR containment across all active host incidents...");
    const res = await fetch("/api/contain-all", { method: "POST" });
    const data = await res.json();

    showModal(`
      <div class="mb-3">
        <div class="fw-bold text-white mb-1">Emergency Containment Complete</div>
        <p class="text-secondary small mb-2">Executed automated isolation across ${data.contained_count} threat vectors:</p>
        <ul class="text-success small mb-0 ps-3">
          ${data.summary.map(s => `<li class="mb-1">${s}</li>`).join('')}
        </ul>
      </div>
      <div class="text-primary small fw-semibold">Endpoint security baseline restored.</div>
    `);
    fetchStatusAndData();
  } catch (err) {
    console.error("Contain all failed", err);
  }
}

// Adversary Simulation
async function triggerScenario(scenario) {
  try {
    appendAuditLine("sim", `Simulating threat scenario: ${scenario}...`);
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
  btn.innerHTML = `<span class="spinner-border spinner-border-sm me-1" role="status" aria-hidden="true"></span> <span>Scanning Host...</span>`;

  try {
    appendAuditLine("scan", `Initiated live host scan across processes, sockets, and persistence mechanisms...`);
    const res = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ mode: mode, scenario: null }),
    });
    const data = await res.json();
    appendAuditLine("scan", `Harvested ${data.signal_count} telemetry signals across ${data.entity_count} entities.`);
    fetchStatusAndData();
  } catch (e) {
    console.error("Scan error", e);
  } finally {
    btn.disabled = false;
    btn.innerHTML = `<i class="bi bi-lightning-charge-fill me-1"></i> <span>Run Host Scan</span>`;
  }
}

// Load Audit Logs
async function loadAuditLogs() {
  try {
    const res = await fetch("/api/audit-log");
    const audits = await res.json();
    const terminal = document.getElementById("auditOutput");

    if (!audits || audits.length === 0) {
      terminal.innerHTML = `<div class="text-secondary small">// No historical audit records logged yet.</div>`;
      return;
    }

    terminal.innerHTML = audits.map(a => `
      <div class="audit-row font-mono small d-flex flex-wrap gap-2 align-items-baseline">
        <span class="text-secondary">[${a.timestamp.substring(11, 19)}]</span>
        <span class="badge text-bg-danger-subtle text-danger border border-danger-subtle font-mono">${a.action}</span>
        <span class="text-primary">${a.incident_id}</span>
        <span class="text-white">— ${a.details}</span>
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
  div.className = "audit-row font-mono small d-flex flex-wrap gap-2 align-items-baseline";

  let badgeColor = "text-bg-warning-subtle text-warning border border-warning-subtle";
  if (tag === "contain") badgeColor = "text-bg-danger-subtle text-danger border border-danger-subtle";
  if (tag === "system") badgeColor = "text-bg-success-subtle text-success border border-success-subtle";
  if (tag === "scan") badgeColor = "text-bg-info-subtle text-info border border-info-subtle";
  if (tag === "sim") badgeColor = "text-bg-primary-subtle text-primary border border-primary-subtle";

  div.innerHTML = `<span class="text-secondary">[${time}]</span> <span class="badge ${badgeColor} font-mono">${tag.toUpperCase()}</span> <span class="text-white">${msg}</span>`;
  terminal.prepend(div);
}

// Modal handling
function showModal(content) {
  document.getElementById("modalContent").innerHTML = content;
  const modalElem = document.getElementById("containmentModal");
  if (window.bootstrap && bootstrap.Modal) {
    const modalInstance = bootstrap.Modal.getOrCreateInstance(modalElem);
    modalInstance.show();
  } else {
    modalElem.classList.add("show");
    modalElem.style.display = "block";
  }
}

function closeModal() {
  const modalElem = document.getElementById("containmentModal");
  if (window.bootstrap && bootstrap.Modal) {
    const modalInstance = bootstrap.Modal.getOrCreateInstance(modalElem);
    modalInstance.hide();
  } else {
    modalElem.classList.remove("show");
    modalElem.style.display = "none";
  }
}

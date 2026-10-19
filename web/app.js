/* ═══════════════════════════════════════════════════════
   Core Defense — Nodal Diagnostic Console & Pre-Flight Workstation
   ═══════════════════════════════════════════════════════
   Dual-surface workstation controller:
   - Physical Network Base Graph (Cartographer)
   - Live Telemetry & Pre-Flight Posture Synchronization
   - Interactive Mermaid AST Rendering & SVG Pan/Zoom
   - Real-Time Investigation Stream & Deterministic Receipts
   - Resilient Payload Extraction & Export
   ═══════════════════════════════════════════════════════ */

// Initialize Mermaid with dark theme matching the console
if (typeof mermaid !== 'undefined') {
    mermaid.initialize({
        startOnLoad: false,
        theme: 'base',
        securityLevel: 'loose',
        themeVariables: {
            primaryColor: 'transparent',
            primaryTextColor: '#E0E0E0',
            primaryBorderColor: '#333',
            lineColor: '#666',
            secondaryColor: '#1A1A1A',
            tertiaryColor: '#050505',
            nodeBorder: '#333',
            mainBkg: '#0A0A0A',
            clusterBkg: 'rgba(255,255,255,0.02)',
            clusterBorder: '#222',
            fontSize: '13px',
            fontFamily: 'Google Sans, Google Sans Text, Roboto, -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif'
        }
    });
}

const STORAGE_KEY = 'nodal_history';
const MAX_HISTORY = 50;

// Pan & Zoom instance tracking
let panZoomInstance = null;
let currentRawMarkdown = '';
let lastTraceId = null;
let lastReceipts = [];

// Centralized State Store
const state = {
    devices: [],
    device: 'all',
    busy: false,
};

let busy = false;
let currentFilter = 'all';
let currentMode = 'diagnostic';

// ═══════════════════════════════════════════════════════
// Initialization
// ═══════════════════════════════════════════════════════

document.addEventListener('DOMContentLoaded', () => {
    window.onAppUnlocked = () => unlockApp();
    bindLogin();
    bindSetup();
    bindForm();
    bindTextarea();
    bindKeyboardShortcuts();
    checkHealth();
    bindGeminiFramework();
    bindModeSelector();
    bindCanvasControls();
    bindResizeHandle();

    // Check if already logged in (sessionStorage or cross-tab localStorage)
    const key = getAuthKey();
    if (key) {
        verifyKey(key).then(valid => {
            if (valid) {
                setAuthKey(key);
                unlockApp();
            } else {
                clearAuthKey();
            }
        });
    }
});

// ═══════════════════════════════════════════════════════
// Health Check & Fleet Devices
// ═══════════════════════════════════════════════════════

function checkHealth() {
    return CoreDefense.checkHealth();
}

function loadDevices() {
    authFetch('/api/devices')
    .then(r => r.json())
    .then(data => {
        const firewalls = data.firewalls || {};
        const deviceNames = Object.keys(firewalls);
        deviceNames.forEach(d => {
            if (!state.devices.includes(d)) state.devices.push(d);
        });
        updateDeviceSelect();
    })
    .catch(err => {
        console.warn('[NODAL] Device load error:', err);
    });
}

function updateDeviceSelect() {
    const select = document.getElementById('deviceFilter');
    if (!select) return;

    const currentVal = select.value;
    select.innerHTML = '';

    if (state.devices.length === 0) {
        const opt = document.createElement('option');
        opt.value = 'fw-hq';
        opt.textContent = 'fw-hq (192.168.1.254)';
        select.appendChild(opt);
    } else {
        state.devices.forEach(d => {
            const opt = document.createElement('option');
            opt.value = d;
            opt.textContent = d;
            select.appendChild(opt);
        });
    }

    if (currentVal && Array.from(select.options).some(o => o.value === currentVal)) {
        select.value = currentVal;
    }
}

// ═══════════════════════════════════════════════════════
// Authentication & Setup Wizard Handlers
// ═══════════════════════════════════════════════════════

function verifyKey(key) {
    return fetch('/api/health', {
        headers: { 'X-API-Key': key }
    })
    .then(r => r.ok)
    .catch(() => false);
}

function bindLogin() {
    CoreDefense.bindLogin({
        onSuccess: () => unlockApp()
    });
}

function unlockApp() {
    const loginOverlay = document.getElementById('loginOverlay');
    if (loginOverlay) loginOverlay.style.display = 'none';
    const setupOverlay = document.getElementById('setupOverlay');
    if (setupOverlay) setupOverlay.style.display = 'none';
    const dashboard = document.getElementById('dashboard');
    if (dashboard) dashboard.style.display = 'flex';

    // Load fleet devices, real-time telemetry & pre-flight Nodal Base Graph
    loadDevices();
    fetchTelemetry();
    loadPreflightGraph();
}

function bindSetup() {
    CoreDefense.bindSetup({
        onProceed: () => unlockApp()
    });
}


function bindKeyboardShortcuts() {
    document.addEventListener('keydown', (e) => {
        const isInputFocused = document.activeElement && document.activeElement.tagName === 'TEXTAREA';
        if (e.key === '/' && !isInputFocused) {
            e.preventDefault();
            const input = document.getElementById('input');
            if (input) {
                input.focus();
                input.select();
            }
        }
        if (e.key === 'Escape') {
            closeHitlTextPopup();
        }
    });
}

// ═══════════════════════════════════════════════════════
// Toast Notification Utility
// ═══════════════════════════════════════════════════════

function showToast(message, type = 'info', duration = 3500) {
    return CoreDefense.showToast(message, type, duration);
}

// ═══════════════════════════════════════════════════════
// Pre-Flight Digital Twin & Topology Compiler
// ═══════════════════════════════════════════════════════

async function loadPreflightGraph() {
    const deviceSelect = document.getElementById('deviceFilter');
    const selectedDevice = deviceSelect ? deviceSelect.value : 'default';

    try {
        const res = await authFetch(`/api/cartographer/base-graph?device=${encodeURIComponent(selectedDevice)}`);
        if (!res.ok) return;
        const data = await res.json();

        updatePostureBanner(data.metadata ? data.metadata.posture : null);

        if (data && data.nodes && data.nodes.length > 0) {
            const mermaidCode = compileBaseGraphToMermaid(data);
            await renderAgentDiagram(mermaidCode, null, 0, 0);
        }
    } catch (err) {
        console.warn('[NODAL] Failed to load pre-flight base graph:', err);
    }
}

function updatePostureBanner(posture) {
    if (!posture) return;

    const valPanos = document.getElementById('valPanos');
    const chipPanos = document.getElementById('chipPanos');
    if (valPanos) {
        valPanos.textContent = posture.panos_version ? `${posture.panos_version}${posture.is_eol ? ' (EOL)' : ''}` : 'Unknown';
        if (chipPanos && posture.is_eol) chipPanos.className = 'posture-chip chip-danger';
        else if (chipPanos) chipPanos.className = 'posture-chip chip-success';
    }

    const valThreat = document.getElementById('valThreat');
    const chipThreat = document.getElementById('chipThreat');
    if (valThreat) {
        if (posture.threat_stale_days !== null && posture.threat_stale_days !== undefined) {
            valThreat.textContent = `${posture.threat_stale_days}d stale`;
            if (chipThreat && posture.is_threat_stale) chipThreat.className = 'posture-chip chip-warning';
            else if (chipThreat) chipThreat.className = 'posture-chip chip-success';
        } else {
            valThreat.textContent = 'Current';
            if (chipThreat) chipThreat.className = 'posture-chip chip-success';
        }
    }

    const valOverlap = document.getElementById('valOverlap');
    const chipOverlap = document.getElementById('chipOverlap');
    if (valOverlap) {
        if (posture.mgmt_dataplane_overlap && posture.overlap_interfaces && posture.overlap_interfaces.length > 0) {
            valOverlap.textContent = `${posture.overlap_interfaces.join(', ')} Overlap`;
            if (chipOverlap) chipOverlap.className = 'posture-chip chip-danger';
        } else {
            valOverlap.textContent = 'Isolated';
            if (chipOverlap) chipOverlap.className = 'posture-chip chip-success';
        }
    }

    const valLicenses = document.getElementById('valLicenses');
    const chipLicenses = document.getElementById('chipLicenses');
    if (valLicenses) {
        const expiredCount = posture.expired_licenses ? posture.expired_licenses.length : 0;
        valLicenses.textContent = `${expiredCount} Expired`;
        if (chipLicenses) {
            chipLicenses.className = expiredCount > 0 ? 'posture-chip chip-warning' : 'posture-chip chip-success';
        }
    }
}

function compileBaseGraphToMermaid(graph) {
    if (!graph || !graph.nodes || graph.nodes.length === 0) {
        return 'graph LR\n  FW["PAN-OS Firewall"]';
    }
    const lines = ['graph LR'];
    const nodes = graph.nodes;
    const edges = graph.edges || [];

    const zones = nodes.filter(n => n.type === 'zone');
    const subnets = nodes.filter(n => n.type === 'subnet');

    zones.forEach(z => {
        const safeZId = z.id.replace(/[^a-zA-Z0-9_]/g, '_');
        const cleanZName = z.label.replace(/^Zone:\s*/, '');
        lines.push(`  subgraph ${safeZId} ["Zone: ${cleanZName}"]`);

        const containedIds = edges
            .filter(e => e.source === z.id && e.label === 'contains')
            .map(e => e.target);

        containedIds.forEach(sId => {
            const sub = subnets.find(s => s.id === sId);
            if (sub) {
                const safeSId = sub.id.replace(/[^a-zA-Z0-9_]/g, '_');
                const mgmtSuffix = sub.mgmt_profile ? `<br>[mgmt: ${sub.mgmt_profile}]` : '';
                lines.push(`    ${safeSId}["${sub.label}${mgmtSuffix}"]`);
            }
        });
        lines.push('  end');
    });

    const fwNode = nodes.find(n => n.type === 'firewall');
    const fwLabel = fwNode ? fwNode.label : 'PAN-OS Firewall';
    lines.push(`  firewall["${fwLabel}"]`);

    zones.forEach(z => {
        const safeZId = z.id.replace(/[^a-zA-Z0-9_]/g, '_');
        lines.push(`  firewall -->|routes| ${safeZId}`);
    });

    const mgtNode = nodes.find(n => n.type === 'management_interface');
    if (mgtNode) {
        lines.push(`  interface_mgmt["${mgtNode.label}"]`);
        lines.push('  firewall -->|managed_by| interface_mgmt');
    }

    edges.filter(e => e.label === 'overlaps_subnet').forEach(e => {
        const safeTarget = e.target.replace(/[^a-zA-Z0-9_]/g, '_');
        lines.push(`  interface_mgmt -.->|OVERLAP WARNING| ${safeTarget}`);
    });

    return lines.join('\n');
}

function sanitizeMermaid(code) {
    if (!code) return 'graph TD\n  Start[No Topology Specified]';
    let s = code.trim();

    if (!s.startsWith('graph ') && !s.startsWith('flowchart ')) {
        s = 'graph TD\n' + s;
    }

    s = s.replace(/(\w+)\[([^"\]]+)\]/g, (match, id, label) => {
        if (label.includes('(') || label.includes(')') || label.includes(':') || label.includes('/') || label.includes('>')) {
            return `${id}["${label.replace(/"/g, "'")}"]`;
        }
        return match;
    });

    // Sanitize edge labels: convert parentheses inside |...| to hyphens
    s = s.replace(/\|([^|\n]+)\|/g, (match, label) => {
        return `|${label.replace(/\(/g, ' - ').replace(/\)/g, '').trim()}|`;
    });

    return s;
}

async function renderAgentDiagram(markdown, agentLogMessage, threats = 0, drops = 0) {
    const diagramContainer = document.getElementById('diagramContainer');
    const mermaidTarget = document.getElementById('mermaidTarget');
    const emptyState = document.getElementById('emptyState');
    const canvasError = document.getElementById('canvasError');
    const statThreats = document.getElementById('statThreats');
    const statDrops = document.getElementById('statDrops');

    if (!diagramContainer || !mermaidTarget) return;

    if (statThreats && threats !== undefined) statThreats.textContent = `Threats: ${threats}`;
    if (statDrops && drops !== undefined) statDrops.textContent = `Drops: ${drops}`;

    currentRawMarkdown = markdown;
    const sanitizedMarkdown = sanitizeMermaid(markdown);

    if (panZoomInstance) {
        try {
            panZoomInstance.destroy();
        } catch (_) {}
        panZoomInstance = null;
    }

    if (emptyState) emptyState.style.display = 'none';
    diagramContainer.style.display = 'flex';
    if (canvasError) canvasError.style.display = 'none';

    try {
        const id = 'graph-' + Date.now();
        mermaidTarget.innerHTML = `<div class="mermaid" id="${id}"></div>`;

        if (typeof mermaid !== 'undefined') {
            const { svg } = await mermaid.render(id, sanitizedMarkdown);
            mermaidTarget.innerHTML = svg;

            const svgElement = mermaidTarget.querySelector('svg');
            if (svgElement) {
                svgElement.removeAttribute('style');
                svgElement.style.width = '100%';
                svgElement.style.height = '100%';
                svgElement.style.maxWidth = '100%';
                svgElement.style.maxHeight = '100%';
                svgElement.style.display = 'block';

                if (typeof svgPanZoom === 'function') {
                    panZoomInstance = svgPanZoom(svgElement, {
                        zoomEnabled: true,
                        controlIconsEnabled: false,
                        fit: true,
                        center: true,
                        minZoom: 0.1,
                        maxZoom: 15
                    });

                    setTimeout(() => {
                        if (panZoomInstance) {
                            try {
                                panZoomInstance.resize();
                                panZoomInstance.fit();
                                panZoomInstance.center();
                            } catch (_) {}
                        }
                    }, 100);
                }
            }
        }
    } catch (err) {
        console.warn('[MERMAID] Render error:', err);
        if (canvasError) {
            canvasError.style.display = 'flex';
            const msgElem = document.getElementById('canvasErrorMsg');
            if (msgElem) msgElem.textContent = 'Topology rendering error. Click View Spec to inspect.';
            const rawBox = document.getElementById('rawSpecBox');
            if (rawBox) rawBox.textContent = sanitizedMarkdown;
        }
    }
}

function extractMermaidDirect(raw) {
    if (!raw) return null;
    const lines = raw.split('\n');
    let capturing = false;
    let mermaidLines = [];

    for (const line of lines) {
        const trimmed = line.trim();
        if (trimmed.startsWith('graph ') || trimmed.startsWith('flowchart ')) {
            capturing = true;
        }
        if (capturing) {
            if (trimmed.startsWith('```') && mermaidLines.length > 0) break;
            mermaidLines.push(line);
        }
    }

    return mermaidLines.length > 0 ? mermaidLines.join('\n') : null;
}

function extractRangePayload(raw) {
    if (!raw) return null;

    // 1. Search for code-fenced mermaid block first (e.g. Traversal Path Analysis)
    const mermaidBlock = raw.match(/```(?:mermaid)?\s*([\s\S]*?)```/);
    if (mermaidBlock && (mermaidBlock[1].includes('graph ') || mermaidBlock[1].includes('flowchart '))) {
        return {
            mermaid: mermaidBlock[1].trim(),
            message: 'Extracted topology from code fence.',
            threats: 1,
            drops: 0
        };
    }

    // 2. Direct line-by-line fallback if code fence missing but graph/flowchart present
    if (raw.includes('graph ') || raw.includes('flowchart ')) {
        const directMermaid = extractMermaidDirect(raw);
        if (directMermaid) {
            return {
                mermaid: directMermaid,
                message: 'Extracted topology from raw stream.',
                threats: 1,
                drops: 0
            };
        }
    }

    // 3. Structured JSON payload (used by range simulations / API macros)
    const firstBrace = raw.indexOf('{');
    const lastBrace = raw.lastIndexOf('}');
    if (firstBrace >= 0 && lastBrace > firstBrace) {
        const candidate = raw.slice(firstBrace, lastBrace + 1);
        try {
            const parsed = JSON.parse(candidate);
            if (parsed && (parsed.mermaid || parsed.nodes)) {
                return parsed;
            }
        } catch (err) {
            try {
                const repaired = candidate.replace(/[\u0000-\u001F]+/g, (match) => {
                    if (match === '\n') return '\\n';
                    if (match === '\r') return '\\r';
                    if (match === '\t') return '\\t';
                    return '';
                });
                const parsed = JSON.parse(repaired);
                if (parsed && (parsed.mermaid || parsed.nodes)) {
                    return parsed;
                }
            } catch (_) {}
        }
    }

    return null;
}

// ═══════════════════════════════════════════════════════
// Form Input & Streaming Investigation Execution
// ═══════════════════════════════════════════════════════

function bindForm() {
    const form = document.getElementById('chatForm');
    if (!form) return;
    form.addEventListener('submit', (e) => {
        e.preventDefault();
        const input = document.getElementById('input');
        if (!input) return;
        const text = input.value.trim();
        if (!text || busy) return;
        sendMessage(text);
    });
}

function bindTextarea() {
    const input = document.getElementById('input');
    if (!input) return;

    input.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            const text = input.value.trim();
            if (text && !busy) {
                sendMessage(text);
            }
        }
    });

    input.addEventListener('input', () => {
        input.style.height = 'auto';
        input.style.height = Math.min(input.scrollHeight, 180) + 'px';
        updateSendBtnState();
    });
}

function sendMessage(text) {
    if (busy) return;
    busy = true;
    updateSendBtnState();

    const existingPrompt = document.querySelector('.post-report-prompt');
    if (existingPrompt) existingPrompt.remove();

    const input = document.getElementById('input');
    if (input) {
        input.value = '';
        input.style.height = 'auto';
    }

    const hero = document.getElementById('chatHero');
    if (hero) hero.style.display = 'none';

    addMsg('user', text);
    if (currentMode === 'advisory') {
        showStatus('Consulting PAN-OS knowledge base and synthesizing architecture advisory...');
    } else {
        showStatus('Compiling nodal telemetry and evaluating policy paths...');
    }

    let currentReceipts = [];
    let currentTraceId = '';

    const deviceSelect = document.getElementById('deviceFilter');
    const selectedDevice = deviceSelect ? deviceSelect.value : 'default';

    authFetch('/api/chat', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            message: text,
            device: selectedDevice,
            mode: currentMode
        })
    })
    .then(res => {
        if (!res.ok) {
            return res.json().catch(() => ({})).then(errData => {
                const msg = errData.error || errData.detail || `HTTP ${res.status}: ${res.statusText}`;
                finish(`[ERROR] ${msg}`, [], '', currentMode);
            });
        }
        const reader = res.body.getReader();
        const decoder = new TextDecoder();
        let buf = '';

        function read() {
            reader.read().then(({ done, value }) => {
                if (done) return finish('', currentReceipts, currentTraceId, currentMode);

                buf += decoder.decode(value, { stream: true });
                const lines = buf.split('\n');
                buf = lines.pop();

                for (const line of lines) {
                    if (!line.startsWith('data: ')) continue;
                    try {
                        const d = JSON.parse(line.slice(6));
                        if (d.type === 'status') {
                            updateStatus(d.content);
                        } else if (d.type === 'receipts') {
                            currentReceipts = d.content || [];
                            lastReceipts = currentReceipts;
                            if (d.trace_id) {
                                currentTraceId = d.trace_id;
                                lastTraceId = d.trace_id;
                            }
                        } else if (d.type === 'response') {
                            if (d.trace_id) {
                                currentTraceId = d.trace_id;
                                lastTraceId = d.trace_id;
                            }
                            return finish(d.content, currentReceipts, currentTraceId, d.mode || currentMode);
                        } else if (d.type === 'done') {
                            if (d.trace_id) {
                                currentTraceId = d.trace_id;
                                lastTraceId = d.trace_id;
                            }
                        } else if (d.type === 'error') {
                            return finish('[ERROR] ' + d.content, [], currentTraceId, currentMode);
                        }
                    } catch (_) {}
                }
                read();
            });
        }
        read();
    })
    .catch(err => finish('[ERROR] Connection error: ' + err.message, [], '', currentMode));
}

function finish(text, receipts = [], traceId = '', mode = currentMode) {
    removeStatus();
    if (text) {
        const payload = extractRangePayload(text);
        if (payload && payload.mermaid) {
            renderAgentDiagram(
                payload.mermaid,
                payload.message || 'Generated semantic topology map.',
                payload.threats ?? 0,
                payload.drops ?? 0
            );
        }
        addMsg('agent', text, { receipts, traceId, mode });
        if (!text.startsWith('[ERROR]')) {
            renderPostReportPrompt(mode);
        }
    }
    busy = false;
    updateSendBtnState();
    const input = document.getElementById('input');
    if (input) input.focus();
}

// ═══════════════════════════════════════════════════════
// Status Line & Cognitive Drift
// ═══════════════════════════════════════════════════════

function showStatus(text) {
    removeStatus();
    const div = document.createElement('div');
    div.className = 'status-line';
    div.id = 'statusLine';
    div.innerHTML = `<div class="status-spinner"></div><span class="status-label">${esc(text)}</span>`;
    const messages = document.getElementById('messages');
    if (messages) messages.appendChild(div);
    scrollChatToBottom();
}

function updateStatus(text) {
    const label = document.querySelector('#statusLine .status-label');
    if (label) {
        label.textContent = text;
    } else {
        showStatus(text);
    }
    scrollChatToBottom();
}

function removeStatus() {
    const el = document.getElementById('statusLine');
    if (el) el.remove();
}

// ═══════════════════════════════════════════════════════
// Message Rendering & Evidence Badging
// ═══════════════════════════════════════════════════════

function addMsg(role, text, metadata = {}) {
    const entry = document.createElement('div');
    let typeClass = 'msg-agent';
    let speakerPrefix = 'DIAGNOSTICS';
    if (role === 'user') {
        typeClass = 'msg-user';
        speakerPrefix = 'OPERATOR';
    } else if (text && text.startsWith('[ERROR]')) {
        typeClass = 'msg-crit';
        speakerPrefix = 'SYSTEM ERROR';
    } else if (metadata.mode === 'advisory') {
        typeClass = 'msg-agent msg-advisory';
        speakerPrefix = 'ADVISOR';
    }

    entry.className = `msg ${typeClass}`;

    let receiptsHtml = '';
    const receipts = metadata.receipts || [];
    const traceId = metadata.traceId || '';
    if (receipts.length > 0) {
        const totalMs = receipts.reduce((acc, r) => acc + (r.duration_ms || 0), 0);
        receiptsHtml = `
            <div class="receipts-container" data-trace-id="${esc(traceId)}">
                <div class="receipts-header">
                    <button class="receipts-toggle-btn" onclick="toggleReceiptsDrawer(this)" aria-expanded="false" title="Inspect raw PAN-OS CLI execution receipts">
                        <svg class="receipts-icon" viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2">
                            <polyline points="4 17 10 11 4 5"></polyline>
                            <line x1="12" y1="19" x2="20" y2="19"></line>
                        </svg>
                        <span class="receipts-count">${receipts.length} CLI Execution Receipts</span>
                        <span class="receipts-duration-badge">${totalMs.toFixed(1)}ms</span>
                        <span class="receipts-chevron">▼</span>
                    </button>
                    ${traceId ? `
                    <button class="export-gdoc-btn" onclick="exportInvestigationToDoc('${esc(traceId)}', this)" title="Download formatted incident diagnosis report (.md)">
                        <svg class="gdoc-icon" viewBox="0 0 24 24" width="14" height="14" fill="currentColor">
                            <path d="M14 2H6c-1.1 0-2 .9-2 2v16c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V8l-6-6zM6 20V4h7v5h5v11H6z"/>
                        </svg>
                        <span>Export (.md)</span>
                    </button>` : ''}
                </div>
                <div class="receipts-drawer" style="display: none;">
                    <div class="receipts-summary-bar">Deterministic pan-os-python CLI / API Audit Trail</div>
                    ${receipts.map((r, idx) => `
                        <div class="receipt-card">
                            <div class="receipt-card-header">
                                <span class="receipt-step">#${idx + 1}</span>
                                <code class="receipt-tool-name">${esc(r.tool || 'unknown')}</code>
                                <span class="receipt-ms">${(r.duration_ms || 0).toFixed(1)}ms</span>
                                <span class="receipt-status-pill status-${esc(r.status || 'success')}">${esc(r.status || 'OK')}</span>
                            </div>
                            <div class="receipt-args-row">
                                <span class="receipt-label">Args:</span>
                                <code class="receipt-args-code">${esc(JSON.stringify(r.args || {}))}</code>
                            </div>
                            <details class="receipt-raw-details">
                                <summary>Raw Output (${(r.raw_output || r.output_snippet || '').length} bytes)</summary>
                                <pre class="receipt-raw-pre"><code>${esc(r.raw_output || r.output_snippet || 'No output captured')}</code></pre>
                            </details>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
    }

    entry.innerHTML = `
        <div class="msg-header">
            <span class="msg-author">${speakerPrefix}</span>
        </div>
        <div class="msg-content msg-body">${formatMsgText(text)}</div>
        ${receiptsHtml}
    `;

    const messages = document.getElementById('messages');
    if (messages) messages.appendChild(entry);
    scrollChatToBottom();
}

function formatMsgText(t) {
    if (!t) return '';
    let s = esc(t);

    // Code blocks
    s = s.replace(/```(\w*)\n([\s\S]*?)```/g, (_, lang, code) => {
        return `<pre class="code-block"><code class="lang-${lang}">${code}</code></pre>`;
    });

    // Inline code
    s = s.replace(/`([^`]+)`/g, '<code>$1</code>');

    // Bold text
    s = s.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');

    // Evidence status chips
    s = s.replace(/\[VERIFIED\]/g, '<span class="posture-chip chip-success">[VERIFIED]</span>');
    s = s.replace(/\[UNVERIFIED\]/g, '<span class="posture-chip chip-danger">[UNVERIFIED]</span>');
    s = s.replace(/\[UNCITED\]/g, '<span class="posture-chip chip-warning">[UNCITED]</span>');

    // Newlines to breaks
    s = s.replace(/\n/g, '<br>');

    return s;
}

function scrollChatToBottom() {
    const m = document.getElementById('messages');
    if (!m) return;
    requestAnimationFrame(() => {
        m.scrollTop = m.scrollHeight;
        setTimeout(() => {
            if (m) m.scrollTop = m.scrollHeight;
        }, 60);
    });
}

function esc(t) {
    const d = document.createElement('div');
    d.textContent = t;
    return d.innerHTML;
}

function toggleReceiptsDrawer(btn) {
    const container = btn.closest('.receipts-container');
    if (!container) return;
    const drawer = container.querySelector('.receipts-drawer');
    const chevron = btn.querySelector('.receipts-chevron');
    if (!drawer) return;

    const isHidden = drawer.style.display === 'none';
    drawer.style.display = isHidden ? 'block' : 'none';
    btn.setAttribute('aria-expanded', isHidden ? 'true' : 'false');
    if (chevron) {
        chevron.style.transform = isHidden ? 'rotate(180deg)' : 'rotate(0deg)';
    }
    scrollChatToBottom();
}

async function exportInvestigationToDoc(traceId, btn) {
    if (!traceId) return;
    const originalHtml = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = `<span>Exporting...</span>`;

    try {
        const res = await authFetch('/api/export/markdown', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ trace_id: traceId })
        });

        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.error || `HTTP ${res.status}`);
        }

        const data = await res.json();
        const blob = new Blob([data.markdown || ''], { type: 'text/markdown;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `PANOS_Investigation_${traceId}.md`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        btn.innerHTML = `Saved .md`;
        btn.classList.add('btn-success');
    } catch (e) {
        showToast('Export failed: ' + e.message, 'error');
        btn.innerHTML = `Failed`;
        btn.classList.add('btn-error');
    } finally {
        setTimeout(() => {
            btn.disabled = false;
            btn.innerHTML = originalHtml;
            btn.classList.remove('btn-success', 'btn-error');
        }, 4000);
    }
}

// ═══════════════════════════════════════════════════════
// Canvas Controls & Workstation Binding
// ═══════════════════════════════════════════════════════

function bindGeminiFramework() {
    const newChatBtn = document.getElementById('newChatBtn');
    if (newChatBtn) {
        newChatBtn.addEventListener('click', resetToZeroState);
    }

    const deviceFilter = document.getElementById('deviceFilter');
    if (deviceFilter) {
        deviceFilter.addEventListener('change', () => {
            fetchTelemetry(deviceFilter.value);
            loadPreflightGraph();
        });
    }

    updateSendBtnState();
}

function resetToZeroState() {
    const existingPrompt = document.querySelector('.post-report-prompt');
    if (existingPrompt) existingPrompt.remove();

    const msgs = document.getElementById('messages');
    if (msgs) {
        msgs.innerHTML = `
            <div class="gemini-hero" id="chatHero">
                <div class="gemini-hero-greeting">
                    <span class="gemini-gradient-text">Nodal Diagnostic Workstation</span>
                </div>
                <p class="gemini-hero-subtitle">Pre-flight digital twin compiled. Evaluate attack vectors, test routing FIB paths, or audit security policies.</p>
            </div>
        `;
    }
    setMode('diagnostic');
    const input = document.getElementById('input');
    if (input) {
        input.value = '';
        input.style.height = 'auto';
        input.focus();
    }
    updateSendBtnState();
    loadPreflightGraph();
    showToast('Workstation reset to baseline', 'info');
}

function bindModeSelector() {
    const btnDiag = document.getElementById('btnModeDiag');
    const btnAdvisor = document.getElementById('btnModeAdvisor');

    if (btnDiag) {
        btnDiag.addEventListener('click', () => {
            setMode('diagnostic');
            showToast('Diagnostic Engine activated (Live Telemetry)', 'info');
        });
    }
    if (btnAdvisor) {
        btnAdvisor.addEventListener('click', () => {
            setMode('advisory');
            showToast('Architecture Advisor activated (Knowledge Base Grounded)', 'info');
        });
    }
}

function setMode(mode) {
    if (mode !== 'diagnostic' && mode !== 'advisory') mode = 'diagnostic';
    currentMode = mode;

    const btnDiag = document.getElementById('btnModeDiag');
    const btnAdvisor = document.getElementById('btnModeAdvisor');
    const input = document.getElementById('input');
    const disclaimer = document.querySelector('.gemini-input-disclaimer');

    if (btnDiag) {
        btnDiag.classList.toggle('active', mode === 'diagnostic');
    }
    if (btnAdvisor) {
        btnAdvisor.classList.toggle('active', mode === 'advisory');
    }

    if (input) {
        if (mode === 'advisory') {
            input.placeholder = 'Ask architectural questions, design migration strategy, or consult best practices...';
        } else {
            input.placeholder = 'Simulate attack vector, verify FIB route, or audit policy...';
        }
    }

    if (disclaimer) {
        if (mode === 'advisory') {
            disclaimer.innerHTML = 'Architecture Advisor &bull; Knowledge Base Grounded &bull; Physical Tools Quarantined';
        } else {
            disclaimer.innerHTML = 'PAN-OS Grounded &bull; Zero-Turn Digital Twin &bull; Evidence Engine Verified';
        }
    }
}

function renderPostReportPrompt(lastMode) {
    const existing = document.querySelector('.post-report-prompt');
    if (existing) existing.remove();

    const messages = document.getElementById('messages');
    if (!messages) return;

    const promptDiv = document.createElement('div');
    promptDiv.className = 'post-report-prompt';

    const isAdvisor = lastMode === 'advisory';
    promptDiv.innerHTML = `
        <span class="post-report-label">Next Action:</span>
        <button type="button" class="action-chip chip-diag" id="chipContinueDiag" title="${isAdvisor ? 'Switch to live telemetry diagnostics' : 'Continue live telemetry investigation'}">
            <span class="mode-led led-green"></span> ${isAdvisor ? 'Switch to Diagnostic Mode' : 'Continue Diagnosis'}
        </button>
        <button type="button" class="action-chip chip-advisor" id="chipSwitchAdvisor" title="${isAdvisor ? 'Continue architectural consultation' : 'Switch to Architecture Advisor with Knowledge Base'}">
            <span class="mode-led led-blue"></span> ${isAdvisor ? 'Continue Consultation' : 'Switch to Advisor Mode'}
        </button>
        <button type="button" class="action-chip chip-stop" id="chipStopSession" title="Clear diagnostic session">
            Stop &amp; Clear
        </button>
    `;

    messages.appendChild(promptDiv);
    scrollChatToBottom();

    const chipDiag = document.getElementById('chipContinueDiag');
    const chipAdv = document.getElementById('chipSwitchAdvisor');
    const chipStop = document.getElementById('chipStopSession');

    if (chipDiag) {
        chipDiag.addEventListener('click', () => {
            setMode('diagnostic');
            showToast(isAdvisor ? 'Switched to Diagnostic Engine' : 'Ready for further diagnostic queries', 'info');
            const input = document.getElementById('input');
            if (input) input.focus();
            promptDiv.remove();
        });
    }

    if (chipAdv) {
        chipAdv.addEventListener('click', () => {
            setMode('advisory');
            showToast(isAdvisor ? 'Continuing Advisor consultation' : 'Switched to Architecture Advisor mode', 'info');
            const input = document.getElementById('input');
            if (input) input.focus();
            promptDiv.remove();
        });
    }

    if (chipStop) {
        chipStop.addEventListener('click', () => {
            resetToZeroState();
        });
    }
}

function updateSendBtnState() {
    const input = document.getElementById('input');
    const sendBtn = document.getElementById('sendBtn');
    if (!input || !sendBtn) return;
    const hasText = input.value.trim().length > 0;
    sendBtn.disabled = !hasText || busy;
}

function bindCanvasControls() {
    const btnZoomIn = document.getElementById('btnZoomIn');
    const btnZoomOut = document.getElementById('btnZoomOut');
    const btnZoomReset = document.getElementById('btnZoomReset');
    const btnCanvasFullscreen = document.getElementById('btnCanvasFullscreen');
    const btnClearTerminal = document.getElementById('btnClearTerminal');
    const btnExportSimulation = document.getElementById('btnExportSimulation');
    const btnViewSpec = document.getElementById('btnViewSpec');
    const rawSpecBox = document.getElementById('rawSpecBox');

    if (btnZoomIn) {
        btnZoomIn.addEventListener('click', () => {
            if (panZoomInstance) panZoomInstance.zoomIn();
        });
    }
    if (btnZoomOut) {
        btnZoomOut.addEventListener('click', () => {
            if (panZoomInstance) panZoomInstance.zoomOut();
        });
    }
    if (btnZoomReset) {
        btnZoomReset.addEventListener('click', () => {
            if (panZoomInstance) {
                panZoomInstance.reset();
                panZoomInstance.fit();
                panZoomInstance.center();
            }
        });
    }
    const btnBaseTopology = document.getElementById('btnBaseTopology');
    if (btnBaseTopology) {
        btnBaseTopology.addEventListener('click', () => {
            loadPreflightGraph();
            showToast('Restored baseline physical topology.', 2000);
        });
    }
    if (btnCanvasFullscreen) {
        btnCanvasFullscreen.addEventListener('click', () => {
            const canvasPanel = document.getElementById('canvasPanel');
            if (canvasPanel) {
                canvasPanel.classList.toggle('canvas-fullscreen');
            }
        });
    }
    if (btnClearTerminal) {
        btnClearTerminal.addEventListener('click', () => {
            resetToZeroState();
        });
    }
    if (btnExportSimulation) {
        btnExportSimulation.addEventListener('click', () => {
            exportInvestigationToDoc(lastTraceId, btnExportSimulation);
        });
    }
    if (btnViewSpec && rawSpecBox) {
        btnViewSpec.addEventListener('click', () => {
            const isHidden = rawSpecBox.style.display === 'none';
            rawSpecBox.style.display = isHidden ? 'block' : 'none';
            btnViewSpec.textContent = isHidden ? 'Hide Spec' : 'View Spec';
        });
    }
}

function bindResizeHandle() {
    const handle = document.getElementById('rangeResizeHandle');
    const cliPanel = document.getElementById('cliPanel');
    if (!handle || !cliPanel) return;

    let isResizing = false;
    handle.addEventListener('mousedown', () => {
        isResizing = true;
        document.body.style.cursor = 'col-resize';
        document.body.style.userSelect = 'none';
    });

    document.addEventListener('mousemove', (e) => {
        if (!isResizing) return;
        const newWidth = Math.max(340, Math.min(e.clientX, window.innerWidth * 0.75));
        cliPanel.style.width = `${newWidth}px`;
    });

    document.addEventListener('mouseup', () => {
        if (isResizing) {
            isResizing = false;
            document.body.style.cursor = '';
            document.body.style.userSelect = '';
            if (panZoomInstance) {
                try {
                    panZoomInstance.resize();
                    panZoomInstance.fit();
                    panZoomInstance.center();
                } catch (_) {}
            }
        }
    });
}

function fetchTelemetry(device = null) {
    const select = document.getElementById('deviceFilter');
    const dev = device || (select ? select.value : 'default');
    const chip = document.getElementById('perimeterStatusChip');
    const text = document.getElementById('perimeterStatusText');
    if (!text) return;

    authFetch(`/api/telemetry?device=${encodeURIComponent(dev)}`)
    .then(r => r.json())
    .then(d => {
        if (d.success) {
            const sess = (d.active_sessions || 0).toLocaleString();
            const mbps = ((d.throughput_kbps || 0) / 1000).toFixed(1);
            const cpu = (d.mgmt_cpu || 0).toFixed(2);
            text.textContent = `${d.device}: ${sess} sess • ${mbps} Mbps • CPU ${cpu}`;
            if (chip) chip.className = 'perimeter-status-chip nominal';
        } else {
            text.textContent = `${dev}: Standby / No Op Data`;
            if (chip) chip.className = 'perimeter-status-chip warning';
        }
    })
    .catch(() => {
        text.textContent = `${dev}: Telemetry Offline`;
        if (chip) chip.className = 'perimeter-status-chip critical';
    });
}

function openHitlTextPopup() {
    const popup = document.getElementById('hitlTextPopup');
    if (popup) popup.style.display = 'flex';
}

function closeHitlTextPopup() {
    const popup = document.getElementById('hitlTextPopup');
    if (popup) popup.style.display = 'none';
}

function confirmHitlTextOverride() {
    closeHitlTextPopup();
    sendMessage("Execute 'show session all' with operator authorization override");
}

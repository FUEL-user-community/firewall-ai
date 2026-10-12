/* ═══════════════════════════════════════════════════════
   Core Defense — Range Simulator Controller
   ═══════════════════════════════════════════════════════
   Handles: Semantic CLI attack scenarios, multi-firewall
   device selection, Cartographer physical base graph sync,
   resilient JSON/Mermaid AST parsing, interactive SVG
   zoom/pan controls, and diagram error recovery.
   ═══════════════════════════════════════════════════════ */

// Initialize Mermaid with a dark cyber theme matching the SOC console
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

// DOM Elements
const terminal = document.getElementById('terminal');
const cliForm = document.getElementById('cliForm');
const cliInput = document.getElementById('cliInput');
const cliSendBtn = document.getElementById('cliSendBtn');
const diagramContainer = document.getElementById('diagramContainer');
const mermaidTarget = document.getElementById('mermaidTarget');
const emptyState = document.getElementById('emptyState');
const deviceSelect = document.getElementById('deviceSelect');
const btnClearTerminal = document.getElementById('btnClearTerminal');
const btnExportSimulation = document.getElementById('btnExportSimulation');
const canvasError = document.getElementById('canvasError');
const canvasErrorMsg = document.getElementById('canvasErrorMsg');
const btnViewSpec = document.getElementById('btnViewSpec');
const rawSpecBox = document.getElementById('rawSpecBox');

// Pan & Zoom instance tracking
let panZoomInstance = null;
let currentRawMarkdown = '';
let commandCount = 0;
let busy = false;
let lastTraceId = null;

// HTML entity escaper to prevent DOM XSS
function esc(t) {
    if (t === null || t === undefined) return '';
    const d = document.createElement('div');
    d.textContent = String(t);
    return d.innerHTML;
}

// Cross-tab and persistent authentication helper
function getAuthKey() {
    return sessionStorage.getItem('nodal_key') || localStorage.getItem('nodal_key') || '';
}

// Helper to append logs to terminal safely (Gemini Chat Style)
function appendLog(speaker, message, styleClass) {
    if (!terminal) return;
    const time = new Date().toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit' });
    const entry = document.createElement('div');
    
    let typeClass = 'log-type-sys';
    let speakerPrefix = 'SYSTEM';
    if (speaker === 'USER') {
        typeClass = 'log-type-user';
        speakerPrefix = 'YOU';
    } else if (speaker === 'NEO') {
        typeClass = 'log-type-agent';
        speakerPrefix = 'RANGE COPILOT';
    } else if (styleClass && styleClass.includes('crit')) {
        typeClass = 'log-type-crit';
        speakerPrefix = 'ALERT';
    }

    entry.className = `log-entry ${typeClass}`;
    if (speaker === 'USER') {
        entry.innerHTML = `<div class="log-content">${esc(message)}</div>`;
    } else {
        entry.innerHTML = `
            <div class="log-meta">
                <span class="log-speaker-badge">${speakerPrefix}</span>
                <span class="log-time">${time}</span>
            </div>
            <div class="log-content ${styleClass || ''}">${esc(message)}</div>
        `;
    }
    terminal.appendChild(entry);
    terminal.scrollTop = terminal.scrollHeight;
}

// ═══════════════════════════════════════════════════════
// Initialization & Fleet Devices
// ═══════════════════════════════════════════════════════

document.addEventListener('DOMContentLoaded', () => {
    bindLogin();
    bindSetup();
    restoreRangeWidth();
    bindRangeResizeHandle();
    loadFleetDevices();
    bindTerminalActions();
    bindCanvasControls();
    bindErrorViewSpec();
    checkHealth();
});

function checkAuthNotice() {
    appendLog('NEO', 'Simulation engine online. Enter an adversary attack vector or policy bypass scenario to begin.', 'log-agent');
    const key = getAuthKey();
    if (!key) {
        appendLog('SYS', 'Notice: No active passphrase in session. If simulation fails with 401/403, unlock in Diagnostic Console first.', 'log-sys');
    }
}

function loadFleetDevices() {
    const key = getAuthKey();
    fetch('/api/devices', {
        headers: { 'X-API-Key': key }
    })
    .then(r => r.json())
    .then(data => {
        if (!deviceSelect) return;
        const firewalls = data.firewalls || {};
        const names = Object.keys(firewalls);
        const targetNames = names.length > 0 ? names : ['fw-hq'];

        // Check if deviceSelect already matches exactly (Prevents flicker on refresh)
        const currentValues = Array.from(deviceSelect.options).map(o => o.value);
        const isMatch = currentValues.length === targetNames.length &&
            currentValues.every((val, idx) => val === targetNames[idx]);

        if (isMatch) {
            // Already matches static HTML! Zero DOM mutation = ZERO flicker
            return;
        }

        const currentVal = deviceSelect.value;
        const frag = document.createDocumentFragment();
        targetNames.forEach(name => {
            const fw = firewalls[name] || {};
            const ipStr = fw.ip ? ` (${fw.ip})` : ' (192.168.1.254)';
            const opt = document.createElement('option');
            opt.value = name;
            opt.textContent = `${name}${ipStr}`;
            frag.appendChild(opt);
        });

        deviceSelect.innerHTML = '';
        deviceSelect.appendChild(frag);

        if (currentVal && Array.from(deviceSelect.options).some(o => o.value === currentVal)) {
            deviceSelect.value = currentVal;
        }
    })
    .catch(err => {
        console.warn('[RANGE] Fleet device load error:', err);
    });
}

// ═══════════════════════════════════════════════════════
// Scenario Presets & Terminal Actions
// ═══════════════════════════════════════════════════════

function bindTerminalActions() {
    if (btnClearTerminal) {
        btnClearTerminal.addEventListener('click', () => {
            if (terminal) terminal.innerHTML = '';
            appendLog('NEO', 'Simulation engine online. Enter an adversary attack vector or policy bypass scenario to begin.', 'log-agent');
            if (emptyState) emptyState.style.display = 'flex';
            if (diagramContainer) diagramContainer.style.display = 'none';
            if (canvasError) canvasError.style.display = 'none';
            if (btnExportSimulation) btnExportSimulation.style.display = 'none';
            lastTraceId = null;
        });
    }

    if (btnExportSimulation) {
        btnExportSimulation.addEventListener('click', () => {
            exportSimulationReport();
        });
    }
}

async function exportSimulationReport() {
    if (!btnExportSimulation) return;
    const targetTrace = lastTraceId || 'latest';

    const originalContent = btnExportSimulation.innerHTML;
    btnExportSimulation.disabled = true;
    btnExportSimulation.innerHTML = `<span>Exporting...</span>`;

    try {
        const key = getAuthKey();
        const res = await fetch('/api/export/markdown', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-API-Key': key
            },
            body: JSON.stringify({ trace_id: targetTrace })
        });

        if (!res.ok) {
            throw new Error(`Export HTTP ${res.status}: ${res.statusText}`);
        }

        const data = await res.json();
        if (data.markdown) {
            const blob = new Blob([data.markdown], { type: 'text/markdown;charset=utf-8' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `${data.title || 'CoreDefense_Simulation'}.md`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);

            btnExportSimulation.innerHTML = `<span>Exported!</span>`;
            setTimeout(() => {
                btnExportSimulation.disabled = false;
                btnExportSimulation.innerHTML = originalContent;
            }, 2500);
        } else {
            throw new Error(data.error || 'No markdown payload returned');
        }
    } catch (e) {
        btnExportSimulation.disabled = false;
        btnExportSimulation.innerHTML = `<span>Failed</span>`;
        console.error('[EXPORT-SIM] Error:', e);
        setTimeout(() => {
            btnExportSimulation.innerHTML = originalContent;
        }, 3000);
    }
}

cliForm.addEventListener('submit', (e) => {
    e.preventDefault();
    const text = cliInput.value.trim();
    if (!text || busy) return;
    runSimulation(text);
});

// ═══════════════════════════════════════════════════════
// Simulation Execution & Streaming
// ═══════════════════════════════════════════════════════

function runSimulation(text) {
    if (busy) return;
    busy = true;

    if (cliSendBtn) {
        cliSendBtn.disabled = true;
        cliSendBtn.textContent = '...';
    }

    appendLog('USER', text, 'log-user');
    cliInput.value = '';
    commandCount++;

    if (emptyState) {
        emptyState.style.display = 'none';
    }
    if (canvasError) {
        canvasError.style.display = 'none';
    }

    const key = getAuthKey();
    const selectedDevice = deviceSelect ? deviceSelect.value : 'default';

    fetch('/api/range/simulate', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-API-Key': key
        },
        body: JSON.stringify({ message: text, device: selectedDevice })
    })
    .then(res => {
        if (!res.ok) {
            throw new Error(`HTTP ${res.status}: ${res.statusText}`);
        }
        const reader = res.body.getReader();
        const decoder = new TextDecoder();
        let buf = '';

        function read() {
            reader.read().then(({ done, value }) => {
                if (done) {
                    finishSimulation();
                    return;
                }

                buf += decoder.decode(value, { stream: true });
                const lines = buf.split('\n');
                buf = lines.pop();

                for (const line of lines) {
                    if (!line.startsWith('data: ')) continue;
                    try {
                        const d = JSON.parse(line.slice(6));
                        if (d.type === 'status') {
                            if (d.content && (d.content.startsWith('[NEO-THINK]') || d.content.startsWith('[DIAGNOSTICS]'))) {
                                const cleanThink = d.content.replace(/^\[(NEO-THINK|DIAGNOSTICS)\]/, '').trim();
                                appendLog('NEO', cleanThink, 'log-think');
                            } else {
                                appendLog('SYS', d.content, 'log-sys');
                            }
                        } else if (d.type === 'response') {
                            if (d.trace_id) lastTraceId = d.trace_id;
                            handleRangeResponse(d.content);
                        } else if (d.type === 'done') {
                            if (d.trace_id) lastTraceId = d.trace_id;
                        } else if (d.type === 'error') {
                            appendLog('SYS', 'ERROR: ' + d.content, 'log-sys');
                        }
                    } catch (_) {}
                }
                read();
            }).catch(err => {
                appendLog('SYS', 'Stream read error: ' + err.message, 'log-sys');
                finishSimulation();
            });
        }
        read();
    })
    .catch(err => {
        appendLog('SYS', 'Network Error: ' + err.message, 'log-sys');
        finishSimulation();
    });
}

function finishSimulation() {
    busy = false;
    if (cliSendBtn) {
        cliSendBtn.disabled = false;
        cliSendBtn.textContent = 'RUN';
    }
    if (btnExportSimulation) {
        btnExportSimulation.style.display = 'inline-flex';
    }
    if (cliInput) cliInput.focus();
}

// ═══════════════════════════════════════════════════════
// Resilient Payload Parsing & Extraction
// ═══════════════════════════════════════════════════════

function handleRangeResponse(rawContent) {
    if (btnExportSimulation) {
        btnExportSimulation.style.display = 'inline-flex';
    }

    if (!rawContent) {
        appendLog('SYS', 'Agent returned empty response payload.', 'log-sys');
        return;
    }

    const payload = extractRangePayload(rawContent);

    if (payload && payload.mermaid) {
        renderAgentDiagram(
            payload.mermaid,
            payload.message || 'Generated semantic topology map.',
            payload.threats ?? 0,
            payload.drops ?? 0
        );
    } else {
        appendLog('SYS', 'Agent returned unstructured output. Attempting direct diagram recovery...', 'log-sys');
        appendLog('NEO', rawContent, 'log-agent');
        
        // Attempt fallback recovery if mermaid keyword is detected anywhere in the output
        if (rawContent.includes('graph ') || rawContent.includes('flowchart ')) {
            const rawMermaid = extractMermaidDirect(rawContent);
            if (rawMermaid) {
                renderAgentDiagram(rawMermaid, 'Recovered diagram from raw agent stream.', 1, 0);
            }
        }
    }
}

function extractRangePayload(raw) {
    if (!raw) return null;

    // 1. Try clean JSON parse from first '{' to last '}'
    const firstBrace = raw.indexOf('{');
    const lastBrace = raw.lastIndexOf('}');
    if (firstBrace >= 0 && lastBrace > firstBrace) {
        const candidate = raw.slice(firstBrace, lastBrace + 1);
        try {
            return JSON.parse(candidate);
        } catch (err) {
            // Repair unescaped newlines/control characters in string literals
            try {
                const repaired = candidate.replace(/[\u0000-\u001F]+/g, (match) => {
                    if (match === '\n') return '\\n';
                    if (match === '\r') return '\\r';
                    if (match === '\t') return '\\t';
                    return '';
                });
                return JSON.parse(repaired);
            } catch (_) {}
        }
    }

    // 2. Fallback: Search for code-fenced mermaid block
    const mermaidBlock = raw.match(/```(?:mermaid)?\s*([\s\S]*?)```/);
    if (mermaidBlock && (mermaidBlock[1].includes('graph ') || mermaidBlock[1].includes('flowchart '))) {
        return {
            mermaid: mermaidBlock[1].trim(),
            message: 'Extracted topology from code fence.',
            threats: 1,
            drops: 0
        };
    }

    return null;
}

function extractMermaidDirect(raw) {
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

// ═══════════════════════════════════════════════════════
// Mermaid AST Sanitizer & Renderer
// ═══════════════════════════════════════════════════════

function sanitizeMermaid(code) {
    if (!code) return 'graph TD\n  Start[No Topology Specified]';
    let s = code.trim();

    // Ensure directive header
    if (!s.startsWith('graph ') && !s.startsWith('flowchart ')) {
        s = 'graph TD\n' + s;
    }

    // Replace unquoted node brackets that crash Mermaid parser:
    // e.g., A[Host (10.0.0.1)] -> A["Host (10.0.0.1)"]
    s = s.replace(/(\w+)\[([^"\]]+)\]/g, (match, id, label) => {
        // If label has parentheses, colons, or slashes, wrap in quotes
        if (label.includes('(') || label.includes(')') || label.includes(':') || label.includes('/') || label.includes('>')) {
            return `${id}["${label.replace(/"/g, "'")}"]`;
        }
        return match;
    });

    return s;
}

async function renderAgentDiagram(markdown, agentLogMessage, threats, drops) {
    if (agentLogMessage) {
        appendLog('NEO', agentLogMessage, 'log-agent');
    }

    if (!diagramContainer || !mermaidTarget) return;

    currentRawMarkdown = markdown;
    const sanitizedMarkdown = sanitizeMermaid(markdown);

    // Destroy previous pan-zoom instance before re-rendering
    if (panZoomInstance) {
        try {
            panZoomInstance.destroy();
        } catch (_) {}
        panZoomInstance = null;
    }

    diagramContainer.classList.remove('active');
    if (canvasError) canvasError.style.display = 'none';

    try {
        const id = 'graph-' + Date.now();
        mermaidTarget.innerHTML = `<div class="mermaid" id="${id}"></div>`;
        
        const { svg } = await mermaid.render(id, sanitizedMarkdown);
        mermaidTarget.innerHTML = svg;
        
        const svgElement = mermaidTarget.querySelector('svg');
        if (svgElement) {
            // Strip hardcoded Mermaid width/max-width inline attributes so topology fills whole canvas
            svgElement.removeAttribute('style');
            svgElement.style.width = '100%';
            svgElement.style.height = '100%';
            svgElement.style.maxWidth = '100%';
            svgElement.style.maxHeight = '100%';
            svgElement.style.display = 'block';

            if (typeof svgPanZoom === 'function') {
                panZoomInstance = svgPanZoom(svgElement, {
                    zoomEnabled: true,
                    controlIconsEnabled: false, // We use custom header buttons
                    fit: true,
                    center: true,
                    minZoom: 0.1,
                    maxZoom: 15
                });

                // Auto-fit & center across the complete canvas surface
                setTimeout(() => {
                    if (panZoomInstance) {
                        panZoomInstance.resize();
                        panZoomInstance.fit();
                        panZoomInstance.center();
                    }
                }, 100);
            }
        }
        
        setTimeout(() => {
            diagramContainer.classList.add('active');
        }, 80);

    } catch (error) {
        appendLog('SYS', 'Mermaid parser exception: ' + error.message, 'log-sys');
        console.error('[RANGE] Mermaid render failure:', error);

        // Display visual error fallback container on canvas
        if (canvasError && canvasErrorMsg) {
            canvasErrorMsg.textContent = error.message || 'Syntax error in generated topology definition.';
            canvasError.style.display = 'block';
            if (rawSpecBox) {
                rawSpecBox.textContent = markdown;
                rawSpecBox.style.display = 'none';
            }
        }
    }
}

// ═══════════════════════════════════════════════════════
// Canvas Controls (Zoom, Pan, Fullscreen)
// ═══════════════════════════════════════════════════════

function bindCanvasControls() {
    const btnIn = document.getElementById('btnZoomIn');
    const btnOut = document.getElementById('btnZoomOut');
    const btnReset = document.getElementById('btnZoomReset');
    const btnFull = document.getElementById('btnCanvasFullscreen');
    const canvasPanel = document.getElementById('canvasPanel');

    if (btnIn) {
        btnIn.addEventListener('click', () => {
            if (panZoomInstance) panZoomInstance.zoomIn();
        });
    }

    if (btnOut) {
        btnOut.addEventListener('click', () => {
            if (panZoomInstance) panZoomInstance.zoomOut();
        });
    }

    if (btnReset) {
        btnReset.addEventListener('click', () => {
            if (panZoomInstance) {
                panZoomInstance.resetZoom();
                panZoomInstance.center();
            }
        });
    }

    const btnExit = document.getElementById('btnExitFullscreen');
    if (btnExit) {
        btnExit.addEventListener('click', () => {
            exitCanvasFullscreen();
        });
    }

    function syncFullscreenState() {
        const isFull = !!(document.fullscreenElement || document.webkitFullscreenElement || document.mozFullScreenElement || document.msFullscreenElement);
        if (canvasPanel) {
            canvasPanel.classList.toggle('is-fullscreen', isFull);
        }
        if (btnExit) {
            btnExit.style.display = isFull ? 'inline-flex' : 'none';
        }
        if (btnFull) {
            btnFull.title = isFull ? 'Exit Fullscreen' : 'Toggle Fullscreen';
        }
        if (panZoomInstance) {
            setTimeout(() => panZoomInstance.resize(), 100);
        }
    }

    ['fullscreenchange', 'webkitfullscreenchange', 'mozfullscreenchange', 'MSFullscreenChange'].forEach(evt => {
        document.addEventListener(evt, syncFullscreenState);
    });

    if (btnFull && canvasPanel) {
        btnFull.addEventListener('click', () => {
            const isFull = !!(document.fullscreenElement || document.webkitFullscreenElement || document.mozFullScreenElement || document.msFullscreenElement);
            if (!isFull) {
                if (canvasPanel.requestFullscreen) {
                    canvasPanel.requestFullscreen().catch(() => {});
                } else if (canvasPanel.webkitRequestFullscreen) {
                    canvasPanel.webkitRequestFullscreen();
                } else if (canvasPanel.mozRequestFullScreen) {
                    canvasPanel.mozRequestFullScreen();
                } else if (canvasPanel.msRequestFullscreen) {
                    canvasPanel.msRequestFullscreen();
                }
            } else {
                exitCanvasFullscreen();
            }
        });
    }
}

function exitCanvasFullscreen() {
    if (document.exitFullscreen) {
        document.exitFullscreen().catch(() => {});
    } else if (document.webkitExitFullscreen) {
        document.webkitExitFullscreen();
    } else if (document.mozCancelFullScreen) {
        document.mozCancelFullScreen();
    } else if (document.msExitFullscreen) {
        document.msExitFullscreen();
    }
    const canvasPanel = document.getElementById('canvasPanel');
    if (canvasPanel) {
        canvasPanel.classList.remove('is-fullscreen');
    }
}

function bindErrorViewSpec() {
    if (btnViewSpec && rawSpecBox) {
        btnViewSpec.addEventListener('click', () => {
            const isHidden = rawSpecBox.style.display === 'none';
            rawSpecBox.style.display = isHidden ? 'block' : 'none';
            btnViewSpec.textContent = isHidden ? 'Hide Raw Spec' : 'View Raw Topology Spec';
        });
    }
}

// ═══════════════════════════════════════════════════════
// BAS Sidebar — Drag Resize
// ═══════════════════════════════════════════════════════

const BAS_MIN_WIDTH = 340;
const BAS_MAX_WIDTH_RATIO = 0.65;
const BAS_WIDTH_STORAGE_KEY = 'nodal_bas_width';

function bindRangeResizeHandle() {
    const handle = document.getElementById('rangeResizeHandle');
    const workspace = document.getElementById('workspace');
    const cliPanel = document.getElementById('cliPanel');
    if (!handle || !workspace || !cliPanel) return;

    let startX, startWidth;

    handle.addEventListener('mousedown', (e) => {
        e.preventDefault();
        startX = e.clientX;
        startWidth = cliPanel.offsetWidth;
        document.body.classList.add('resizing');
        handle.classList.add('dragging');

        function onMouseMove(e) {
            const delta = e.clientX - startX;
            const maxW = window.innerWidth * BAS_MAX_WIDTH_RATIO;
            const newWidth = Math.min(maxW, Math.max(BAS_MIN_WIDTH, startWidth + delta));
            setRangeWidth(newWidth);
        }

        function onMouseUp() {
            document.removeEventListener('mousemove', onMouseMove);
            document.removeEventListener('mouseup', onMouseUp);
            document.body.classList.remove('resizing');
            handle.classList.remove('dragging');
            localStorage.setItem(BAS_WIDTH_STORAGE_KEY, cliPanel.offsetWidth);
            if (panZoomInstance) {
                panZoomInstance.resize();
            }
        }

        document.addEventListener('mousemove', onMouseMove);
        document.addEventListener('mouseup', onMouseUp);
    });
}

function setRangeWidth(px) {
    const workspace = document.getElementById('workspace');
    if (workspace) {
        workspace.style.setProperty('--bas-sidebar-width', px + 'px');
    }
}

function restoreRangeWidth() {
    const saved = localStorage.getItem(BAS_WIDTH_STORAGE_KEY);
    if (saved) {
        const w = parseInt(saved, 10);
        if (w >= BAS_MIN_WIDTH && w <= window.innerWidth * BAS_MAX_WIDTH_RATIO) {
            setRangeWidth(w);
        }
    }
}

// ═══════════════════════════════════════════════════════
// Authentication & Setup Wizard Engine
// ═══════════════════════════════════════════════════════

function setAuthKey(key) {
    if (key) {
        sessionStorage.setItem('nodal_key', key);
        localStorage.setItem('nodal_key', key);
    }
}

function clearAuthKey() {
    sessionStorage.removeItem('nodal_key');
    localStorage.removeItem('nodal_key');
}

function checkHealth() {
    fetch('/api/health')
        .then(r => r.json())
        .then(data => {
            if (data.access_token) {
                setAuthKey(data.access_token);
            }
            checkAuthNotice();

            const loginOverlay = document.getElementById('loginOverlay');
            const setupOverlay = document.getElementById('setupOverlay');

            if (!data.configured) {
                if (loginOverlay) loginOverlay.style.display = 'none';
                if (setupOverlay) setupOverlay.style.display = 'flex';
            } else if (getAuthKey()) {
                unlockApp();
            } else {
                if (setupOverlay) setupOverlay.style.display = 'none';
                if (loginOverlay) {
                    loginOverlay.style.display = 'flex';
                    const loginInput = document.getElementById('loginInput');
                    if (loginInput) loginInput.focus();
                }
            }

            const statusChip = document.getElementById('perimeterStatusChip');
            const statusText = document.getElementById('perimeterStatusText');
            if (statusText) {
                if (data.firewall_reachable) {
                    statusText.textContent = data.firewall_ip ? `PAN-OS (${data.firewall_ip})` : 'PAN-OS CONNECTED';
                    if (statusChip) statusChip.className = 'perimeter-status-chip nominal';
                } else if (data.configured) {
                    statusText.textContent = 'PAN-OS UNREACHABLE';
                    if (statusChip) statusChip.className = 'perimeter-status-chip critical';
                } else {
                    statusText.textContent = 'NOT CONFIGURED';
                }
            }
        })
        .catch(err => {
            console.warn('[RANGE] Health check failed:', err);
        });
}

function unlockApp() {
    const loginOverlay = document.getElementById('loginOverlay');
    if (loginOverlay) loginOverlay.style.display = 'none';
    const setupOverlay = document.getElementById('setupOverlay');
    if (setupOverlay) setupOverlay.style.display = 'none';
    const workspace = document.getElementById('workspace');
    if (workspace) workspace.style.display = 'flex';
}

function bindLogin() {
    const form = document.getElementById('loginForm');
    if (!form) return;

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const input = document.getElementById('loginInput');
        const btn = document.getElementById('loginBtn');
        const err = document.getElementById('loginError');
        const key = input.value.trim();
        if (!key) return;

        btn.disabled = true;
        btn.textContent = 'Verifying...';
        err.textContent = '';

        try {
            const res = await fetch('/api/login', {
                method: 'POST',
                headers: { 'X-API-Key': key }
            });
            if (res.ok) {
                setAuthKey(key);
                unlockApp();
                appendLog('SYS', 'Session unlocked successfully', 'log-sys');
            } else {
                clearAuthKey();
                err.textContent = 'Invalid passphrase. Try again.';
            }
        } catch (_) {
            err.textContent = 'Connection error verifying passphrase.';
        }
        btn.disabled = false;
        btn.textContent = 'Connect';
    });
}

function bindSetup() {
    const s1 = document.getElementById('setupStep1');
    const s2 = document.getElementById('setupStep2');
    const s3 = document.getElementById('setupStep3');
    if (!s1 || !s2 || !s3) return;

    document.getElementById('btnSetupSimple').addEventListener('click', () => {
        document.getElementById('setupBackend').value = 'dotenv';
        document.getElementById('setupSimpleFields').style.display = 'flex';
        document.getElementById('setupVaultFields').style.display = 'none';
        s1.style.display = 'none';
        s2.style.display = 'block';
    });

    document.getElementById('btnSetupVault').addEventListener('click', () => {
        document.getElementById('setupBackend').value = 'vault';
        document.getElementById('setupSimpleFields').style.display = 'none';
        document.getElementById('setupVaultFields').style.display = 'flex';
        s1.style.display = 'none';
        s2.style.display = 'block';
    });

    document.getElementById('btnSetupBack').addEventListener('click', () => {
        s2.style.display = 'none';
        s1.style.display = 'block';
    });

    document.getElementById('setupForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const btn = document.getElementById('setupSubmitBtn');
        const err = document.getElementById('setupError');
        btn.disabled = true;
        btn.textContent = 'Saving...';
        err.textContent = '';

        const payload = {
            backend_type: document.getElementById('setupBackend').value,
            firewall_ip: document.getElementById('setupFwIp').value,
            panos_key: document.getElementById('setupPanosKey').value,
            gemini_key: document.getElementById('setupGeminiKey').value,
            vault_addr: document.getElementById('setupVaultAddr').value,
            vault_role: document.getElementById('setupVaultRole').value,
            vault_secret: document.getElementById('setupVaultSecret').value
        };

        try {
            const res = await fetch('/api/setup', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            const data = await res.json();
            if (data.success) {
                document.getElementById('setupPassphrase').textContent = data.passphrase;
                s2.style.display = 'none';
                s3.style.display = 'block';
            } else {
                err.textContent = data.error || 'Setup failed';
            }
        } catch (_) {
            err.textContent = 'Network error saving configuration.';
        }
        btn.disabled = false;
        btn.textContent = 'Save & Initialize';
    });

    document.getElementById('btnCopyPassphrase').addEventListener('click', () => {
        const text = document.getElementById('setupPassphrase').textContent;
        navigator.clipboard.writeText(text);
        const btn = document.getElementById('btnCopyPassphrase');
        btn.textContent = 'Copied!';
        setTimeout(() => btn.textContent = 'Copy to Clipboard', 2000);
    });

    document.getElementById('btnProceedLogin').addEventListener('click', () => {
        document.getElementById('setupOverlay').style.display = 'none';
        document.getElementById('loginOverlay').style.display = 'flex';
        document.getElementById('loginInput').focus();
        checkHealth();
    });
}

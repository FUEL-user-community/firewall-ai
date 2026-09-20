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
        fontFamily: 'Inter, -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif'
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
const canvasError = document.getElementById('canvasError');
const canvasErrorMsg = document.getElementById('canvasErrorMsg');
const btnViewSpec = document.getElementById('btnViewSpec');
const rawSpecBox = document.getElementById('rawSpecBox');

// Pan & Zoom instance tracking
let panZoomInstance = null;
let currentRawMarkdown = '';
let commandCount = 0;
let busy = false;

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

// Helper to append logs to terminal safely
function appendLog(speaker, message, styleClass) {
    if (!terminal) return;
    const time = new Date().toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second:'2-digit' });
    const entry = document.createElement('div');
    
    let typeClass = 'log-type-sys';
    let speakerPrefix = 'SYSTEM';
    if (speaker === 'USER') {
        typeClass = 'log-type-user';
        speakerPrefix = 'OPERATOR';
    } else if (speaker === 'NEO') {
        typeClass = 'log-type-agent';
        speakerPrefix = 'NEO-COPILOT';
    } else if (styleClass && styleClass.includes('crit')) {
        typeClass = 'log-type-crit';
    }

    entry.className = `log-entry ${typeClass}`;
    entry.innerHTML = `
        <div class="log-meta">
            <span>[${speakerPrefix}]</span>
            <span>${time}</span>
        </div>
        <div class="log-content ${styleClass || ''}">${esc(message)}</div>
    `;
    terminal.appendChild(entry);
    terminal.scrollTop = terminal.scrollHeight;
}

// ═══════════════════════════════════════════════════════
// Initialization & Fleet Devices
// ═══════════════════════════════════════════════════════

document.addEventListener('DOMContentLoaded', () => {
    restoreRangeWidth();
    bindRangeResizeHandle();
    loadFleetDevices();
    bindScenarioPresets();
    bindCanvasControls();
    bindErrorViewSpec();
    checkAuthNotice();
});

function checkAuthNotice() {
    appendLog('NEO', 'NEO-COPILOT v2.4 // READY\nSelect a simulation vector or specify custom attack bypass scenario.', 'log-agent');
    const key = getAuthKey();
    if (!key) {
        appendLog('SYS', 'Notice: No active passphrase in session. If simulation fails with 401/403, unlock in Defense Deck first.', 'log-sys');
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

        deviceSelect.innerHTML = '';
        const defOpt = document.createElement('option');
        defOpt.value = 'default';
        defOpt.textContent = 'default (primary)';
        deviceSelect.appendChild(defOpt);

        names.forEach(name => {
            if (name !== 'default') {
                const opt = document.createElement('option');
                opt.value = name;
                opt.textContent = name;
                deviceSelect.appendChild(opt);
            }
        });

        deviceSelect.addEventListener('change', () => {
            const dev = deviceSelect.value;
            appendLog('SYS', `Target device switched to '${dev}'`, 'log-sys');
        });
    })
    .catch(err => {
        console.warn('[RANGE] Fleet device load error:', err);
    });
}

// ═══════════════════════════════════════════════════════
// Scenario Presets & Terminal Actions
// ═══════════════════════════════════════════════════════

function bindScenarioPresets() {
    const presets = document.getElementById('scenarioPresets');
    if (!presets) return;

    presets.addEventListener('click', (e) => {
        const pill = e.target.closest('.preset-pill');
        if (!pill || busy) return;

        const scenario = pill.dataset.scenario;
        if (scenario) {
            cliInput.value = scenario;
            runSimulation(scenario);
        }
    });

    if (btnClearTerminal) {
        btnClearTerminal.addEventListener('click', () => {
            if (terminal) terminal.innerHTML = '';
            appendLog('SYS', 'Terminal buffer cleared.', 'log-sys');
        });
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
                            if (d.content && d.content.startsWith('[NEO-THINK]')) {
                                appendLog('NEO', d.content.replace('[NEO-THINK]', '').trim(), 'log-think');
                            } else {
                                appendLog('SYS', d.content, 'log-sys');
                            }
                        } else if (d.type === 'response') {
                            handleRangeResponse(d.content);
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
    if (cliInput) cliInput.focus();
}

// ═══════════════════════════════════════════════════════
// Resilient Payload Parsing & Extraction
// ═══════════════════════════════════════════════════════

function handleRangeResponse(rawContent) {
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
        if (svgElement && typeof svgPanZoom === 'function') {
            panZoomInstance = svgPanZoom(svgElement, {
                zoomEnabled: true,
                controlIconsEnabled: false, // We use custom header buttons
                fit: true,
                center: true,
                minZoom: 0.2,
                maxZoom: 12
            });
        }
        
        setTimeout(() => {
            diagramContainer.classList.add('active');
        }, 80);

    } catch (error) {
        appendLog('SYS', 'Mermaid parser exception: ' + error.message, 'log-sys');
        console.error('[RANGE] Mermaid render failure:', error);

        // Display visual error fallback card on canvas
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

// Initialize Mermaid with a dark theme that matches the UI
mermaid.initialize({ 
    startOnLoad: false,
    theme: 'base',
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
        fontFamily: 'JetBrains Mono, monospace'
    }
});

// DOM Elements
const terminal = document.getElementById('terminal');
const cliForm = document.getElementById('cliForm');
const cliInput = document.getElementById('cliInput');
const diagramContainer = document.getElementById('diagramContainer');
const mermaidTarget = document.getElementById('mermaidTarget');
const emptyState = document.getElementById('emptyState');

let commandCount = 0;
let busy = false;

// Helper to append logs to terminal
function appendLog(speaker, message, styleClass) {
    const time = new Date().toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second:'2-digit' });
    const entry = document.createElement('div');
    entry.className = 'log-entry';
    
    let speakerPrefix = '';
    if(speaker === 'USER') speakerPrefix = 'test_usr';
    if(speaker === 'NEO') speakerPrefix = 'nodal_agent';
    if(speaker === 'SYS') speakerPrefix = 'system';

    entry.innerHTML = `
        <span class="log-meta">${speakerPrefix} [${time}]</span>
        <span class="${styleClass}">${message}</span>
    `;
    terminal.appendChild(entry);
    terminal.scrollTop = terminal.scrollHeight;
}

cliForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const text = cliInput.value.trim();
    if (!text || busy) return;

    // 1. User inputs command
    appendLog('USER', text, 'log-user');
    cliInput.value = '';
    commandCount++;
    busy = true;
    
    // Hide empty state if first command
    if(commandCount === 1) {
        emptyState.style.display = 'none';
    }

    const key = sessionStorage.getItem('nodal_key'); // Assume user logged in via index.html

    fetch('/api/chat', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-API-Key': key
        },
        body: JSON.stringify({ message: text })
    })
    .then(res => {
        const reader = res.body.getReader();
        const decoder = new TextDecoder();
        let buf = '';

        function read() {
            reader.read().then(({ done, value }) => {
                if (done) {
                    busy = false;
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
                            appendLog('SYS', d.content, 'log-sys');
                        } else if (d.type === 'response') {
                            // The response from the LLM. 
                            // If it contains a mermaid block, let's extract it.
                            let mermaidCode = null;
                            const match = d.content.match(/```mermaid\n([\s\S]*?)```/);
                            if (match) {
                                mermaidCode = match[1];
                            }
                            
                            // Log the agent's explanation (strip out the mermaid block to not clutter terminal)
                            const logMsg = d.content.replace(/```mermaid\n[\s\S]*?```/g, '').trim();
                            
                            // Mock stats for the UI
                            const threats = Math.floor(Math.random() * 5);
                            const drops = Math.floor(Math.random() * 10);

                            if (mermaidCode) {
                                renderAgentDiagram(mermaidCode, logMsg || 'Generated semantic topology map.', threats, drops);
                            } else {
                                appendLog('NEO', logMsg || d.content, 'log-agent');
                            }
                            busy = false;
                        } else if (d.type === 'error') {
                            appendLog('SYS', 'ERROR: ' + d.content, 'log-sys');
                            busy = false;
                        }
                    } catch (_) {}
                }
                read();
            });
        }
        read();
    })
    .catch(err => {
        appendLog('SYS', 'Network Error: ' + err, 'log-sys');
        busy = false;
    });
});

async function renderAgentDiagram(markdown, agentLogMessage, threats, drops) {
    appendLog('NEO', agentLogMessage, 'log-agent');
    document.getElementById('threatCount').innerText = threats;
    document.getElementById('dropCount').innerText = drops;

    // Clear previous, reset state, render new diagram
    diagramContainer.classList.remove('active');
    
    try {
        const id = 'graph-' + Date.now();
        mermaidTarget.innerHTML = `<div class="mermaid" id="${id}"></div>`;
        
        const { svg } = await mermaid.render(id, markdown);
        mermaidTarget.innerHTML = svg;
        
        const svgElement = mermaidTarget.querySelector('svg');
        if (svgElement) {
            svgPanZoom(svgElement, {
                zoomEnabled: true,
                controlIconsEnabled: true,
                fit: true,
                center: true,
                minZoom: 0.5,
                maxZoom: 10
            });
        }
        
        setTimeout(() => {
            diagramContainer.classList.add('active');
        }, 100);

    } catch (error) {
        appendLog('SYS', 'Error rendering agent diagram payload.', 'log-sys');
        console.error(error);
    }
}

/**
 * CyberDefenseAI — SOC Command Dashboard Reactive Controller
 * Obsidian Cyber Defense Design System (Stitch-generated)
 * Handles real-time WebSockets, REST synchronization, MITRE ATT&CK visualization,
 * SOAR containment tracking, and interactive forensic report inspection.
 */

let state = {
    incidents: {},
    alerts: [],
    soarActions: [],
    soarSummary: {
        total_actions: 0,
        quarantined_count: 0,
        blocked_ips_count: 0,
        revoked_tokens_count: 0,
    },
    activeFilter: 'ALL',
    activeTab: 'mitre',
    ws: null,
};

// Initialize Dashboard
document.addEventListener('DOMContentLoaded', () => {
    initWebSocket();
    fetchInitialData();
    // Support direct tab linking via hash (e.g. #soar, #mitre, #feed)
    const hash = window.location.hash.replace('#', '');
    if (hash === 'soar' || hash === 'mitre' || hash === 'feed') {
        const targetBtn = document.querySelector(`.tab-btn[onclick*="${hash}"]`);
        switchRightTab(hash, targetBtn);
    }
    // Periodic safety sync every 5 seconds
    setInterval(fetchInitialData, 5000);
});

// WebSocket Setup
function initWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws`;
    
    try {
        state.ws = new WebSocket(wsUrl);

        state.ws.onopen = () => {
            const statusEl = document.getElementById('engine-status');
            if (statusEl) {
                statusEl.textContent = 'ONLINE';
                statusEl.style.color = 'var(--green-500)';
            }
        };

        state.ws.onmessage = (event) => {
            try {
                const msg = JSON.parse(event.data);
                handleWebSocketMessage(msg);
            } catch (err) {
                console.error('Error parsing WebSocket message:', err);
            }
        };

        state.ws.onclose = () => {
            const statusEl = document.getElementById('engine-status');
            if (statusEl) {
                statusEl.textContent = 'RECONNECTING';
                statusEl.style.color = 'var(--orange-500)';
            }
            setTimeout(initWebSocket, 2500);
        };

        state.ws.onerror = (err) => {
            console.warn('WebSocket encountered error:', err);
        };
    } catch (ex) {
        console.error('WebSocket connection initialization failed:', ex);
    }
}

function handleWebSocketMessage(msg) {
    if (msg.event === 'INIT_STATE') {
        const d = msg.data;
        if (d.incidents) {
            d.incidents.forEach(inc => { state.incidents[inc.incident_id] = inc; });
        }
        if (d.alerts) state.alerts = d.alerts;
        if (d.actions) state.soarActions = d.actions;
        if (d.soar_summary) state.soarSummary = d.soar_summary;
        refreshUI();
    } else if (msg.event === 'INCIDENT_UPDATED') {
        const inc = msg.data;
        state.incidents[inc.incident_id] = inc;
        refreshUI();
    } else if (msg.event === 'ALERT_INGESTED') {
        state.alerts.unshift(msg.data);
        if (state.alerts.length > 200) state.alerts.pop();
        renderAlertStream();
        updateMetricsBar();
    } else if (msg.event === 'SOAR_STATE') {
        state.soarSummary = msg.data;
        updateMetricsBar();
    } else if (msg.event === 'SOAR_ACTION_TRIGGERED' || msg.event === 'SOAR_ACTION_REVERTED') {
        fetchSOARActions();
    }
}

// REST API Fallbacks
async function fetchInitialData() {
    try {
        const [incRes, altRes, soarRes, mitreRes] = await Promise.all([
            fetch('/api/incidents'),
            fetch('/api/alerts?limit=50'),
            fetch('/api/soar/actions'),
            fetch('/api/mitre/matrix')
        ]);

        if (incRes.ok) {
            const incs = await incRes.json();
            incs.forEach(inc => { state.incidents[inc.incident_id] = inc; });
        }
        if (altRes.ok) {
            state.alerts = await altRes.json();
        }
        if (soarRes.ok) {
            state.soarActions = await soarRes.json();
        }
        if (mitreRes.ok) {
            const mitreData = await mitreRes.json();
            renderMitreMatrix(mitreData);
        }

        const sumRes = await fetch('/api/soar/summary');
        if (sumRes.ok) {
            state.soarSummary = await sumRes.json();
        }

        refreshUI();
    } catch (err) {
        console.warn('Sync error:', err);
    }
}

async function fetchSOARActions() {
    try {
        const res = await fetch('/api/soar/actions');
        if (res.ok) {
            state.soarActions = await res.json();
            renderSOARTable();
        }
        const sumRes = await fetch('/api/soar/summary');
        if (sumRes.ok) {
            state.soarSummary = await sumRes.json();
            updateMetricsBar();
        }
    } catch (err) {
        console.error('Error fetching SOAR actions:', err);
    }
}

// Render Controllers
function refreshUI() {
    updateMetricsBar();
    renderIncidents();
    renderAlertStream();
    renderSOARTable();
    fetchMitreMatrix();
}

function updateMetricsBar() {
    const totalAlertsEl = document.getElementById('metric-total-alerts');
    const p1El = document.getElementById('metric-p1-count');
    const p2El = document.getElementById('metric-p2-count');
    const quarEl = document.getElementById('metric-quarantined');
    const blkEl = document.getElementById('metric-blocked-ips');
    const soarActEl = document.getElementById('metric-soar-actions');
    const revokedEl = document.getElementById('metric-revoked-tokens');
    const incTotalEl = document.getElementById('metric-incidents-total');

    const incidentsList = Object.values(state.incidents);
    const p1Count = incidentsList.filter(i => i.severity === 'P1' && i.status !== 'REVERTED').length;
    const p2Count = incidentsList.filter(i => i.severity === 'P2' && i.status !== 'REVERTED').length;

    if (totalAlertsEl) totalAlertsEl.textContent = state.alerts.length;
    if (p1El) p1El.textContent = p1Count;
    if (p2El) p2El.textContent = p2Count;
    if (quarEl) quarEl.textContent = state.soarSummary.quarantined_count || 0;
    if (blkEl) blkEl.textContent = state.soarSummary.blocked_ips_count || 0;
    if (soarActEl) soarActEl.textContent = state.soarSummary.total_actions || 0;
    if (revokedEl) revokedEl.textContent = state.soarSummary.revoked_tokens_count || 0;
    if (incTotalEl) incTotalEl.textContent = incidentsList.length;

    // Footer bar counters
    const fAlerts = document.getElementById('footer-alerts');
    const fInc = document.getElementById('footer-incidents');
    const fSoar = document.getElementById('footer-soar');
    const fRep = document.getElementById('footer-reports');
    if (fAlerts) fAlerts.textContent = state.alerts.length;
    if (fInc) fInc.textContent = incidentsList.length;
    if (fSoar) fSoar.textContent = state.soarSummary.total_actions || 0;
    if (fRep) fRep.textContent = incidentsList.filter(i => i.status === 'CONTAINED').length;

    const badgeCount = document.getElementById('incident-badge-count');
    if (badgeCount) badgeCount.textContent = `${incidentsList.length} Cases`;
}

function renderIncidents() {
    const container = document.getElementById('incident-container');
    if (!container) return;

    let list = Object.values(state.incidents).sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

    if (state.activeFilter !== 'ALL') {
        list = list.filter(i => i.severity === state.activeFilter);
    }

    if (list.length === 0) {
        container.innerHTML = `<div class="empty-state">No incidents matching filter '${state.activeFilter}'.</div>`;
        return;
    }

    container.innerHTML = list.map(inc => {
        const timeStr = new Date(inc.created_at).toLocaleTimeString();
        const sev = inc.severity || 'P3';
        const actionsCount = (inc.soar_actions || []).length;
        const statusColor = inc.status === 'CONTAINED' ? 'var(--green-500)' : (inc.status === 'REVERTED' ? 'var(--text-dim)' : 'var(--orange-500)');

        return `
            <div class="incident-card sev-${sev}" onclick="openIncidentModal('${inc.incident_id}')">
                <div class="incident-header">
                    <span class="incident-pill pill-${sev}">${sev} // ${inc.triage ? inc.triage.severity_label : 'ACTIVE'}</span>
                    <span class="incident-time">${timeStr}</span>
                </div>
                <div class="incident-title">${escapeHtml(inc.title)}</div>
                <div class="incident-meta">
                    <span class="meta-tag">MITRE: <strong>${inc.mitre_technique_id}</strong> (${escapeHtml(inc.mitre_technique_name || '')})</span>
                    <span class="meta-tag">ATTACKER: ${escapeHtml(inc.threat_actor_ip || 'N/A')}</span>
                    <span class="meta-tag">TARGET: ${escapeHtml(inc.target_host || 'N/A')}</span>
                </div>
                <div class="incident-actions-preview">
                    <span class="soar-status-badge" style="color: ${statusColor};">
                        ● ${inc.status} (${actionsCount} SOAR Actions)
                    </span>
                    <div class="btn-group" onclick="event.stopPropagation();">
                        <button class="btn btn-sm btn-outline-cyan" onclick="openIncidentModal('${inc.incident_id}')">Inspect</button>
                        <button class="btn btn-sm btn-cyan" onclick="openReportModal('${inc.incident_id}')">Report</button>
                        ${inc.status === 'CONTAINED' ? `
                            <button class="btn btn-sm btn-outline-red" onclick="revertIncident('${inc.incident_id}')">Revert</button>
                        ` : ''}
                    </div>
                </div>
            </div>
        `;
    }).join('');
}

async function fetchMitreMatrix() {
    try {
        const res = await fetch('/api/mitre/matrix');
        if (res.ok) {
            const data = await res.json();
            renderMitreMatrix(data);
        }
    } catch (err) {
        console.error('Error fetching MITRE matrix:', err);
    }
}

function renderMitreMatrix(data) {
    const container = document.getElementById('mitre-matrix-container');
    const coverageBadge = document.getElementById('mitre-coverage-count');
    if (!container) return;

    if (!data.techniques || data.techniques.length === 0) {
        container.innerHTML = '<div class="empty-state">No adversary techniques mapped yet.</div>';
        return;
    }

    if (coverageBadge) coverageBadge.textContent = `${data.total_coverage || data.techniques.length} techniques`;

    // Group techniques by tactic
    const tacticMap = {};
    data.techniques.forEach(tech => {
        if (!tacticMap[tech.tactic]) tacticMap[tech.tactic] = [];
        tacticMap[tech.tactic].push(tech);
    });

    container.innerHTML = Object.entries(tacticMap).map(([tactic, techs]) => `
        <div class="mitre-tactic-card">
            <div class="mitre-tactic-title">${escapeHtml(tactic)} <span style="color:#475569;">(${techs.length})</span></div>
            <div class="technique-tags">
                ${techs.map(t => `
                    <div class="technique-tag">
                        <strong>${t.technique_id}</strong>
                        <span style="color:#7dd3fc;font-size:9px;">${escapeHtml(t.name)}</span>
                        <span class="technique-tag-hit">Hits: ${t.count}</span>
                    </div>
                `).join('')}
            </div>
        </div>
    `).join('');
}

function formatActionBadge(actionType) {
    const configs = {
        'BLOCK_FIREWALL_IP': { label: 'BLOCK IP', color: '#f87171', border: 'rgba(239, 68, 68, 0.25)', bg: 'rgba(239, 68, 68, 0.08)' },
        'QUARANTINE_HOST': { label: 'QUARANTINE', color: '#fb923c', border: 'rgba(251, 146, 60, 0.25)', bg: 'rgba(251, 146, 60, 0.08)' },
        'TERMINATE_PROCESS': { label: 'KILL PROC', color: '#e879f9', border: 'rgba(232, 121, 249, 0.25)', bg: 'rgba(232, 121, 249, 0.08)' },
        'REVOKE_USER_TOKEN': { label: 'REVOKE TOKEN', color: '#38bdf8', border: 'rgba(56, 189, 248, 0.25)', bg: 'rgba(56, 189, 248, 0.08)' }
    };
    const cfg = configs[actionType] || {
        label: (actionType || 'UNKNOWN').replace(/_/g, ' '),
        color: '#94a3b8',
        border: 'rgba(148, 163, 184, 0.2)',
        bg: 'rgba(255, 255, 255, 0.04)'
    };
    return `<span class="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-mono font-medium tracking-wide whitespace-nowrap" style="color: ${cfg.color}; background: ${cfg.bg}; border: 1px solid ${cfg.border};">${cfg.label}</span>`;
}

function formatStatusBadge(status) {
    const isReverted = status === 'REVERTED';
    if (isReverted) {
        return `<span class="inline-flex items-center gap-1.5 text-[10px] font-mono text-slate-500 whitespace-nowrap"><span class="w-1.5 h-1.5 rounded-full bg-slate-600"></span>REVERTED</span>`;
    }
    return `<span class="inline-flex items-center gap-1.5 text-[10px] font-mono text-emerald-400 font-medium whitespace-nowrap"><span class="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>ACTIVE</span>`;
}

function renderSOARTable() {
    const tbody = document.getElementById('soar-actions-tbody');
    if (!tbody) return;

    if (!state.soarActions || state.soarActions.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="text-center py-8 text-slate-500 font-mono text-xs">No active containment rules</td></tr>';
        return;
    }

    tbody.innerHTML = state.soarActions.map(act => {
        const isReverted = act.status === 'REVERTED';
        const timeStr = new Date(act.executed_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });

        return `
            <tr class="hover:bg-white/[0.02] transition-colors">
                <td class="px-3.5 py-2.5 whitespace-nowrap align-middle">
                    ${formatActionBadge(act.action_type)}
                </td>
                <td class="px-3.5 py-2.5 align-middle max-w-[140px]">
                    <span class="font-mono text-xs text-slate-200 truncate block" title="${escapeHtml(act.target)}">${escapeHtml(act.target)}</span>
                </td>
                <td class="px-3.5 py-2.5 whitespace-nowrap align-middle">
                    ${formatStatusBadge(act.status)}
                </td>
                <td class="px-3.5 py-2.5 font-mono text-[10px] text-slate-400 whitespace-nowrap align-middle">
                    ${timeStr}
                </td>
                <td class="px-3.5 py-2.5 text-right whitespace-nowrap align-middle">
                    ${act.is_reversible && !isReverted ? `
                        <button class="btn btn-sm btn-outline-red" onclick="revertAction('${act.action_id}')" title="Revert containment rule">
                            <span class="material-symbols-outlined text-[12px]">undo</span>Revert
                        </button>
                    ` : `
                        <span class="inline-flex items-center px-1.5 py-0.5 rounded text-[9px] font-mono tracking-wider uppercase ${isReverted ? 'text-slate-600 bg-white/[0.02]' : 'text-slate-500 bg-white/[0.03] border border-white/[0.04]'}">
                            ${isReverted ? 'Reverted' : 'Permanent'}
                        </span>
                    `}
                </td>
            </tr>
        `;
    }).join('');
}

function renderAlertStream() {
    const container = document.getElementById('alert-stream-container');
    if (!container) return;

    if (!state.alerts || state.alerts.length === 0) {
        container.innerHTML = '<div class="empty-state">Listening to ingestion stream...</div>';
        return;
    }

    container.innerHTML = state.alerts.slice(0, 30).map(alert => {
        const timeStr = new Date(alert.timestamp).toLocaleTimeString();
        const sev = alert.triage ? alert.triage.severity : 'P3';
        return `
            <div class="feed-item">
                <div class="feed-item-top">
                    <span class="meta-tag">[${alert.source_type.toUpperCase()}]</span>
                    <span>${timeStr}</span>
                    <span class="incident-pill pill-${sev}">${sev}</span>
                </div>
                <div class="feed-item-sig">${escapeHtml(alert.signature)}</div>
                <div style="color: var(--text-dim); font-size: 0.72rem;">
                    SRC: ${alert.source_ip || 'None'} -> DST: ${alert.dest_ip || 'None'} | Proto: ${alert.protocol || 'TCP'}
                </div>
            </div>
        `;
    }).join('');
}

// Tab Switching
function switchRightTab(tab, btn) {
    state.activeTab = tab;
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    if (btn) btn.classList.add('active');

    document.getElementById('tab-content-mitre').classList.toggle('hidden', tab !== 'mitre');
    document.getElementById('tab-content-soar').classList.toggle('hidden', tab !== 'soar');
    document.getElementById('tab-content-feed').classList.toggle('hidden', tab !== 'feed');

    if (tab === 'mitre') fetchMitreMatrix();
    if (tab === 'soar') fetchSOARActions();
}

function filterIncidents(sev, btn) {
    state.activeFilter = sev;
    document.querySelectorAll('.filter-btn').forEach(b => {
        b.classList.remove('active');
        // re-apply colour class
        b.classList.remove('filter-p1', 'filter-p2', 'filter-p3');
    });
    if (btn) {
        btn.classList.add('active');
        if (sev === 'P1') btn.classList.add('filter-p1');
        if (sev === 'P2') btn.classList.add('filter-p2');
        if (sev === 'P3') btn.classList.add('filter-p3');
    }
    renderIncidents();
}

// Modal Controllers
async function openIncidentModal(incidentId) {
    const modal = document.getElementById('incident-modal');
    const titleEl = document.getElementById('modal-incident-title');
    const idEl = document.getElementById('modal-incident-id');
    const bodyEl = document.getElementById('modal-incident-body');

    try {
        const res = await fetch(`/api/incidents/${incidentId}`);
        if (!res.ok) return;
        const inc = await res.json();

        titleEl.textContent = inc.title;
        idEl.textContent = `ID: ${inc.incident_id}`;

        const triage = inc.triage || {};
        const alertFirst = inc.alerts && inc.alerts[0] ? inc.alerts[0] : {};
        const enrichment = alertFirst.enrichment || {};

        bodyEl.innerHTML = `
            <!-- Severity meta pills -->
            <div style="display:flex;flex-wrap:wrap;gap:6px;">
                <span class="incident-pill pill-${inc.severity}">${inc.severity} — ${inc.triage ? inc.triage.severity_label : 'ACTIVE'}</span>
                <span class="meta-tag">Tactic: <strong>${inc.mitre_tactic}</strong></span>
                <span class="meta-tag">Technique: <strong>${inc.mitre_technique_id}</strong> ${escapeHtml(inc.mitre_technique_name || '')}</span>
                <span class="meta-tag">Confidence: <strong style="color:var(--cyan-400)">${Math.round((triage.confidence_score || 0.95) * 100)}%</strong></span>
                <span class="meta-tag">Status: <strong style="color:${inc.status === 'CONTAINED' ? 'var(--emerald-400)' : 'var(--orange-400)'}">${inc.status}</strong></span>
            </div>

            <!-- AI Rationale -->
            <div>
                <div class="modal-section-title">AI Triage &amp; Decision Rationale</div>
                <div class="modal-code-block" style="color:#bcc9cd;font-size:12px;line-height:1.7;">
                    ${escapeHtml(triage.rationale || 'Automated AI classification executed.')}
                </div>
            </div>

            <!-- Threat Intel -->
            <div>
                <div class="modal-section-title">Threat Intelligence Enrichment</div>
                <div class="modal-code-block">
                    <div>Source IP: <strong>${inc.threat_actor_ip || 'None'}</strong></div>
                    <div>Provider: <strong>${enrichment.provider || 'local_threat_db'}</strong></div>
                    <div>Threat Score: <strong>${enrichment.source_ip_intel ? enrichment.source_ip_intel.threat_score : 0}/100</strong></div>
                    <div>Category: <strong>${enrichment.source_ip_intel ? enrichment.source_ip_intel.threat_type : 'N/A'}</strong></div>
                    <div>Country / ASN: <strong>${enrichment.source_ip_intel ? `${enrichment.source_ip_intel.country} / ${enrichment.source_ip_intel.asn}` : 'N/A'}</strong></div>
                </div>
            </div>

            <!-- SOAR Actions -->
            <div>
                <div class="modal-section-title">Automated SOAR Actions (${(inc.soar_actions || []).length})</div>
                <table class="modal-soar-table">
                    <thead><tr>
                        <th>Action</th><th>Target</th><th>Status</th><th>Rollback Command</th>
                    </tr></thead>
                    <tbody>
                        ${(inc.soar_actions || []).map(act => `
                            <tr>
                                <td>${formatActionBadge(act.action_type)}</td>
                                <td class="font-mono text-slate-200 text-xs">${escapeHtml(act.target)}</td>
                                <td>${formatStatusBadge(act.status)}</td>
                                <td class="font-mono text-slate-400 text-[11px]">${escapeHtml(act.rollback_command || 'N/A')}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>

            <!-- Footer actions -->
            <div style="display:flex;gap:8px;padding-top:4px;border-top:1px solid var(--border-dim);">
                <button class="btn btn-outline" onclick="closeIncidentModal()">Close</button>
                <button class="btn btn-cyan" onclick="openReportModal('${inc.incident_id}')">
                    <span class="material-symbols-outlined" style="font-size:15px;">description</span>
                    Open Forensic Report
                </button>
            </div>
        `;

        modal.classList.remove('hidden');
    } catch (err) {
        console.error('Error displaying incident:', err);
    }
}

function closeIncidentModal() {
    document.getElementById('incident-modal').classList.add('hidden');
}

function openReportModal(incidentId) {
    const modal = document.getElementById('report-modal');
    const idEl = document.getElementById('modal-report-incident-id');
    const iframe = document.getElementById('report-iframe');

    idEl.textContent = `Incident ID: ${incidentId}`;
    iframe.src = `/api/reports/${incidentId}/html`;
    modal.classList.remove('hidden');
}

function closeReportModal() {
    const modal = document.getElementById('report-modal');
    const iframe = document.getElementById('report-iframe');
    iframe.src = 'about:blank';
    modal.classList.add('hidden');
}

function printReportIframe() {
    const iframe = document.getElementById('report-iframe');
    if (iframe && iframe.contentWindow) {
        iframe.contentWindow.print();
    }
}

// SOAR Actions Reversibility
async function revertAction(actionId) {
    try {
        const res = await fetch(`/api/soar/revert/${actionId}`, { method: 'POST' });
        if (res.ok) {
            await fetchSOARActions();
            renderIncidents();
        }
    } catch (err) {
        console.error('Failed to revert action:', err);
    }
}

async function revertIncident(incidentId) {
    if (!confirm('Are you sure you want to revert all automated containment actions for this incident?')) return;
    try {
        const res = await fetch(`/api/soar/revert_incident/${incidentId}`, { method: 'POST' });
        if (res.ok) {
            await fetchInitialData();
        }
    } catch (err) {
        console.error('Failed to revert incident:', err);
    }
}

// Manual Override Trigger
function openManualOverrideModal() {
    document.getElementById('override-modal').classList.remove('hidden');
}

function closeManualOverrideModal() {
    document.getElementById('override-modal').classList.add('hidden');
}

async function submitManualOverride() {
    const actionType = document.getElementById('override-action-type').value;
    const target = document.getElementById('override-target').value.trim();
    const reason = document.getElementById('override-reason').value.trim();

    if (!target) {
        alert('Please specify a target (Host IP or Target).');
        return;
    }

    try {
        const res = await fetch('/api/soar/override', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                action_type: actionType,
                target: target,
                reason: reason
            })
        });

        if (res.ok) {
            closeManualOverrideModal();
            await fetchSOARActions();
        } else {
            alert('Failed to execute override.');
        }
    } catch (err) {
        console.error('Error submitting override:', err);
    }
}

// Open first available incident report (footer button)
function openReportsListModal() {
    const incidents = Object.values(state.incidents);
    if (incidents.length > 0) {
        openReportModal(incidents[0].incident_id);
    }
}

// In-Browser Attack Simulation & Demo Reset
async function triggerInBrowserSimulation() {
    const btn = document.getElementById('btn-run-sim');
    if (!btn) return;
    const originalText = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = `
        <span class="material-symbols-outlined text-[15px] animate-spin">sync</span>
        Simulating 5 Attacks...
    `;

    try {
        const res = await fetch('/api/simulate', { method: 'POST' });
        if (res.ok) {
            btn.innerHTML = `
                <span class="material-symbols-outlined text-[15px] text-emerald-950">check_circle</span>
                5/5 Contained!
            `;
            await fetchInitialData();
            setTimeout(() => {
                btn.innerHTML = originalText;
                btn.disabled = false;
            }, 3000);
        } else {
            alert('Simulation encountered an error.');
            btn.innerHTML = originalText;
            btn.disabled = false;
        }
    } catch (err) {
        console.error('Error during in-browser simulation:', err);
        btn.innerHTML = originalText;
        btn.disabled = false;
    }
}

async function triggerResetDemo() {
    if (!confirm('Reset SOC pipeline state to zero (clears all incidents and containment rules)?')) return;
    try {
        const res = await fetch('/api/reset', { method: 'POST' });
        if (res.ok) {
            state.incidents = {};
            state.alerts = [];
            state.soarActions = [];
            state.soarSummary = {
                total_actions: 0,
                quarantined_count: 0,
                blocked_ips_count: 0,
                revoked_tokens_count: 0,
            };
            refreshUI();
        }
    } catch (err) {
        console.error('Error resetting demo state:', err);
    }
}

function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, "&amp;")
              .replace(/</g, "&lt;")
              .replace(/>/g, "&gt;")
              .replace(/"/g, "&quot;")
              .replace(/'/g, "&#039;");
}

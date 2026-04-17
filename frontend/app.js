/* Project DUME — Frontend Logic (Phase 2) */

const API = '/api';

async function apiFetch(path, opts = {}) {
    try {
        const res = await fetch(API + path, opts);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return await res.json();
    } catch (err) {
        console.error('API error:', path, err);
        throw err;
    }
}

function severityBadge(sev) {
    if (!sev) return '';
    const s = sev.toLowerCase();
    const cls = ['critical','high','medium','low','info'].includes(s) ? s : 'info';
    return `<span class="badge badge-${cls}">${sev}</span>`;
}

function healthBadge(val) {
    if (val === true) return '<span class="badge badge-ok">OK</span>';
    if (val === false) return '<span class="badge badge-fail">FAIL</span>';
    return `<span class="badge badge-info">${val}</span>`;
}

function showStatus(id, msg, type) {
    const el = document.getElementById(id);
    if (!el) return;
    el.className = `status-msg show ${type}`;
    el.innerHTML = type === 'loading' ? `<span class="spinner"></span>${msg}` : msg;
}

function hideStatus(id) {
    const el = document.getElementById(id);
    if (el) el.className = 'status-msg';
}

function escapeHtml(s) {
    if (s === null || s === undefined) return '';
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function shortTs(ts) {
    if (!ts) return 'N/A';
    try { return new Date(ts).toLocaleString(); } catch { return ts; }
}

/* ── Dashboard (index.html) ──────────────────────────────────────────── */

async function loadDashboard() {
    try {
        const d = await apiFetch('/status');
        setText('baseline-status', d.baseline?.exists ? 'Yes' : 'No');
        setText('baseline-ts', shortTs(d.baseline?.timestamp));
        setText('last-severity', d.last_run?.severity?.toUpperCase() || 'N/A');
        setText('last-score', d.last_run?.total_score ?? 'N/A');
        setText('last-scan-ts', shortTs(d.last_run?.timestamp));
        setText('total-runs', d.total_runs ?? 0);
        setText('total-alerts', d.total_alerts ?? 0);
        setText('total-findings', d.total_findings ?? 0);

        const reportsData = await apiFetch('/reports');
        setText('total-reports', reportsData.length ?? 0);
    } catch (err) {
        showStatus('dash-status', 'Failed to load dashboard data', 'error');
    }
}

function setText(id, val) {
    const el = document.getElementById(id);
    if (el) el.textContent = val;
}

async function dashRunBaseline() {
    const btn = event.target;
    btn.disabled = true;
    showStatus('dash-status', 'Creating baseline...', 'loading');
    try {
        const r = await apiFetch('/run-baseline', { method: 'POST' });
        showStatus('dash-status', r.message || 'Baseline created', 'ok');
        setTimeout(() => loadDashboard(), 500);
    } catch (err) {
        showStatus('dash-status', 'Baseline creation failed', 'error');
    }
    btn.disabled = false;
}

async function dashRunDetection() {
    const btn = event.target;
    btn.disabled = true;
    showStatus('dash-status', 'Running detection cycle...', 'loading');
    try {
        const r = await apiFetch('/run-detection', { method: 'POST' });
        showStatus('dash-status',
            `Detection complete — score: ${r.total_score} (${r.severity})`, 'ok');
        setTimeout(() => loadDashboard(), 500);
    } catch (err) {
        showStatus('dash-status', 'Detection cycle failed', 'error');
    }
    btn.disabled = false;
}

/* ── Baseline page ───────────────────────────────────────────────────── */

async function loadBaseline() {
    try {
        const d = await apiFetch('/status');
        const b = d.baseline || {};
        setText('bl-exists', b.exists ? 'Yes' : 'No');
        setText('bl-ts', shortTs(b.timestamp));
        setText('bl-modules', b.modules ?? 0);
        setText('bl-sysctls', b.sysctls ?? 0);
        setText('bl-hashes', b.binary_hashes ?? 0);

        if (b.detail) {
            const pre = document.getElementById('bl-detail');
            if (pre) pre.textContent = JSON.stringify(b.detail, null, 2);
        }
    } catch (err) {
        showStatus('bl-status', 'Failed to load baseline', 'error');
    }
}

/* ── Runs page ───────────────────────────────────────────────────────── */

async function loadRuns() {
    try {
        const runs = await apiFetch('/runs?limit=50');
        const tbody = document.getElementById('runs-body');
        if (!tbody) return;
        if (runs.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--text-secondary)">No runs yet</td></tr>';
            return;
        }
        tbody.innerHTML = runs.map(r => `<tr>
            <td>${r.id}</td>
            <td>${shortTs(r.timestamp)}</td>
            <td>${severityBadge(r.severity)}</td>
            <td>${r.total_score}</td>
            <td>${r.total_findings_count ?? '-'}</td>
            <td>${escapeHtml(r.summary?.substring(0, 80))}</td>
        </tr>`).join('');
    } catch (err) {
        showStatus('runs-status', 'Failed to load runs', 'error');
    }
}

/* ── Alerts page ─────────────────────────────────────────────────────── */

async function loadAlerts() {
    try {
        const alerts = await apiFetch('/alerts?limit=50');
        const tbody = document.getElementById('alerts-body');
        if (!tbody) return;
        if (alerts.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--text-secondary)">No alerts yet</td></tr>';
            return;
        }
        tbody.innerHTML = alerts.map(a => `<tr>
            <td>${a.id}</td>
            <td>${shortTs(a.timestamp)}</td>
            <td>${severityBadge(a.severity)}</td>
            <td>${a.total_score}</td>
            <td>${escapeHtml(a.summary?.substring(0, 100))}</td>
        </tr>`).join('');
    } catch (err) {
        showStatus('alerts-status', 'Failed to load alerts', 'error');
    }
}

/* ── Findings page ───────────────────────────────────────────────────── */

async function loadFindings() {
    try {
        const findings = await apiFetch('/findings?limit=100');
        const tbody = document.getElementById('findings-body');
        if (!tbody) return;
        if (findings.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--text-secondary)">No findings yet</td></tr>';
            return;
        }
        tbody.innerHTML = findings.map(f => `<tr>
            <td>${f.id}</td>
            <td>${f.run_id ?? '-'}</td>
            <td><code>${escapeHtml(f.finding_type)}</code></td>
            <td>${severityBadge(f.severity)}</td>
            <td>${f.score}</td>
            <td>${escapeHtml(f.description?.substring(0, 100))}</td>
        </tr>`).join('');
    } catch (err) {
        showStatus('findings-status', 'Failed to load findings', 'error');
    }
}

/* ── Reports page ────────────────────────────────────────────────────── */

async function loadReports() {
    try {
        const reports = await apiFetch('/reports');
        const tbody = document.getElementById('reports-body');
        if (!tbody) return;
        if (reports.length === 0) {
            tbody.innerHTML = '<tr><td colspan="3" style="text-align:center;color:var(--text-secondary)">No reports yet</td></tr>';
            return;
        }
        tbody.innerHTML = reports.map(r => `<tr>
            <td><a href="/api/reports/${encodeURIComponent(r.filename)}" target="_blank">${escapeHtml(r.filename)}</a></td>
            <td>${shortTs(r.modified)}</td>
            <td>${r.size_bytes} B</td>
        </tr>`).join('');
    } catch (err) {
        showStatus('reports-status', 'Failed to load reports', 'error');
    }
}

/* ── Health page ─────────────────────────────────────────────────────── */

async function loadHealth() {
    try {
        const h = await apiFetch('/health');
        const container = document.getElementById('health-list');
        if (!container) return;
        const items = [
            ['Platform', h.platform],
            ['Python', h.python_version],
            ['Running in Docker', h.running_in_docker],
            ['/proc/modules Readable', h.proc_modules_readable],
            ['sysctl Readable', h.sysctl_readable],
            ['dmesg Available', h.dmesg_available],
            ['dmesg Accessible', h.dmesg_accessible],
            ['journalctl Available', h.journalctl_available],
            ['Audit Log Present', h.audit_log_present],
            ['Baseline Exists', h.baseline_exists],
            ['Database Backend', h.database_backend],
            ['Database Reachable', h.database_reachable],
            ['Report Dir Exists', h.report_dir_exists],
        ];
        container.innerHTML = items.map(([label, val]) =>
            `<div class="health-item">
                <span>${escapeHtml(label)}</span>
                ${healthBadge(val)}
            </div>`
        ).join('');
    } catch (err) {
        showStatus('health-status', 'Failed to load health data', 'error');
    }
}

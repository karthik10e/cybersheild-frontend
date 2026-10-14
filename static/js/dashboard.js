/**
 * CyberShield SOC Dashboard Controller
 * Real-time SSE streaming, telemetry polling, attack injection & mitigation.
 */

let audioAlertsEnabled = false;
let audioCtx = null;
let lastPacketCount = 0;
let lastThreatCount = 0;
let isSimulatorRunning = true;
let isSnifferRunning = false;
let sseSource = null;

// Initialize Web Audio API for threat sounds
function playThreatBeep(severity) {
    if (!audioAlertsEnabled) return;
    try {
        if (!audioCtx) audioCtx = new (window.AudioContext || window.webkitAudioContext)();
        const osc = audioCtx.createOscillator();
        const gain = audioCtx.createGain();
        osc.type = severity === 'CRITICAL' ? 'sawtooth' : 'sine';
        osc.frequency.setValueAtTime(severity === 'CRITICAL' ? 880 : 580, audioCtx.currentTime);
        gain.gain.setValueAtTime(0.08, audioCtx.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.001, audioCtx.currentTime + 0.25);
        osc.connect(gain);
        gain.connect(audioCtx.destination);
        osc.start();
        osc.stop(audioCtx.currentTime + 0.25);
    } catch (e) {
        console.debug('Audio error', e);
    }
}

// Format seconds into HH:MM:SS
function formatUptime(seconds) {
    const hrs = String(Math.floor(seconds / 3600)).padStart(2, '0');
    const mins = String(Math.floor((seconds % 3600) / 60)).padStart(2, '0');
    const secs = String(seconds % 60).padStart(2, '0');
    return `${hrs}:${mins}:${secs}`;
}

// Fetch & update global system statistics
async function fetchStats() {
    try {
        const res = await fetch('/api/stats');
        const stats = await res.json();

        // Update KPI values
        document.getElementById('stat-total-packets').textContent = stats.total_packets.toLocaleString();
        document.getElementById('stat-total-threats').textContent = stats.total_threats.toLocaleString();
        document.getElementById('stat-threat-rate').textContent = `${stats.threat_rate_percent}%`;
        document.getElementById('stat-blocked-ips').textContent = stats.blocked_ips_count;
        document.getElementById('stat-uptime').textContent = formatUptime(stats.uptime_seconds);

        // Update rate velocity for charts
        const currentTotal = stats.total_packets;
        const currentThreats = stats.total_threats;
        const pktsInSec = lastPacketCount > 0 ? Math.max(0, currentTotal - lastPacketCount) : 1;
        const threatsInSec = lastThreatCount > 0 ? Math.max(0, currentThreats - lastThreatCount) : 0;
        lastPacketCount = currentTotal;
        lastThreatCount = currentThreats;

        updateCharts(stats, pktsInSec, threatsInSec);

        // Update Simulator Status
        if (stats.simulator) {
            isSimulatorRunning = stats.simulator.is_running;
            const badge = document.getElementById('sim-status-badge');
            const toggleBtn = document.getElementById('btn-toggle-stream');
            if (isSimulatorRunning) {
                badge.className = 'badge badge-pulse';
                badge.innerHTML = `<span class="pulse-dot"></span> STREAMING (${stats.simulator.mode})`;
                toggleBtn.innerHTML = '<i class="fa-solid fa-pause"></i> Pause Stream';
            } else {
                badge.className = 'badge badge-safe';
                badge.textContent = 'STREAM PAUSED';
                toggleBtn.innerHTML = '<i class="fa-solid fa-play"></i> Resume Stream';
            }
        }

        // Update Sniffer Status
        if (stats.sniffer) {
            isSnifferRunning = stats.sniffer.is_running;
            const snifferBtn = document.getElementById('btn-toggle-sniffer');
            if (isSnifferRunning) {
                snifferBtn.className = 'btn btn-threat';
                snifferBtn.innerHTML = '<i class="fa-solid fa-stop"></i> Stop Live Sniffer';
            } else {
                snifferBtn.className = 'btn btn-cyan';
                snifferBtn.innerHTML = '<i class="fa-solid fa-satellite-dish"></i> Start Live Scapy Capture';
            }
        }

    } catch (err) {
        console.error('Failed to fetch stats:', err);
    }
}

// Append new packet to the real-time table
function appendPacketToTable(pkt) {
    const tbody = document.getElementById('live-packet-tbody');
    if (!tbody) return;

    const row = document.createElement('tr');
    if (pkt.is_attack) {
        row.classList.add('table-row-attack');
        playThreatBeep(pkt.severity);
    }

    // Severity badge style
    let sevBadge = `<span class="badge badge-safe">SAFE</span>`;
    if (pkt.severity === 'CRITICAL') sevBadge = `<span class="badge badge-threat"><i class="fa-solid fa-skull"></i> CRITICAL</span>`;
    else if (pkt.severity === 'HIGH') sevBadge = `<span class="badge badge-threat">HIGH</span>`;
    else if (pkt.severity === 'MEDIUM') sevBadge = `<span class="badge badge-purple">MEDIUM</span>`;
    else if (pkt.severity === 'LOW') sevBadge = `<span class="badge badge-cyan">LOW</span>`;

    // Classification badge
    let classBadge = `<span class="badge badge-safe">Normal</span>`;
    if (pkt.is_attack) {
        classBadge = `<span class="badge badge-threat">${pkt.attack_type}</span>`;
    }

    // Explainable insight
    const reasonText = (pkt.reasons && pkt.reasons.length > 0) ? pkt.reasons[0] : 'Normal flow signature';

    // Action button
    let actionBtn = `<span class="text-muted text-xs">Monitored</span>`;
    if (pkt.is_attack) {
        if (pkt.is_blocked) {
            actionBtn = `<span class="badge badge-threat"><i class="fa-solid fa-ban"></i> BLOCKED</span>`;
        } else {
            actionBtn = `<button class="btn btn-outline btn-xs" onclick="blockAttackerIp('${pkt.src_ip}')"><i class="fa-solid fa-ban"></i> Block IP</button>`;
        }
    }

    const confPercent = Math.round(pkt.confidence * 100);

    row.innerHTML = `
        <td>#${pkt.id}</td>
        <td>${pkt.time_str}</td>
        <td><b>${pkt.src_ip}</b></td>
        <td>${pkt.dst_ip}:${pkt.dst_port}</td>
        <td><span class="badge badge-cyan">${pkt.protocol}</span></td>
        <td>${pkt.service}</td>
        <td>${pkt.flag}</td>
        <td>${classBadge}</td>
        <td>
            <div class="d-flex align-items-center gap-1">
                <span>${confPercent}%</span>
            </div>
        </td>
        <td>${sevBadge}</td>
        <td title="${reasonText}" style="max-width: 260px; overflow: hidden; text-overflow: ellipsis;">${reasonText}</td>
        <td>${actionBtn}</td>
    `;

    // Prepend to top of table
    tbody.insertBefore(row, tbody.firstChild);

    // Limit to 50 rows in DOM to ensure zero browser lag
    if (tbody.children.length > 50) {
        tbody.removeChild(tbody.lastChild);
    }
}

// Connect to Server-Sent Events (SSE)
function initLiveStream() {
    if (!!window.EventSource) {
        sseSource = new EventSource('/api/stream');
        sseSource.onmessage = function (event) {
            const pkt = JSON.parse(event.data);
            appendPacketToTable(pkt);
        };
        sseSource.onerror = function () {
            console.debug('SSE disconnected, will reconnect...');
        };
    } else {
        // Fallback polling
        setInterval(async () => {
            try {
                const res = await fetch('/api/packets/recent?limit=1');
                const data = await res.json();
                if (data.length > 0) appendPacketToTable(data[0]);
            } catch (e) {}
        }, 800);
    }
}

// Trigger Instant Burst Attack
async function triggerBurst(attackType) {
    try {
        const res = await fetch('/api/simulate/burst', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ attack: attackType, count: 15 })
        });
        const data = await res.json();
        console.log('Burst attack triggered:', data);
    } catch (e) {
        alert('Failed to trigger burst: ' + e.message);
    }
}

// Toggle Simulator Pause/Resume
async function toggleSimulator() {
    try {
        const url = isSimulatorRunning ? '/api/simulate/stop' : '/api/simulate/start';
        await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ mode: 'mixed' }) });
        fetchStats();
    } catch (e) {
        console.error(e);
    }
}

// Toggle Live Scapy Capture
async function toggleLiveSniffer() {
    try {
        const url = isSnifferRunning ? '/api/sniff/stop' : '/api/sniff/start';
        const res = await fetch(url, { method: 'POST' });
        const data = await res.json();
        if (data.status === 'ERROR_NO_DRIVER') {
            alert('Live sniffing requires Npcap driver or elevated administrator privileges on Windows. The synthetic traffic generator is currently protecting the pipeline.');
        }
        fetchStats();
    } catch (e) {
        alert('Sniffer toggle error: ' + e.message);
    }
}

// Block Attacker IP directly from table action
async function blockAttackerIp(ip) {
    if (!ip) return;
    try {
        const res = await fetch('/api/firewall/block', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip: ip, reason: 'Manually quarantined from live SOC inspection stream' })
        });
        const data = await res.json();
        if (data.success) {
            alert(`IP ${ip} successfully blocked and firewall rule injected!`);
            fetchStats();
        }
    } catch (e) {
        alert('Failed to block IP: ' + e.message);
    }
}

// Clear table rows
function clearFeedTable() {
    const tbody = document.getElementById('live-packet-tbody');
    if (tbody) tbody.innerHTML = '';
}

// Document initialization
document.addEventListener('DOMContentLoaded', () => {
    // Mode Buttons Click Listeners
    document.querySelectorAll('.btn-mode').forEach(btn => {
        btn.addEventListener('click', async () => {
            document.querySelectorAll('.btn-mode').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            const mode = btn.dataset.mode;
            await fetch('/api/simulate/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ mode: mode, delay: 0.8 })
            });
            fetchStats();
        });
    });

    // Toggle Audio Alert Button
    const audioBtn = document.getElementById('toggle-audio-btn');
    if (audioBtn) {
        audioBtn.addEventListener('click', () => {
            audioAlertsEnabled = !audioAlertsEnabled;
            const icon = document.getElementById('audio-icon');
            if (audioAlertsEnabled) {
                audioBtn.classList.add('btn-cyan');
                icon.className = 'fa-solid fa-volume-high text-cyan';
                playThreatBeep('HIGH');
            } else {
                audioBtn.classList.remove('btn-cyan');
                icon.className = 'fa-solid fa-volume-xmark';
            }
        });
    }

    // Initial load
    fetchStats();
    setInterval(fetchStats, 1000);
    initLiveStream();
});

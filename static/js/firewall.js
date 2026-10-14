/**
 * CyberShield Active Defense & Firewall Controller
 */

async function loadFirewallData() {
    try {
        const res = await fetch('/api/firewall/list');
        const data = await res.json();

        const blockedList = data.blocked_ips || [];
        const incidents = data.incidents || [];

        document.getElementById('fw-blocked-count').textContent = blockedList.length;
        document.getElementById('fw-incidents-count').textContent = incidents.length;

        // Render Blocked IPs Table
        const blockedTbody = document.getElementById('blocked-ips-tbody');
        blockedTbody.innerHTML = '';

        if (blockedList.length === 0) {
            blockedTbody.innerHTML = `<tr><td colspan="7" class="text-center text-muted">No IPs currently quarantined. System clean.</td></tr>`;
        } else {
            let synthesizedCommands = "# Windows Command (netsh advfirewall)\n";
            let linuxCommands = "\n# Linux Command (iptables)\n";

            blockedList.forEach(item => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td><b><span class="text-threat">${item.ip}</span></b></td>
                    <td>${item.time_str || 'Just now'}</td>
                    <td><span class="badge badge-threat">${item.attack_type || 'Malicious'}</span></td>
                    <td>${item.reason}</td>
                    <td><code class="text-cyan">${item.rule_command || 'netsh advfirewall block'}</code></td>
                    <td><span class="badge badge-threat"><i class="fa-solid fa-lock"></i> ACTIVE DROP</span></td>
                    <td>
                        <button class="btn btn-outline btn-xs" onclick="unbanIp('${item.ip}')">
                            <i class="fa-solid fa-unlock"></i> Unban IP
                        </button>
                    </td>
                `;
                blockedTbody.appendChild(row);

                synthesizedCommands += `netsh advfirewall firewall add rule name="CyberShield_Block_${item.ip.replace(/\./g, '_')}" dir=in action=block remoteip=${item.ip}\n`;
                linuxCommands += `iptables -A INPUT -s ${item.ip} -j DROP\n`;
            });

            const codeBox = document.getElementById('firewall-rules-code');
            if (codeBox) codeBox.textContent = synthesizedCommands + linuxCommands;
        }

        // Render Incidents Audit Trail
        const incidentsTbody = document.getElementById('incidents-tbody');
        incidentsTbody.innerHTML = '';

        if (incidents.length === 0) {
            incidentsTbody.innerHTML = `<tr><td colspan="8" class="text-center text-muted">No security incidents logged yet.</td></tr>`;
        } else {
            incidents.forEach(inc => {
                const row = document.createElement('tr');
                if (inc.action === 'AUTO-BLOCKED') row.classList.add('table-row-attack');

                const confPct = Math.round(inc.confidence * 100);
                row.innerHTML = `
                    <td>#${inc.id}</td>
                    <td>${inc.time_str}</td>
                    <td><b>${inc.src_ip}</b></td>
                    <td>${inc.dst_ip}:${inc.dst_port}</td>
                    <td><span class="badge badge-cyan">${inc.protocol}</span></td>
                    <td><span class="badge badge-threat">${inc.attack_type}</span></td>
                    <td>${confPct}%</td>
                    <td><span class="badge ${inc.is_blocked ? 'badge-threat' : 'badge-purple'}">${inc.action}</span></td>
                `;
                incidentsTbody.appendChild(row);
            });
        }

    } catch (err) {
        console.error('Failed to load firewall data:', err);
    }
}

// Handle manual ban submit
async function handleManualBlock(e) {
    e.preventDefault();
    const ip = document.getElementById('block-ip-input').value.trim();
    const reason = document.getElementById('block-reason-input').value.trim();

    if (!ip) return;

    try {
        const res = await fetch('/api/firewall/block', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip: ip, reason: reason })
        });
        const data = await res.json();
        if (data.success) {
            document.getElementById('block-ip-input').value = '';
            document.getElementById('block-reason-input').value = '';
            loadFirewallData();
        } else {
            alert('Could not block IP (might be whitelisted or already blocked).');
        }
    } catch (err) {
        alert('Error: ' + err.message);
    }
}

// Handle unban button
async function unbanIp(ip) {
    if (!confirm(`Are you sure you want to unban and restore traffic from ${ip}?`)) return;

    try {
        const res = await fetch('/api/firewall/unblock', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip: ip })
        });
        const data = await res.json();
        if (data.success) {
            loadFirewallData();
        }
    } catch (err) {
        alert('Error: ' + err.message);
    }
}

document.addEventListener('DOMContentLoaded', () => {
    loadFirewallData();
    setInterval(loadFirewallData, 2500);
});

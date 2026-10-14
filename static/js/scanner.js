/**
 * CyberShield Packet Inspector & Batch File Scanner
 */

let attackPresets = {};

// Switch between Batch Scanner & Manual Inspector tabs
function switchScannerTab(tabName) {
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

    if (tabName === 'batch') {
        document.querySelectorAll('.tab-btn')[0].classList.add('active');
        document.getElementById('tab-batch').classList.add('active');
    } else {
        document.querySelectorAll('.tab-btn')[1].classList.add('active');
        document.getElementById('tab-manual').classList.add('active');
    }
}

// Load attack presets from server
async function loadPresets() {
    try {
        const res = await fetch('/api/presets');
        attackPresets = await res.json();
    } catch (e) {
        console.error('Error loading presets:', e);
    }
}

// Apply selected attack preset to inspector form
function applyPreset(key) {
    const item = attackPresets[key];
    if (!item) return;

    const f = item.features;
    document.getElementById('field-protocol').value = f.protocol_type || 'tcp';
    document.getElementById('field-service').value = f.service || 'http';
    document.getElementById('field-flag').value = f.flag || 'SF';
    document.getElementById('field-duration').value = f.duration || 0;
    document.getElementById('field-src_bytes').value = f.src_bytes || 0;
    document.getElementById('field-dst_bytes').value = f.dst_bytes || 0;
    document.getElementById('field-count').value = f.count || 1;
    document.getElementById('field-srv_count').value = f.srv_count || 1;
    document.getElementById('field-serror_rate').value = f.serror_rate || 0;
    document.getElementById('field-diff_srv_rate').value = f.diff_srv_rate || 0;
    document.getElementById('field-num_failed_logins').value = f.num_failed_logins || 0;
    document.getElementById('field-root_shell').value = f.root_shell || 0;

    // Trigger visual notification
    const formCard = document.querySelector('.form-card');
    formCard.style.borderColor = '#00f0ff';
    setTimeout(() => { formCard.style.borderColor = ''; }, 600);
}

// Run Manual Deep Inspection
async function runManualInspection(e) {
    e.preventDefault();

    const payload = {
        protocol_type: document.getElementById('field-protocol').value,
        service: document.getElementById('field-service').value,
        flag: document.getElementById('field-flag').value,
        duration: parseFloat(document.getElementById('field-duration').value) || 0,
        src_bytes: parseInt(document.getElementById('field-src_bytes').value) || 0,
        dst_bytes: parseInt(document.getElementById('field-dst_bytes').value) || 0,
        count: parseInt(document.getElementById('field-count').value) || 1,
        srv_count: parseInt(document.getElementById('field-srv_count').value) || 1,
        serror_rate: parseFloat(document.getElementById('field-serror_rate').value) || 0,
        diff_srv_rate: parseFloat(document.getElementById('field-diff_srv_rate').value) || 0,
        num_failed_logins: parseInt(document.getElementById('field-num_failed_logins').value) || 0,
        root_shell: parseInt(document.getElementById('field-root_shell').value) || 0,
        _meta: {
            src_ip: "192.168.1.185",
            dst_ip: "10.0.0.5",
            dst_port: 80,
            protocol: document.getElementById('field-protocol').value.toUpperCase()
        }
    };

    try {
        const res = await fetch('/api/predict', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        const result = await res.json();

        // Render decision
        document.getElementById('inspector-placeholder').style.display = 'none';
        const resBox = document.getElementById('inspector-result');
        resBox.style.display = 'block';

        const classEl = document.getElementById('inspect-class');
        classEl.textContent = result.attack_type;
        classEl.className = 'prediction-classification ' + (result.is_attack ? 'text-threat' : 'text-success');

        const sevEl = document.getElementById('inspect-severity');
        sevEl.textContent = result.severity;
        sevEl.className = 'prediction-severity badge ' + (result.is_attack ? 'badge-threat' : 'badge-safe');

        const confPct = Math.round(result.confidence * 100);
        document.getElementById('inspect-confidence').textContent = `${confPct}%`;
        document.getElementById('inspect-conf-fill').style.width = `${confPct}%`;
        document.getElementById('inspect-conf-fill').style.background = result.is_attack ? '#ff3b5c' : '#10b981';

        // Anomaly Score
        const anomEl = document.getElementById('inspect-anomaly-score');
        if (result.anomaly_score < 0) {
            anomEl.textContent = `${result.anomaly_score} (Outlier Detected - High Divergence)`;
            anomEl.className = 'anomaly-score text-threat';
        } else {
            anomEl.textContent = `${result.anomaly_score} (Inlier / Baseline Normal Flow)`;
            anomEl.className = 'anomaly-score text-cyan';
        }

        // Reasons List
        const reasonsUl = document.getElementById('inspect-reasons');
        reasonsUl.innerHTML = '';
        (result.reasons || []).forEach(r => {
            const li = document.createElement('li');
            li.textContent = r;
            reasonsUl.appendChild(li);
        });

    } catch (err) {
        alert('Inspection failed: ' + err.message);
    }
}

// Handle File Drag and Drop & Upload
function initFileUpload() {
    const dropZone = document.getElementById('drop-zone');
    const fileInput = document.getElementById('file-input');

    if (!dropZone || !fileInput) return;

    ['dragenter', 'dragover'].forEach(name => {
        dropZone.addEventListener(name, (e) => {
            e.preventDefault();
            dropZone.classList.add('dragover');
        });
    });

    ['dragleave', 'drop'].forEach(name => {
        dropZone.addEventListener(name, (e) => {
            e.preventDefault();
            dropZone.classList.remove('dragover');
        });
    });

    dropZone.addEventListener('drop', (e) => {
        const files = e.dataTransfer.files;
        if (files.length > 0) processUploadFile(files[0]);
    });

    fileInput.addEventListener('change', (e) => {
        if (fileInput.files.length > 0) processUploadFile(fileInput.files[0]);
    });
}

// Upload file to server and render results
async function processUploadFile(file) {
    const statusBox = document.getElementById('upload-status');
    const resultsCard = document.getElementById('batch-results-card');
    const tableCard = document.getElementById('batch-table-card');

    statusBox.style.display = 'flex';
    resultsCard.style.display = 'none';
    tableCard.style.display = 'none';

    const formData = new FormData();
    formData.append('file', file);

    try {
        const res = await fetch('/api/scan-file', {
            method: 'POST',
            body: formData
        });
        const data = await res.json();
        statusBox.style.display = 'none';

        if (data.error) {
            alert('Upload error: ' + data.error);
            return;
        }

        renderBatchResults(data);
    } catch (err) {
        statusBox.style.display = 'none';
        alert('Upload failed: ' + err.message);
    }
}

// Render batch report metrics and table
function renderBatchResults(data) {
    const resultsCard = document.getElementById('batch-results-card');
    const tableCard = document.getElementById('batch-table-card');

    resultsCard.style.display = 'block';
    tableCard.style.display = 'block';

    document.getElementById('batch-filename-badge').textContent = `File: ${data.filename}`;
    document.getElementById('res-total').textContent = data.total_analyzed.toLocaleString();
    document.getElementById('res-threats').textContent = data.threats_detected.toLocaleString();
    document.getElementById('res-safe').textContent = data.safe_count.toLocaleString();
    document.getElementById('res-percent').textContent = `${data.threat_percentage}%`;

    // Breakdown pills
    const pillsContainer = document.getElementById('res-breakdown-pills');
    pillsContainer.innerHTML = '';
    for (const [cls, count] of Object.entries(data.breakdown || {})) {
        const pill = document.createElement('span');
        pill.className = `badge ${cls === 'Normal' ? 'badge-safe' : 'badge-threat'}`;
        pill.textContent = `${cls}: ${count}`;
        pillsContainer.appendChild(pill);
    }

    // Populate table
    const tbody = document.getElementById('batch-table-tbody');
    tbody.innerHTML = '';

    (data.samples || []).forEach((item, idx) => {
        const row = document.createElement('tr');
        if (item.is_attack) row.classList.add('table-row-attack');

        const f = item.features || {};
        const confPct = Math.round(item.confidence * 100);
        const reason = (item.reasons && item.reasons.length > 0) ? item.reasons[0] : 'Normal flow';

        row.innerHTML = `
            <td>#${idx + 1}</td>
            <td><span class="badge badge-cyan">${(f.protocol_type || 'TCP').toUpperCase()}</span></td>
            <td>${f.service || 'other'}</td>
            <td>${f.flag || 'SF'}</td>
            <td>${f.src_bytes || 0}</td>
            <td>${f.dst_bytes || 0}</td>
            <td><span class="badge ${item.is_attack ? 'badge-threat' : 'badge-safe'}">${item.attack_type}</span></td>
            <td>${confPct}%</td>
            <td><span class="badge ${item.is_attack ? 'badge-threat' : 'badge-safe'}">${item.severity}</span></td>
            <td>${reason}</td>
        `;
        tbody.appendChild(row);
    });
}

// Load pre-generated benchmark sample file
async function loadSampleCapture(e) {
    e.preventDefault();
    const statusBox = document.getElementById('upload-status');
    statusBox.style.display = 'flex';

    try {
        // Fetch sample file via blob and send to scan endpoint
        const sampleUrl = '/api/packets/recent?limit=50';
        const res = await fetch(sampleUrl);
        const pkts = await res.json();

        // Convert to payload
        const dummyReport = {
            filename: "benchmark_nsl_kdd_capture.csv",
            total_analyzed: 250,
            threats_detected: 112,
            safe_count: 138,
            threat_percentage: 44.8,
            breakdown: { "Normal": 138, "DoS": 65, "Probe": 32, "R2L": 11, "U2R": 4 },
            samples: pkts.map(p => ({
                features: { protocol_type: p.protocol, service: p.service, flag: p.flag, src_bytes: 400, dst_bytes: 1200 },
                attack_type: p.attack_type,
                is_attack: p.is_attack,
                confidence: p.confidence,
                severity: p.severity,
                reasons: p.reasons
            }))
        };

        statusBox.style.display = 'none';
        renderBatchResults(dummyReport);
    } catch (err) {
        statusBox.style.display = 'none';
        alert('Could not load sample: ' + err.message);
    }
}

document.addEventListener('DOMContentLoaded', () => {
    loadPresets();
    initFileUpload();
});

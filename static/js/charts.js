/**
 * CyberShield Dashboard Chart.js Visualizations
 */

let timelineChart = null;
let attackTypeChart = null;
let protocolChart = null;

const MAX_TIMELINE_POINTS = 25;
const timelineLabels = [];
const packetsData = [];
const threatsData = [];

// Initialize Timeline Line Chart
function initTimelineChart() {
    const ctx = document.getElementById('timelineChart')?.getContext('2d');
    if (!ctx) return;

    // Pre-populate empty labels
    for (let i = MAX_TIMELINE_POINTS; i >= 0; i--) {
        timelineLabels.push('');
        packetsData.push(0);
        threatsData.push(0);
    }

    timelineChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: timelineLabels,
            datasets: [
                {
                    label: 'Total Packets/s',
                    data: packetsData,
                    borderColor: '#00f0ff',
                    backgroundColor: 'rgba(0, 240, 255, 0.1)',
                    borderWidth: 2,
                    tension: 0.35,
                    fill: true,
                    pointRadius: 1
                },
                {
                    label: 'Threats/s',
                    data: threatsData,
                    borderColor: '#ff3b5c',
                    backgroundColor: 'rgba(255, 59, 92, 0.2)',
                    borderWidth: 2,
                    tension: 0.35,
                    fill: true,
                    pointRadius: 2,
                    pointBackgroundColor: '#ff3b5c'
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: false,
            plugins: {
                legend: {
                    labels: { color: '#94a3b8', font: { family: 'Inter', size: 11 } }
                }
            },
            scales: {
                x: {
                    grid: { color: 'rgba(255, 255, 255, 0.04)' },
                    ticks: { display: false }
                },
                y: {
                    beginAtZero: true,
                    grid: { color: 'rgba(255, 255, 255, 0.05)' },
                    ticks: { color: '#94a3b8', font: { family: 'JetBrains Mono', size: 10 } }
                }
            }
        }
    });
}

// Initialize Threat Classification Donut Chart
function initAttackTypeChart() {
    const ctx = document.getElementById('attackTypeChart')?.getContext('2d');
    if (!ctx) return;

    attackTypeChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['DoS', 'Probe', 'R2L', 'U2R', 'Zero-Day', 'Normal'],
            datasets: [{
                data: [0, 0, 0, 0, 0, 1],
                backgroundColor: [
                    '#ff3b5c', // DoS (Red)
                    '#a855f7', // Probe (Purple)
                    '#f59e0b', // R2L (Amber)
                    '#e11d48', // U2R (Rose)
                    '#f97316', // Zero-Day (Orange)
                    '#10b981'  // Normal (Green)
                ],
                borderWidth: 1,
                borderColor: '#0a111e'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '68%',
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { color: '#94a3b8', font: { family: 'Inter', size: 10 }, boxWidth: 10 }
                }
            }
        }
    });
}

// Initialize Protocol Bar Chart
function initProtocolChart() {
    const ctx = document.getElementById('protocolChart')?.getContext('2d');
    if (!ctx) return;

    protocolChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ['TCP', 'UDP', 'ICMP'],
            datasets: [{
                label: 'Volume',
                data: [0, 0, 0],
                backgroundColor: [
                    'rgba(0, 240, 255, 0.7)',
                    'rgba(168, 85, 247, 0.7)',
                    'rgba(245, 158, 11, 0.7)'
                ],
                borderColor: ['#00f0ff', '#a855f7', '#f59e0b'],
                borderWidth: 1,
                borderRadius: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false }
            },
            scales: {
                x: {
                    grid: { display: false },
                    ticks: { color: '#94a3b8', font: { family: 'JetBrains Mono', size: 11 } }
                },
                y: {
                    beginAtZero: true,
                    grid: { color: 'rgba(255, 255, 255, 0.05)' },
                    ticks: { color: '#94a3b8', font: { family: 'JetBrains Mono', size: 10 } }
                }
            }
        }
    });
}

// Updates charts with real-time telemetry stats
function updateCharts(stats, recentPktsInSec, recentThreatsInSec) {
    if (timelineChart) {
        timelineLabels.shift();
        timelineLabels.push(new Date().toLocaleTimeString());
        packetsData.shift();
        packetsData.push(recentPktsInSec);
        threatsData.shift();
        threatsData.push(recentThreatsInSec);
        timelineChart.update();
    }

    if (attackTypeChart && stats.attacks_by_type) {
        const at = stats.attacks_by_type;
        const normalCount = Math.max(0, stats.total_packets - stats.total_threats);
        attackTypeChart.data.datasets[0].data = [
            at['DoS'] || 0,
            at['Probe'] || 0,
            at['R2L'] || 0,
            at['U2R'] || 0,
            at['Zero-Day Anomaly'] || 0,
            normalCount
        ];
        attackTypeChart.update();
    }

    if (protocolChart && stats.protocol_distribution) {
        const pd = stats.protocol_distribution;
        protocolChart.data.datasets[0].data = [
            pd['TCP'] || 0,
            pd['UDP'] || 0,
            pd['ICMP'] || 0
        ];
        protocolChart.update();
    }
}

document.addEventListener('DOMContentLoaded', () => {
    initTimelineChart();
    initAttackTypeChart();
    initProtocolChart();
});

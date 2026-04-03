/* ═══════════════════════════════════════════════════════════════════════════
   IDS with Machine Learning – Charts & Interactions (Chart.js)
   ═══════════════════════════════════════════════════════════════════════════ */

// ── Color Palette ────────────────────────────────────────────────────────────
const COLORS = {
    green:  '#27AE60',
    red:    '#E74C3C',
    orange: '#F39C12',
    blue:   '#3498DB',
    yellow: '#F1C40F',
    teal:   '#1ABC9C',
    purple: '#9B59B6',
};

const ATTACK_COLORS = {
    'Normal':              COLORS.green,
    'Brute Force':         COLORS.red,
    'Port Scanning':       COLORS.orange,
    'DDoS Attack':         COLORS.red,
    'Service Exploit':     COLORS.purple,
    'DNS Spoofing':        COLORS.yellow,
    'MITM Attack':         COLORS.teal,
    'Suspicious Activity': COLORS.blue,
};

// ── Dashboard Charts ─────────────────────────────────────────────────────────
function initDashboardCharts(attackTypes, total, attacks, benign) {
    // Overview of Network Activity – Line Chart
    const activityCtx = document.getElementById('activityChart');
    if (activityCtx) {
        new Chart(activityCtx, {
            type: 'line',
            data: {
                labels: ['00', '04', '08', '12', '16', '20', '24'],
                datasets: [
                    {
                        label: 'Total Traffic',
                        data: [total||0, Math.round((total||0)*0.8), Math.round((total||0)*0.6), Math.round((total||0)*0.9), Math.round((total||0)*0.7), Math.round((total||0)*0.85), total||0],
                        borderColor: COLORS.green,
                        backgroundColor: COLORS.green + '20',
                        tension: 0.4,
                        fill: true,
                        pointRadius: 5,
                        pointBackgroundColor: COLORS.green,
                    },
                    {
                        label: 'Threats Detected',
                        data: [attacks||0, Math.round((attacks||0)*0.5), Math.round((attacks||0)*1.2), attacks||0, Math.round((attacks||0)*0.8), Math.round((attacks||0)*0.6), attacks||0],
                        borderColor: COLORS.red,
                        backgroundColor: COLORS.red + '20',
                        tension: 0.4,
                        fill: true,
                        pointRadius: 5,
                        pointBackgroundColor: COLORS.red,
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { position: 'top' } },
                scales: {
                    y: { beginAtZero: true, grid: { color: '#F0F0F0' } },
                    x: { grid: { display: false } }
                }
            }
        });
    }

    // Distribution of Attack Types – Donut Chart
    const donutCtx = document.getElementById('attackDonutChart');
    if (donutCtx) {
        const labels = Object.keys(attackTypes).length > 0 ? Object.keys(attackTypes) : ['No Data'];
        const values = Object.keys(attackTypes).length > 0 ? Object.values(attackTypes) : [0];
        const colors = labels.map(l => ATTACK_COLORS[l] || COLORS.blue);

        new Chart(donutCtx, {
            type: 'doughnut',
            data: {
                labels: labels,
                datasets: [{ data: values, backgroundColor: colors, borderWidth: 0 }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '65%',
                plugins: {
                    legend: { display: true, position: 'bottom', labels: { font: { size: 11 }, usePointStyle: true, pointStyle: 'circle' } }
                }
            }
        });
    }

    // Algorithm Comparison – Bar Chart
    const algoCtx = document.getElementById('algoComparisonChart');
    if (algoCtx) {
        new Chart(algoCtx, {
            type: 'bar',
            data: {
                labels: ['Random Forest', 'Decision Tree', 'XGBoost'],
                datasets: [
                    { label: 'Accuracy (%)', data: [98.12, 98.06, 98.20], backgroundColor: COLORS.green },
                    { label: 'F1-Score (%)', data: [98.13, 98.07, 98.22], backgroundColor: COLORS.orange },
                    { label: 'Precision (%)', data: [98.17, 98.12, 98.25], backgroundColor: COLORS.yellow },
                    { label: 'Recall (%)', data: [98.12, 98.06, 98.18], backgroundColor: COLORS.blue }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { position: 'top', labels: { font: { size: 11 }, usePointStyle: true, pointStyle: 'circle' } } },
                scales: {
                    y: { beginAtZero: false, min: 0, max: 100, grid: { color: '#F0F0F0' } },
                    x: { grid: { display: false } }
                }
            }
        });
    }
}

// ── Report / Live Monitoring Charts ──────────────────────────────────────────
function initReportCharts(attackTypes, attacks, benign, barId, donutId) {
    barId = barId || 'reportBarChart';
    donutId = donutId || 'reportDonutChart';

    // Attack Types Distribution – Bar Chart
    const barCtx = document.getElementById(barId);
    if (barCtx) {
        const labels = Object.keys(attackTypes).length > 0 ? Object.keys(attackTypes) : ['No Data'];
        const values = Object.keys(attackTypes).length > 0 ? Object.values(attackTypes) : [0];
        const colors = labels.map(l => ATTACK_COLORS[l] || COLORS.blue);

        new Chart(barCtx, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [{ label: 'Count', data: values, backgroundColor: colors, borderRadius: 4 }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    y: { beginAtZero: true, grid: { color: '#F0F0F0' } },
                    x: { grid: { display: false } }
                }
            }
        });
    }

    // Prediction Results – Donut
    const donutCtx = document.getElementById(donutId);
    if (donutCtx) {
        new Chart(donutCtx, {
            type: 'doughnut',
            data: {
                labels: ['Attack', 'Normal'],
                datasets: [{
                    data: [attacks || 0, benign || 0],
                    backgroundColor: [COLORS.red, COLORS.green],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '65%',
                plugins: {
                    legend: { position: 'bottom', labels: { font: { size: 11 }, usePointStyle: true, pointStyle: 'circle' } }
                }
            }
        });
    }
}

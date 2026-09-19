/**
 * SCAMSHIELD AI - Dashboard Analytics & Chart.js Visualizations
 */

document.addEventListener('DOMContentLoaded', () => {
    // 1. Scam Risk Distribution Chart (Doughnut)
    const riskCtx = document.getElementById('riskChart');
    if (riskCtx) {
        const low = parseInt(riskCtx.getAttribute('data-low') || 0);
        const suspicious = parseInt(riskCtx.getAttribute('data-suspicious') || 0);
        const high = parseInt(riskCtx.getAttribute('data-high') || 0);

        new Chart(riskCtx, {
            type: 'doughnut',
            data: {
                labels: ['🟢 Low Risk', '🟡 Suspicious', '🔴 High Risk'],
                datasets: [{
                    data: [low, suspicious, high],
                    backgroundColor: [
                        '#10b981',
                        '#f59e0b',
                        '#ef4444'
                    ],
                    borderColor: '#0f172a',
                    borderWidth: 3
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            color: '#94a3b8',
                            font: { family: 'Plus Jakarta Sans', size: 12, weight: '600' }
                        }
                    }
                }
            }
        });
    }

    // 2. Scam Type Distribution Chart (Bar)
    const typeCtx = document.getElementById('typeChart');
    if (typeCtx) {
        const typesData = JSON.parse(typeCtx.getAttribute('data-types') || '{}');
        const labels = Object.keys(typesData);
        const counts = Object.values(typesData);

        new Chart(typeCtx, {
            type: 'bar',
            data: {
                labels: labels.length > 0 ? labels : ['No Data'],
                datasets: [{
                    label: 'Number of Scams Detected',
                    data: counts.length > 0 ? counts : [0],
                    backgroundColor: 'rgba(56, 189, 248, 0.7)',
                    borderColor: '#38bdf8',
                    borderWidth: 1,
                    borderRadius: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: {
                        ticks: { color: '#94a3b8', font: { family: 'Plus Jakarta Sans', size: 11 } },
                        grid: { color: 'rgba(255,255,255,0.05)' }
                    },
                    y: {
                        beginAtZero: true,
                        ticks: { color: '#94a3b8', precision: 0 },
                        grid: { color: 'rgba(255,255,255,0.05)' }
                    }
                },
                plugins: {
                    legend: { display: false }
                }
            }
        });
    }

    // 3. Real-Time Scam Trends Chart
    const trendCtx = document.getElementById('trendChart');
    if (trendCtx) {
        const trendData = JSON.parse(trendCtx.getAttribute('data-trends') || '{}');
        const labels = Object.keys(trendData);
        const values = Object.values(trendData);

        new Chart(trendCtx, {
            type: 'line',
            data: {
                labels: labels.length > 0 ? labels : ['Payment/UPI', 'Fake Job', 'Prize', 'Phishing'],
                datasets: [{
                    label: 'Platform Detected Instances',
                    data: values.length > 0 ? values : [12, 9, 7, 5],
                    borderColor: '#a855f7',
                    backgroundColor: 'rgba(168, 85, 247, 0.15)',
                    fill: true,
                    tension: 0.4,
                    pointBackgroundColor: '#a855f7',
                    pointRadius: 5
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: { ticks: { color: '#94a3b8' }, grid: { color: 'rgba(255,255,255,0.05)' } },
                    y: { beginAtZero: true, ticks: { color: '#94a3b8' }, grid: { color: 'rgba(255,255,255,0.05)' } }
                },
                plugins: {
                    legend: { display: false }
                }
            }
        });
    }
});

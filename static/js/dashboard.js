/**
 * RedOps Dashboard Controller
 * Initializes Chart.js charts for risk posture and severity distribution.
 */

let riskChart = null;
let severityChart = null;

document.addEventListener("DOMContentLoaded", () => {
    loadDashboardStats();
    // Auto-refresh stats every 45 seconds
    setInterval(loadDashboardStats, 45000);
});

async function loadDashboardStats() {
    try {
        const response = await fetch("/api/dashboard/stats");
        const data = await response.json();
        if (data.success) {
            updateDashboardMetrics(data.metrics);
            renderRiskChart(data.metrics);
            renderSeverityChart(data.metrics);
        }
    } catch (err) {
        console.error("Failed to load dashboard metrics:", err);
    }
}

function updateDashboardMetrics(m) {
    // Stat counters
    setText("statTotalAssets", m.total_assets);
    setText("statActiveHosts", m.active_hosts);
    setText("statOpenPorts", m.open_ports);
    setText("statTotalVulns", m.total_vulnerabilities);
    setText("statCriticalVulns", m.critical_vulns);
    setText("statHighVulns", m.high_vulns);
    setText("statAttackPaths", m.attack_paths);
    setText("statSimulations", m.completed_simulations);

    // Posture score
    const scoreEl = document.getElementById("postureScoreVal");
    const statusEl = document.getElementById("postureStatusBadge");
    if (scoreEl) scoreEl.textContent = `${m.posture_score}%`;
    if (statusEl) {
        statusEl.textContent = m.posture_status;
        statusEl.className = `badge ${m.posture_score < 40 ? 'badge-critical' : m.posture_score < 70 ? 'badge-high' : 'badge-success'}`;
    }
}

function setText(id, val) {
    const el = document.getElementById(id);
    if (el) el.textContent = val !== undefined ? val : "--";
}

function renderRiskChart(m) {
    const ctx = document.getElementById("riskDoughnutChart");
    if (!ctx) return;

    const healthyScore = m.posture_score;
    const riskScore = 100 - healthyScore;

    if (riskChart) riskChart.destroy();

    riskChart = new Chart(ctx, {
        type: "doughnut",
        data: {
            labels: ["Hardened Defense Posture", "Compromise Risk Factor"],
            datasets: [{
                data: [healthyScore, riskScore],
                backgroundColor: [
                    "#00e676",
                    "#ff2a5f"
                ],
                borderColor: "#080c14",
                borderWidth: 2,
                hoverOffset: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: "75%",
            plugins: {
                legend: {
                    position: "bottom",
                    labels: { color: "#8899b5", font: { size: 11 } }
                }
            }
        }
    });
}

function renderSeverityChart(m) {
    const ctx = document.getElementById("severityBarChart");
    if (!ctx) return;

    if (severityChart) severityChart.destroy();

    severityChart = new Chart(ctx, {
        type: "bar",
        data: {
            labels: ["Critical", "High", "Medium", "Low"],
            datasets: [{
                label: "Identified Vulnerabilities",
                data: [m.critical_vulns, m.high_vulns, m.medium_vulns, m.low_vulns],
                backgroundColor: [
                    "#ff2a5f",
                    "#ff7700",
                    "#ffb703",
                    "#00b4d8"
                ],
                borderRadius: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: { color: "#8899b5", stepSize: 1 },
                    grid: { color: "rgba(255, 255, 255, 0.05)" }
                },
                x: {
                    ticks: { color: "#8899b5" },
                    grid: { display: false }
                }
            },
            plugins: {
                legend: { display: false }
            }
        }
    });
}

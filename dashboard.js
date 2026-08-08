"use strict";
/// <reference path="common.ts" />
var OZ;
(function (OZ) {
    const $ = (sel) => document.querySelector(sel);
    const statTotal = $("#stat-total");
    const statAvg = $("#stat-avg");
    const statCommon = $("#stat-common");
    const historyBody = document.querySelector("#history-table tbody");
    const btnClear = $("#btn-clear-history");
    const quickInput = $("#quick-input");
    const PALETTE = {
        "Very Weak": "#dc2626",
        "Weak": "#dc2626",
        "Fair": "#d97706",
        "Good": "#2563eb",
        "Strong": "#0ea5a0",
        "Excellent": "#16a34a",
    };
    function renderStats() {
        const history = OZ.getHistory();
        statTotal.textContent = String(history.length);
        if (history.length === 0) {
            statAvg.textContent = "0";
            statCommon.textContent = "—";
            return;
        }
        const avg = Math.round(history.reduce((sum, h) => sum + h.score, 0) / history.length);
        statAvg.textContent = String(avg);
        const counts = {};
        history.forEach((h) => (counts[h.level] = (counts[h.level] || 0) + 1));
        const common = Object.entries(counts).sort((a, b) => b[1] - a[1])[0];
        statCommon.textContent = common ? common[0] : "—";
        historyBody.innerHTML = "";
        history.slice(0, 12).forEach((h) => {
            const tr = document.createElement("tr");
            const time = new Date(h.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
            tr.innerHTML = `<td>${time}</td><td class="oz-mono">${h.score}</td><td style="color:${PALETTE[h.level]}; font-weight:600;">${OZ.escapeHtml(h.level)}</td><td class="oz-mono">${h.entropyBits.toFixed(1)} b</td>`;
            historyBody.appendChild(tr);
        });
        renderLevelChart(counts);
        renderEntropyChart(history.slice(0, 20).reverse());
    }
    let levelChart, entropyChart, distChart, radarChart;
    function renderLevelChart(counts) {
        const ctx = $("#chart-levels").getContext("2d");
        const labels = ["Very Weak", "Weak", "Fair", "Good", "Strong", "Excellent"];
        const data = labels.map((l) => counts[l] || 0);
        if (levelChart)
            levelChart.destroy();
        levelChart = new Chart(ctx, {
            type: "bar",
            data: {
                labels,
                datasets: [{ data, backgroundColor: labels.map((l) => PALETTE[l]), borderRadius: 6, maxBarThickness: 36 }],
            },
            options: {
                plugins: { legend: { display: false } },
                scales: { y: { beginAtZero: true, ticks: { precision: 0 } } },
            },
        });
    }
    function renderEntropyChart(history) {
        const ctx = $("#chart-entropy").getContext("2d");
        if (entropyChart)
            entropyChart.destroy();
        entropyChart = new Chart(ctx, {
            type: "line",
            data: {
                labels: history.map((_, i) => `#${i + 1}`),
                datasets: [{
                        data: history.map((h) => h.entropyBits),
                        borderColor: "#0ea5a0",
                        backgroundColor: "rgba(14,165,160,0.12)",
                        fill: true,
                        tension: 0.35,
                        pointRadius: 3,
                    }],
            },
            options: {
                plugins: { legend: { display: false } },
                scales: { y: { beginAtZero: true } },
            },
        });
    }
    function renderDistribution(pw) {
        const result = OZ.analyzePassword(pw);
        const quickExplain = document.getElementById("quick-explain");
        if (quickExplain)
            quickExplain.textContent = pw ? OZ.explainLevel(result) : "";
        const ctx = $("#chart-distribution").getContext("2d");
        if (distChart)
            distChart.destroy();
        distChart = new Chart(ctx, {
            type: "doughnut",
            data: {
                labels: Object.keys(result.charDistribution),
                datasets: [{
                        data: Object.values(result.charDistribution),
                        backgroundColor: ["#0ea5a0", "#4a5fea", "#2563eb", "#d97706"],
                        borderWidth: 0,
                    }],
            },
            options: { plugins: { legend: { position: "bottom", labels: { boxWidth: 10, font: { size: 11 } } } } },
        });
        const radarCtx = $("#chart-radar").getContext("2d");
        if (radarChart)
            radarChart.destroy();
        const norm = (v, max) => Math.min(100, Math.round((v / max) * 100));
        radarChart = new Chart(radarCtx, {
            type: "radar",
            data: {
                labels: ["Length", "Diversity", "Entropy", "Unpredictability", "No patterns"],
                datasets: [{
                        label: "This password",
                        data: [
                            norm(result.length, 20),
                            norm(new Set(pw.split("")).size / (pw.length || 1) * 100, 100),
                            norm(result.entropyBits, 100),
                            norm(result.heatmap.filter((h) => h.category === "strong").length, result.length || 1),
                            norm(result.checks.filter((c) => c.passed).length, result.checks.length),
                        ],
                        borderColor: "#0ea5a0",
                        backgroundColor: "rgba(14,165,160,0.2)",
                        pointBackgroundColor: "#0ea5a0",
                    }],
            },
            options: {
                scales: { r: { beginAtZero: true, max: 100, ticks: { display: false } } },
                plugins: { legend: { display: false } },
            },
        });
    }
    quickInput.addEventListener("input", OZ.debounce(() => renderDistribution(quickInput.value), 150));
    btnClear.addEventListener("click", () => {
        OZ.clearHistory();
        renderStats();
        OZ.showToast("Local history cleared", "info");
    });
    OZ.initMobileNav();
    OZ.initThemeSwitcher();
    OZ.initFactsCarousel("fact-text");
    renderStats();
    renderDistribution("");
})(OZ || (OZ = {}));

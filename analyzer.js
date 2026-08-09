"use strict";
/// <reference path="common.ts" />
/**
 * SekPass — analyzer.ts
 * Wires the Analyzer page UI to the pure functions in common.ts.
 * No password is ever logged, stored verbatim, or transmitted.
 */
var OZ;
(function (OZ) {
    const $ = (sel) => document.querySelector(sel);
    const pwInput = $("#pw-input");
    const lengthReadout = $("#length-readout");
    const heatmapEl = $("#heatmap");
    const scoreValue = $("#score-value");
    const scoreBar = $("#score-bar");
    const levelPill = $("#level-pill");
    const levelExplain = $("#level-explain");
    const entropyGauge = $("#entropy-gauge");
    const entropyValue = $("#entropy-value");
    const entropyLabel = $("#entropy-label");
    const checksList = $("#checks-list");
    const crackTable = $("#crack-table tbody");
    const suggestionsList = $("#suggestions-list");
    const breachResult = $("#breach-result");
    const btnToggle = $("#btn-toggle-visibility");
    const btnCopy = $("#btn-copy");
    const btnClear = $("#btn-clear");
    const btnBreach = $("#btn-check-breach");
    const btnExport = $("#btn-export");
    const LEVEL_COLORS = {
        "Very Weak": { fg: "var(--oz-danger)", bg: "var(--oz-danger-soft)" },
        "Weak": { fg: "var(--oz-danger)", bg: "var(--oz-danger-soft)" },
        "Fair": { fg: "var(--oz-warning)", bg: "var(--oz-warning-soft)" },
        "Good": { fg: "var(--oz-info)", bg: "var(--oz-info-soft)" },
        "Strong": { fg: "var(--oz-accent-ink)", bg: "var(--oz-accent-soft)" },
        "Excellent": { fg: "var(--oz-safe)", bg: "var(--oz-safe-soft)" },
    };
    const SEVERITY_CLASS = {
        critical: "oz-heat-seg--critical",
        warning: "oz-heat-seg--warning",
        info: "oz-heat-seg--info",
        safe: "oz-heat-seg--safe",
    };
    let lastResult = null;
    let lastBreach = null;
    let visible = false;
    function renderHeatmap(result) {
        heatmapEl.innerHTML = "";
        if (!result.password) {
            heatmapEl.innerHTML = '<span class="oz-heatmap-empty">Your password heatmap will appear here as you type…</span>';
            return;
        }
        result.heatmap.forEach((seg, i) => {
            const span = document.createElement("span");
            span.className = `oz-heat-seg ${SEVERITY_CLASS[seg.severity]}`;
            span.style.animationDelay = `${i * 25}ms`;
            span.textContent = visible ? seg.text : "•".repeat(seg.text.length);
            span.title = seg.category === "strong" ? "Unpredictable segment" : seg.label;
            heatmapEl.appendChild(span);
        });
    }
    function renderScore(result) {
        scoreValue.textContent = String(result.score);
        scoreBar.style.width = `${result.score}%`;
        const colors = LEVEL_COLORS[result.level];
        scoreBar.style.background = colors.fg;
        levelPill.textContent = result.level;
        levelPill.style.color = colors.fg;
        levelPill.style.background = colors.bg;
        levelExplain.textContent = OZ.explainLevel(result);
    }
    function renderEntropyGauge(result) {
        const pct = Math.max(0, Math.min(1, result.entropyBits / 100));
        const r = 30;
        const c = 2 * Math.PI * r;
        const offset = c * (1 - pct);
        const colors = LEVEL_COLORS[result.level];
        entropyGauge.innerHTML = `
      <svg width="76" height="76" viewBox="0 0 76 76">
        <circle cx="38" cy="38" r="${r}" fill="none" stroke="var(--oz-border)" stroke-width="8"/>
        <circle cx="38" cy="38" r="${r}" fill="none" stroke="${colors.fg}" stroke-width="8"
          stroke-linecap="round" stroke-dasharray="${c}" stroke-dashoffset="${offset}"
          transform="rotate(-90 38 38)" style="transition: stroke-dashoffset 0.5s cubic-bezier(.22,1,.36,1);"/>
      </svg>`;
        entropyValue.textContent = `${result.entropyBits.toFixed(1)} bits`;
        entropyLabel.textContent = result.randomness;
    }
    function renderChecks(result) {
        checksList.innerHTML = "";
        for (const check of result.checks) {
            const row = document.createElement("div");
            row.className = "oz-check-row";
            row.innerHTML = `
        <div class="oz-check-icon ${check.passed ? "oz-check-icon--pass" : "oz-check-icon--fail"}">
          ${check.passed
                ? '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><path d="M5 13l4 4L19 7"/></svg>'
                : '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><path d="M6 6l12 12M18 6L6 18"/></svg>'}
        </div>
        <div>
          <div class="oz-check-label">${OZ.escapeHtml(check.label)}</div>
          <div class="oz-check-detail">${OZ.escapeHtml(check.detail)}</div>
        </div>`;
            checksList.appendChild(row);
        }
    }
    function renderCrackTimes(result) {
        crackTable.innerHTML = "";
        for (const c of result.crackTimes) {
            const tr = document.createElement("tr");
            tr.innerHTML = `<td>${OZ.escapeHtml(c.scenario)}</td><td class="oz-mono" style="text-align:right; font-weight:600;">${OZ.escapeHtml(c.human)}</td>`;
            crackTable.appendChild(tr);
        }
    }
    function renderSuggestions(result) {
        suggestionsList.innerHTML = "";
        for (const s of result.suggestions) {
            const li = document.createElement("li");
            li.textContent = s;
            suggestionsList.appendChild(li);
        }
    }
    function runAnalysis() {
        const pw = pwInput.value;
        const result = OZ.analyzePassword(pw);
        lastResult = result;
        lastBreach = null;
        breachResult.textContent = pw
            ? 'Click "Check breach status" above to look this password up.'
            : "Type a password, then check its breach status.";
        lengthReadout.textContent = `${result.length} character${result.length === 1 ? "" : "s"}`;
        renderHeatmap(result);
        renderScore(result);
        renderEntropyGauge(result);
        renderChecks(result);
        renderCrackTimes(result);
        renderSuggestions(result);
        if (pw.length > 0) {
            OZ.saveHistoryEntry({
                id: OZ.makeId(),
                timestamp: Date.now(),
                score: result.score,
                level: result.level,
                entropyBits: result.entropyBits,
                length: result.length,
                breached: null,
            });
        }
    }
    const debouncedAnalysis = OZ.debounce(runAnalysis, 120);
    pwInput.addEventListener("input", debouncedAnalysis);
    btnToggle.addEventListener("click", () => {
        visible = !visible;
        pwInput.type = visible ? "text" : "password";
        if (lastResult)
            renderHeatmap(lastResult);
    });
    btnCopy.addEventListener("click", async () => {
        if (!pwInput.value) {
            OZ.showToast("Nothing to copy yet", "error");
            return;
        }
        const ok = await OZ.copyToClipboard(pwInput.value);
        OZ.showToast(ok ? "Password copied to clipboard" : "Copy failed", ok ? "success" : "error");
    });
    btnClear.addEventListener("click", () => {
        pwInput.value = "";
        pwInput.focus();
        runAnalysis();
        OZ.showToast("Cleared", "info");
    });
    btnBreach.addEventListener("click", async () => {
        const pw = pwInput.value;
        if (!pw) {
            OZ.showToast("Type a password first", "error");
            return;
        }
        btnBreach.disabled = true;
        btnBreach.textContent = "Checking…";
        breachResult.innerHTML = '<span class="oz-skeleton" style="display:inline-block; width:220px; height:14px;"></span>';
        const result = await OZ.checkPwned(pw);
        lastBreach = result;
        btnBreach.disabled = false;
        btnBreach.textContent = "Check breach status";
        if (result.error) {
            breachResult.innerHTML = `<span style="color:var(--oz-warning);">Couldn't reach the breach database (${OZ.escapeHtml(result.error)}). Try again later.</span>`;
            return;
        }
        if (result.breached) {
            breachResult.innerHTML = `<span style="color:var(--oz-danger); font-weight:600;">⚠ Found in ${OZ.formatNumber(result.count)} known data breaches.</span> Choose a different password.`;
            OZ.showToast("This password has appeared in known breaches", "error");
        }
        else {
            breachResult.innerHTML = `<span style="color:var(--oz-safe); font-weight:600;">✓ Not found in any known breach.</span>`;
            OZ.showToast("No breach match found", "success");
        }
    });
    btnExport.addEventListener("click", () => {
        if (!lastResult || !lastResult.password) {
            OZ.showToast("Analyze a password first", "error");
            return;
        }
        exportReport(lastResult, lastBreach);
    });
    function exportReport(result, breach) {
        const date = new Date().toLocaleString();
        const breachLine = breach
            ? breach.error
                ? "Could not be checked (network unavailable)"
                : breach.breached
                    ? `Found in ${breach.count.toLocaleString()} known breaches`
                    : "Not found in any known breach"
            : "Not checked";
        const maskedLength = result.length;
        const html = `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>SEKPASS Security Report</title>
      <style>
        body{font-family:Inter,system-ui,sans-serif;color:#0b1f33;max-width:640px;margin:40px auto;padding:0 20px;}
        h1{font-size:20px;} table{width:100%;border-collapse:collapse;margin-top:16px;}
        td,th{padding:8px;border-bottom:1px solid #dce7f0;text-align:left;font-size:13.5px;}
        .badge{display:inline-block;padding:4px 10px;border-radius:999px;font-weight:700;font-size:12.5px;}
      </style></head><body>
      <h1>SEKPASS — Password Security Report</h1>
      <p style="color:#4a6178;font-size:13px;">Generated locally in your browser. The password itself is never included in this report.</p>
      <table>
        <tr><th>Date analyzed</th><td>${OZ.escapeHtml(date)}</td></tr>
        <tr><th>Password length</th><td>${maskedLength} characters</td></tr>
        <tr><th>Security score</th><td>${result.score} / 100</td></tr>
        <tr><th>Strength level</th><td>${OZ.escapeHtml(result.level)}</td></tr>
        <tr><th>Entropy</th><td>${result.entropyBits.toFixed(1)} bits (${OZ.escapeHtml(result.randomness)})</td></tr>
        <tr><th>Fastest realistic crack time</th><td>${OZ.escapeHtml(result.crackTimes[0]?.human ?? "n/a")} (${OZ.escapeHtml(result.crackTimes[0]?.scenario ?? "")})</td></tr>
        <tr><th>Breach status</th><td>${OZ.escapeHtml(breachLine)}</td></tr>
      </table>
      <h2 style="font-size:15px;margin-top:24px;">Recommendations</h2>
      <ul>${result.suggestions.map((s) => `<li>${OZ.escapeHtml(s)}</li>`).join("")}</ul>
      </body></html>`;
        const blob = new Blob([html], { type: "text/html" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `SekPass-report-${Date.now()}.html`;
        a.click();
        URL.revokeObjectURL(url);
        OZ.showToast("Report downloaded", "success");
    }
    document.addEventListener("keydown", (e) => {
        if (e.ctrlKey && e.key === "Enter") {
            e.preventDefault();
            btnBreach.click();
        }
    });
    OZ.initMobileNav();
    OZ.initThemeSwitcher();
    OZ.initFactsCarousel("fact-text");
    runAnalysis();
})(OZ || (OZ = {}));

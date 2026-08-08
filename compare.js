"use strict";
/// <reference path="common.ts" />
var OZ;
(function (OZ) {
    const $ = (sel) => document.querySelector(sel);
    const pwA = $("#pw-a");
    const pwB = $("#pw-b");
    const body = $("#compare-body");
    const banner = $("#winner-banner");
    document.querySelectorAll("[data-show-toggle]").forEach((btn) => {
        btn.addEventListener("click", () => {
            const id = btn.getAttribute("data-show-toggle");
            const input = document.getElementById(id);
            input.type = input.type === "password" ? "text" : "password";
        });
    });
    function row(label, a, b, aWins) {
        const tr = document.createElement("tr");
        tr.innerHTML = `
      <td style="font-weight:600;">${OZ.escapeHtml(label)}</td>
      <td class="oz-mono" style="${aWins === true ? "color:var(--oz-safe); font-weight:700;" : ""}">${OZ.escapeHtml(a)}</td>
      <td class="oz-mono" style="${aWins === false ? "color:var(--oz-safe); font-weight:700;" : ""}">${OZ.escapeHtml(b)}</td>`;
        body.appendChild(tr);
    }
    const explainA = document.getElementById("explain-a");
    const explainB = document.getElementById("explain-b");
    function render() {
        body.innerHTML = "";
        const a = pwA.value;
        const b = pwB.value;
        if (explainA)
            explainA.textContent = "";
        if (explainB)
            explainB.textContent = "";
        if (!a && !b) {
            banner.style.display = "none";
            row("Security score", "—", "—", null);
            row("Strength level", "—", "—", null);
            row("Entropy", "—", "—", null);
            row("Fastest crack time (GPU)", "—", "—", null);
            return;
        }
        const ra = OZ.analyzePassword(a);
        const rb = OZ.analyzePassword(b);
        row("Length", `${ra.length} chars`, `${rb.length} chars`, ra.length === rb.length ? null : ra.length > rb.length);
        row("Security score", `${ra.score} / 100`, `${rb.score} / 100`, ra.score === rb.score ? null : ra.score > rb.score);
        row("Strength level", ra.level, rb.level, null);
        row("Entropy", `${ra.entropyBits.toFixed(1)} bits`, `${rb.entropyBits.toFixed(1)} bits`, ra.entropyBits === rb.entropyBits ? null : ra.entropyBits > rb.entropyBits);
        const crackA = ra.crackTimes[ra.crackTimes.length - 1];
        const crackB = rb.crackTimes[rb.crackTimes.length - 1];
        row("Fastest crack time (GPU)", crackA?.human ?? "—", crackB?.human ?? "—", ra.entropyBits === rb.entropyBits ? null : ra.entropyBits > rb.entropyBits);
        row("Failed checks", String(ra.checks.filter((c) => !c.passed).length), String(rb.checks.filter((c) => !c.passed).length), null);
        if (explainA)
            explainA.textContent = a ? OZ.explainLevel(ra) : "";
        if (explainB)
            explainB.textContent = b ? OZ.explainLevel(rb) : "";
        if (a && b) {
            banner.style.display = "flex";
            if (ra.score === rb.score) {
                banner.innerHTML = `<span>Both passwords score equally at ${ra.score}/100.</span>`;
            }
            else {
                const winner = ra.score > rb.score ? "A" : "B";
                const winnerScore = Math.max(ra.score, rb.score);
                banner.innerHTML = `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" style="flex-shrink:0;"><path d="M12 15a5 5 0 005-5V4H7v6a5 5 0 005 5z"/><path d="M7 4H3v2a4 4 0 004 4M17 4h4v2a4 4 0 01-4 4"/><path d="M12 15v4m-3 2h6"/></svg>
          <span><strong>Password ${winner}</strong> is stronger — scoring ${winnerScore}/100 vs ${Math.min(ra.score, rb.score)}/100.</span>`;
            }
        }
        else {
            banner.style.display = "none";
        }
    }
    pwA.addEventListener("input", OZ.debounce(render, 120));
    pwB.addEventListener("input", OZ.debounce(render, 120));
    OZ.initMobileNav();
    OZ.initThemeSwitcher();
    render();
})(OZ || (OZ = {}));

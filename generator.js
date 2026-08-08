"use strict";
/// <reference path="common.ts" />
var OZ;
(function (OZ) {
    const $ = (sel) => document.querySelector(sel);
    const SCRAMBLE_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
    // ── Tabs ──
    const tabPassword = $("#tab-password");
    const tabPassphrase = $("#tab-passphrase");
    const tabPersonalize = $("#tab-personalize");
    const panelPassword = $("#panel-password");
    const panelPassphrase = $("#panel-passphrase");
    const panelPersonalize = $("#panel-personalize");
    function setTab(tab) {
        panelPassword.style.display = tab === "password" ? "" : "none";
        panelPassphrase.style.display = tab === "passphrase" ? "" : "none";
        panelPersonalize.style.display = tab === "personalize" ? "" : "none";
        tabPassword.className = `oz-btn ${tab === "password" ? "oz-btn--primary" : "oz-btn--secondary"}`;
        tabPassphrase.className = `oz-btn ${tab === "passphrase" ? "oz-btn--primary" : "oz-btn--secondary"}`;
        tabPersonalize.className = `oz-btn ${tab === "personalize" ? "oz-btn--primary" : "oz-btn--secondary"}`;
    }
    tabPassword.addEventListener("click", () => setTab("password"));
    tabPassphrase.addEventListener("click", () => setTab("passphrase"));
    tabPersonalize.addEventListener("click", () => setTab("personalize"));
    // ── Password generator ──
    const lengthSlider = $("#length-slider");
    const lengthReadout = $("#length-readout-gen");
    const pwOutput = $("#pw-output");
    const pwPill = $("#pw-strength-pill");
    const pwEntropyReadout = $("#pw-entropy-readout");
    const optUpper = $("#opt-upper");
    const optLower = $("#opt-lower");
    const optNumbers = $("#opt-numbers");
    const optSymbols = $("#opt-symbols");
    const optExclude = $("#opt-exclude");
    const btnGeneratePw = $("#btn-generate-pw");
    const btnRegenPw = $("#btn-regen-pw");
    const btnCopyPw = $("#btn-copy-pw");
    function wireToggle(btn) {
        btn.addEventListener("click", () => {
            const checked = btn.getAttribute("aria-checked") === "true";
            btn.setAttribute("aria-checked", String(!checked));
        });
    }
    [optUpper, optLower, optNumbers, optSymbols, optExclude].forEach(wireToggle);
    lengthSlider.addEventListener("input", () => (lengthReadout.textContent = lengthSlider.value));
    function isOn(btn) {
        return btn.getAttribute("aria-checked") === "true";
    }
    const LEVEL_COLORS = {
        "Very Weak": { fg: "var(--oz-danger)", bg: "var(--oz-danger-soft)" },
        "Weak": { fg: "var(--oz-danger)", bg: "var(--oz-danger-soft)" },
        "Fair": { fg: "var(--oz-warning)", bg: "var(--oz-warning-soft)" },
        "Good": { fg: "var(--oz-info)", bg: "var(--oz-info-soft)" },
        "Strong": { fg: "var(--oz-accent-ink)", bg: "var(--oz-accent-soft)" },
        "Excellent": { fg: "var(--oz-safe)", bg: "var(--oz-safe-soft)" },
    };
    function animateReveal(el, finalText, onDone) {
        const frames = 10;
        let frame = 0;
        const timer = window.setInterval(() => {
            frame++;
            let display = "";
            for (let i = 0; i < finalText.length; i++) {
                const revealAt = (i / finalText.length) * frames;
                if (frame >= revealAt + frames * 0.4) {
                    display += finalText[i];
                }
                else {
                    display += SCRAMBLE_CHARS[Math.floor(Math.random() * SCRAMBLE_CHARS.length)];
                }
            }
            el.textContent = display;
            if (frame >= frames) {
                window.clearInterval(timer);
                el.textContent = finalText;
                onDone?.();
            }
        }, 35);
    }
    function generatePasswordFlow() {
        const opts = {
            length: parseInt(lengthSlider.value, 10),
            upper: isOn(optUpper),
            lower: isOn(optLower),
            numbers: isOn(optNumbers),
            symbols: isOn(optSymbols),
            excludeSimilar: isOn(optExclude),
        };
        if (!opts.upper && !opts.lower && !opts.numbers && !opts.symbols) {
            OZ.showToast("Enable at least one character type", "error");
            return;
        }
        const pw = OZ.generatePassword(opts);
        animateReveal(pwOutput, pw, () => {
            const analysis = OZ.analyzePassword(pw);
            const colors = LEVEL_COLORS[analysis.level];
            pwPill.textContent = analysis.level;
            pwPill.style.color = colors.fg;
            pwPill.style.background = colors.bg;
            pwEntropyReadout.textContent = `${analysis.entropyBits.toFixed(1)} bits of entropy`;
        });
    }
    btnGeneratePw.addEventListener("click", generatePasswordFlow);
    btnRegenPw.addEventListener("click", generatePasswordFlow);
    btnCopyPw.addEventListener("click", async () => {
        const text = pwOutput.textContent || "";
        if (!text || text === "Click Generate to begin") {
            OZ.showToast("Generate a password first", "error");
            return;
        }
        const ok = await OZ.copyToClipboard(text);
        OZ.showToast(ok ? "Password copied" : "Copy failed", ok ? "success" : "error");
    });
    // ── Passphrase generator ──
    const wordsSlider = $("#words-slider");
    const wordsReadout = $("#words-readout");
    const separatorSelect = $("#separator-select");
    const ppOutput = $("#pp-output");
    const ppPill = $("#pp-strength-pill");
    const ppEntropyReadout = $("#pp-entropy-readout");
    const ppOptCapitalize = $("#pp-opt-capitalize");
    const ppOptNumbers = $("#pp-opt-numbers");
    const ppOptSymbols = $("#pp-opt-symbols");
    const btnGeneratePp = $("#btn-generate-pp");
    const btnRegenPp = $("#btn-regen-pp");
    const btnCopyPp = $("#btn-copy-pp");
    [ppOptCapitalize, ppOptNumbers, ppOptSymbols].forEach(wireToggle);
    wordsSlider.addEventListener("input", () => (wordsReadout.textContent = wordsSlider.value));
    function generatePassphraseFlow() {
        const opts = {
            words: parseInt(wordsSlider.value, 10),
            separator: separatorSelect.value,
            capitalize: isOn(ppOptCapitalize),
            addNumbers: isOn(ppOptNumbers),
            addSymbols: isOn(ppOptSymbols),
        };
        const phrase = OZ.generatePassphrase(opts);
        animateReveal(ppOutput, phrase, () => {
            const analysis = OZ.analyzePassword(phrase);
            const colors = LEVEL_COLORS[analysis.level];
            ppPill.textContent = analysis.level;
            ppPill.style.color = colors.fg;
            ppPill.style.background = colors.bg;
            ppEntropyReadout.textContent = `${analysis.entropyBits.toFixed(1)} bits of entropy`;
        });
    }
    btnGeneratePp.addEventListener("click", generatePassphraseFlow);
    btnRegenPp.addEventListener("click", generatePassphraseFlow);
    btnCopyPp.addEventListener("click", async () => {
        const text = ppOutput.textContent || "";
        if (!text || text === "Click Generate to begin") {
            OZ.showToast("Generate a passphrase first", "error");
            return;
        }
        const ok = await OZ.copyToClipboard(text);
        OZ.showToast(ok ? "Passphrase copied" : "Copy failed", ok ? "success" : "error");
    });
    // ── Personalize & Strengthen ──
    const piName = $("#pi-name");
    const piDate = $("#pi-date");
    const piNumber = $("#pi-number");
    const paddingSlider = $("#padding-slider");
    const paddingReadout = $("#padding-readout");
    const piOptLeet = $("#pi-opt-leet");
    const piOptSymbols = $("#pi-opt-symbols");
    const piOptShuffle = $("#pi-opt-shuffle");
    const btnGeneratePi = $("#btn-generate-pi");
    const btnRegenPi = $("#btn-regen-pi");
    const btnCopyPi = $("#btn-copy-pi");
    const piOutput = $("#pi-output");
    const piPill = $("#pi-strength-pill");
    const piEntropyReadout = $("#pi-entropy-readout");
    const piSegments = $("#pi-segments");
    const piSteps = $("#pi-steps");
    [piOptLeet, piOptSymbols, piOptShuffle].forEach(wireToggle);
    paddingSlider.addEventListener("input", () => (paddingReadout.textContent = paddingSlider.value));
    const SEGMENT_LABEL = {
        name: "from name",
        date: "from date",
        number: "from number",
        random: "random padding",
    };
    function personalizeFlow() {
        const opts = {
            name: piName.value,
            date: piDate.value,
            number: piNumber.value,
            padding: parseInt(paddingSlider.value, 10),
            leetspeak: isOn(piOptLeet),
            addSymbols: isOn(piOptSymbols),
            shuffleSegments: isOn(piOptShuffle),
        };
        if (!opts.name.trim() && !opts.date.trim() && !opts.number.trim()) {
            OZ.showToast("Enter a name, date, or number first", "error");
            return;
        }
        const { password, segments } = OZ.buildFromPersonalInfo(opts);
        animateReveal(piOutput, password, () => {
            const analysis = OZ.analyzePassword(password);
            const colors = LEVEL_COLORS[analysis.level];
            piPill.textContent = analysis.level;
            piPill.style.color = colors.fg;
            piPill.style.background = colors.bg;
            piEntropyReadout.textContent = `${analysis.entropyBits.toFixed(1)} bits of entropy`;
            piSteps.innerHTML = `<li>${OZ.escapeHtml(OZ.explainLevel(analysis) || "Ready to use.")}</li>`;
        });
        piSegments.innerHTML = segments
            .map((s) => `<span class="oz-segment-chip oz-segment-chip--${s.source}">${SEGMENT_LABEL[s.source]}</span>`)
            .join("");
    }
    btnGeneratePi.addEventListener("click", personalizeFlow);
    btnRegenPi.addEventListener("click", personalizeFlow);
    btnCopyPi.addEventListener("click", async () => {
        const text = piOutput.textContent || "";
        if (!text || text.startsWith("Fill in")) {
            OZ.showToast("Generate a password first", "error");
            return;
        }
        const ok = await OZ.copyToClipboard(text);
        OZ.showToast(ok ? "Password copied" : "Copy failed", ok ? "success" : "error");
    });
    document.addEventListener("keydown", (e) => {
        if (e.ctrlKey && e.key === "Enter") {
            e.preventDefault();
            if (panelPassword.style.display !== "none")
                generatePasswordFlow();
            else if (panelPassphrase.style.display !== "none")
                generatePassphraseFlow();
            else
                personalizeFlow();
        }
    });
    OZ.initMobileNav();
    OZ.initThemeSwitcher();
    OZ.initFactsCarousel("fact-text");
    generatePasswordFlow();
})(OZ || (OZ = {}));

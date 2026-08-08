# SekPass — Password Strength Analyzer

A local-first, cybersecurity-grade password strength analyzer built with **HTML5, CSS3, TypeScript, and the Web Crypto API**. No frameworks. No servers. Nothing you type is ever transmitted, logged, or stored outside your own browser.

## Features

- **Real-time analyzer** — score (0–100), six-tier strength label, animated gauge and progress bar, updated as you type.
- **Personal information warnings** — flags passwords that contain a supplied name, username, email, or birth year.
- **11 security checks** — length, case mix, digits, symbols, character diversity, repeated runs, sequential runs, keyboard-walk patterns, common-password matches, and dictionary words, each with a pass/fail state and remediation tip.
- **Entropy calculator** — character-pool Shannon entropy in bits, with a plain-language explanation.
- **Crack time estimation** — separate brute-force and dictionary-attack estimates, formatted from seconds up to billions of years.
- **Secure password generator** — 8–64 character length, toggleable character sets, "exclude similar characters" mode, all randomness from `crypto.getRandomValues` (never `Math.random`).
- **Breach detection** — Have I Been Pwned integration using the **k-Anonymity** model: only the first 5 hex characters of a local SHA-1 hash are sent; your password and full hash never leave the browser.
- **Comparison tool** — score, entropy, and crack time for two passwords side by side, with a "which is stronger" verdict.
- **Security dashboard** — Chart.js character-distribution and strength-history charts, backed by a local, metadata-only history in `localStorage` (scores and lengths only — never raw passwords).
- **Export security report** — downloads a JSON report of score, checks, entropy, and crack times (never the password).
- **Education section** — short, practical password-security guidance.

## Project structure

```
Password-Analyzer/
├── index.html
├── css/
│   └── style.css
├── src/
│   ├── main.ts          # DOM wiring & app orchestration (entry point)
│   ├── analyzer.ts       # Core scoring & security-check engine
│   ├── generator.ts       # Secure password generation
│   ├── entropy.ts         # Entropy & crack-time calculations
│   ├── breachChecker.ts   # HIBP k-Anonymity breach lookup
│   ├── utils.ts            # Sanitization, hashing, shared helpers/data
│   └── types.ts             # Shared TypeScript interfaces
├── dist/                # Compiled JavaScript output (generated)
├── package.json
├── tsconfig.json
└── README.md
```

## Getting started

**Requirements:** Node.js (for the TypeScript compiler) and any static file server.

```bash
# Install the TypeScript compiler
npm install

# Compile src/*.ts -> dist/*.js
npm run build

# Serve the app locally
npm run serve
# then open http://localhost:8080
```

For active development, run `npm run watch` in one terminal and `npm run serve` in another; the browser will pick up recompiled files on refresh.

> The pre-built `dist/` folder in this project is already compiled and ready to open directly — you only need to run `npm run build` again after editing a `.ts` file.

## Security design notes

- **No network transmission of raw input.** The only outbound request the app makes is the 5-character SHA-1 prefix sent to the Pwned Passwords range API during a breach check.
- **No password logging or storage.** `localStorage` only ever holds score/strength/entropy/length metadata for the dashboard history — never the password string.
- **XSS mitigation.** Any user-influenced string written via `innerHTML` (warnings, compare labels) is passed through `sanitizeHtml()` first.
- **Cryptographically secure randomness.** The generator uses `crypto.getRandomValues` with rejection sampling to avoid modulo bias, never `Math.random()`.
- **Type safety.** `tsconfig.json` runs in `strict` mode with `noUnusedLocals`/`noUnusedParameters` to catch mistakes at compile time.

## Browser support

Any modern evergreen browser (Chrome, Firefox, Safari, Edge) with support for the Web Crypto API, ES2020 modules, and `<details>`/`<summary>`.

## License

MIT — build on it freely.

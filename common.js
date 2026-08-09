"use strict";
/**
 * SEKPASS— Password Strength Analyzer
 * common.ts
 *
 * Shared types, data sets and pure analysis functions used across every page.
 * SECURITY NOTE: nothing in this file ever sends a raw password anywhere.
 * The only network call made anywhere in the app is the k-Anonymity range
 * lookup against the HIBP breach API (see checkPwned), which only ever
 * transmits the first 5 hex characters of a SHA-1 hash — never the password
 * itself, and never the full hash.
 */
var OZ;
(function (OZ) {
    // ───────────────────────────── Types ──────────────────────────────
    // ───────────────────────────── Data ──────────────────────────────
    const CHAR_SETS = {
        lower: "abcdefghijklmnopqrstuvwxyz",
        upper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        numbers: "0123456789",
        symbols: "!@#$%^&*()_+-=[]{}|;:,.<>?/~`",
    };
    const SIMILAR_CHARS = "il1Lo0OI";
    // A representative sample of frequently breached / dictionary passwords.
    // Not exhaustive — used for fast local pattern matching only.
    OZ.COMMON_PASSWORDS = [
        "123456", "123456789", "12345678", "12345", "1234567", "password",
        "password1", "qwerty", "qwerty123", "111111", "123123", "abc123",
        "1q2w3e4r", "letmein", "welcome", "monkey", "dragon", "football",
        "iloveyou", "admin", "login", "starwars", "sunshine", "princess",
        "master", "hello", "freedom", "whatever", "trustno1", "superman",
        "shadow", "michael", "jennifer", "hunter", "baseball", "batman",
        "passw0rd", "p@ssw0rd", "p@ssword", "letmein123", "changeme",
        "welcome1", "qazwsx", "zaq12wsx", "1qaz2wsx", "asdfghjkl", "000000",
        "121212", "654321", "666666", "888888", "aaaaaa", "qwertyuiop",
        "iloveyou1", "charlie", "donald", "michelle", "jordan23", "asdf1234",
        "flower", "summer", "winter", "autumn", "ninja", "pokemon", "google",
        "facebook", "instagram", "twitter", "netflix", "amazon", "apple123",
    ];
    // Small offline dictionary used to flag plain dictionary words inside a
    // password (not the same list as COMMON_PASSWORDS — these are ordinary
    // words that weaken a password when used alone or lightly modified).
    OZ.DICTIONARY_WORDS = [
        "love", "hate", "money", "happy", "family", "friend", "school",
        "work", "music", "dance", "dream", "angel", "tiger", "eagle", "lion",
        "wolf", "snake", "spider", "flower", "ocean", "river", "mountain",
        "forest", "desert", "island", "planet", "galaxy", "rocket", "guitar",
        "soccer", "basketball", "cricket", "hockey", "tennis", "chicken",
        "coffee", "chocolate", "pizza", "burger", "cookie", "candy", "purple",
        "orange", "yellow", "silver", "golden", "crystal", "diamond", "phoenix",
        "dragon", "wizard", "knight", "castle", "kingdom", "warrior", "hunter",
        "champion", "victory", "legend", "hero", "master", "genius", "power",
        "secret", "mystery", "shadow", "thunder", "lightning", "storm", "rain",
        "snow", "fire", "water", "earth", "wind", "spirit", "soul", "heart",
    ];
    // Common first names used to flag personal-information style segments.
    OZ.COMMON_NAMES = [
        "james", "john", "robert", "michael", "william", "david", "richard",
        "joseph", "thomas", "charles", "mary", "patricia", "jennifer", "linda",
        "elizabeth", "barbara", "susan", "jessica", "sarah", "karen", "chichi",
        "chidi", "chioma", "amara", "kwame", "thabo", "amina", "fatima",
        "ahmed", "mohamed", "grace", "ruth", "peter", "paul", "george",
        "daniel", "matthew", "anthony", "mark", "steven", "andrew", "joshua",
        "kevin", "brian", "edward", "ronald", "timothy", "jason", "jeffrey",
        "chris", "kate", "emma", "olivia", "ava", "sophia", "mia", "amelia",
        "harper", "evelyn", "abigail", "emily", "ella", "madison", "chloe",
    ];
    // Rows / runs commonly typed on a QWERTY keyboard, forward and reverse.
    const KEYBOARD_ROWS = [
        "qwertyuiop",
        "asdfghjkl",
        "zxcvbnm",
        "1234567890",
        "!@#$%^&*()",
    ];
    OZ.KEYBOARD_PATTERNS = (() => {
        const patterns = new Set();
        for (const row of KEYBOARD_ROWS) {
            for (let i = 0; i <= row.length - 3; i++) {
                const fwd = row.slice(i, i + 3);
                patterns.add(fwd);
                patterns.add(fwd.split("").reverse().join(""));
            }
        }
        ["qwerty", "asdf", "zxcv", "qazwsx", "qweasd"].forEach((p) => patterns.add(p));
        return Array.from(patterns);
    })();
    OZ.CYBERSECURITY_FACTS = [
        "Weak passwords remain a leading cause of account compromise worldwide.",
        "Longer passphrases are often easier to remember and harder to crack than short complex passwords.",
        "Multi-factor authentication significantly reduces the risk of account takeover.",
        "Reusing the same password across sites means one breach can expose every account.",
        "A password manager lets you use a unique, random password for every account without memorizing them.",
        "Attackers use lists of billions of breached passwords to guess yours instantly — not just brute force.",
        "Adding a single random word can increase a password's entropy more than swapping letters for symbols.",
        "Most password crackers try dictionary words and common substitutions (a→@, e→3) before random guessing.",
        "Changing a password after a breach is only useful if it wasn't reused anywhere else.",
        "Biometrics and hardware security keys offer stronger protection than passwords alone.",
    ];
    // ───────────────────────────── Entropy & scoring ──────────────────────────────
    function poolSizeFor(pw) {
        let pool = 0;
        if (/[a-z]/.test(pw))
            pool += 26;
        if (/[A-Z]/.test(pw))
            pool += 26;
        if (/[0-9]/.test(pw))
            pool += 10;
        if (/[^a-zA-Z0-9]/.test(pw))
            pool += 33;
        return pool || 1;
    }
    OZ.poolSizeFor = poolSizeFor;
    /** Standard pool-size entropy estimate, in bits. */
    function calculateEntropy(pw) {
        if (pw.length === 0)
            return 0;
        const pool = poolSizeFor(pw);
        return +(pw.length * Math.log2(pool)).toFixed(2);
    }
    OZ.calculateEntropy = calculateEntropy;
    function randomnessLevel(bits) {
        if (bits < 28)
            return "Very Predictable";
        if (bits < 36)
            return "Predictable";
        if (bits < 60)
            return "Moderate";
        if (bits < 90)
            return "Random";
        return "Highly Random";
    }
    OZ.randomnessLevel = randomnessLevel;
    function scoreToLevel(score) {
        if (score < 20)
            return "Very Weak";
        if (score < 40)
            return "Weak";
        if (score < 60)
            return "Fair";
        if (score < 75)
            return "Good";
        if (score < 90)
            return "Strong";
        return "Excellent";
    }
    OZ.scoreToLevel = scoreToLevel;
    /**
     * Turns a bare strength label like "Weak" into a plain-language reason,
     * built from the specific checks and heatmap categories that hurt the
     * score most. Never invents a reason that isn't backed by a real signal.
     */
    function explainLevel(result) {
        if (!result.password)
            return "";
        const reasons = [];
        const failed = new Set(result.checks.filter((c) => !c.passed).map((c) => c.id));
        if (isCommonPassword(result.password))
            reasons.push("it's a widely known common password");
        if (result.heatmap.some((h) => h.category === "name"))
            reasons.push("it appears to include a personal name");
        if (result.heatmap.some((h) => h.category === "year"))
            reasons.push("it appears to include a birth year or date");
        if (failed.has("dictionary"))
            reasons.push("it contains a plain dictionary word");
        if (failed.has("keyboard"))
            reasons.push("it contains a keyboard-walk pattern like \u2018qwerty\u2019");
        if (failed.has("sequential"))
            reasons.push("it contains sequential characters like \u20181234\u2019");
        if (failed.has("repeated"))
            reasons.push("it repeats the same character several times in a row");
        if (result.length < 8)
            reasons.push(`it's only ${result.length} character${result.length === 1 ? "" : "s"} long`);
        else if (failed.has("length"))
            reasons.push(`it's just ${result.length} characters (12+ is recommended)`);
        if (failed.has("upper") && failed.has("lower"))
            reasons.push("it uses only one letter case");
        else if (failed.has("upper"))
            reasons.push("it has no uppercase letters");
        else if (failed.has("lower"))
            reasons.push("it has no lowercase letters");
        if (failed.has("number"))
            reasons.push("it has no numbers");
        if (failed.has("symbol"))
            reasons.push("it has no special characters");
        if (result.entropyBits < 28 && reasons.length === 0)
            reasons.push("its entropy is very low, making it highly predictable");
        if (reasons.length === 0) {
            return result.level === "Excellent" || result.level === "Strong"
                ? "This password passes every local check and has strong entropy."
                : "No major red flags found, but small changes would raise the score further.";
        }
        const top = reasons.slice(0, 3);
        const joined = top.length === 1 ? top[0] : top.slice(0, -1).join(", ") + " and " + top[top.length - 1];
        return `Rated ${result.level} because ${joined}.`;
    }
    OZ.explainLevel = explainLevel;
    // ───────────────────────────── Pattern detection ──────────────────────────────
    function findRuns(pw, matcher, minLen = 3) {
        const runs = [];
        let runStart = 0;
        for (let i = 1; i <= pw.length; i++) {
            const broke = i === pw.length || !matcher(pw[i - 1], pw[i]);
            if (broke) {
                if (i - runStart >= minLen)
                    runs.push({ start: runStart, end: i - 1 });
                runStart = i;
            }
        }
        return runs;
    }
    function detectRepeatedChars(pw) {
        return findRuns(pw, (a, b) => a === b, 3);
    }
    OZ.detectRepeatedChars = detectRepeatedChars;
    function detectSequentialChars(pw) {
        const asc = findRuns(pw, (a, b) => b.charCodeAt(0) - a.charCodeAt(0) === 1, 3);
        const desc = findRuns(pw, (a, b) => a.charCodeAt(0) - b.charCodeAt(0) === 1, 3);
        return [...asc, ...desc];
    }
    OZ.detectSequentialChars = detectSequentialChars;
    function detectKeyboardPatterns(pw) {
        const lower = pw.toLowerCase();
        const hits = [];
        for (const pattern of OZ.KEYBOARD_PATTERNS) {
            if (pattern.length < 3)
                continue;
            let idx = lower.indexOf(pattern);
            while (idx !== -1) {
                hits.push({ start: idx, end: idx + pattern.length - 1 });
                idx = lower.indexOf(pattern, idx + 1);
            }
        }
        return hits;
    }
    OZ.detectKeyboardPatterns = detectKeyboardPatterns;
    function detectYearPattern(pw) {
        const hits = [];
        const regex = /(19|20)\d{2}/g;
        let m;
        while ((m = regex.exec(pw)) !== null) {
            hits.push({ start: m.index, end: m.index + m[0].length - 1 });
        }
        return hits;
    }
    OZ.detectYearPattern = detectYearPattern;
    function detectNamePattern(pw) {
        const lower = pw.toLowerCase();
        const hits = [];
        for (const name of OZ.COMMON_NAMES) {
            if (name.length < 3)
                continue;
            let idx = lower.indexOf(name);
            while (idx !== -1) {
                hits.push({ start: idx, end: idx + name.length - 1 });
                idx = lower.indexOf(name, idx + 1);
            }
        }
        return hits;
    }
    OZ.detectNamePattern = detectNamePattern;
    function detectDictionaryWord(pw) {
        const lower = pw.toLowerCase();
        const hits = [];
        for (const word of OZ.DICTIONARY_WORDS) {
            if (word.length < 4)
                continue;
            let idx = lower.indexOf(word);
            while (idx !== -1) {
                hits.push({ start: idx, end: idx + word.length - 1 });
                idx = lower.indexOf(word, idx + 1);
            }
        }
        return hits;
    }
    OZ.detectDictionaryWord = detectDictionaryWord;
    function isCommonPassword(pw) {
        return OZ.COMMON_PASSWORDS.includes(pw.toLowerCase());
    }
    OZ.isCommonPassword = isCommonPassword;
    // ───────────────────────────── Heatmap ──────────────────────────────
    const CATEGORY_META = {
        year: { label: "Birth year / date pattern", severity: "critical" },
        name: { label: "Personal name", severity: "critical" },
        keyboard: { label: "Keyboard pattern", severity: "warning" },
        sequential: { label: "Sequential characters", severity: "warning" },
        repeated: { label: "Repeated characters", severity: "warning" },
        dictionary: { label: "Dictionary word", severity: "info" },
        strong: { label: "Unpredictable segment", severity: "safe" },
    };
    /** Build a set of non-overlapping, priority-ranked heatmap segments. */
    function buildHeatmap(pw) {
        if (!pw)
            return [];
        const hits = [];
        detectYearPattern(pw).forEach((h) => hits.push({ ...h, category: "year", priority: 1 }));
        detectNamePattern(pw).forEach((h) => hits.push({ ...h, category: "name", priority: 1 }));
        detectKeyboardPatterns(pw).forEach((h) => hits.push({ ...h, category: "keyboard", priority: 2 }));
        detectSequentialChars(pw).forEach((h) => hits.push({ ...h, category: "sequential", priority: 2 }));
        detectRepeatedChars(pw).forEach((h) => hits.push({ ...h, category: "repeated", priority: 2 }));
        detectDictionaryWord(pw).forEach((h) => hits.push({ ...h, category: "dictionary", priority: 3 }));
        // Sort by priority (lower = more important) then by length (longer wins)
        hits.sort((a, b) => a.priority - b.priority || (b.end - b.start) - (a.end - a.start));
        const claimed = new Array(pw.length).fill(false);
        const chosen = [];
        for (const h of hits) {
            let overlap = false;
            for (let i = h.start; i <= h.end; i++) {
                if (claimed[i]) {
                    overlap = true;
                    break;
                }
            }
            if (!overlap) {
                chosen.push(h);
                for (let i = h.start; i <= h.end; i++)
                    claimed[i] = true;
            }
        }
        chosen.sort((a, b) => a.start - b.start);
        const segments = [];
        let cursor = 0;
        for (const h of chosen) {
            if (h.start > cursor) {
                segments.push(makeSegment(pw, cursor, h.start - 1, "strong"));
            }
            segments.push(makeSegment(pw, h.start, h.end, h.category));
            cursor = h.end + 1;
        }
        if (cursor < pw.length) {
            segments.push(makeSegment(pw, cursor, pw.length - 1, "strong"));
        }
        return segments;
    }
    OZ.buildHeatmap = buildHeatmap;
    function makeSegment(pw, start, end, category) {
        const meta = CATEGORY_META[category];
        return {
            text: pw.slice(start, end + 1),
            start,
            end,
            category,
            label: meta.label,
            severity: meta.severity,
        };
    }
    // ───────────────────────────── Security checks ──────────────────────────────
    function runSecurityChecks(pw) {
        const checks = [];
        checks.push({
            id: "length",
            label: "At least 12 characters",
            passed: pw.length >= 12,
            detail: `Password is ${pw.length} character${pw.length === 1 ? "" : "s"} long.`,
        });
        checks.push({
            id: "upper",
            label: "Contains uppercase letters",
            passed: /[A-Z]/.test(pw),
            detail: "Uppercase letters expand the character pool.",
        });
        checks.push({
            id: "lower",
            label: "Contains lowercase letters",
            passed: /[a-z]/.test(pw),
            detail: "Lowercase letters expand the character pool.",
        });
        checks.push({
            id: "number",
            label: "Contains numbers",
            passed: /[0-9]/.test(pw),
            detail: "Numbers add variety beyond alphabetic characters.",
        });
        checks.push({
            id: "symbol",
            label: "Contains special characters",
            passed: /[^a-zA-Z0-9]/.test(pw),
            detail: "Symbols meaningfully increase brute-force difficulty.",
        });
        const diversity = pw.length ? new Set(pw.split("")).size / pw.length : 0;
        checks.push({
            id: "diversity",
            label: "High character diversity",
            passed: diversity >= 0.6,
            detail: `${Math.round(diversity * 100)}% of characters are unique.`,
        });
        checks.push({
            id: "repeated",
            label: "No repeated character runs",
            passed: detectRepeatedChars(pw).length === 0,
            detail: "Runs of 3+ identical characters (e.g. 'aaa') are easy to guess.",
        });
        checks.push({
            id: "sequential",
            label: "No sequential characters",
            passed: detectSequentialChars(pw).length === 0,
            detail: "Sequences like '1234' or 'abcd' are among the first guesses tried.",
        });
        checks.push({
            id: "keyboard",
            label: "No keyboard-walk patterns",
            passed: detectKeyboardPatterns(pw).length === 0,
            detail: "Patterns like 'qwerty' or 'asdf' follow physical key layout.",
        });
        checks.push({
            id: "common",
            label: "Not a known breached/common password",
            passed: !isCommonPassword(pw),
            detail: "Checked locally against a list of frequently used passwords.",
        });
        checks.push({
            id: "dictionary",
            label: "No plain dictionary word",
            passed: detectDictionaryWord(pw).length === 0,
            detail: "Whole dictionary words are highly guessable by wordlist attacks.",
        });
        return checks;
    }
    OZ.runSecurityChecks = runSecurityChecks;
    function buildSuggestions(pw, checks) {
        const suggestions = [];
        const failed = new Set(checks.filter((c) => !c.passed).map((c) => c.id));
        if (pw.length === 0)
            return ["Start typing a password to see suggestions."];
        if (failed.has("length"))
            suggestions.push("Use at least 12 characters — longer is stronger.");
        if (failed.has("upper"))
            suggestions.push("Add one or more uppercase letters.");
        if (failed.has("lower"))
            suggestions.push("Add one or more lowercase letters.");
        if (failed.has("number"))
            suggestions.push("Add one or more numbers.");
        if (failed.has("symbol"))
            suggestions.push("Add a special character such as !, #, or %.");
        if (failed.has("repeated"))
            suggestions.push("Avoid repeating the same character multiple times in a row.");
        if (failed.has("sequential"))
            suggestions.push("Avoid sequences like '1234' or 'abcd'.");
        if (failed.has("keyboard"))
            suggestions.push("Avoid keyboard patterns like 'qwerty' or 'asdf'.");
        if (failed.has("common"))
            suggestions.push("This is a known common password — choose something unique.");
        if (failed.has("dictionary"))
            suggestions.push("Avoid plain dictionary words; try an uncommon phrase instead.");
        if (detectYearPattern(pw).length)
            suggestions.push("Avoid using birth years or dates — these are easy to guess.");
        if (detectNamePattern(pw).length)
            suggestions.push("Avoid personal names — attackers try these first.");
        if (suggestions.length === 0)
            suggestions.push("Great work — this password passes every local check.");
        return suggestions;
    }
    OZ.buildSuggestions = buildSuggestions;
    /**
     * Turns a bare strength label into a short, specific reason — e.g. instead
     * of just "Weak", explain *why*: which pattern was found, or which checks
     * failed, ranked by how much they matter.
     */
    function explainStrength(result) {
        if (!result.password)
            return "Type a password to see an explanation.";
        if (isCommonPassword(result.password)) {
            return `${result.level} — this exact password appears on lists of the most commonly used passwords.`;
        }
        const critical = result.heatmap.filter((h) => h.severity === "critical");
        if (critical.length) {
            const kinds = Array.from(new Set(critical.map((h) => h.label.toLowerCase())));
            return `${result.level} — contains ${kinds.join(" and ")}, which attackers try first.`;
        }
        const warningHits = result.heatmap.filter((h) => h.severity === "warning");
        if (warningHits.length) {
            const kinds = Array.from(new Set(warningHits.map((h) => h.label.toLowerCase())));
            return `${result.level} — includes ${kinds.join(" and ")}, which are easy for cracking tools to predict.`;
        }
        const dictionaryHit = result.heatmap.some((h) => h.category === "dictionary");
        if (dictionaryHit) {
            return `${result.level} — built around a plain dictionary word, which wordlist attacks try early.`;
        }
        const failedChecks = result.checks.filter((c) => !c.passed);
        if (failedChecks.length) {
            const labels = failedChecks.slice(0, 2).map((c) => c.label.toLowerCase());
            return `${result.level} — missing: ${labels.join(", ")}.`;
        }
        if (result.entropyBits < 60) {
            return `${result.level} — passes basic checks, but at ${result.entropyBits.toFixed(0)} bits of entropy it's still short enough to be cracked in a realistic timeframe.`;
        }
        if (result.score >= 90) {
            return `${result.level} — long, unpredictable, and passes every local check.`;
        }
        return `${result.level} — solid overall, with a bit more length or variety it could reach Excellent.`;
    }
    OZ.explainStrength = explainStrength;
    // ───────────────────────────── Crack time estimation ──────────────────────────────
    function formatDuration(seconds) {
        if (!isFinite(seconds))
            return "Effectively never";
        if (seconds < 1)
            return "Instantly";
        const units = [
            ["second", 1],
            ["minute", 60],
            ["hour", 3600],
            ["day", 86400],
            ["year", 31536000],
            ["thousand years", 31536000 * 1e3],
            ["million years", 31536000 * 1e6],
            ["billion years", 31536000 * 1e9],
            ["trillion years", 31536000 * 1e12],
        ];
        let chosen = units[0];
        for (const u of units) {
            if (seconds >= u[1])
                chosen = u;
            else
                break;
        }
        const value = seconds / chosen[1];
        const rounded = value >= 100 ? Math.round(value).toLocaleString() : value.toFixed(1);
        return `${rounded} ${chosen[0]}${value >= 2 && !chosen[0].includes("years") ? "s" : ""}`;
    }
    OZ.formatDuration = formatDuration;
    function estimateCrackTimes(pw, entropyBits) {
        const scenarios = [
            { scenario: "Online (throttled, 100 guesses/sec)", guessesPerSecond: 100 },
            { scenario: "Online (no throttling, 1K guesses/sec)", guessesPerSecond: 1000 },
            { scenario: "Offline, slow hash (10K guesses/sec)", guessesPerSecond: 10000 },
            { scenario: "Offline, fast hash / GPU (10B guesses/sec)", guessesPerSecond: 10000000000 },
        ];
        const isDictionaryWeak = isCommonPassword(pw) || detectDictionaryWord(pw).length > 0;
        const results = scenarios.map((s) => {
            const seconds = Math.pow(2, entropyBits) / s.guessesPerSecond / 2; // average case
            return {
                scenario: s.scenario,
                guessesPerSecond: s.guessesPerSecond,
                seconds,
                human: formatDuration(seconds),
            };
        });
        if (isDictionaryWeak) {
            // Dictionary / wordlist attack: assume the password is found within
            // the first few million targeted guesses rather than brute force.
            const seconds = 1000000 / 10000; // ~100s against a 1M-entry wordlist at 10k/s
            results.unshift({
                scenario: "Dictionary attack (known wordlist)",
                guessesPerSecond: 10000,
                seconds,
                human: formatDuration(seconds),
            });
        }
        return results;
    }
    OZ.estimateCrackTimes = estimateCrackTimes;
    // ───────────────────────────── Composite score ──────────────────────────────
    function analyzePassword(pw) {
        const checks = runSecurityChecks(pw);
        const entropyBits = calculateEntropy(pw);
        const heatmap = buildHeatmap(pw);
        let score = 0;
        if (pw.length > 0) {
            // Length contributes up to 30 points (12+ chars = full marks)
            score += Math.min(30, (pw.length / 16) * 30);
            // Character class variety contributes up to 25 points
            const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^a-zA-Z0-9]/].filter((r) => r.test(pw)).length;
            score += (classes / 4) * 25;
            // Entropy contributes up to 30 points (80 bits = full marks)
            score += Math.min(30, (entropyBits / 80) * 30);
            // Diversity contributes up to 15 points
            const diversity = new Set(pw.split("")).size / pw.length;
            score += diversity * 15;
            // Penalties
            const criticalHits = heatmap.filter((h) => h.severity === "critical").length;
            const warningHits = heatmap.filter((h) => h.severity === "warning").length;
            score -= criticalHits * 12;
            score -= warningHits * 8;
            if (isCommonPassword(pw))
                score = Math.min(score, 5);
        }
        score = Math.max(0, Math.min(100, Math.round(score)));
        const charDistribution = { Lowercase: 0, Uppercase: 0, Numbers: 0, Symbols: 0 };
        for (const ch of pw) {
            if (/[a-z]/.test(ch))
                charDistribution.Lowercase++;
            else if (/[A-Z]/.test(ch))
                charDistribution.Uppercase++;
            else if (/[0-9]/.test(ch))
                charDistribution.Numbers++;
            else
                charDistribution.Symbols++;
        }
        return {
            password: pw,
            length: pw.length,
            score,
            level: scoreToLevel(score),
            entropyBits,
            randomness: randomnessLevel(entropyBits),
            checks,
            heatmap,
            crackTimes: estimateCrackTimes(pw, entropyBits),
            charDistribution,
            poolSize: poolSizeFor(pw),
            suggestions: buildSuggestions(pw, checks),
        };
    }
    OZ.analyzePassword = analyzePassword;
    // ───────────────────────────── Generators ──────────────────────────────
    function secureRandomInt(max) {
        const array = new Uint32Array(1);
        crypto.getRandomValues(array);
        return array[0] % max;
    }
    function generatePassword(opts) {
        let pool = "";
        if (opts.lower)
            pool += CHAR_SETS.lower;
        if (opts.upper)
            pool += CHAR_SETS.upper;
        if (opts.numbers)
            pool += CHAR_SETS.numbers;
        if (opts.symbols)
            pool += CHAR_SETS.symbols;
        if (opts.excludeSimilar) {
            pool = pool.split("").filter((c) => !SIMILAR_CHARS.includes(c)).join("");
        }
        if (!pool)
            pool = CHAR_SETS.lower;
        const required = [];
        if (opts.lower)
            required.push(pick(CHAR_SETS.lower, opts.excludeSimilar));
        if (opts.upper)
            required.push(pick(CHAR_SETS.upper, opts.excludeSimilar));
        if (opts.numbers)
            required.push(pick(CHAR_SETS.numbers, opts.excludeSimilar));
        if (opts.symbols)
            required.push(pick(CHAR_SETS.symbols, opts.excludeSimilar));
        const chars = [...required];
        while (chars.length < opts.length) {
            chars.push(pool[secureRandomInt(pool.length)]);
        }
        // Fisher-Yates shuffle using CSPRNG
        for (let i = chars.length - 1; i > 0; i--) {
            const j = secureRandomInt(i + 1);
            [chars[i], chars[j]] = [chars[j], chars[i]];
        }
        return chars.slice(0, opts.length).join("");
    }
    OZ.generatePassword = generatePassword;
    function pick(set, excludeSimilar) {
        const usable = excludeSimilar ? set.split("").filter((c) => !SIMILAR_CHARS.includes(c)).join("") : set;
        return usable[secureRandomInt(usable.length)];
    }
    OZ.PASSPHRASE_WORDS = [
        "anchor", "beacon", "canyon", "delta", "ember", "falcon", "glacier",
        "harbor", "island", "jungle", "kettle", "lagoon", "meadow", "nectar",
        "oasis", "prairie", "quartz", "ridge", "summit", "timber", "umbra",
        "valley", "willow", "xenon", "yonder", "zephyr", "amber", "boulder",
        "cascade", "dune", "echo", "fjord", "granite", "horizon", "indigo",
        "juniper", "karma", "lunar", "monsoon", "nimbus", "orbit", "pebble",
        "quill", "raven", "sable", "thistle", "umber", "violet", "wander",
        "yield", "zenith", "arbor", "birch", "cedar", "drift", "ember",
        "flint", "grove", "hollow", "ivory", "jasper", "knoll", "lark",
        "maple", "north", "opal", "pine", "quiet", "reef", "stone", "tide",
        "vale", "wisp", "yarn", "zeal", "brisk", "coral", "dusk", "frost",
        "glow", "haze", "iris", "jolt", "kite", "loom", "mist", "nova",
        "onyx", "peak", "quest", "rune", "spark", "trail", "urge", "vivid",
        "wave", "yolk", "zest",
    ];
    function generatePassphrase(opts) {
        const chosen = [];
        for (let i = 0; i < opts.words; i++) {
            let word = OZ.PASSPHRASE_WORDS[secureRandomInt(OZ.PASSPHRASE_WORDS.length)];
            if (opts.capitalize)
                word = word[0].toUpperCase() + word.slice(1);
            chosen.push(word);
        }
        let phrase = chosen.join(opts.separator);
        if (opts.addNumbers)
            phrase += secureRandomInt(90) + 10;
        if (opts.addSymbols) {
            const symbols = "!@#$%&*";
            phrase += symbols[secureRandomInt(symbols.length)];
        }
        return phrase;
    }
    OZ.generatePassphrase = generatePassphrase;
    // ───────────────────────────── Build-from-your-info generator ──────────────────────────────
    const LEET_MAP = { a: "4", e: "3", i: "1", o: "0", s: "5", t: "7", b: "8" };
    function applyLeetspeak(word) {
        return word
            .split("")
            .map((ch) => {
            const lower = ch.toLowerCase();
            if (LEET_MAP[lower] && secureRandomInt(2) === 0)
                return LEET_MAP[lower];
            return ch;
        })
            .join("");
    }
    function randomPaddingString(length) {
        const pool = CHAR_SETS.upper + CHAR_SETS.lower + CHAR_SETS.numbers + CHAR_SETS.symbols;
        let out = "";
        for (let i = 0; i < length; i++)
            out += pool[secureRandomInt(pool.length)];
        return out;
    }
    /**
     * Builds a password around user-supplied personal seeds (name / date /
     * number). The raw seeds alone would be highly guessable — the analyzer
     * itself flags names and dates as critical weaknesses — so this function
     * transforms each seed (optional leetspeak, mixed case) and always mixes
     * in a block of true random padding from the CSPRNG, then optionally
     * shuffles the order of the resulting blocks. It never returns the seeds
     * unmodified and unpadded.
     */
    function buildFromPersonalInfo(opts) {
        const segments = [];
        const name = opts.name.trim().replace(/[^a-zA-Z]/g, "");
        if (name) {
            let transformed = name[0].toUpperCase() + name.slice(1).toLowerCase();
            if (opts.leetspeak)
                transformed = applyLeetspeak(transformed);
            segments.push({ text: transformed, source: "name" });
        }
        const dateDigits = opts.date.trim().replace(/[^0-9]/g, "");
        if (dateDigits) {
            // Reorder date digits (e.g. DDMMYYYY -> non-obvious order) rather than
            // keeping the literal, guessable sequence.
            const chars = dateDigits.split("");
            for (let i = chars.length - 1; i > 0; i--) {
                const j = secureRandomInt(i + 1);
                [chars[i], chars[j]] = [chars[j], chars[i]];
            }
            segments.push({ text: chars.join(""), source: "date" });
        }
        const numberDigits = opts.number.trim().replace(/[^0-9]/g, "");
        if (numberDigits)
            segments.push({ text: numberDigits, source: "number" });
        if (opts.padding > 0) {
            segments.push({ text: randomPaddingString(opts.padding), source: "random" });
        }
        if (segments.length === 0) {
            segments.push({ text: randomPaddingString(Math.max(opts.padding, 12)), source: "random" });
        }
        if (opts.shuffleSegments) {
            for (let i = segments.length - 1; i > 0; i--) {
                const j = secureRandomInt(i + 1);
                [segments[i], segments[j]] = [segments[j], segments[i]];
            }
        }
        const symbolPool = "!@#$%&*-_";
        let password = "";
        segments.forEach((seg, i) => {
            password += seg.text;
            if (i < segments.length - 1 && opts.addSymbols) {
                password += symbolPool[secureRandomInt(symbolPool.length)];
            }
        });
        return { password, segments };
    }
    OZ.buildFromPersonalInfo = buildFromPersonalInfo;
    // ───────────────────────────── Web Crypto helpers ──────────────────────────────
    async function sha1Hex(input) {
        const enc = new TextEncoder().encode(input);
        const digest = await crypto.subtle.digest("SHA-1", enc);
        return Array.from(new Uint8Array(digest))
            .map((b) => b.toString(16).padStart(2, "0"))
            .join("")
            .toUpperCase();
    }
    OZ.sha1Hex = sha1Hex;
    /**
     * Checks a password against the Have I Been Pwned range API using
     * k-Anonymity: only the first 5 characters of the SHA-1 hash ever leave
     * the browser. The full password and full hash never leave the device.
     */
    async function checkPwned(password) {
        try {
            const hash = await sha1Hex(password);
            const prefix = hash.slice(0, 5);
            const suffix = hash.slice(5);
            const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
                headers: { "Add-Padding": "true" },
            });
            if (!res.ok)
                throw new Error(`HIBP responded with ${res.status}`);
            const text = await res.text();
            const lines = text.split("\n");
            for (const line of lines) {
                const [lineSuffix, count] = line.trim().split(":");
                if (lineSuffix === suffix) {
                    return { breached: true, count: parseInt(count, 10) || 0 };
                }
            }
            return { breached: false, count: 0 };
        }
        catch (err) {
            return { breached: false, count: 0, error: err instanceof Error ? err.message : "Network error" };
        }
    }
    OZ.checkPwned = checkPwned;
    // ───────────────────────────── Storage (metadata only) ──────────────────────────────
    const HISTORY_KEY = "SekPass_history_v1";
    const MAX_HISTORY = 25;
    function saveHistoryEntry(entry) {
        const history = getHistory();
        history.unshift(entry);
        localStorage.setItem(HISTORY_KEY, JSON.stringify(history.slice(0, MAX_HISTORY)));
    }
    OZ.saveHistoryEntry = saveHistoryEntry;
    function getHistory() {
        try {
            const raw = localStorage.getItem(HISTORY_KEY);
            return raw ? JSON.parse(raw) : [];
        }
        catch {
            return [];
        }
    }
    OZ.getHistory = getHistory;
    function clearHistory() {
        localStorage.removeItem(HISTORY_KEY);
    }
    OZ.clearHistory = clearHistory;
    function makeId() {
        return `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    }
    OZ.makeId = makeId;
    // ───────────────────────────── DOM / UX utilities ──────────────────────────────
    function escapeHtml(str) {
        const div = document.createElement("div");
        div.textContent = str;
        return div.innerHTML;
    }
    OZ.escapeHtml = escapeHtml;
    function debounce(fn, wait) {
        let timer;
        return ((...args) => {
            window.clearTimeout(timer);
            timer = window.setTimeout(() => fn(...args), wait);
        });
    }
    OZ.debounce = debounce;
    async function copyToClipboard(text) {
        try {
            await navigator.clipboard.writeText(text);
            return true;
        }
        catch {
            const textarea = document.createElement("textarea");
            textarea.value = text;
            textarea.style.position = "fixed";
            textarea.style.opacity = "0";
            document.body.appendChild(textarea);
            textarea.select();
            const ok = document.execCommand("copy");
            document.body.removeChild(textarea);
            return ok;
        }
    }
    OZ.copyToClipboard = copyToClipboard;
    function showToast(message, type = "info") {
        let container = document.getElementById("oz-toast-container");
        if (!container) {
            container = document.createElement("div");
            container.id = "oz-toast-container";
            container.className = "oz-toast-container";
            document.body.appendChild(container);
        }
        const toast = document.createElement("div");
        toast.className = `oz-toast oz-toast--${type}`;
        toast.textContent = message;
        container.appendChild(toast);
        requestAnimationFrame(() => toast.classList.add("oz-toast--visible"));
        window.setTimeout(() => {
            toast.classList.remove("oz-toast--visible");
            window.setTimeout(() => toast.remove(), 300);
        }, 3200);
    }
    OZ.showToast = showToast;
    function initMobileNav() {
        const toggle = document.querySelector("[data-nav-toggle]");
        const menu = document.querySelector("[data-nav-menu]");
        if (!toggle || !menu)
            return;
        toggle.addEventListener("click", () => {
            const isOpen = menu.classList.toggle("oz-nav__menu--open");
            toggle.setAttribute("aria-expanded", String(isOpen));
        });
    }
    OZ.initMobileNav = initMobileNav;
    function initFactsCarousel(elementId, intervalMs = 5000) {
        const el = document.getElementById(elementId);
        if (!el)
            return;
        let index = 0;
        const render = () => {
            el.style.opacity = "0";
            window.setTimeout(() => {
                el.textContent = OZ.CYBERSECURITY_FACTS[index];
                el.style.opacity = "1";
            }, 250);
            index = (index + 1) % OZ.CYBERSECURITY_FACTS.length;
        };
        render();
        window.setInterval(render, intervalMs);
    }
    OZ.initFactsCarousel = initFactsCarousel;
    function formatNumber(n) {
        return n.toLocaleString();
    }
    OZ.formatNumber = formatNumber;
    // ───────────────────────────── Theming ──────────────────────────────
    const THEME_KEY = "SekPass_theme_v1";
    OZ.THEMES = [
        { id: "sky", label: "Sky (light)", swatch: "linear-gradient(135deg,#eef5fb,#0ea5a0)" },
        { id: "midnight", label: "Midnight", swatch: "linear-gradient(135deg,#0b1f33,#0ea5a0)" },
        { id: "slate", label: "Slate", swatch: "linear-gradient(135deg,#334155,#4a5fea)" },
        { id: "contrast", label: "High contrast", swatch: "linear-gradient(135deg,#000000,#ffd60a)" },
    ];
    function getStoredTheme() {
        const raw = localStorage.getItem(THEME_KEY);
        return (OZ.THEMES.some((t) => t.id === raw) ? raw : "sky");
    }
    OZ.getStoredTheme = getStoredTheme;
    function applyTheme(theme) {
        document.documentElement.setAttribute("data-theme", theme);
        localStorage.setItem(THEME_KEY, theme);
        document.querySelectorAll("[data-theme-swatch]").forEach((btn) => {
            const active = btn.getAttribute("data-theme-swatch") === theme;
            btn.classList.toggle("oz-theme-swatch--active", active);
            btn.setAttribute("aria-pressed", String(active));
        });
    }
    OZ.applyTheme = applyTheme;
    /** Renders the swatch buttons into any container marked [data-theme-switcher] and wires them up. */
    function initThemeSwitcher() {
        const current = getStoredTheme();
        document.documentElement.setAttribute("data-theme", current);
        document.querySelectorAll("[data-theme-switcher]").forEach((container) => {
            container.innerHTML = OZ.THEMES.map((t) => `<button type="button" class="oz-theme-swatch" data-theme-swatch="${t.id}"
                  style="background:${t.swatch}" title="${t.label}" aria-label="${t.label}" aria-pressed="false"></button>`).join("");
        });
        document.querySelectorAll("[data-theme-swatch]").forEach((btn) => {
            btn.addEventListener("click", () => {
                const theme = btn.getAttribute("data-theme-swatch");
                applyTheme(theme);
            });
        });
        applyTheme(current);
    }
    OZ.initThemeSwitcher = initThemeSwitcher;
    function levelColorVar(level) {
        const map = {
            "Very Weak": "var(--oz-danger)",
            "Weak": "var(--oz-danger)",
            "Fair": "var(--oz-warning)",
            "Good": "var(--oz-info)",
            "Strong": "var(--oz-accent)",
            "Excellent": "var(--oz-safe)",
        };
        return map[level];
    }
    OZ.levelColorVar = levelColorVar;
})(OZ || (OZ = {}));

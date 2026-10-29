# PhishGuard — AI-Inspired Phishing URL Detector

> **An explainable, client-side cybersecurity web application designed to detect, analyze, and demystify phishing URLs through transparent heuristic inspection, risk scoring, and interactive education.**

---

## 🛡️ Project Overview

**PhishGuard** was engineered to solve a fundamental problem in automated link scanning: **the black-box dilemma**. Many conventional scanners present users with a binary "Safe" or "Unsafe" verdict without explaining *why*, leaving users uninformed about the underlying social engineering and domain-spoofing vectors.

PhishGuard provides:
- **14 Explainable Heuristic Security Checks** with individual point weightings.
- **Dynamic Risk Gauge (0–100)** categorized into Low Risk, Medium Risk, and High Risk.
- **Glassmorphism Cyber Theme** with dark navy backgrounds, electric cyan & violet accents, and an accessible Light Mode toggle.
- **Comprehensive Analytics Dashboard** featuring Chart.js activity timelines and security distribution donut charts.
- **Persistent Scan History** with URL search, verdict filtering, chronological/score sorting, and CSV export.
- **Threat Education Hub** breaking down the anatomy of fraudulent URLs, typosquatting, IDN homoglyphs, and URL shorteners.
- **Zero-Dependency Local Execution** with zero data exfiltration by default, plus an optional backend proxy for Google Safe Browsing and VirusTotal APIs.

---

## 🚀 Key Features

### 1. Transparent Diagnostic Engine (`analyzer.js`)
Evaluates any user-provided URL across 14 dedicated security layers:
1. **HTTPS Transport Security**: Flags unencrypted HTTP and severely penalizes HTTP paired with authentication endpoints.
2. **IP Address as Hostname**: Detects bare IPv4, IPv6, and obfuscated numeric hosts.
3. **Subdomain Nesting Depth**: Analyzes deep subdomain chains (3+ subdomains) often used to conceal target infrastructure.
4. **URL & Domain Length**: Highlights abnormally long query strings and domain tokens designed to push the real host off mobile address bars.
5. **URL Shortener Detection**: Identifies known redirection services (`bit.ly`, `tinyurl.com`, `t.co`, etc.) masking destination addresses.
6. **Brand Spoofing & Typosquatting**:
   - Detects targeted brand names (PayPal, Apple, Google, Chase, Binance, etc.) embedded in subdomains or path tokens.
   - Computes **Levenshtein Distance** against high-profile target brands to catch letter substitutions (e.g. `paypa1`, `goog1e`, `micros0ft`).
7. **Unusual Characters & Encodings**: Identifies high hyphen frequency, double slashes (`//`) in paths, excessive dots, and percent-encoded hex sequences.
8. **"@" Symbol Deception**: Detects the classic browser userinfo credential trick (`http://trusted.com@attacker.com`).
9. **Credential & Urgency Keywords**: Scans tokens for phishing bait phrases (`login`, `signin`, `verify`, `account`, `banking`, `security-alert`, `wallet`, `kyc`, `unlock`).
10. **Punycode & Homoglyph Attacks**: Detects `xn--` internationalized domains and Cyrillic/Greek lookalike homoglyphs.
11. **Non-Standard Port Analysis**: Flags uncommon web ports (`:8080`, `:8443`, `:7777`, `:21`).
12. **Open Redirection Indicators**: Inspects query parameters (`?url=`, `?redirect=`, `?next=`, `?dest=`) pointing to secondary hosts.
13. **High-Abuse Top-Level Domains**: Identifies historically disposable, spam-heavy TLDs (`.xyz`, `.top`, `.tk`, `.ml`, `.buzz`, `.click`).
14. **Shannon Entropy (DGA Detection)**: Computes character randomness to detect machine-generated disposable domains.

---

## 📊 Transparent Risk Scoring Matrix

| Risk Score | Classification | Color Badge | Recommended Action |
|:---:|:---:|:---:|:---|
| **0 – 29** | **SAFE (Low Risk)** | 🟢 Emerald Green | Safe to proceed under standard caution. Standard FQDN and encryption verified. |
| **30 – 59** | **SUSPICIOUS (Medium Risk)** | 🟡 Amber Orange | Exercise heightened caution. Verify sender and do not enter credentials directly. |
| **60 – 100** | **PHISHING (High Risk)** | 🔴 Crimson Red | **DO NOT CLICK.** High confidence of fraudulent impersonation or credential theft. |

> **Important Disclosure:** These scores are heuristic probabilistic indicators for education and awareness. They do not constitute an absolute guarantee of safety.

---

## 📁 Project Architecture

```
Projects/
├── index.html            # Main Single-Page Application (All 6 views + modals)
├── css/
│   ├── main.css          # Design system tokens, typography, dark/light themes, sidebar layout
│   ├── components.css    # Cards, SVG risk gauge, badges, charts wrapper, tables, toasts
│   └── responsive.css    # Breakpoints for mobile, tablet, and responsive grid reflows
├── js/
│   ├── analyzer.js       # Modular explainable heuristic URL analysis engine
│   ├── storage.js        # localStorage CRUD manager, statistics aggregation, CSV exporter
│   ├── charts.js         # Chart.js initialization (Activity Line + Distribution Donut)
│   ├── ui.js             # SVG circular gauge animator, toasts, safe HTML escaping, modal manager
│   └── app.js            # Main application coordinator, event bindings, and hash router
├── proxy_server.py       # (Optional) Threat intelligence backend proxy (Safe Browsing & VirusTotal)
└── README.md             # Project documentation and setup guide
```

---

## 💻 How to Run the Application

PhishGuard is built with modern vanilla web standards (HTML5, CSS3, ES6+ JavaScript, Chart.js CDN, Lucide CDN). It requires **no build step, no npm install, and no compiler**.

### Option 1: Direct File Launch (Quickest)
Double-click `index.html` or open it directly in any modern browser (Google Chrome, Microsoft Edge, Mozilla Firefox, Brave, Safari).

### Option 2: Local Python Server (Recommended for local HTTP testing)
Open PowerShell or your terminal in the project directory:
```bash
python -m http.server 8000
```
Then visit:
```
http://localhost:8000
```

### Option 3: VS Code Live Server
1. Open the project folder in Visual Studio Code.
2. Right-click `index.html` and click **"Open with Live Server"**.

---

## 🔒 Optional Real Threat Intelligence Integration (`proxy_server.py`)

To adhere to strict cybersecurity best practices:
- **API Keys are NEVER exposed in frontend JavaScript.**
- External threat feeds are contacted via the Python backend proxy `proxy_server.py`.
- If the proxy is not running, PhishGuard defaults smoothly to **Autonomous Local Heuristic Mode** with zero telemetry or network calls.

### Starting the Proxy Server:
```bash
# Optional: Provide API keys in environment variables
set GOOGLE_SAFE_BROWSING_KEY=your_google_key_here
set VIRUSTOTAL_API_KEY=your_virustotal_key_here

python proxy_server.py
```
When running, the URL Scanner automatically detects the proxy on `http://127.0.0.1:8765` and appends verified external reputation results directly into the diagnostic panel.

---

## 🧪 Demonstration Test Scenarios

Use these test cases to observe how PhishGuard evaluates different risk profiles:

1. **Legitimate Banking Portal (Expected: SAFE, 0/100)**
   - `https://chase.com/personal/banking`
2. **Typosquatting & Brand Spoofing (Expected: PHISHING, 85–90/100)**
   - `https://secure-login.paypa1-security-verification.xyz/signin`
3. **Bare IP Address Host (Expected: PHISHING, 80–85/100)**
   - `http://192.168.1.105:8080/portal/update-credentials.php`
4. **URL Shortener (Expected: SUSPICIOUS, 30/100)**
   - `https://bit.ly/3xY8a9Q`
5. **Deep Subdomain Nesting & Urgency Trap (Expected: PHISHING, 70–80/100)**
   - `https://login.verification.bank-security.account-update.xyz/auth?user=victim@domain.com`
6. **Legitimate Developer Resource (Expected: SAFE, 0/100)**
   - `https://github.com/security/advisories`

---

## 🛡️ Security & Privacy Principles

- **No Arbitrary Code Execution:** Submitted URLs are sanitized with `UIManager.escapeHTML()` and never evaluated as raw HTML or loaded in iframes.
- **No Automatic Navigation:** The application never automatically visits or opens submitted links.
- **Client-Side Privacy:** Scan history is persisted exclusively in the browser's `localStorage`. No user URLs are uploaded to external tracking databases.
- **Transparent Heuristics:** Every point added to the risk score is accompanied by an understandable explanation and category tag.

---

## 📜 Educational Purpose & Responsible Disclosure

*PhishGuard was created for cybersecurity education, awareness, and demonstration. While the heuristic engine evaluates common structural patterns used in malicious campaigns, sophisticated threat actors continuously evolve their techniques. PhishGuard should be utilized alongside reputable antivirus software, multi-factor authentication (MFA), and safe browsing habits.*

Built for cybersecurity awareness and education.


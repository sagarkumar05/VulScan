# 🔒 VulnScanner — Web Vulnerability Scanner
### B.Tech Final Year Project | Cybersecurity / Network Security By Majid Ansari

---

## 📋 Project Overview

VulnScanner is a Python-based **automated web vulnerability scanner** that performs comprehensive security analysis on a target website or IP address. It covers:

| Module | What it does |
|--------|-------------|
| 🌐 URL & IP Analysis | DNS resolution, WHOIS lookup, HTTP server info |
| 🔌 Port Scanner | Multi-threaded TCP port scan (22 ports default) |
| 🗺️ Subdomain Enumerator | DNS brute-force for subdomains |
| 🔐 SSL/TLS Checker | Certificate expiry, issuer, weak protocols |
| 💉 SQL Injection | Payload-based GET parameter testing |
| ⚡ XSS Checker | Reflected XSS payload injection |
| ⚠️ Risk Analyzer | Weighted scoring + recommendations |
| 📄 Report Generator | PDF + JSON reports |

---

## 🚀 Quick Start (Windows VS Code)

### Step 1: Install Python
- Download Python 3.11 from https://www.python.org/downloads/
- ✅ Check **"Add Python to PATH"** during installation

### Step 2: Open project in VS Code
```
File → Open Folder → select the VulnScanner folder
```

### Step 3: Open Terminal in VS Code
```
Terminal → New Terminal   (or Ctrl + `)
```

### Step 4: Install dependencies
```bash
pip install -r requirements.txt
```

### Step 5: Run the scanner
```bash
python main.py
```
Or with a specific target:
```bash
python main.py --target http://testphp.vulnweb.com
```

---

## 💻 VS Code Recommended Extensions
- **Python** (Microsoft) — IntelliSense + debugging
- **Pylance** — type checking
- **indent-rainbow** — indentation visualization

---

## 🎯 Safe Test Targets (Legal!)
These are intentionally vulnerable sites for testing:

| URL | Description |
|-----|-------------|
| `http://testphp.vulnweb.com` | Acunetix test PHP site (SQL + XSS vulnerable) |
| `http://zero.webappsecurity.com` | WebApp Security test site |
| `http://scanme.nmap.org` | Nmap's official scan-me server |

> ⚠️ **NEVER scan sites you don't own or have permission to test!**

---

## 🗂️ Project Structure
```
VulnScanner/
├── main.py                  ← Entry point — run this!
├── config.py                ← All settings (payloads, ports, timeouts)
├── requirements.txt         ← Python packages
├── modules/
│   ├── url_ip.py            ← URL & IP resolution
│   ├── port_scanner.py      ← TCP port scanner
│   ├── subdomain_scanner.py ← Subdomain enumeration
│   ├── ssl_checker.py       ← SSL/TLS analysis
│   ├── sql_injection_checker.py ← SQLi testing
│   ├── xss_checker.py       ← XSS testing
│   └── risk_analyzer.py     ← Risk scoring engine
├── utils/
│   ├── logger.py            ← Logging (file + colored console)
│   └── report_generator.py  ← PDF + JSON report generation
├── logs/                    ← Auto-created scan logs
└── reports/                 ← Auto-created PDF + JSON reports
```

---

## ⚙️ Configuration
Edit **`config.py`** to customize:
- `DEFAULT_PORTS` — ports to scan
- `SQL_PAYLOADS` — SQL injection payloads
- `XSS_PAYLOADS` — XSS payloads
- `COMMON_SUBDOMAINS` — subdomain wordlist
- `REQUEST_TIMEOUT` — HTTP timeout
- `MAX_THREADS` — parallel scan threads

---

## 📊 CLI Options
```bash
python main.py --help

Options:
  --target URL        Target URL or IP
  --skip-ports        Skip port scanning
  --skip-subdomains   Skip subdomain enumeration
  --skip-ssl          Skip SSL check
  --skip-sql          Skip SQL injection test
  --skip-xss          Skip XSS test
```

---

## 🛠️ Troubleshooting

| Error | Fix |
|-------|-----|
| `ModuleNotFoundError: colorama` | `pip install -r requirements.txt` |
| `python not recognized` | Reinstall Python, check "Add to PATH" |
| `Connection refused` | Target may be offline / firewall blocking |
| `SSL: CERTIFICATE_VERIFY_FAILED` | Normal for self-signed certs — scanner handles it |

---

## 📚 Tech Stack
- **Python 3.8+**
- `requests` — HTTP scanning
- `dnspython` — DNS queries
- `colorama` — colored terminal output
- `python-whois` — WHOIS lookups
- `reportlab` — PDF report generation
- `socket` — TCP port scanning (stdlib)
- `ssl` — SSL/TLS inspection (stdlib)
- `concurrent.futures` — multi-threaded scanning (stdlib)

---

*For educational and authorized security testing use only.*

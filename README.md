# VulScan — Python Web Vulnerability Scanner

A Python-based web and network security assessment tool for educational use and authorized security testing.

**Developer:** Sagar Kumar  
**Project type:** Cybersecurity portfolio project  
**Language:** Python  
**Platform:** Kali Linux / Linux / Windows

## Overview

VulScan is an extended fork of [VulnerabilityScanner by Majid Ansari](https://github.com/majidansari2/VulnerabilityScanner).

It combines basic web vulnerability checks, network scanning, SSL/TLS inspection, and automated reporting in a command-line application.

### Features

| Module | Functionality |
|---|---|
| URL and IP Analysis | DNS resolution, IP information, WHOIS lookup, HTTP server information |
| Port Scanner | Multi-threaded TCP port scanning |
| Subdomain Enumerator | DNS-based subdomain discovery |
| SSL/TLS Checker | Certificate and SSL/TLS analysis |
| SQL Injection Checker | Basic payload-based SQL injection checks |
| XSS Checker | Basic reflected XSS payload checks |
| Risk Analyzer | Risk scoring and security recommendations |
| Report Generator | PDF and JSON assessment reports |
| Scope Validator | Validates the initial target against explicitly configured domains or IP addresses |

### Additional modifications

- Added explicit target scope validation.
- Added command-line authorization options.
- Added tests for scope validation.
- Disabled automatic HTTP redirect following in the HTTP scanning modules.
- Restored default TLS certificate verification.
- Removed a destructive SQL injection payload from the default payload list.

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/sagarkumar05/VulScan.git
cd VulScan
```

### 2. Create a virtual environment

```bash
python3 -m venv .venv
```

### 3. Activate it

Linux / Kali Linux:

```bash
source .venv/bin/activate
```

Windows:

```powershell
.venv\Scripts\activate
```

### 4. Install dependencies

```bash
python -m pip install -r requirements.txt
```

### 5. Run the application

```bash
python main.py --help
```

## Usage

VulScan requires an explicitly configured authorized target.

### Scan an authorized IP

```bash
python main.py --target http://127.0.0.1 --allow-ip 127.0.0.1 --skip-subdomains
```

### Scan an authorized domain

```bash
python main.py --target https://example.com --allow-domain example.com --skip-subdomains
```

Only replace the example domain with a system you own or have explicit permission to test.

### Skip individual modules

```bash
python main.py \
  --target http://127.0.0.1 \
  --allow-ip 127.0.0.1 \
  --skip-subdomains \
  --skip-ports \
  --skip-ssl
```

Available options:

| Argument | Description |
|---|---|
| `--target`, `-t` | Target URL or IP |
| `--allow-domain` | Explicitly authorized domain; repeatable |
| `--allow-ip` | Explicitly authorized IP; repeatable |
| `--allow-subdomains` | Permit subdomain enumeration |
| `--skip-ports` | Skip TCP port scanning |
| `--skip-subdomains` | Skip subdomain enumeration |
| `--skip-ssl` | Skip SSL/TLS analysis |
| `--skip-sql` | Skip SQL injection checks |
| `--skip-xss` | Skip XSS checks |

Use `python main.py --help` for the complete command reference.

**Important:** Subdomain enumeration is disabled by default unless explicitly enabled. The current scope validator validates the initial target; it does not independently validate every discovered subdomain or resolved IP. Keep subdomain enumeration disabled unless you have separately established authorization for the relevant targets.

## Testing

Run the test suite:

```bash
python -m pytest -v
```

Compile-check the application:

```bash
python -m py_compile main.py
```

The current test suite contains 16 tests covering scope validation, including domain matching, IP validation, unsupported schemes, malformed URLs, and subdomain handling.

These tests do not constitute complete testing of every scanner module.

## Reports and Logs

After a successful scan, VulScan generates:

- PDF assessment report
- JSON assessment report
- Scan log

Generated files are stored in:

```text
reports/
logs/
```

## Project Structure

```text
VulScan/
├── main.py
├── config.py
├── requirements.txt
├── README.md
├── security/
│   └── scope_validator.py
├── tests/
│   └── test_scope_validator.py
├── modules/
│   ├── __init__.py
│   ├── url_ip.py
│   ├── port_scanner.py
│   ├── subdomain_scanner.py
│   ├── ssl_checker.py
│   ├── sql_injection_checker.py
│   ├── xss_checker.py
│   └── risk_analyzer.py
├── utils/
│   ├── __init__.py
│   ├── logger.py
│   └── report_generator.py
├── reports/
└── logs/
```

The root-level Python modules contain the scanner implementations; the `modules/` directory provides compatibility imports.

## Technology Stack

- Python
- Requests
- urllib3
- dnspython
- python-whois
- Colorama
- ReportLab
- Pytest
- Socket and SSL standard libraries

## Limitations

- SQL injection and XSS checks use basic payload-based techniques.
- Results require manual verification; false positives and false negatives are possible.
- The tool does not replace Burp Suite, professional penetration testing, or manual vulnerability analysis.
- Scope validation currently checks the initial target, not every DNS resolution, redirect destination, or discovered subdomain.
- Automatic HTTP redirect following is disabled.
- TLS certificate verification uses Requests' default behavior.

## Legal Disclaimer

VulScan is intended for educational purposes and authorized security assessments only.

Only scan systems you own or have explicit permission to test. You are responsible for obtaining authorization and complying with applicable laws and program rules.

## Original Project Attribution

This project is based on and extends:

[VulnerabilityScanner — Majid Ansari](https://github.com/majidansari2/VulnerabilityScanner)

Original project attribution and applicable license terms should be preserved.

---

**Maintained by Sagar Kumar**  
GitHub: https://github.com/sagarkumar05


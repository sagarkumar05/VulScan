import argparse
import sys
import os
from datetime import datetime
# Colorama use for windos terminal color
from colorama import Fore, Style, init
init(autoreset=True)

from utils.logger import setup_logger
from utils.report_generator import generate_report
from modules.url_ip import get_url_ip_info
from modules.port_scanner import scan_ports
from modules.subdomain_scanner import scan_subdomains
from modules.ssl_checker import check_ssl
from modules.sql_injection_checker import check_sql_injection
from modules.xss_checker import check_xss
from modules.risk_analyzer import analyze_risk
from config import REPORT_DIR, LOG_DIR

# Default target URL changes by you
DEFAULT_TARGET = "http://testphp.vulnweb.com"   # Acunetix ka free test site


def print_banner():
    """ASCII art banner print karta hai."""
    banner = f"""
{Fore.CYAN}{Style.BRIGHT}
╔══════════════════════════════════════════════════════════╗
║          🔒  VulnScanner — Web Vulnerability Scanner     ║
║              B.Tech Final Year Project                   ║
║         Modules: Port | SSL | SQLi | XSS | Subdomain     ║
╚══════════════════════════════════════════════════════════╝
{Style.RESET_ALL}"""
    print(banner)


def parse_args():
    parser = argparse.ArgumentParser(
        description="VulnScanner — B.Tech Final Year Web Vulnerability Scanner"
    )
    parser.add_argument(
        "--target", "-t",
        type=str,
        default=None,
        help="Target URL or IP (e.g., https://example.com)"
    )
    # if need flage then add me
    parser.add_argument("--skip-ports",    action="store_true", help="Skip port scanning")
    parser.add_argument("--skip-subdomains", action="store_true", help="Skip subdomain enumeration")
    parser.add_argument("--skip-ssl",      action="store_true", help="Skip SSL check")
    parser.add_argument("--skip-sql",      action="store_true", help="Skip SQL injection test")
    parser.add_argument("--skip-xss",      action="store_true", help="Skip XSS test")
    return parser.parse_args()


def get_target_from_user() -> str:
    print(f"\n{Fore.YELLOW}[?] Enter target URL or IP address:")
    print(f"    Examples:")
    print(f"      http://testphp.vulnweb.com    (recommended test site)")
    print(f"      https://example.com")
    print(f"      192.168.1.1")
    print(f"    Press Enter for default: {DEFAULT_TARGET}{Style.RESET_ALL}\n")

    target = input(f"{Fore.GREEN}  Target > {Style.RESET_ALL}").strip()
    if not target:
        target = DEFAULT_TARGET
        print(f"  Using default: {target}")

    # http: is add me if missing
    if not target.startswith(("http://", "https://", "ftp://")):
        target = "http://" + target
        print(f"  Auto-added http://: {target}")

    return target


def run_scan(target: str, args) -> dict:
    scan_start = datetime.now()
    logger = setup_logger(target, LOG_DIR)

    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"  TARGET : {target}")
    print(f"  STARTED: {scan_start.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}{Style.RESET_ALL}\n")

    results = {
        "target":    target,
        "scan_time": scan_start.strftime("%Y-%m-%d %H:%M:%S"),
    }

    # URL & IP Info
    print(f"\n{Fore.BLUE}[1/6] 🌐 URL & IP Analysis...{Style.RESET_ALL}")
    url_info = get_url_ip_info(target, logger)
    results["url_ip"] = url_info
    host = url_info.get("host", target)
    _print_result("IP Address", url_info.get("ip", "N/A"))
    _print_result("Server",    url_info.get("server", "N/A"))
    _print_result("WHOIS Org", url_info.get("whois_org", "N/A"))

    # Port Scan 
    print(f"\n{Fore.BLUE}[2/6] 🔌 Port Scanner...{Style.RESET_ALL}")
    if args.skip_ports:
        print(f"  {Fore.YELLOW}Skipped (--skip-ports){Style.RESET_ALL}")
        results["ports"] = {}
    else:
        port_results = scan_ports(host, logger)
        results["ports"] = port_results
        open_count = port_results.get("total_open", 0)
        _print_result("Open Ports", f"{open_count} found")
        for p in port_results.get("open_ports", []):
            print(f"    {Fore.GREEN}↳ Port {p['port']:5d}  {p['service']}{Style.RESET_ALL}")

    # Subdomain Scan 
    print(f"\n{Fore.BLUE}[3/6] 🗺️  Subdomain Enumeration...{Style.RESET_ALL}")
    if args.skip_subdomains:
        print(f"  {Fore.YELLOW}Skipped (--skip-subdomains){Style.RESET_ALL}")
        results["subdomains"] = {}
    else:
        sub_results = scan_subdomains(host, logger)
        results["subdomains"] = sub_results
        _print_result("Subdomains Found", sub_results.get("total_found", 0))
        for s in sub_results.get("found", [])[:5]:   # sirf pehle 5 print karo
            print(f"    {Fore.GREEN}↳ {s['subdomain']}  ({s['ip']}){Style.RESET_ALL}")
        if sub_results.get("total_found", 0) > 5:
            print(f"    {Fore.YELLOW}  ... and {sub_results['total_found'] - 5} more (see report){Style.RESET_ALL}")

    # SSL Check 
    print(f"\n{Fore.BLUE}[4/6] 🔐 SSL/TLS Analysis...{Style.RESET_ALL}")
    if args.skip_ssl:
        print(f"  {Fore.YELLOW}Skipped (--skip-ssl){Style.RESET_ALL}")
        results["ssl"] = {}
    else:
        ssl_results = check_ssl(host, logger)
        results["ssl"] = ssl_results
        _print_result("SSL Enabled",   ssl_results.get("ssl_enabled", False))
        _print_result("Version",       ssl_results.get("version", "N/A"))
        _print_result("Issuer",        ssl_results.get("issuer", "N/A"))
        _print_result("Expires",       ssl_results.get("expires", "N/A"))
        _print_result("Days Left",     ssl_results.get("days_remaining", "N/A"))
        for issue in ssl_results.get("issues", []):
            print(f"    {Fore.RED}⚠ {issue}{Style.RESET_ALL}")

    # SQL Injection 
    print(f"\n{Fore.BLUE}[5/6] 💉 SQL Injection Test...{Style.RESET_ALL}")
    if args.skip_sql:
        print(f"  {Fore.YELLOW}Skipped (--skip-sql){Style.RESET_ALL}")
        results["sql"] = {}
    else:
        sql_results = check_sql_injection(target, logger)
        results["sql"] = sql_results
        vuln_text = (
            f"{Fore.RED}⚠ VULNERABLE — {len(sql_results['findings'])} finding(s){Style.RESET_ALL}"
            if sql_results["vulnerable"]
            else f"{Fore.GREEN}✓ Not Vulnerable{Style.RESET_ALL}"
        )
        print(f"  Result: {vuln_text}")

    #  XSS 
    print(f"\n{Fore.BLUE}[6/6] ⚡ XSS Test...{Style.RESET_ALL}")
    if args.skip_xss:
        print(f"  {Fore.YELLOW}Skipped (--skip-xss){Style.RESET_ALL}")
        results["xss"] = {}
    else:
        xss_results = check_xss(target, logger)
        results["xss"] = xss_results
        vuln_text = (
            f"{Fore.RED}⚠ VULNERABLE — {len(xss_results['findings'])} finding(s){Style.RESET_ALL}"
            if xss_results["vulnerable"]
            else f"{Fore.GREEN}✓ Not Vulnerable{Style.RESET_ALL}"
        )
        print(f"  Result: {vuln_text}")

    # Risk Analysis
    print(f"\n{Fore.MAGENTA}{'='*60}")
    print(f"  ⚠️  RISK ANALYSIS")
    print(f"{'='*60}{Style.RESET_ALL}")

    risk = analyze_risk(results, logger)
    results["risk"]         = risk
    results["overall_risk"] = risk.get("overall_risk", "N/A")

    print(f"\n  Overall Risk : {Fore.RED if 'CRITICAL' in str(risk['overall_risk']) else Fore.YELLOW}{risk['overall_risk']}{Style.RESET_ALL}")
    print(f"  Score        : {risk['score']}/100")
    print(f"\n  Recommendations:")
    for rec in risk.get("recommendations", []):
        print(f"    • {rec}")

    # Scan duration 
    duration = (datetime.now() - scan_start).seconds
    results["duration_seconds"] = duration
    print(f"\n{Fore.CYAN}  Scan completed in {duration}s{Style.RESET_ALL}")

    return results


def _print_result(label: str, value):
    """Formatted key-value print helper."""
    print(f"  {Fore.WHITE}{label:<18}{Style.RESET_ALL}: {value}")


def main():
    print_banner()
    args = parse_args()

    # Target determining
    if args.target:
        target = args.target
        if not target.startswith(("http://", "https://")):
            target = "http://" + target
    else:
        target = get_target_from_user()

    # Safety disclaimer 
    print(f"\n{Fore.RED}{'!'*60}")
    print(f"  ⚠  LEGAL DISCLAIMER")
    print(f"  Scan ONLY targets you own or have explicit permission to test.")
    print(f"  Unauthorized scanning is illegal.")
    print(f"{'!'*60}{Style.RESET_ALL}\n")

    confirm = input(f"{Fore.YELLOW}  Continue? (yes/no): {Style.RESET_ALL}").strip().lower()
    if confirm not in ("yes", "y"):
        print("  Scan cancelled.")
        sys.exit(0)

    # Run scan 
    try:
        results = run_scan(target, args)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}  Scan interrupted by user.{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}  Scan failed: {e}{Style.RESET_ALL}")
        raise

    # Generate Reports 
    print(f"\n{Fore.CYAN}  Generating reports...{Style.RESET_ALL}")
    os.makedirs(REPORT_DIR, exist_ok=True)
    try:
        report_paths = generate_report(results, REPORT_DIR)
        print(f"\n  {Fore.GREEN}✓ PDF Report  : {report_paths['pdf']}{Style.RESET_ALL}")
        print(f"  {Fore.GREEN}✓ JSON Report : {report_paths['json']}{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n  {Fore.RED}Report generation failed: {e}{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}Hint: Run 'pip install reportlab' to fix this{Style.RESET_ALL}")

    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"  ✅ Scan Complete! Check the 'reports/' folder.")
    print(f"{'='*60}{Style.RESET_ALL}\n")


if __name__ == "__main__":
    main()


import argparse
import sys
import os
from datetime import datetime

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
from security.scope_validator import ScopeValidator, ScopeValidationError

from config import REPORT_DIR, LOG_DIR


DEFAULT_TARGET = "http://testphp.vulnweb.com"


def print_banner():
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
        description="VulnScanner — Web Vulnerability Scanner"
    )

    parser.add_argument(
        "--target", "-t",
        type=str,
        default=None,
        help="Target URL or IP address"
    )

    parser.add_argument(
        "--allow-domain",
        action="append",
        default=[],
        help="Explicitly authorized domain. Can be repeated."
    )

    parser.add_argument(
        "--allow-ip",
        action="append",
        default=[],
        help="Explicitly authorized IP address. Can be repeated."
    )

    parser.add_argument(
        "--allow-subdomains",
        action="store_true",
        help="Allow subdomains of explicitly authorized domains"
    )

    parser.add_argument(
        "--skip-ports",
        action="store_true",
        help="Skip port scanning"
    )

    parser.add_argument(
        "--skip-subdomains",
        action="store_true",
        help="Skip subdomain enumeration"
    )

    parser.add_argument(
        "--skip-ssl",
        action="store_true",
        help="Skip SSL check"
    )

    parser.add_argument(
        "--skip-sql",
        action="store_true",
        help="Skip SQL injection test"
    )

    parser.add_argument(
        "--skip-xss",
        action="store_true",
        help="Skip XSS test"
    )

    return parser.parse_args()


def get_target_from_user() -> str:
    print(f"\n{Fore.YELLOW}[?] Enter target URL or IP address:")
    print("    Example: http://127.0.0.1")
    print("    Example: https://example.com")
    print(f"    Press Enter for default: {DEFAULT_TARGET}{Style.RESET_ALL}\n")

    target = input(
        f"{Fore.GREEN}  Target > {Style.RESET_ALL}"
    ).strip()

    if not target:
        target = DEFAULT_TARGET
        print(f"  Using default: {target}")

    if not target.startswith(("http://", "https://")):
        target = "http://" + target
        print(f"  Auto-added http://: {target}")

    return target


def validate_target_scope(target: str, args):
    if not args.allow_domain and not args.allow_ip:
        raise ScopeValidationError(
            "No authorized scope provided. Specify --allow-domain or --allow-ip."
        )

    if not args.skip_subdomains and not args.allow_subdomains:
        raise ScopeValidationError(
            "Subdomain scanning requires --allow-subdomains. "
            "Alternatively, use --skip-subdomains."
        )

    scope = ScopeValidator(
        allowed_domains=args.allow_domain,
        allowed_ips=args.allow_ip,
        allow_subdomains=args.allow_subdomains
    )

    scope.validate(target)


def run_scan(target: str, args) -> dict:
    scan_start = datetime.now()
    logger = setup_logger(target, LOG_DIR)

    print(f"\n{Fore.CYAN}{'=' * 60}")
    print(f"  TARGET : {target}")
    print(f"  STARTED: {scan_start.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'=' * 60}{Style.RESET_ALL}\n")

    results = {
        "target": target,
        "scan_time": scan_start.strftime("%Y-%m-%d %H:%M:%S"),
    }

    # 1. URL and IP information
    print(f"\n{Fore.BLUE}[1/6] URL & IP Analysis...{Style.RESET_ALL}")

    url_info = get_url_ip_info(target, logger)
    results["url_ip"] = url_info

    host = url_info.get("host")

    if not host:
        raise RuntimeError("Could not determine target hostname.")

    _print_result("IP Address", url_info.get("ip", "N/A"))
    _print_result("Server", url_info.get("server", "N/A"))
    _print_result("WHOIS Org", url_info.get("whois_org", "N/A"))

    # 2. Port scanning
    print(f"\n{Fore.BLUE}[2/6] Port Scanner...{Style.RESET_ALL}")

    if args.skip_ports:
        print(f"  {Fore.YELLOW}Skipped (--skip-ports){Style.RESET_ALL}")
        results["ports"] = {}
    else:
        port_results = scan_ports(host, logger)
        results["ports"] = port_results

        _print_result(
            "Open Ports",
            f"{port_results.get('total_open', 0)} found"
        )

        for port in port_results.get("open_ports", []):
            print(
                f"    {Fore.GREEN}Port {port['port']:5d} "
                f"{port['service']}{Style.RESET_ALL}"
            )

    # 3. Subdomain enumeration
    print(f"\n{Fore.BLUE}[3/6] Subdomain Enumeration...{Style.RESET_ALL}")

    if args.skip_subdomains:
        print(f"  {Fore.YELLOW}Skipped (--skip-subdomains){Style.RESET_ALL}")
        results["subdomains"] = {}
    else:
        sub_results = scan_subdomains(host, logger)
        results["subdomains"] = sub_results

        _print_result(
            "Subdomains Found",
            sub_results.get("total_found", 0)
        )

        for subdomain in sub_results.get("found", [])[:5]:
            print(
                f"    {Fore.GREEN}{subdomain['subdomain']} "
                f"({subdomain['ip']}){Style.RESET_ALL}"
            )

        if sub_results.get("total_found", 0) > 5:
            print(
                f"    {Fore.YELLOW}...and "
                f"{sub_results['total_found'] - 5} more{Style.RESET_ALL}"
            )

    # 4. SSL/TLS analysis
    print(f"\n{Fore.BLUE}[4/6] SSL/TLS Analysis...{Style.RESET_ALL}")

    if args.skip_ssl:
        print(f"  {Fore.YELLOW}Skipped (--skip-ssl){Style.RESET_ALL}")
        results["ssl"] = {}
    else:
        ssl_results = check_ssl(host, logger)
        results["ssl"] = ssl_results

        _print_result(
            "SSL Enabled",
            ssl_results.get("ssl_enabled", False)
        )
        _print_result("Version", ssl_results.get("version", "N/A"))
        _print_result("Issuer", ssl_results.get("issuer", "N/A"))
        _print_result("Expires", ssl_results.get("expires", "N/A"))
        _print_result(
            "Days Left",
            ssl_results.get("days_remaining", "N/A")
        )

        for issue in ssl_results.get("issues", []):
            print(f"    {Fore.RED}WARNING: {issue}{Style.RESET_ALL}")

    # 5. SQL injection testing
    print(f"\n{Fore.BLUE}[5/6] SQL Injection Test...{Style.RESET_ALL}")

    if args.skip_sql:
        print(f"  {Fore.YELLOW}Skipped (--skip-sql){Style.RESET_ALL}")
        results["sql"] = {}
    else:
        sql_results = check_sql_injection(target, logger)
        results["sql"] = sql_results

        findings = sql_results.get("findings", [])

        if sql_results.get("vulnerable", False):
            print(
                f"  {Fore.RED}VULNERABLE — "
                f"{len(findings)} finding(s){Style.RESET_ALL}"
            )
        else:
            print(f"  {Fore.GREEN}No SQLi detected{Style.RESET_ALL}")

    # 6. Cross-site scripting testing
    print(f"\n{Fore.BLUE}[6/6] XSS Test...{Style.RESET_ALL}")

    if args.skip_xss:
        print(f"  {Fore.YELLOW}Skipped (--skip-xss){Style.RESET_ALL}")
        results["xss"] = {}
    else:
        xss_results = check_xss(target, logger)
        results["xss"] = xss_results

        findings = xss_results.get("findings", [])

        if xss_results.get("vulnerable", False):
            print(
                f"  {Fore.RED}VULNERABLE — "
                f"{len(findings)} finding(s){Style.RESET_ALL}"
            )
        else:
            print(f"  {Fore.GREEN}No XSS detected{Style.RESET_ALL}")

    # Risk analysis
    print(f"\n{Fore.MAGENTA}{'=' * 60}")
    print("  RISK ANALYSIS")
    print(f"{'=' * 60}{Style.RESET_ALL}")

    risk = analyze_risk(results, logger)

    results["risk"] = risk
    results["overall_risk"] = risk.get("overall_risk", "N/A")

    print(f"\n  Overall Risk: {results['overall_risk']}")
    print(f"  Score: {risk.get('score', 'N/A')}/100")

    print("\n  Recommendations:")

    for recommendation in risk.get("recommendations", []):
        print(f"    - {recommendation}")

    duration = int((datetime.now() - scan_start).total_seconds())
    results["duration_seconds"] = duration

    print(f"\n{Fore.CYAN}  Scan completed in {duration}s{Style.RESET_ALL}")

    return results


def _print_result(label: str, value):
    print(
        f"  {Fore.WHITE}{label:<18}{Style.RESET_ALL}: {value}"
    )


def main():
    print_banner()
    args = parse_args()

    if args.target:
        target = args.target.strip()

        if not target.startswith(("http://", "https://")):
            target = "http://" + target
    else:
        target = get_target_from_user()

    # Mandatory scope validation before any scanning activity
    try:
        validate_target_scope(target, args)

    except ScopeValidationError as error:
        print(
            f"\n{Fore.RED}[SCOPE BLOCKED] {error}{Style.RESET_ALL}"
        )
        sys.exit(1)

    print(
        f"\n{Fore.GREEN}[SCOPE OK] "
        f"Target is inside the configured scope.{Style.RESET_ALL}"
    )

    # Legal disclaimer
    print(f"\n{Fore.RED}{'!' * 60}")
    print("  LEGAL DISCLAIMER")
    print("  Scan only systems you own or have explicit permission to test.")
    print("  Unauthorized scanning may be illegal.")
    print(f"{'!' * 60}{Style.RESET_ALL}\n")

    confirm = input(
        f"{Fore.YELLOW}  Continue? (yes/no): {Style.RESET_ALL}"
    ).strip().lower()

    if confirm not in ("yes", "y"):
        print("  Scan cancelled.")
        sys.exit(0)

    try:
        results = run_scan(target, args)

    except KeyboardInterrupt:
        print(
            f"\n{Fore.YELLOW}Scan interrupted by user.{Style.RESET_ALL}"
        )
        sys.exit(0)

    except Exception as error:
        print(
            f"\n{Fore.RED}Scan failed: {error}{Style.RESET_ALL}"
        )
        sys.exit(1)

    # Generate PDF and JSON reports
    print(f"\n{Fore.CYAN}Generating reports...{Style.RESET_ALL}")

    os.makedirs(REPORT_DIR, exist_ok=True)

    try:
        report_paths = generate_report(results, REPORT_DIR)

        print(
            f"\n  {Fore.GREEN}PDF Report: "
            f"{report_paths['pdf']}{Style.RESET_ALL}"
        )

        print(
            f"  {Fore.GREEN}JSON Report: "
            f"{report_paths['json']}{Style.RESET_ALL}"
        )

    except Exception as error:
        print(
            f"\n{Fore.RED}Report generation failed: {error}{Style.RESET_ALL}"
        )
        sys.exit(1)

    print(f"\n{Fore.CYAN}{'=' * 60}")
    print("  Scan complete! Check the reports/ folder.")
    print(f"{'=' * 60}{Style.RESET_ALL}\n")


if __name__ == "__main__":
    main()

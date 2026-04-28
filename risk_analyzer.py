import logging


# Risk score weights , if any risk can optimize then change its weight here
WEIGHTS = {
    "sql_vulnerable":     40,   # SQL injection — critical
    "xss_vulnerable":     30,   # XSS — high
    "ssl_expired":        25,   # Expired SSL cert — high
    "ssl_self_signed":    15,   # Self-signed cert — medium
    "ssl_weak_protocol":  20,   # Old TLS/SSL protocol — high
    "ssl_disabled":       20,   # No SSL at all — high
    "dangerous_port":     10,   # Per dangerous open port
    "many_subdomains":    10,   # Too many exposed subdomains
}

# Risk level thresholds, if Thresholds adjust then change these values according to your needs
RISK_LEVELS = [
    (0,  19,  "LOW",      "🟢"),
    (20, 49,  "MEDIUM",   "🟡"),
    (50, 79,  "HIGH",     "🔴"),
    (80, 999, "CRITICAL", "💀"),
]


def analyze_risk(scan_results: dict, logger: logging.Logger) -> dict:
    """
    Saare module results ko combine karke risk score calculate karta hai.
    
    Args:
        scan_results: Dict containing results from all modules
        logger: Logger instance
    
    Returns:
        dict with: overall_risk, score, breakdown, recommendations
    """
    logger.info("[Risk] Analyzing overall risk posture...")

    score = 0
    breakdown = {}
    recommendations = []

    # SQL Injection
    sql_result = scan_results.get("sql", {})
    sql_vuln = sql_result.get("vulnerable", False)
    if sql_vuln:
        score += WEIGHTS["sql_vulnerable"]
        breakdown["SQL Injection"] = f"+{WEIGHTS['sql_vulnerable']} (Critical)"
        recommendations.append(
            "🔴 SQL Injection: Use parameterized queries / prepared statements. "
            "Never concatenate user input into SQL strings."
        )

    # XSS
    xss_result = scan_results.get("xss", {})
    xss_vuln = xss_result.get("vulnerable", False)
    if xss_vuln:
        score += WEIGHTS["xss_vulnerable"]
        breakdown["XSS"] = f"+{WEIGHTS['xss_vulnerable']} (High)"
        recommendations.append(
            "🔴 XSS: Sanitize and encode all user input before rendering. "
            "Implement Content Security Policy (CSP) headers."
        )

    #  SSL/TLS
    ssl_result = scan_results.get("ssl", {})
    if ssl_result:
        if ssl_result.get("expired"):
            score += WEIGHTS["ssl_expired"]
            breakdown["SSL Expired"] = f"+{WEIGHTS['ssl_expired']} (High)"
            recommendations.append("🔴 SSL: Certificate expired — renew immediately!")

        if ssl_result.get("self_signed"):
            score += WEIGHTS["ssl_self_signed"]
            breakdown["Self-Signed Cert"] = f"+{WEIGHTS['ssl_self_signed']} (Medium)"
            recommendations.append(
                "🟡 SSL: Replace self-signed certificate with a trusted CA certificate "
                "(e.g., Let's Encrypt)."
            )

        if ssl_result.get("weak_protocol"):
            score += WEIGHTS["ssl_weak_protocol"]
            breakdown["Weak Protocol"] = f"+{WEIGHTS['ssl_weak_protocol']} (High)"
            recommendations.append(
                f"🔴 SSL: Weak protocol {ssl_result.get('version')} in use. "
                "Upgrade to TLS 1.2 or TLS 1.3."
            )

        if not ssl_result.get("ssl_enabled", True):
            score += WEIGHTS["ssl_disabled"]
            breakdown["No SSL"] = f"+{WEIGHTS['ssl_disabled']} (High)"
            recommendations.append(
                "🔴 SSL: No HTTPS detected. Install SSL certificate and force HTTPS redirects."
            )

    # Port Scanner
    port_result = scan_results.get("ports", {})
    dangerous_open = port_result.get("dangerous_open", [])
    if dangerous_open:
        port_score = len(dangerous_open) * WEIGHTS["dangerous_port"]
        score += port_score
        breakdown["Dangerous Ports"] = f"+{port_score} ({len(dangerous_open)} dangerous ports)"
        port_advice = {
            21:   "FTP (21): Disable FTP, use SFTP instead",
            23:   "Telnet (23): Disable Telnet, use SSH instead",
            135:  "MS-RPC (135): Close if not needed, firewall it",
            139:  "NetBIOS (139): Disable NetBIOS over TCP if not needed",
            445:  "SMB (445): Firewall port 445 from internet — ransomware target!",
            3389: "RDP (3389): Change port or VPN-gate it — brute force target!",
            5900: "VNC (5900): Firewall and password-protect VNC access",
        }
        for dp in dangerous_open:
            if dp in port_advice:
                recommendations.append(f"🔴 Port {dp}: {port_advice[dp]}")

    # ── Subdomains ────────────────────────────────────────────────────────────
    sub_result = scan_results.get("subdomains", {})
    total_subs = sub_result.get("total_found", 0)
    if total_subs > 10:
        score += WEIGHTS["many_subdomains"]
        breakdown["Many Subdomains"] = f"+{WEIGHTS['many_subdomains']} ({total_subs} found)"
        recommendations.append(
            f"🟡 Subdomains: {total_subs} subdomains exposed. "
            "Audit and remove unused/test subdomains."
        )

    # Cap score at 100
    score = min(score, 100)

    # Determine risk level
    risk_label = "LOW"
    risk_emoji = "🟢"
    for low, high, label, emoji in RISK_LEVELS:
        if low <= score <= high:
            risk_label = label
            risk_emoji = emoji
            break

    if not recommendations:
        recommendations.append(
            "✅ No critical issues found. Keep dependencies updated and monitor regularly."
        )

    logger.info(f"[Risk] Score: {score}/100 | Level: {risk_emoji} {risk_label}")
    for item, pts in breakdown.items():
        logger.info(f"[Risk]   {item}: {pts}")

    return {
        "overall_risk":        f"{risk_emoji} {risk_label}",
        "score":               score,
        "breakdown":           breakdown,
        "recommendations":     recommendations,
        "sql_vulnerable":      sql_vuln,
        "xss_vulnerable":      xss_vuln,
        "ssl_issues":          bool(ssl_result.get("issues")),
        "open_ports_count":    port_result.get("total_open", 0),
        "subdomains_count":    total_subs,
    }

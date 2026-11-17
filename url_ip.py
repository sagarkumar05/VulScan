import socket
import logging
from urllib.parse import urlparse

from config import HEADERS, REQUEST_TIMEOUT

try:
    import requests
except ImportError:
    requests = None  # type: ignore

try:
    import whois as python_whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False


def get_url_ip_info(target: str, logger: logging.Logger) -> dict:
    logger.info(f"[URL/IP] Starting URL & IP analysis for: {target}")
    result = {
        "url": target,
        "host": "",
        "ip": "",
        "whois_org": "N/A",
        "whois_country": "N/A",
        "server": "N/A",
        "status_code": "N/A",
        "error": None,
    }
    parsed = urlparse(target)
    host = parsed.netloc or parsed.path  
    host = host.split(":")[0].strip()
    result["host"] = host

    # DNS lookup 
    try:
        ip = socket.gethostbyname(host)
        result["ip"] = ip
        logger.info(f"[URL/IP] Resolved {host} → {ip}")
    except socket.gaierror as e:
        result["error"] = f"DNS resolution failed: {e}"
        logger.warning(f"[URL/IP] DNS failed for {host}: {e}")
        return result

    # HTTP HEAD request for server info 
    if requests:
        try:
            resp = requests.head(
                target, headers=HEADERS,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=False,
            )
            result["status_code"] = resp.status_code
            result["server"] = resp.headers.get("Server", "N/A")
            logger.info(f"[URL/IP] HTTP {resp.status_code} | Server: {result['server']}")
        except Exception as e:
            logger.warning(f"[URL/IP] HTTP request failed: {e}")

    #  WHOIS lookup , WHOIS se aur fields chahiye then seen python_whois.whois(host) output
    if WHOIS_AVAILABLE:
        try:
            w = python_whois.whois(host)
            result["whois_org"]     = str(getattr(w, "org", "N/A") or "N/A")[:100]
            result["whois_country"] = str(getattr(w, "country", "N/A") or "N/A")
            logger.info(f"[URL/IP] WHOIS: org={result['whois_org']}, country={result['whois_country']}")
        except Exception as e:
            logger.warning(f"[URL/IP] WHOIS lookup failed: {e}")
    else:
        logger.warning("[URL/IP] python-whois not installed, skipping WHOIS")

    return result

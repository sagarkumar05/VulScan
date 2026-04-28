import socket
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

from config import COMMON_SUBDOMAINS, MAX_THREADS


def scan_subdomains(domain: str, logger: logging.Logger,
                    wordlist: list = None) -> dict:

    domain = domain.replace("http://", "").replace("https://", "").split("/")[0]

    if wordlist is None:
        wordlist = COMMON_SUBDOMAINS

    logger.info(f"[Subdomain] Checking {len(wordlist)} subdomains for {domain}")

    found = []

    def check_subdomain(sub: str) -> dict | None:
        """Single subdomain DNS check."""
        full = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(full)
            return {"subdomain": full, "ip": ip}
        except socket.gaierror:
            return None

    # Parallel DNS resolution 
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {executor.submit(check_subdomain, sub): sub for sub in wordlist}
        for future in as_completed(futures):
            res = future.result()
            if res:
                found.append(res)
                logger.info(f"[Subdomain] FOUND → {res['subdomain']} ({res['ip']})")

    # Sort alphabetically
    found.sort(key=lambda x: x["subdomain"])

    logger.info(f"[Subdomain] Done. {len(found)}/{len(wordlist)} subdomains found.")

    return {
        "found":         found,
        "total_checked": len(wordlist),
        "total_found":   len(found),
    }

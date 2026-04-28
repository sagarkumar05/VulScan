import logging
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import requests
import urllib3

from config import (
    SQL_PAYLOADS, SQL_ERROR_SIGNATURES,
    HEADERS, REQUEST_TIMEOUT
)

# SSL warnings suppress
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def check_sql_injection(url: str, logger: logging.Logger) -> dict:
    logger.info(f"[SQLi] Starting SQL injection test on: {url}")

    result = {
        "vulnerable":    False,
        "findings":      [],
        "tested_params": [],
        "error":         None,
    }
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    if not params:
        # if query parameter is not available then check simple error
        logger.info("[SQLi] No query parameters found — doing basic URL injection test")
        test_url = url.rstrip("/") + "?"
        for payload in SQL_PAYLOADS[:3]:
            try:
                r = requests.get(
                    test_url + payload,
                    headers=HEADERS, timeout=REQUEST_TIMEOUT,
                    verify=False, allow_redirects=True
                )
                if _check_sql_errors(r.text):
                    result["vulnerable"] = True
                    result["findings"].append({
                        "url":      test_url + payload,
                        "parameter": "URL",
                        "payload":   payload,
                        "evidence":  _extract_error_snippet(r.text)
                    })
                    logger.warning(f"[SQLi] ⚠ Potential SQLi via URL: payload='{payload}'")
            except Exception as e:
                logger.debug(f"[SQLi] Request failed: {e}")
        return result

    result["tested_params"] = list(params.keys())
    logger.info(f"[SQLi] Testing parameters: {result['tested_params']}")

    # Test each parameter with each payload 
    for param_name in params:
        for payload in SQL_PAYLOADS:
            # Original params copy and one parameter is injected with payload
            test_params = {k: v[0] for k, v in params.items()}
            test_params[param_name] = payload
            new_query = urlencode(test_params)
            test_url = urlunparse(parsed._replace(query=new_query))

            try:
                response = requests.get(
                    test_url,
                    headers=HEADERS,
                    timeout=REQUEST_TIMEOUT,
                    verify=False,
                    allow_redirects=True,
                )
                response_text = response.text.lower()

                if _check_sql_errors(response_text):
                    result["vulnerable"] = True
                    finding = {
                        "url":       test_url,
                        "parameter": param_name,
                        "payload":   payload,
                        "evidence":  _extract_error_snippet(response.text),
                    }
                    result["findings"].append(finding)
                    logger.warning(
                        f"[SQLi] ⚠ VULNERABLE! param='{param_name}', payload='{payload}'"
                    )
                    break

            except requests.exceptions.Timeout:
                logger.debug(f"[SQLi] Timeout for param='{param_name}', payload='{payload}'")
            except Exception as e:
                logger.debug(f"[SQLi] Error: {e}")

    if not result["vulnerable"]:
        logger.info("[SQLi] ✓ No SQL injection vulnerabilities detected")
    else:
        logger.warning(f"[SQLi] {len(result['findings'])} SQLi finding(s) confirmed!")

    return result


def _check_sql_errors(response_text: str) -> bool:
    """Response mein SQL error messages dhundta hai."""
    text_lower = response_text.lower()
    return any(sig in text_lower for sig in SQL_ERROR_SIGNATURES)


def _extract_error_snippet(response_text: str, max_len: int = 200) -> str:
    """Response se relevant error snippet extract karta hai."""
    text_lower = response_text.lower()
    for sig in SQL_ERROR_SIGNATURES:
        idx = text_lower.find(sig)
        if idx != -1:
            start = max(0, idx - 50)
            end   = min(len(response_text), idx + max_len)
            return response_text[start:end].strip()
    return "Error pattern found in response"
